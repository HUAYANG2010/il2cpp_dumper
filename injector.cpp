//
// injector.cpp  --  ptrace 远程调用实现（arm64 / arm）
//
// 思路：
//   1. PTRACE_ATTACH 停住目标进程某个线程
//   2. 保存寄存器，把 PC 处的指令临时改成断点指令（brk / bkpt），
//      把 LR 指向这条断点，这样函数返回时会落回断点让我们捕获
//   3. 设置 PC = 目标函数，参数寄存器 = 实参，PTRACE_CONT 让它跑
//   4. 命中断点后读取 x0/r0 即返回值，恢复原指令与寄存器
//
// 用它在目标进程里调用 dlopen("/path/to/payload.so", RTLD_NOW)，
// payload 的 constructor 会在目标进程内启动 dump 线程。
//
#include "injector.h"

#include <elf.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>

#include <cerrno>
#include <cinttypes>
#include <csignal>
#include <cstdio>
#include <cstring>
#include <ctime>

#include "elf_remote.h"
#include "log.h"
#include "proc_maps.h"

#ifndef PTRACE_GETREGS
#define PTRACE_GETREGS 12
#define PTRACE_SETREGS 13
#endif
#ifndef PTRACE_GETREGSET
#define PTRACE_GETREGSET 0x4204
#endif
#ifndef PTRACE_SETREGSET
#define PTRACE_SETREGSET 0x4205
#endif

namespace injector {
namespace {

constexpr int kMaxWaitIterations = 60000;  // 60s（1ms 一次）

bool attachProcess(pid_t pid, std::string* error) {
    if (ptrace(PTRACE_ATTACH, pid, nullptr, nullptr) < 0) {
        error->assign("PTRACE_ATTACH 失败: ").append(strerror(errno));
        return false;
    }
    int status = 0;
    if (waitpid(pid, &status, __WALL) < 0) {
        error->assign("waitpid 失败");
        ptrace(PTRACE_DETACH, pid, nullptr, nullptr);
        return false;
    }
    if (!WIFSTOPPED(status)) {
        error->assign("目标进程未进入停止状态");
        ptrace(PTRACE_DETACH, pid, nullptr, nullptr);
        return false;
    }
    return true;
}

void detachProcess(pid_t pid) {
    ptrace(PTRACE_DETACH, pid, nullptr, nullptr);
}

#if defined(__aarch64__)

// ---------------------------------------------------------------
//  arm64
// ---------------------------------------------------------------
struct Regs {
    uint64_t regs[31];
    uint64_t sp;
    uint64_t pc;
    uint64_t pstate;
};

bool getRegs(pid_t pid, Regs* r) {
    iovec io{ r, sizeof(*r) };
    return ptrace(PTRACE_GETREGSET, pid, (void*)NT_PRSTATUS, &io) == 0;
}

bool setRegs(pid_t pid, const Regs* r) {
    iovec io{ const_cast<Regs*>(r), sizeof(*r) };
    return ptrace(PTRACE_SETREGSET, pid, (void*)NT_PRSTATUS, &io) == 0;
}

bool remoteCall(pid_t pid, RemoteMemory& mem, uintptr_t func, const uintptr_t* args,
                int nargs, uintptr_t* out, std::string* error) {
    Regs saved{};
    if (!getRegs(pid, &saved)) {
        *error = "PTRACE_GETREGSET 失败";
        return false;
    }

    const uintptr_t trapAddr = saved.pc;
    uint32_t origInsn = 0;
    if (!mem.read(trapAddr, &origInsn, sizeof(origInsn))) {
        *error = "读取目标线程原指令失败";
        return false;
    }
    const uint32_t brkInsn = 0xD4200000u;  // brk #0
    if (!mem.write(trapAddr, &brkInsn, sizeof(brkInsn))) {
        *error = "写入断点指令失败";
        return false;
    }

    Regs regs = saved;
    for (int i = 0; i < 8; ++i) regs.regs[i] = (i < nargs) ? args[i] : 0;
    regs.regs[30] = trapAddr;                 // lr -> 断点
    regs.pc = func;
    regs.sp = (saved.sp - 0x1000) & ~(uint64_t)0xF;  // 给被调用函数留栈空间

    bool ok = false;
    std::string fail;

    if (!setRegs(pid, &regs)) {
        fail = "PTRACE_SETREGSET 失败";
    } else if (ptrace(PTRACE_CONT, pid, nullptr, nullptr) < 0) {
        fail = "PTRACE_CONT 失败";
    } else {
        for (int i = 0; i < kMaxWaitIterations; ++i) {
            int status = 0;
            pid_t r = waitpid(pid, &status, __WALL | WNOHANG);
            if (r == 0) {
                usleep(1000);
                continue;
            }
            if (r < 0) {
                fail = "waitpid 失败";
                break;
            }
            if (WIFEXITED(status) || WIFSIGNALED(status)) {
                fail = "目标进程在远程调用期间退出";
                break;
            }
            if (!WIFSTOPPED(status)) continue;

            const int sig = WSTOPSIG(status);
            Regs cur{};
            if (!getRegs(pid, &cur)) {
                fail = "读取寄存器失败";
                break;
            }
            if (cur.pc == trapAddr) {
                *out = cur.regs[0];
                ok = true;
                break;
            }
            // 不是我们埋的断点，把信号转发回去继续等
            const int deliver = (sig == SIGTRAP || sig == SIGSTOP) ? 0 : sig;
            ptrace(PTRACE_CONT, pid, nullptr, (void*)(long)deliver);
        }
        if (!ok && fail.empty()) fail = "等待远程调用返回超时";
    }

    // 恢复现场
    mem.write(trapAddr, &origInsn, sizeof(origInsn));
    setRegs(pid, &saved);

    if (!ok) *error = fail;
    return ok;
}

#elif defined(__arm__)

// ---------------------------------------------------------------
//  arm (32 位)
// ---------------------------------------------------------------
struct Regs {
    uint32_t uregs[18];
};

enum { REG_SP = 13, REG_LR = 14, REG_PC = 15, REG_CPSR = 16 };
constexpr uint32_t kCpsrThumbBit = 0x20;

bool getRegs(pid_t pid, Regs* r) {
    return ptrace(PTRACE_GETREGS, pid, nullptr, r) == 0;
}

bool setRegs(pid_t pid, const Regs* r) {
    return ptrace(PTRACE_SETREGS, pid, nullptr, const_cast<Regs*>(r)) == 0;
}

bool remoteCall(pid_t pid, RemoteMemory& mem, uintptr_t func, const uintptr_t* args,
                int nargs, uintptr_t* out, std::string* error) {
    Regs saved{};
    if (!getRegs(pid, &saved)) {
        *error = "PTRACE_GETREGS 失败";
        return false;
    }

    const uintptr_t trapAddr = saved.uregs[REG_PC];
    const bool trapThumb = (saved.uregs[REG_CPSR] & kCpsrThumbBit) != 0;
    uint32_t origInsn = 0;
    if (!mem.read(trapAddr, &origInsn, sizeof(origInsn))) {
        *error = "读取目标线程原指令失败";
        return false;
    }
    uint32_t brkInsn = trapThumb ? ((origInsn & 0xFFFF0000u) | 0xBE00u)  // thumb: bkpt #0
                                 : 0xE1200070u;                          // arm:   bkpt #0
    if (!mem.write(trapAddr, &brkInsn, sizeof(brkInsn))) {
        *error = "写入断点指令失败";
        return false;
    }

    Regs regs = saved;
    for (int i = 0; i < 4; ++i) regs.uregs[i] = (i < nargs) ? args[i] : 0;
    regs.uregs[REG_LR] = trapAddr;
    // 目标函数是否为 Thumb（ARM 下 st_value 最低位为 1 表示 Thumb 函数）
    const bool funcThumb = (func & 1u) != 0;
    regs.uregs[REG_PC] = (uint32_t)(func & ~(uintptr_t)1u);
    if (funcThumb) regs.uregs[REG_CPSR] |= kCpsrThumbBit;
    else regs.uregs[REG_CPSR] &= ~kCpsrThumbBit;
    regs.uregs[REG_SP] = (saved.uregs[REG_SP] - 0x100) & ~(uint32_t)0x7;

    bool ok = false;
    std::string fail;

    if (!setRegs(pid, &regs)) {
        fail = "PTRACE_SETREGS 失败";
    } else if (ptrace(PTRACE_CONT, pid, nullptr, nullptr) < 0) {
        fail = "PTRACE_CONT 失败";
    } else {
        for (int i = 0; i < kMaxWaitIterations; ++i) {
            int status = 0;
            pid_t r = waitpid(pid, &status, __WALL | WNOHANG);
            if (r == 0) {
                usleep(1000);
                continue;
            }
            if (r < 0) {
                fail = "waitpid 失败";
                break;
            }
            if (WIFEXITED(status) || WIFSIGNALED(status)) {
                fail = "目标进程在远程调用期间退出";
                break;
            }
            if (!WIFSTOPPED(status)) continue;

            const int sig = WSTOPSIG(status);
            Regs cur{};
            if (!getRegs(pid, &cur)) {
                fail = "读取寄存器失败";
                break;
            }
            if (cur.uregs[REG_PC] == trapAddr + (trapThumb ? 2 : 0) || cur.uregs[REG_PC] == trapAddr) {
                *out = cur.uregs[0];
                ok = true;
                break;
            }
            const int deliver = (sig == SIGTRAP || sig == SIGSTOP) ? 0 : sig;
            ptrace(PTRACE_CONT, pid, nullptr, (void*)(long)deliver);
        }
        if (!ok && fail.empty()) fail = "等待远程调用返回超时";
    }

    mem.write(trapAddr, &origInsn, sizeof(origInsn));
    setRegs(pid, &saved);

    if (!ok) *error = fail;
    return ok;
}

#else
#error "本注入器仅支持 arm64-v8a 与 armeabi-v7a"
#endif

// 在目标进程里找 dlopen
uintptr_t findDlopen(pid_t pid, RemoteMemory& mem, const std::vector<MapEntry>& maps) {
    static const struct {
        const char* module;
        const char* symbol;
    } candidates[] = {
        {"linker64", "__loader_dlopen"},
        {"linker",   "__loader_dlopen"},
        {"libdl.so", "dlopen"},
        {"libc.so",  "dlopen"},
    };
    for (const auto& c : candidates) {
        uintptr_t addr = remoteFindSymbol(mem, maps, c.module, c.symbol);
        if (addr) {
            LOGI("找到 %s!%s = 0x%" PRIxPTR, c.module, c.symbol, addr);
            return addr;
        }
    }
    return 0;
}

// 把字符串放到目标进程里（优先用目标线程栈下方的空闲空间，失败则远程 mmap）
uintptr_t placeString(pid_t pid, RemoteMemory& mem, const std::vector<MapEntry>& maps,
                      const std::string& text, std::string* error) {
    Regs regs{};
#if defined(__aarch64__)
    uintptr_t sp = 0;
    if (getRegs(pid, &regs)) sp = regs.sp;
#else
    uintptr_t sp = 0;
    if (getRegs(pid, &regs)) sp = regs.uregs[REG_SP];
#endif

    if (sp != 0) {
        uintptr_t scratch = (sp - 0x200) & ~(uintptr_t)0xF;
        if (mem.write(scratch, text.c_str(), text.size() + 1)) {
            LOGI("字符串写入目标线程栈: 0x%" PRIxPTR, scratch);
            return scratch;
        }
    }

    // 兜底：远程 mmap 一页
    uintptr_t mmapAddr = remoteFindSymbol(mem, maps, "libc.so", "mmap");
    if (!mmapAddr) {
        *error = "无法在目标进程里分配内存（找不到 mmap）";
        return 0;
    }
    uintptr_t mmapResult = 0;
    uintptr_t margs[6] = {
        0,
        0x1000,
        (uintptr_t)(PROT_READ | PROT_WRITE),
        (uintptr_t)(MAP_PRIVATE | MAP_ANONYMOUS),
        (uintptr_t)-1,
        0,
    };
    std::string callErr;
    if (!remoteCall(pid, mem, mmapAddr, margs, 6, &mmapResult, &callErr) || mmapResult == 0 ||
        (intptr_t)mmapResult < 0) {
        *error = "远程 mmap 失败: " + callErr;
        return 0;
    }
    if (!mem.write(mmapResult, text.c_str(), text.size() + 1)) {
        *error = "向远程内存写入字符串失败";
        return 0;
    }
    LOGI("字符串写入远程 mmap 内存: 0x%" PRIxPTR, mmapResult);
    return mmapResult;
}

} // namespace

bool isAttachable(pid_t pid, std::string* error) {
    if (!attachProcess(pid, error)) return false;
    detachProcess(pid);
    return true;
}

bool injectLibrary(pid_t pid, const std::string& libPath, uintptr_t* outHandle, std::string* error) {
    if (outHandle) *outHandle = 0;

    std::vector<MapEntry> maps;
    if (!readMaps(pid, maps)) {
        *error = "读取 /proc/pid/maps 失败";
        return false;
    }

    if (!attachProcess(pid, error)) return false;

    bool ok = false;
    {
        RemoteMemory mem(pid);
        if (!mem.ok()) {
            *error = "打开 /proc/pid/mem 失败（需要 root）";
        } else {
            uintptr_t dlopenAddr = findDlopen(pid, mem, maps);
            if (!dlopenAddr) {
                *error = "在目标进程里找不到 dlopen 地址";
            } else {
                uintptr_t remoteStr = placeString(pid, mem, maps, libPath, error);
                if (remoteStr) {
                    uintptr_t dlopenArgs[2] = { remoteStr, (uintptr_t)2 /*RTLD_NOW*/ };
                    uintptr_t handle = 0;
                    std::string callErr;
                    if (remoteCall(pid, mem, dlopenAddr, dlopenArgs, 2, &handle, &callErr)) {
                        LOGI("dlopen(%s) 返回 0x%" PRIxPTR, libPath.c_str(), handle);
                        if (handle != 0) {
                            if (outHandle) *outHandle = handle;
                            ok = true;
                        } else {
                            *error = "dlopen 返回 NULL（库加载失败，看 logcat 里的 linker 报错）";
                        }
                    } else {
                        *error = "远程调用 dlopen 失败: " + callErr;
                    }
                }
            }
        }
    }

    detachProcess(pid);
    return ok;
}

} // namespace injector