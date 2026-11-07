//
// elf_remote.h  --  从“目标进程内存”里解析 ELF 动态符号
//                   用于在注入前拿到 linker 的 __loader_dlopen / libc 的 mmap 等地址
//
#ifndef IL2CPP_DUMPER_ELF_REMOTE_H
#define IL2CPP_DUMPER_ELF_REMOTE_H

#include <stdint.h>
#include <sys/types.h>
#include <string>
#include <vector>

#include "proc_maps.h"

// 目标进程内存读写（走 /proc/<pid>/mem，需要 root + 已 ptrace attach）
class RemoteMemory {
public:
    explicit RemoteMemory(pid_t pid);
    ~RemoteMemory();

    bool ok() const { return fd_ >= 0; }
    pid_t pid() const { return pid_; }

    bool read(uintptr_t addr, void* buf, size_t len) const;
    bool write(uintptr_t addr, const void* buf, size_t len) const;
    bool readCStr(uintptr_t addr, std::string& out, size_t maxLen = 512) const;
    bool readU32(uintptr_t addr, uint32_t* out) const;

private:
    pid_t pid_;
    int fd_;
};

struct RemoteElf {
    uintptr_t load_bias = 0;
    bool is64 = false;
    uintptr_t symtab = 0;
    uintptr_t strtab = 0;
    uintptr_t sysvHash = 0;
    uintptr_t gnuHash = 0;
    size_t strtabSize = 0;
};

// 解析目标进程内某个模块（load_bias 为模块基址）的 .dynamic
bool remoteElfInit(RemoteMemory& mem, uintptr_t loadBias, RemoteElf* elf);

// 在已解析的模块里查符号；返回值保留了 ARM 的 Thumb 标志位，
// 即返回 load_bias + st_value（ARM 下低位为 1 表示 Thumb 函数）
uintptr_t remoteElfLookup(RemoteMemory& mem, const RemoteElf& elf, const char* symbolName);

// 一步到位：在目标进程里按模块名后缀 + 符号名求地址；找不到返回 0
uintptr_t remoteFindSymbol(RemoteMemory& mem, const std::vector<MapEntry>& maps,
                           const char* moduleSuffix, const char* symbolName,
                           uintptr_t* outModuleBase = nullptr);

#endif // IL2CPP_DUMPER_ELF_REMOTE_H