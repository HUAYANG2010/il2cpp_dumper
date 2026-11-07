//
// main.cpp  --  注入器命令行入口
//
//   用法: il2cpp_dumper <pid|包名> [选项]
//     -o <目录>     输出目录（默认 /sdcard/il2cpp_dump）
//     -t <秒>       等待 dump 完成的超时（默认 600）
//     -l <路径>     手动指定 payload .so 路径
//     -a, --all     额外导出 libil2cpp.so 与 global-metadata.dat
//     -k, --keep    注入后保留目标 lib 目录里的 payload（默认删除）
//     -n, --no-wait 注入成功即退出，不等待 dump 结果
//     -h, --help    显示帮助
//
#include <dirent.h>
#include <elf.h>
#include <fcntl.h>
#include <limits.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#include "injector.h"
#include "log.h"
#include "proc_maps.h"

namespace {

constexpr const char* kPayloadName = "libil2cppdump_payload.so";

struct Options {
    std::string target;         // pid 或包名
    std::string outDir = "/sdcard/il2cpp_dump";
    std::string payloadPath;    // 手动指定
    int timeoutSec = 600;
    bool dumpAll = false;
    bool keepPayload = false;
    bool noWait = false;
};

void usage() {
    printf(
        "il2cpp_dumper —— 输入游戏包名/PID，自动注入并 dump il2cpp\n"
        "\n"
        "最简用法（推荐）: 直接运行，按提示输入游戏包名\n"
        "  su -c ./il2cpp_dumper\n"
        "\n"
        "命令行用法: il2cpp_dumper <pid|包名> [选项]\n"
        "\n"
        "选项:\n"
        "  -o <目录>      输出目录（默认 /sdcard/il2cpp_dump）\n"
        "  -t <秒>        等待 dump 完成的超时（默认 600）\n"
        "  -l <路径>      手动指定 payload(.so) 路径\n"
        "  -a, --all      额外导出 libil2cpp.so 与 global-metadata.dat\n"
        "  -k, --keep     注入后保留目标目录里的 payload\n"
        "  -n, --no-wait  注入成功即退出\n"
        "  -h, --help     显示本帮助\n"
        "\n"
        "示例:\n"
        "  su -c ./il2cpp_dumper\n"
        "  su -c 'il2cpp_dumper 12345'\n"
        "  su -c 'il2cpp_dumper com.miHoYo.Yuanshen -a -o /sdcard/dump'\n"
        "\n"
        "注意: 必须 root 运行；注入器与目标进程 ABI 必须一致\n"
        "      (64 位游戏用 arm64-v8a 里的两个文件，32 位游戏用 armeabi-v7a 里的)\n");
}

bool fileExists(const std::string& path) {
    struct stat st {};
    return stat(path.c_str(), &st) == 0;
}

long long fileSize(const std::string& path) {
    struct stat st {};
    if (stat(path.c_str(), &st) != 0) return -1;
    return (long long)st.st_size;
}

bool readWholeFile(const std::string& path, std::string* out) {
    int fd = open(path.c_str(), O_RDONLY | O_CLOEXEC);
    if (fd < 0) return false;
    char buf[64 * 1024];
    ssize_t n;
    out->clear();
    while ((n = read(fd, buf, sizeof(buf))) > 0) out->append(buf, (size_t)n);
    close(fd);
    return true;
}

bool writeWholeFile(const std::string& path, const std::string& data, mode_t mode = 0644) {
    int fd = open(path.c_str(), O_WRONLY | O_CREAT | O_TRUNC, mode);
    if (fd < 0) return false;
    size_t off = 0;
    while (off < data.size()) {
        ssize_t n = write(fd, data.data() + off, data.size() - off);
        if (n <= 0) {
            close(fd);
            return false;
        }
        off += (size_t)n;
    }
    close(fd);
    chmod(path.c_str(), mode);
    return true;
}

bool copyFile(const std::string& from, const std::string& to, mode_t mode) {
    int in = open(from.c_str(), O_RDONLY | O_CLOEXEC);
    if (in < 0) return false;
    int out = open(to.c_str(), O_WRONLY | O_CREAT | O_TRUNC, mode);
    if (out < 0) {
        close(in);
        return false;
    }
    std::vector<char> buf(128 * 1024);
    bool ok = true;
    for (;;) {
        ssize_t n = read(in, buf.data(), buf.size());
        if (n == 0) break;
        if (n < 0) {
            ok = false;
            break;
        }
        ssize_t off = 0;
        while (off < n) {
            ssize_t w = write(out, buf.data() + off, (size_t)(n - off));
            if (w <= 0) {
                ok = false;
                break;
            }
            off += w;
        }
        if (!ok) break;
    }
    close(in);
    fsync(out);
    close(out);
    if (ok) chmod(to.c_str(), mode);
    return ok;
}

void mkdirs(const std::string& path) {
    std::string cur;
    for (size_t i = 0; i < path.size(); ++i) {
        cur.push_back(path[i]);
        if (path[i] == '/' && cur.size() > 1) mkdir(cur.c_str(), 0775);
    }
    if (!path.empty()) mkdir(path.c_str(), 0775);
}

std::string dirName(const std::string& path) {
    size_t pos = path.find_last_of('/');
    if (pos == std::string::npos) return ".";
    if (pos == 0) return "/";
    return path.substr(0, pos);
}

// 包名（去掉 :子进程）
std::string packageOf(pid_t pid) {
    std::string cmd = readCmdline(pid);
    size_t colon = cmd.find(':');
    if (colon != std::string::npos) cmd = cmd.substr(0, colon);
    return cmd;
}

bool hasIl2cpp(const std::vector<MapEntry>& maps) {
    for (const auto& m : maps) {
        if (m.path.size() >= 12 && m.path.compare(m.path.size() - 12, 12, "libil2cpp.so") == 0) return true;
    }
    return false;
}

pid_t resolvePid(const std::string& target, std::string* error) {
    bool numeric = !target.empty();
    for (char c : target) {
        if (c < '0' || c > '9') {
            numeric = false;
            break;
        }
    }
    if (numeric) {
        pid_t pid = (pid_t)atoi(target.c_str());
        char path[64];
        snprintf(path, sizeof(path), "/proc/%d", (int)pid);
        if (!fileExists(path)) {
            *error = "进程 " + target + " 不存在";
            return -1;
        }
        return pid;
    }

    std::vector<pid_t> pids = findPidsByName(target);
    if (pids.empty()) {
        *error = "找不到包名/进程名: " + target;
        return -1;
    }
    // 优先选真正加载了 libil2cpp.so 的那个进程
    for (pid_t pid : pids) {
        std::vector<MapEntry> maps;
        if (readMaps(pid, maps) && hasIl2cpp(maps)) {
            if (pids.size() > 1) LOGI("同名进程 %zu 个，选择加载了 libil2cpp.so 的 %d", pids.size(), (int)pid);
            return pid;
        }
    }
    return pids[0];
}

// 判断 ELF 文件是 32 位还是 64 位；失败返回 -1
int elfClassOf(const std::string& path) {
    int fd = open(path.c_str(), O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    unsigned char ident[EI_NIDENT] = {0};
    ssize_t n = read(fd, ident, sizeof(ident));
    close(fd);
    if (n < (ssize_t)sizeof(ident)) return -1;
    if (memcmp(ident, ELFMAG, SELFMAG) != 0) return -1;
    if (ident[EI_CLASS] == ELFCLASS64) return 64;
    if (ident[EI_CLASS] == ELFCLASS32) return 32;
    return -1;
}

std::string findPayload(const Options& opt) {
    if (!opt.payloadPath.empty()) return opt.payloadPath;

    char self[PATH_MAX] = {0};
    ssize_t n = readlink("/proc/self/exe", self, sizeof(self) - 1);
    std::string selfPath = (n > 0) ? std::string(self, (size_t)n) : std::string("il2cpp_dumper");
    std::string dir = dirName(selfPath);

    std::vector<std::string> candidates = {
        dir + "/" + kPayloadName,
        "/data/local/tmp/" + std::string(kPayloadName),
        std::string(kPayloadName),
    };
    for (const auto& c : candidates) {
        if (fileExists(c)) return c;
    }
    return dir + "/" + kPayloadName;
}

std::string findTargetLibDir(pid_t pid) {
    std::vector<MapEntry> maps;
    if (!readMaps(pid, maps)) return std::string();
    std::string dir;
    if (findNativeLibDir(maps, &dir)) return dir;
    return std::string();
}

// 打印 payload 写的状态文件（有变化才打印）
void pumpStatus(const std::string& statusPath, std::string* last) {
    if (!fileExists(statusPath)) return;
    std::string content;
    if (!readWholeFile(statusPath, &content)) return;
    if (content == *last) return;
    *last = content;
    while (!content.empty() && (content.back() == '\n' || content.back() == '\r')) content.pop_back();
    if (!content.empty()) printf("  [payload] %s\n", content.c_str());
    fflush(stdout);
}

// /sdcard 写不进去时改用 /data/media/0（同为内部存储，只是绕过 FUSE）
bool copyToOut(const std::string& src, const std::string& dstDir, const std::string& fileName) {
    std::string dst = dstDir + "/" + fileName;
    if (copyFile(src, dst, 0644)) return true;
    if (dstDir.compare(0, 8, "/sdcard/") == 0 || dstDir == "/sdcard") {
        std::string alt = "/data/media/0" + dstDir.substr(7);
        mkdirs(alt);
        std::string dst2 = alt + "/" + fileName;
        if (copyFile(src, dst2, 0644)) {
            printf("  (已写入 %s ，因 /sdcard 挂载限制改走 /data/media/0)\n", dst2.c_str());
            return true;
        }
    }
    fprintf(stderr, "  复制失败: %s -> %s\n", src.c_str(), dst.c_str());
    return false;
}

// ---------------------------------------------------------------
//  交互式：扫描候选进程 + 提示输入包名
// ---------------------------------------------------------------
void trimStr(std::string* s) {
    size_t b = s->find_first_not_of(" \t\r\n");
    size_t e = s->find_last_not_of(" \t\r\n");
    if (b == std::string::npos) {
        s->clear();
        return;
    }
    *s = s->substr(b, e - b + 1);
}

bool readLine(std::string* out) {
    char buf[512];
    if (!fgets(buf, sizeof(buf), stdin)) return false;
    *out = buf;
    trimStr(out);
    return true;
}

struct Candidate {
    pid_t pid;
    std::string pkg;
};

// 扫一遍所有进程，找出已经加载 libil2cpp.so 的（即 Unity il2cpp 游戏）
std::vector<Candidate> scanIl2cppProcesses() {
    std::vector<Candidate> result;
    DIR* dir = opendir("/proc");
    if (!dir) return result;
    struct dirent* ent;
    while ((ent = readdir(dir)) != nullptr) {
        if (ent->d_name[0] < '0' || ent->d_name[0] > '9') continue;
        pid_t pid = (pid_t)atoi(ent->d_name);
        if (pid == getpid()) continue;

        char mp[64];
        snprintf(mp, sizeof(mp), "/proc/%d/maps", (int)pid);
        FILE* fp = fopen(mp, "re");
        if (!fp) continue;
        bool found = false;
        char line[512];
        while (fgets(line, sizeof(line), fp)) {
            if (strstr(line, "libil2cpp.so")) {
                found = true;
                break;
            }
        }
        fclose(fp);
        if (!found) continue;

        Candidate c;
        c.pid = pid;
        c.pkg = packageOf(pid);
        if (c.pkg.empty()) continue;
        result.push_back(c);
    }
    closedir(dir);
    return result;
}

// 让用户输入包名 / PID / 列表编号，返回输入原样（外部再解析）
std::string promptTarget(const std::vector<Candidate>& cands) {
    for (;;) {
        printf("\n请输入游戏包名或进程 PID（直接回车退出）: ");
        fflush(stdout);

        std::string line;
        if (!readLine(&line)) return std::string();
        if (line.empty()) return std::string();
        if (line == "q" || line == "Q" || line == "quit" || line == "exit") return std::string();

        bool numeric = true;
        for (char c : line) {
            if (c < '0' || c > '9') {
                numeric = false;
                break;
            }
        }
        // 纯数字：先当列表编号用（PID 一般远大于列表长度）
        if (numeric) {
            long v = atol(line.c_str());
            if (v >= 1 && (size_t)v <= cands.size()) {
                pid_t pid = cands[(size_t)v - 1].pid;
                printf("→ 已选择 [%ld] pid %d %s\n", v, (int)pid, cands[(size_t)v - 1].pkg.c_str());
                return std::to_string(pid);
            }
        }

        std::string err;
        pid_t pid = resolvePid(line, &err);
        if (pid >= 0) return line;
        printf("× %s（请确认游戏已启动后重试）\n", err.c_str());
    }
}

} // namespace

int main(int argc, char** argv) {
    Options opt;

    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        if (a == "-h" || a == "--help") {
            usage();
            return 0;
        } else if (a == "-o" && i + 1 < argc) {
            opt.outDir = argv[++i];
        } else if (a == "-t" && i + 1 < argc) {
            opt.timeoutSec = atoi(argv[++i]);
        } else if (a == "-l" && i + 1 < argc) {
            opt.payloadPath = argv[++i];
        } else if (a == "-a" || a == "--all") {
            opt.dumpAll = true;
        } else if (a == "-k" || a == "--keep") {
            opt.keepPayload = true;
        } else if (a == "-n" || a == "--no-wait") {
            opt.noWait = true;
        } else if (!a.empty() && a[0] == '-') {
            fprintf(stderr, "未知选项: %s\n", a.c_str());
            usage();
            return 1;
        } else if (opt.target.empty()) {
            opt.target = a;
        }
    }

    printf("==== il2cpp_dumper ====\n");

    // ---- 0. 没给目标就交互式询问 ----
    if (opt.target.empty()) {
        printf("正在扫描已加载 libil2cpp.so 的进程...\n");
        std::vector<Candidate> cands = scanIl2cppProcesses();
        if (cands.empty()) {
            printf("（没扫到正在运行的 il2cpp 游戏：游戏可能没启动，或还没进入 Unity 场景）\n");
        } else {
            printf("\n当前候选进程:\n");
            for (size_t i = 0; i < cands.size(); ++i) {
                printf("  [%zu] pid %-6d  %s\n", i + 1, (int)cands[i].pid, cands[i].pkg.c_str());
            }
        }

        std::string t = promptTarget(cands);
        if (t.empty()) {
            printf("已取消\n");
            return 1;
        }
        opt.target = t;
    }

    // ---- 1. 找进程 ----
    std::string err;
    pid_t pid = resolvePid(opt.target, &err);
    if (pid < 0) {
        fprintf(stderr, "错误: %s\n", err.c_str());
        return 1;
    }

    std::string pkg = packageOf(pid);
    bool target64 = isProcess64Bit(pid);
    bool self64 = (sizeof(void*) == 8);

    printf("目标进程: pid=%d  包名=%s\n", (int)pid, pkg.c_str());
    printf("进程架构: %s    注入器架构: %s\n", target64 ? "64位" : "32位", self64 ? "64位" : "32位");

    if (target64 != self64) {
        fprintf(stderr,
                "错误: ABI 不一致。32 位注入器无法操作 64 位进程，反之亦然。\n"
                "      请改用 libs/%s 目录下的 il2cpp_dumper 与 %s\n",
                target64 ? "arm64-v8a" : "armeabi-v7a", kPayloadName);
        return 1;
    }

    std::vector<MapEntry> maps;
    readMaps(pid, maps);
    if (!hasIl2cpp(maps)) {
        printf("提示: 当前 maps 里还没有 libil2cpp.so，"
               "若游戏尚未进入 Unity 界面，payload 会自己等你，最多 300 秒\n");
    }

    std::string dataDir = "/data/data/" + pkg;
    std::string filesDir = dataDir + "/files";
    if (!fileExists(filesDir)) mkdirs(filesDir);

    // ---- 2. 找 payload 并部署到目标可读目录 ----
    std::string payload = findPayload(opt);
    if (!fileExists(payload)) {
        fprintf(stderr, "错误: 找不到 payload: %s\n", payload.c_str());
        fprintf(stderr, "      请确认 %s 与注入器放在同一目录\n", kPayloadName);
        return 1;
    }
    int payloadClass = elfClassOf(payload);
    if (payloadClass > 0 && (payloadClass == 64) != target64) {
        fprintf(stderr, "错误: payload 是 %d 位，目标进程是 %s，请换成对应 ABI 的 payload\n",
                payloadClass, target64 ? "64位" : "32位");
        return 1;
    }

    std::string libDir = findTargetLibDir(pid);
    if (libDir.empty()) {
        fprintf(stderr,
                "错误: 找不到目标进程的 nativeLibraryDir（/data/app/.../lib/<abi>）\n"
                "      请确认游戏已经加载过自己的 .so\n");
        return 1;
    }
    std::string deployed = libDir + "/" + kPayloadName;
    printf("部署 payload: %s -> %s\n", payload.c_str(), deployed.c_str());
    if (!copyFile(payload, deployed, 0755)) {
        fprintf(stderr, "错误: 复制 payload 失败（需要 root）\n");
        return 1;
    }
    chmod(deployed.c_str(), 0755);

    // ---- 3. 预置标记 / 清理旧结果 ----
    std::string flagAll = filesDir + "/.il2cpp_dump_all";
    if (opt.dumpAll) {
        writeWholeFile(flagAll, "1\n");
        printf("已开启 --all: 将同时导出 libil2cpp.so / global-metadata.dat\n");
    } else {
        unlink(flagAll.c_str());
    }
    unlink((filesDir + "/dump.done").c_str());
    unlink((filesDir + "/dump.error").c_str());
    unlink((filesDir + "/dump.cs").c_str());
    unlink((filesDir + "/dump_status.txt").c_str());

    // ---- 4. 注入 ----
    printf("开始注入...\n");
    uintptr_t handle = 0;
    if (!injector::injectLibrary(pid, deployed, &handle, &err)) {
        fprintf(stderr, "注入失败: %s\n", err.c_str());
        fprintf(stderr,
                "排查建议:\n"
                "  1) 是否 root（su）运行；\n"
                "  2) 部分游戏有反调试，可尝试先让其进入游戏再注入；\n"
                "  3) 查看 logcat: su -c 'logcat -s Il2CppDumper linker'\n");
        if (!opt.keepPayload) unlink(deployed.c_str());
        return 1;
    }
    printf("注入成功，payload handle = 0x%llx\n", (unsigned long long)handle);

    if (opt.noWait) {
        printf("已按 --no-wait 退出，dump 结果会出现在 %s\n", filesDir.c_str());
        if (!opt.keepPayload) unlink(deployed.c_str());
        return 0;
    }

    // ---- 5. 等待 payload 完成 dump ----
    printf("等待 dump 完成（超时 %d 秒，中途可按 Ctrl+C）...\n", opt.timeoutSec);
    std::string statusPath = filesDir + "/dump_status.txt";
    std::string lastStatus;
    bool done = false, failed = false;
    for (int i = 0; i < opt.timeoutSec; ++i) {
        pumpStatus(statusPath, &lastStatus);
        if (fileExists(filesDir + "/dump.done")) {
            done = true;
            break;
        }
        if (fileExists(filesDir + "/dump.error")) {
            failed = true;
            break;
        }
        sleep(1);
    }
    pumpStatus(statusPath, &lastStatus);

    if (!opt.keepPayload) unlink(deployed.c_str());

    if (!done) {
        fprintf(stderr, "%s\n", failed ? "payload 报告 dump 失败，看 logcat 里的 Il2CppDumper 日志"
                                       : "等待超时（可加大 -t，或先用 -n 注入后自己看 logcat）");
        return 1;
    }

    // ---- 6. 拷出结果 ----
    mkdirs(opt.outDir);
    printf("\n开始导出结果到 %s\n", opt.outDir.c_str());

    std::vector<std::string> produced;
    struct Item {
        const char* src;
        const char* dst;
    };
    std::vector<Item> items = {{"dump.cs", nullptr}};
    if (opt.dumpAll) {
        items.push_back({"libil2cpp.so", nullptr});
        items.push_back({"global-metadata.dat", nullptr});
    }

    int okCount = 0;
    for (const auto& it : items) {
        std::string src = filesDir + "/" + it.src;
        if (!fileExists(src)) continue;
        std::string dstName = pkg + "_" + it.src;
        if (copyToOut(src, opt.outDir, dstName)) {
            long long sz = fileSize(opt.outDir + "/" + dstName);
            printf("  ✓ %s (%lld 字节)\n", (opt.outDir + "/" + dstName).c_str(), sz);
            produced.push_back(opt.outDir + "/" + dstName);
            ++okCount;
        }
    }

    // 顺带把 payload 日志里最后一次状态留下
    printf("\n完成: 成功导出 %d 个文件\n", okCount);
    for (const auto& p : produced) printf("  %s\n", p.c_str());
    printf("\n下一步: 用 Il2CppDumper(PC 版) 配合 libil2cpp.so + global-metadata.dat 生成 dummy dll，\n"
           "        或直接用 dump.cs 里的 RVA/VA 到 IDA 里定位函数。\n");
    return okCount > 0 ? 0 : 1;
}