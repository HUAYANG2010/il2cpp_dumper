//
// proc_maps.cpp
//
#include "proc_maps.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <dirent.h>
#include <fcntl.h>
#include <unistd.h>

static bool skipTokens(const char* line, int n, const char** out) {
    const char* p = line;
    for (int i = 0; i < n; ++i) {
        while (*p && *p != ' ') ++p;
        if (!*p) return false;
        ++p; // 跳过空格
    }
    *out = p;
    return true;
}

bool readMaps(pid_t pid, std::vector<MapEntry>& out) {
    out.clear();
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/maps", (int)pid);
    FILE* fp = fopen(path, "re");
    if (!fp) return false;

    char line[1024];
    while (fgets(line, sizeof(line), fp)) {
        unsigned long long start = 0, end = 0, offset = 0;
        char perms[8] = {0};
        if (sscanf(line, "%llx-%llx %7s %llx", &start, &end, perms, &offset) != 4) continue;

        MapEntry e;
        e.start = (uintptr_t)start;
        e.end = (uintptr_t)end;
        e.offset = (uint64_t)offset;
        e.perms = perms;

        const char* rest = nullptr;
        // start-end / perms / offset / dev / inode 共 5 个字段之后就是路径
        if (skipTokens(line, 5, &rest)) {
            while (*rest == ' ') ++rest;
            std::string p(rest);
            while (!p.empty() && (p.back() == '\n' || p.back() == '\r' || p.back() == ' ')) p.pop_back();
            // 映射过的已删除文件会带 " (deleted)"
            const char* del = " (deleted)";
            if (p.size() > strlen(del) && p.compare(p.size() - strlen(del), strlen(del), del) == 0)
                p.erase(p.size() - strlen(del));
            e.path = p;
        }
        out.push_back(std::move(e));
    }
    fclose(fp);
    return true;
}

std::string readCmdline(pid_t pid) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/cmdline", (int)pid);
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return std::string();
    char buf[512];
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n <= 0) return std::string();
    buf[n] = '\0';
    return std::string(buf);  // cmdline 用 \0 分隔，第一个字段即为进程名
}

std::vector<pid_t> findPidsByName(const std::string& name) {
    std::vector<pid_t> out;
    DIR* dir = opendir("/proc");
    if (!dir) return out;
    struct dirent* ent;
    while ((ent = readdir(dir)) != nullptr) {
        if (ent->d_name[0] < '0' || ent->d_name[0] > '9') continue;
        pid_t pid = (pid_t)atoi(ent->d_name);
        std::string cmd = readCmdline(pid);
        if (cmd.empty()) continue;
        if (cmd == name) {
            out.push_back(pid);
        } else if (cmd.size() > name.size() && cmd.compare(0, name.size(), name) == 0 &&
                   cmd[name.size()] == ':') {
            out.push_back(pid);  // 子进程 com.xxx:unity
        }
    }
    closedir(dir);
    return out;
}

bool isProcess64Bit(pid_t pid) {
    std::vector<MapEntry> maps;
    if (!readMaps(pid, maps)) return false;
    for (const auto& m : maps) {
        if (m.path == "/system/bin/linker64") return true;
        if (m.path == "/system/bin/linker") return false;
    }
    // 退化判断：地址宽度（32 位编译时这条恒为 false，直接跳过）
    for (const auto& m : maps) {
        if (m.start > (uintptr_t)0xFFFFFFFFULL) return true;
    }
    return false;
}

bool findModule(const std::vector<MapEntry>& maps, const char* suffix,
                uintptr_t* base, std::string* fullPath) {
    size_t suffixLen = strlen(suffix);
    uintptr_t best = UINTPTR_MAX;
    std::string bestPath;
    for (const auto& m : maps) {
        if (m.path.empty() || m.path[0] != '/') continue;
        if (m.path.size() < suffixLen) continue;
        if (m.path.compare(m.path.size() - suffixLen, suffixLen, suffix) != 0) continue;

        std::string p = m.path;
        if (p != bestPath) {
            // 新模块：以 offset==0 的段作为 load bias
            if (m.offset == 0) {
                if (best == UINTPTR_MAX || m.start < best) {
                    best = m.start;
                    bestPath = p;
                }
            }
        } else if (m.start < best) {
            best = m.start;
        }
    }
    if (best == UINTPTR_MAX) return false;
    *base = best;
    if (fullPath) *fullPath = bestPath;
    return true;
}

bool findNativeLibDir(const std::vector<MapEntry>& maps, std::string* dir) {
    for (const auto& m : maps) {
        const std::string& p = m.path;
        if (p.size() < 5 || p.compare(p.size() - 3, 3, ".so") != 0) continue;
        // /data/app/~~xxx==/com.game-yyy==/lib/arm64/libxxx.so
        if (p.compare(0, 10, "/data/app/") != 0) continue;
        size_t slash = p.rfind('/');
        if (slash == std::string::npos || slash == 0) continue;
        std::string d = p.substr(0, slash);
        // 必须是 .../lib/<abi>
        if (d.find("/lib/") == std::string::npos) continue;
        *dir = d;
        return true;
    }
    return false;
}