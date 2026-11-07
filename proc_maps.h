//
// proc_maps.h  --  /proc/<pid>/maps 解析、进程查找等辅助
//
#ifndef IL2CPP_DUMPER_PROC_MAPS_H
#define IL2CPP_DUMPER_PROC_MAPS_H

#include <stdint.h>
#include <sys/types.h>
#include <string>
#include <vector>

struct MapEntry {
    uintptr_t start = 0;
    uintptr_t end = 0;
    uint64_t offset = 0;
    std::string perms;   // 例如 "r-xp"
    std::string path;    // 映射的文件路径，可能为空
};

// 读取 /proc/<pid>/maps
bool readMaps(pid_t pid, std::vector<MapEntry>& out);

// 读取进程命令行（第一个参数，通常是包名/进程名）
std::string readCmdline(pid_t pid);

// 按名字（包名/进程名）查找 pid，可能多个（:子进程）
std::vector<pid_t> findPidsByName(const std::string& name);

// 判断进程是 64 位还是 32 位（依据 linker 映射或地址宽度）
bool isProcess64Bit(pid_t pid);

// 在 maps 里找指定后缀的模块，返回起始地址（load bias 的近似值）与真实路径
bool findModule(const std::vector<MapEntry>& maps, const char* suffix,
                uintptr_t* base, std::string* fullPath);

// 找某个进程里任意一个已加载 .so 所在的目录（即 nativeLibraryDir）
bool findNativeLibDir(const std::vector<MapEntry>& maps, std::string* dir);

#endif // IL2CPP_DUMPER_PROC_MAPS_H