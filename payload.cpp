//
// payload.cpp  --  被注入到游戏进程里的那个 .so
//
// 流程：
//   dlopen 之后 constructor 被调用 -> 起一个线程
//   -> 从 /proc/self/cmdline 得到包名，输出目录 = /data/data/<包名>/files
//   -> 等待 libil2cpp.so 被加载 & il2cpp 初始化完成
//   -> dump 出 dump.cs，并写 dump.done / dump.error 标记给注入器
//
#include <fcntl.h>
#include <pthread.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cstdio>
#include <cstring>
#include <string>

#include "il2cpp_dump.h"
#include "log.h"
#include "xdl.h"

namespace {

// 从 /proc/self/cmdline 取进程名（包名），去掉 ":子进程" 后缀
std::string currentPackageName() {
    int fd = open("/proc/self/cmdline", O_RDONLY | O_CLOEXEC);
    if (fd < 0) return std::string();
    char buf[512];
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n <= 0) return std::string();
    buf[n] = '\0';
    std::string name(buf);
    // <pkg>:remote -> <pkg>
    size_t colon = name.find(':');
    if (colon != std::string::npos) name = name.substr(0, colon);
    return name;
}

void writeTextFile(const std::string& path, const std::string& content) {
    int fd = open(path.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) return;
    (void)!write(fd, content.c_str(), content.size());
    close(fd);
}

void writeStatus(const std::string& outDir, const std::string& text) {
    LOGI("[status] %s", text.c_str());
    writeTextFile(outDir + "/dump_status.txt", text + "\n");
}

void* dumpThread(void* arg) {
    std::string outDir = *(std::string*)arg;
    delete (std::string*)arg;

    // 清理上次的标记
    unlink((outDir + "/dump.done").c_str());
    unlink((outDir + "/dump.error").c_str());

    writeStatus(outDir, "payload 已注入，等待 libil2cpp.so 加载...");

    // 等待 libil2cpp.so 出现在自己的 maps 里（最多 300 秒）
    void* handle = nullptr;
    for (int i = 0; i < 300; ++i) {
        handle = xdl_open("libil2cpp.so", 0);
        if (handle) break;
        if (i % 10 == 0) writeStatus(outDir, "等待 libil2cpp.so 加载... " + std::to_string(i) + "s");
        sleep(1);
    }
    if (!handle) {
        writeStatus(outDir, "失败：libil2cpp.so 未加载（该进程不是 Unity il2cpp 游戏？）");
        writeTextFile(outDir + "/dump.error", "libil2cpp.so not found\n");
        return nullptr;
    }

    writeStatus(outDir, "已找到 libil2cpp.so，开始 dump（大游戏可能需要几十秒）...");

    bool ok = il2cpp_dump_all(handle, outDir.c_str());
    xdl_close(handle);

    if (ok) {
        struct stat st {};
        std::string dumpPath = outDir + "/dump.cs";
        unsigned long long size = 0;
        if (stat(dumpPath.c_str(), &st) == 0) size = (unsigned long long)st.st_size;
        writeStatus(outDir, "dump 完成，dump.cs = " + std::to_string(size) + " 字节");
        writeTextFile(outDir + "/dump.done", dumpPath + "\n");
    } else {
        writeStatus(outDir, "dump 失败，详见 logcat（tag: Il2CppDumper）");
        writeTextFile(outDir + "/dump.error", "dump failed\n");
    }
    return nullptr;
}

__attribute__((constructor)) void payloadMain() {
    LOGI("payload 已注入进程 %d", getpid());

    std::string pkg = currentPackageName();
    if (pkg.empty()) {
        LOGE("无法获取进程名，放弃");
        return;
    }
    std::string outDir = "/data/data/" + pkg + "/files";
    mkdir(outDir.c_str(), 0771);
    LOGI("输出目录: %s", outDir.c_str());

    // 目录不可写时（极少见）退化到 app 外部私有目录
    if (access(outDir.c_str(), W_OK) != 0) {
        std::string alt = "/storage/emulated/0/Android/data/" + pkg + "/files";
        mkdir(alt.c_str(), 0771);
        if (access(alt.c_str(), W_OK) == 0) outDir = alt;
        LOGW("私有目录不可写，改用 %s", outDir.c_str());
    }

    pthread_t tid;
    std::string* arg = new std::string(outDir);
    if (pthread_create(&tid, nullptr, dumpThread, arg) != 0) {
        LOGE("创建 dump 线程失败");
        delete arg;
        return;
    }
    pthread_detach(tid);
}

} // namespace
