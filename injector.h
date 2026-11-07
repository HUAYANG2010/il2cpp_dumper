//
// injector.h  --  ptrace 远程调用注入器
//
#ifndef IL2CPP_DUMPER_INJECTOR_H
#define IL2CPP_DUMPER_INJECTOR_H

#include <stdint.h>
#include <sys/types.h>
#include <string>

namespace injector {

// 把 libPath 注入到 pid 进程（等价于在目标进程里执行 dlopen(libPath, RTLD_NOW)）
// 成功时 outHandle 为 dlopen 返回的 handle 地址
bool injectLibrary(pid_t pid, const std::string& libPath, uintptr_t* outHandle, std::string* error);

// 只 attach / detach（排查用）
bool isAttachable(pid_t pid, std::string* error);

} // namespace injector

#endif // IL2CPP_DUMPER_INJECTOR_H