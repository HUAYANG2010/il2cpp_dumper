//
// il2cpp_dump.h  --  payload 内实际执行 dump 的入口
//
#ifndef IL2CPP_DUMPER_IL2CPP_DUMP_H
#define IL2CPP_DUMPER_IL2CPP_DUMP_H

// handle: libil2cpp.so 的 xdl handle（目标进程内已加载的那个）
// outDir: 输出目录（payload 会在其中写 dump.cs / dump.done）
// 返回 true 表示 dump.cs 已成功写出
bool il2cpp_dump_all(void* handle, const char* outDir);

#endif // IL2CPP_DUMPER_IL2CPP_DUMP_H