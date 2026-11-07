//
// log.h  --  统一日志宏（注入器与 payload 共用）
//
#ifndef IL2CPP_DUMPER_LOG_H
#define IL2CPP_DUMPER_LOG_H

#include <android/log.h>

#define DP_TAG "Il2CppDumper"

#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, DP_TAG, __VA_ARGS__)
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,  DP_TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN,  DP_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, DP_TAG, __VA_ARGS__)

// 终端上也要看到的输出（payload 里 stdout 不可见，但不会出错）
#define PRINTF(...) do { printf(__VA_ARGS__); fflush(stdout); } while (0)

#endif // IL2CPP_DUMPER_LOG_H
