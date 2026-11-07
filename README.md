# il2cpp_dumper —— 免模块版动态 dump 工具

把 [Perfare/Zygisk-Il2CppDumper](https://github.com/Perfare/Zygisk-Il2CppDumper)
从「Zygisk 模块」改造成「一个可执行文件 + 一个 payload .so」：
**运行后输入游戏包名（或 PID），自动注入并 dump 出 `dump.cs`，再自动拷到 /sdcard。**

不需要刷 Magisk/Zygisk 模块，只需要 root（su）。

---

## 1. 目录结构

```
/storage/emulated/0/A/dump/Il2cpp/
├── aide_ndk.sh                  ← 编译脚本（AIDE 内置 NDK）
├── run.sh                       ← 一键运行（自动装到 /data/local/tmp 再启动）
├── jni/
│   ├── Android.mk / Application.mk
│   ├── common/                  ← 公共：log / maps 解析 / 远程 ELF 符号解析
│   │   ├── log.h
│   │   ├── proc_maps.h .cpp
│   │   └── elf_remote.h .cpp
│   ├── injector/                ← 注入器（可执行文件主体）
│   │   ├── main.cpp             ← 交互输入包名 + 输出整理
│   │   ├── injector.h .cpp      ← ptrace 远程调用 / 注入 dlopen
│   ├── payload/                 ← 注入到游戏进程里的 .so（真正 dump 的部分）
│   │   ├── payload.cpp          ← constructor：起线程、等 libil2cpp、调 dump
│   │   ├── il2cpp_dump.h .cpp   ← 改写自原工程的 dump 逻辑
│   │   ├── il2cpp-api-functions.h / il2cpp-class.h / il2cpp-tabledefs.h
│   └── xdl/                     ← 原工程的 xDL（进程内查已加载 .so 与符号）
└── libs/
    ├── arm64-v8a/il2cpp_dumper、libil2cppdump_payload.so
    └── armeabi-v7a/il2cpp_dumper、libil2cppdump_payload.so
```

## 2. 编译

```sh
sh /storage/emulated/0/A/dump/Il2cpp/aide_ndk.sh
```

产物在 `libs/arm64-v8a/` 与 `libs/armeabi-v7a/`：
- `il2cpp_dumper`：可执行文件（注入器）
- `libil2cppdump_payload.so`：被注入到游戏里的 payload

> 注意：注入器与目标进程 ABI 必须一致。
> 64 位游戏用 `arm64-v8a` 那一对，32 位游戏用 `armeabi-v7a` 那一对。

## 3. 使用

```sh
su -c "sh /storage/emulated/0/A/dump/Il2cpp/run.sh"
```

运行后会：

1. 扫描所有进程，列出**已经加载 libil2cpp.so** 的候选游戏；
2. 提示 `请输入游戏包名或进程 PID`；
3. 自动完成：部署 payload → ptrace 注入 dlopen → payload 等 il2cpp 就绪 →
   生成 `dump.cs` → 拷出到 `/sdcard/il2cpp_dump/<包名>_dump.cs`。

输入可以是：
- 列表编号（如 `1`）
- 包名（如 `com.sofunny.Sausage`）
- PID（如 `12257`）
- `q` / 回车：退出

### 常用参数

```sh
# 额外导出 libil2cpp.so 内存镜像与 global-metadata.dat（IDA / PC 版 Il2CppDumper 用得上）
su -c "sh /storage/emulated/0/A/dump/Il2cpp/run.sh -a"

# 直接给包名（跳过交互）
su -c "/data/local/tmp/il2cpp_dumper/il2cpp_dumper com.sofunny.Sausage"

# 指定输出目录 / 超时
su -c "/data/local/tmp/il2cpp_dumper/il2cpp_dumper com.xxx.yyy -o /sdcard/dump -t 900"
```

| 参数 | 说明 |
| --- | --- |
| `-o <目录>` | 输出目录，默认 `/sdcard/il2cpp_dump` |
| `-t <秒>` | 等待 dump 完成的超时，默认 600 |
| `-a, --all` | 额外导出 `libil2cpp.so`、`global-metadata.dat` |
| `-l <路径>` | 手动指定 payload `.so` 路径 |
| `-k, --keep` | 注入后保留游戏目录里的 payload（默认注入完就删） |
| `-n, --no-wait` | 注入成功即退出，自己去看 logcat |
| `-h, --help` | 帮助 |

## 4. 工作原理

```
il2cpp_dumper（root 运行）
  ├─ 读 /proc/<pid>/maps 找 linker64 / libc.so 基址
  ├─ 直接读目标进程内存里的 .dynamic / .dynsym（GNU hash / sysv hash）
  │     → 解析出 __loader_dlopen、mmap 等地址（不依赖本地 so 文件）
  ├─ PTRACE_ATTACH 停住目标线程
  ├─ 把 PC 处指令临时改成 brk，把 LR 指向它（用作“返回地址”）
  ├─ 设置 PC=__loader_dlopen、参数=("/…/libil2cppdump_payload.so", RTLD_NOW)
  ├─ PTRACE_CONT → 游戏进程内完成 dlopen → 命中断点 → 读返回值 → 恢复寄存器
  └─ detach
        ↓
libil2cppdump_payload.so 的 constructor（在游戏进程内）
  ├─ 输出目录 = /data/data/<包名>/files（游戏自己有写权限）
  ├─ 轮询 xdl_open("libil2cpp.so") 直到它被加载
  ├─ xdl_sym 解析出全部 il2cpp 导出 API
  ├─ 等 il2cpp 域和程序集就绪 → il2cpp_thread_attach(当前线程)
  ├─ 遍历 image/class/field/property/method → 写 dump.cs
  └─ 写 dump.done 标记
        ↓
il2cpp_dumper 轮询 dump.done → 把结果拷到 /sdcard → 退出
```

相比原 Zygisk 模块的改动：
- 去掉了 `zygisk.hpp`、`game.h`、`main.cpp` 的模块生命周期，改成一次性注入；
- 注入目标从「按包名在 `preAppSpecialize` 里拦截」改成「对已运行进程 ptrace 注入」；
- `il2cpp_api_init` 的 `while (!il2cpp_is_vm_thread(nullptr))` 死等改成
  「等 domain/assemblies 就绪 + 主动 attach 当前线程」，注入线程才不会卡死；
- dump 输出目录由外部传入，并额外支持导出 `libil2cpp.so` / `global-metadata.dat`。

## 5. 可能遇到的问题

| 现象 | 处理 |
| --- | --- |
| `can't execute: Permission denied` | `/sdcard` 是 noexec，用 `run.sh`（会装到 `/data/local/tmp`） |
| `注入失败: PTRACE_ATTACH 失败` | 没 root；或游戏有反调试（先让它进游戏画面再注入） |
| `找不到 nativeLibraryDir` | 游戏还没加载任何 .so，等它进 Unity 场景再试 |
| payload 报告 `libil2cpp.so not found` | 该进程不是 il2cpp 游戏（可能是 mono 或子进程选错了） |
| `dlopen 返回 NULL` | `su -c 'logcat -s Il2CppDumper linker'` 看 linker 报错 |
| 32/64 位不匹配 | 换 `libs/armeabi-v7a` 或 `libs/arm64-v8a` 那一对文件 |

日志统一 tag 为 `Il2CppDumper`：

```sh
su -c "logcat -s Il2CppDumper"
```
