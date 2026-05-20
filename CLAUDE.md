# CLAUDE.md

此文件为 Claude Code (claude.ai/code) 在此仓库中工作时提供指导。

## 构建

```
luamake
```

`luamake` 生成 `build/build.ninja` 后调用 ninja。产物为 `build/bin/pdb-addr2line.exe`。需要 MSVC (cl.exe)，luamake 会自动定位 VS 环境。

完全重编译：删除 `build/obj/` 和 `build/bin/*.exe` 后重新运行 `luamake`。

## 架构

将二进制地址（RVA、VA、section:offset、文件偏移）解析为源码位置和调用链。

管道：`main.cpp` 解析参数 → `Resolver::Load()` 加载 PDB 元数据和段贡献 → `Resolver::LoadModulesForRva()` 只处理相关模块 → `Resolver::Find/FindFunction/FindInlineFrames()` 查询 → `PrintResult()` 输出。

### 核心设计

**延迟加载链** — `Load()` 只加载 PDB 头、段信息、模块信息流和段贡献表。public symbol 扫描延迟到 `LoadModulesForRva()` 中按需触发；IPI/TPI 内联名称解析进一步延迟到 `FindInlineFrames()` 真正命中 inline site 时才触发，并按 inlinee id / class type 做增量缓存。

**段贡献过滤** — `Load()` 从 `SectionContributionStream` 构建 `contribution_rvas_`/`contribution_modules_` 数组。`FindModuleIndicesForRva()` 据此定位目标 RVA 所属的模块。`ProcessModules()` 再用 `GetModule(index)` 直接处理这 1-2 个模块，避免遍历全部约 5000 个模块。

**状态缓存** — `loaded_module_indices_` 和 `all_modules_loaded_` 避免重复查询时重处理模块。inlinee 名字和类类型名按 id 增量缓存，`public_symbols_loaded_` 标记 public symbol 全量扫描是否已经完成。

### 关键文件

| 文件 | 职责 |
|------|------|
| `src/main.cpp` | 命令行解析，`PrintResult`（addr2line 风格输出） |
| `src/resolver.h/cpp` | 核心：PDB 加载、模块处理、查询 |
| `src/binary_annotations.h/cpp` | MSVC 二进制注解解压（内联站点） |
| `src/types.h` | 共享结构体：`CommandLine`、`LineEntry`、`FunctionEntry`、`InlineSiteEntry` 等 |
| `src/pe_utils.h/cpp` | PE 头解析：文件偏移→RVA、提取 ImageBase |
| `src/memory_mapped_file.h/cpp` | Win32 文件映射封装 |
| `src/string_pool.h` | 字符串驻留（基于 hash map） |
| `src/utils.h/cpp` | 整数解析、十六进制格式化 |
| `make.lua` | luamake 构建定义 |
| `third_party/raw_pdb/` | raw_pdb 库（BSD-2-Clause），git submodule |

### 重要实现细节

- **二进制注解修复**（`binary_annotations.cpp`）：4字节压缩整数格式用 `(first & 0xC0u) == 0xC0u` 检测（bits 7-6 = 11），用 `(first & 0x3Fu)` 提取值（bits 0-5）。原代码错用了 `0xE0`/`0x1F`，导致 0xE0-0xFF 范围的值解析失败。

- **文件校验和安全**（`resolver.cpp`）：不再通过 `Pointer::Offset` 从原始注解偏移直接计算指针（可能越界崩溃），而是用 `ForEachFileChecksum` 预先构建 `module_filename_offset_by_checksum_offset` 映射表，再做安全的 map 查找。

- **输出格式**：普通帧输出 `func at file:line`，内联调用链输出 ` (inlined by) func at file:line`（由内到外）。

- 单线程，所有 PDB 数据通过内存映射只读访问。
