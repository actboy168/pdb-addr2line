# pdb-addr2line

把 **PDB + 地址** 解析回源码位置的 Windows 命令行工具，适合在崩溃分析、日志回溯、符号化脚本里快速把 RVA / VA 还原成函数名、文件路径和行号。

输出风格接近 `addr2line`，并支持 MSVC 的 inline 调用链显示。

## 特性

- 支持 **RVA** 和 **VA** 查询
- 支持一次输入多个地址做 **批量解析**
- 输出函数名、源码文件和行号
- 支持显示 **inline 调用链**
- 对大 PDB 做了按需加载优化，普通单点查询延迟较低

## 构建

```powershell
luamake
```

构建产物：

```text
build\bin\pdb-addr2line.exe
```

完全重编译时，可删除 `build\obj\` 和 `build\bin\pdb-addr2line.exe` 后重新执行 `luamake`。

## 用法

```text
pdb-addr2line <pdb-path> <rva> [more-rva...]
pdb-addr2line <pdb-path> --rva <rva> [more-rva...]
pdb-addr2line <pdb-path> --va <virtual-address> [more-virtual-address...]
pdb-addr2line <pdb-path> --image <binary-path> --va <virtual-address> [more-virtual-address...]
pdb-addr2line <pdb-path> --image-base <hex> --va <virtual-address> [more-virtual-address...]
```

### 参数说明

| 参数 | 说明 |
| --- | --- |
| `<pdb-path>` | PDB 文件路径 |
| `--rva` | 按相对虚拟地址查询 |
| `--va` | 按虚拟地址查询 |
| `--image <binary-path>` | 查询 VA 时，从 PE 文件读取 ImageBase |
| `--image-base <hex>` | 查询 VA 时手动指定 ImageBase |

## 示例

### 按 RVA 查询

```powershell
build\bin\pdb-addr2line.exe foo.pdb --rva 0x18444aa
```

示例输出：

```text
FMallocAnsi::Realloc at C:\project\src\hal\MallocAnsi.cpp:205
```

### 按 VA 查询

```powershell
build\bin\pdb-addr2line.exe foo.pdb --image-base 0x140000000 --va 0x1418444aa
```

### 批量查询

```powershell
build\bin\pdb-addr2line.exe foo.pdb --image-base 0x140000000 --va 0x1418444aa 0x1419052eb
```

## 输出格式

普通帧：

```text
function at path:line
```

存在 inline 调用链时：

```text
inlined_function at path:line
 (inlined by) caller_inline at path:line
 (inlined by) outer_function at path:line
```

如果只找到行号但没有函数名，则输出：

```text
path:line
```

如果没有命中：

```text
<input> -> <not found>
```

## 限制

- 当前面向 **Windows + PDB** 场景
- 当前命令行接口支持 **RVA / VA** 查询
- `--va` 需要提供 `--image` 或 `--image-base`
- 不支持 `/DEBUG:FASTLINK` 生成的 PDB
