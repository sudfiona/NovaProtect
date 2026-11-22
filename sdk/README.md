# NovaProtect SDK

给应用代码打标记，让 NovaProtect 客户端在打包时把这些函数/区域虚拟化或混淆。

- **不想改源码？** 用客户端的函数扫描（`.pdata` 枚举），勾选即可，见下文。
- **想知道能虚拟化什么？** 见[虚拟化覆盖](#虚拟化覆盖)——约束比早期版本宽松得多。

## 目录

| 路径 | 内容 |
| --- | --- |
| `include/novaprotect_sdk.h` | C/C++ 头文件：`NOVAPROTECT_BEGIN(name)` / `NOVAPROTECT_END()` |
| `examples/example.cpp` | C++ 使用示例（普通函数体打标记） |
| `examples/example_vm.S` | 寄存器直通的手写汇编示例（最紧凑的虚拟化形态） |
| `examples/example_driver.c` | 汇编示例的驱动，验证保护前后结果一致 |

## 快速开始

```cpp
#include "novaprotect_sdk.h"

int secret(int x)
{
    NOVAPROTECT_BEGIN("secret");
    int y = x * 7 + 13;
    y ^= 0x5A5A;
    NOVAPROTECT_END();
    return y;
}
```

1. 编译 EXE（标记在未保护的构建里是惰性的，几条 `nop` + 一个 `lea` 定位锚点）。
2. 把 EXE 拖进 NovaProtect 客户端，选择「虚拟化」或「Ultra」模式。
3. 构建。受保护镜像里这段逻辑以 wire 字节码存在，由随镜像分发的解释器执行。

标记字节模式在保护器侧被扫描：`NOVAPROTECT_BEGIN` 展开为一个 `lea` 锚点 + 20 字节 `nop` 填充，`NOVAPROTECT_END` 是另 20 字节 `nop`。打包器据此定位区域边界。

## API 参考

### `NOVAPROTECT_BEGIN(name)`

标记保护区域开始。`name` 是给打包器与构建日志看的标签，不影响生成的字节。

| 平台 | 展开为 |
| --- | --- |
| x64 Windows | `lea rcx, [rip+0]`（锚点）+ 20 × `nop` |
| x86 Windows | `lea ecx, [eip+0]`（锚点）+ 20 × `nop` |

### `NOVAPROTECT_END()`

标记保护区域结束：20 × `nop`。

### `NOVAPACK_BEGIN` / `NOVAPACK_END`

旧名别名，字节模式与新版完全相同，已有项目无需改动。

### 编译器要求

`__asm__ volatile(...)` 内联汇编语法，支持：

| 编译器 | 平台 | 备注 |
| --- | --- | --- |
| GCC / MinGW-w64 | x86 / x64 Windows | 首选；本仓库的构建链路就是它 |
| Clang | x86 / x64 Windows | 同上 |
| MSVC | x64 | `NOVAPROTECT_INLINE` 走 `__forceinline`；但 MSVC 不支持 GCC 风格内联汇编，标记需用单独的 `.asm` 文件或改用函数扫描 |

非 Windows 平台会触发 `#error`——标记是 Windows 专用的。

## 手动添加函数保护（无需改源码）

客户端「保护」页提供函数扫描器：对 x64 目标读取 `.pdata` 异常目录，枚举全部运行时函数（含静态函数），勾选即可对整个函数体做 VM 保护。

- 扫描结果按 RVA 排序，显示名称 / 地址 / 所在节 / 大小 / 是否导出 / 是否含栈帧。
- 「添加所有函数」一键全选；批量设置模式（继承 / 虚拟化 / Ultra / 变异 / 跳过）、VM 复杂度、变异强度与激活锁定。
- **区域表上限 8192**（早期版本是 64，2.3.20 起放开）。8192 只是损坏计数的防护上限，每个描述符仍按自身区域大小做边界检查。
- 扫描出来的函数按**完整函数区间**虚拟化：帧序言与尾声/`ret` 同样进 VM（push/leave/ret 全降低），多返回、共享尾声、尾调用全部正确；降不了的指令形式经原生桥执行。

## 虚拟化覆盖

同一目标 5266 个 `.pdata` 函数实测，**100.0% 的函数字节被虚拟化**（5351 个 chunk 全部可虚拟化、零拒绝桶，1,589,043 / 1,589,307 字节）。翻译器把 x86-64 翻译成 wire 指令集（145 个操作码），由解释器执行。

### 已覆盖

| 类别 | 内容 |
| --- | --- |
| 整数 ALU | ADD / SUB / ADC / SBB / AND / OR / XOR / NOT / NEG / INC / DEC / MUL，**8/16/32/64 位全宽度**，标志在操作数宽度上精确计算（`add al,bl` 之后的 `jb` 读到的是字节进位） |
| 移位旋转 | SHL / SHR / SAR / ROL / ROR，8/16/32/64 位，立即数与 CL 形式；SHLD/SHRD |
| 数据移动 | MOV（含 8/16 位拼接）、MOVZX/MOVSX、LEA（含 SIB 比例变址、无基址、RIP 相对）、XCHG、XADD、PUSH/POP（含帧序言的 `push rbp`）、moffs 直接寻址（A0-A3） |
| 控制流 | 全部条件跳转、JMP（直接/间接）、CALL（直接/间接/`call [mem]`）、RET（含 `ret imm16`，降低为返回地址间接出口 + 栈调整）、尾调用、SETcc、CMOVcc |
| SSE 算术/浮点 | ADD/SUB/MUL/DIV/MIN/MAX/SQRT × ps/pd/ss/sd、AND/OR/XOR/ANDN、CMPPS/CMPPD/CMPSS/CMPSD 全部谓词、COMIS*/UCOMIS*、16 种数据类型转换（`cvt*` 舍入到最近偶数、`cvtt*` 截断） |
| 整数 SIMD | PCMPEQB/W/D/Q、PCMPGTB/W/D/Q、PUNPCK*、PACK*、PADD/PSUB B/W/D/Q、PAND/POR/PXOR/PANDN、PSHUF*、PSLL/PSRL/PSRAW/D/Q、PSLLDQ/PSRLDQ、PMOVMSKB、PMULLW 等乘法 |
| SSE 数据移动 | MOVUPS/MOVAPS/MOVDQA/MOVDQU/MOVSS/MOVSD/MOVQ/MOVD 取存、MOVLPS/MOVHPS/MOVHLPS/MOVLHPS、PXOR 归零 |
| 位操作 | BT / BTS / BTR / BTC（寄存器与内存形态、imm8 组形态）、BSF / BSR（含 TZCNT/LZCNT） |
| x87 | D8-DF 转义（`WIRE_X87` 按 (esc,modrm) 原始编码查表执行，语义等价原生） |
| 字符串 | MOVS / STOS / LODS / SCAS / CMPS（REP 前缀、DF 方向标志为真实 VM 状态，CLD/STD 生效） |
| 原子/系统 | CMPXCHG（内存形态，含 LOCK）、CPUID、RDTSC、RDRAND/RDSEED、UD2 |
| 栈与帧 | `enter imm16, 0`（= push/mov/sub 三步，分配量按 CPU 实测为原样 imm16）、`pushfq`/`popfq`（flag 文件按 RFLAGS 布局往返）、8 位乘除对（`mul/div r/m8`，AX 对语义与 AH 驱动的 CF/OF） |
| 标志 | SAHF / LAHF / STC / CLC / CMC / CLD / STD，全部条件码 |
| 其它 | 128 位乘除（RDX:RAX）、CDQ/CQO、RIP 相对寻址（运行期映像基址重定位，ASLR 下语义不变） |

### 经原生桥执行（功能不受影响）

降不了的指令形式**不再放弃整个函数**：chunk 在该指令前停止，指令按原生语义在两个 VM 区之间执行，随后继续开新 chunk。实测目标中这些形式零出现：

| 形式 | 原因 |
| --- | --- |
| AVX/VEX/EVEX 前缀指令 | 三操作数、非破坏性，需扩展寄存器文件（长度已精确解码，桥切分位置准确） |
| `cmpxchg8b/16b` | 原子原语——任何 VM 合成都会丢跨线程原子性，必须原生执行 |
| 寄存器-寄存器 `cmpxchg` | 原子性语义保留在原生 |
| 16 位 `push`/`pop`、`enter` 嵌套帧（level>0） | 窄栈语义 / 帧链遍历无 wire 降低 |

深度不可界定的栈深（`sub rsp, reg`，即 `__chkstk`/alloca 形态）同样经原生桥切分，前后区域继续虚拟化。

跳过原因在构建日志里**按类计数**打印（`VM skip summary`），不是静默丢弃。

### 区域尺寸下限

**5 字节。** trampoline 生成到独立的可执行 arena（每个区域预留 1024 字节），区域头部只写一个 5 字节 `jmp rel32`。早期版本要求区域容纳完整 trampoline（约 137 字节），现在没有这个限制。

## 标记示例

### 普通 C++ 函数体

```cpp
#include "novaprotect_sdk.h"

int verify_license(const char* key)
{
    NOVAPROTECT_BEGIN("verify_license");
    unsigned h = 0x811C9DC5;
    for (const char* p = key; *p; ++p) { h ^= (unsigned char)*p; h *= 0x01000193; }
    NOVAPROTECT_END();
    return h == 0x4B1D3F2Au ? 1 : 0;
}
```

### 寄存器直通手写汇编（最紧凑形态）

见 `examples/example_vm.S`。手写汇编块可以做到无栈帧、纯寄存器，是虚拟化密度最高的形态：

```asm
# 见 examples/example_vm.S —— 寄存器直通，无栈帧
```

配套的 `examples/example_driver.c` 演示怎么验证保护前后输出一致。

## 与商业 VMProtect 的关系

本 SDK 的标记字节模式与商业 VMProtect SDK 的调用点**互不冲突**：`src/client_gate.cpp` 与 `runtime/managed_host.cpp` 里的 VMProtect 标记调用在缺少商业 SDK 时编译为无操作（`NOVAPROTECT_VMP_STUB`）。想叠加商业保护器那层，自行购买授权后把 SDK 放到 `third_party/vmprotect/`，构建会自动检测并使用。

## 兼容性

| 项 | 支持 |
| --- | --- |
| 平台 | Windows x64（完整）、Windows x86（引导桩与保护运行时都有 32 位实现） |
| 编译器 | GCC / MinGW-w64（首选）、Clang；MSVC 需外部 `.asm` 或改用函数扫描 |
| 目标产物 | EXE / DLL |
| 旧 API | `NOVAPACK_BEGIN` / `NOVAPACK_END` 继续可用，字节模式不变 |
| SDK 版本 | 见 `novaprotect_sdk.h` 里的 `NOVAPROTECT_SDK_VERSION` |

## 常见问题

**编译后没被打包器识别到标记？**
确认 `NOVAPROTECT_BEGIN` 与 `NOVAPROTECT_END` 成对出现、之间没有 `return`/`goto` 跳出，且编译器没有把整块内联优化掉（标记用 `volatile` 内联汇编，正常不会被优化）。构建日志会打印扫描到的区域数。

**想保护的函数被跳过了？**
看构建日志的 `VM skip summary` 按类计数。当前口径下函数不再因栈帧/内存被整体跳过——降不了的指令形式（AVX、`cmpxchg8b/16b` 等）经原生桥执行，其余字节照常虚拟化；仍会整段保留原生的只剩罕见形态（`enter` 嵌套帧、16 位 `push/pop` 等，见上表）。

**保护后输出变了？**
不该发生。`tests/regress.ps1` 对每个样本都做「保护后运行输出 == 保护前输出」的比对。请报告复现步骤。
