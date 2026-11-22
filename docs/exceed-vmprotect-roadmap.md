# 全面超越 VMProtect Professional — 差距分析与落地路线

> 目标：让 NovaProtect 的保护强度在「VM 覆盖率、抗分析、运行时对抗、产物可验证性」四个维度上全面超过 VMProtect Professional。
> 本文件是路线图；已落地的改动见文末「本轮已改」。

更新日期：2026-11-20

---

## 0. 结论先行

NovaProtect 的 VM 引擎机制已经相当完整（85+ 操作码、二次虚拟化多层嵌套、阶段切分、字节码滑动窗口解密、乱序 handler 表、不透明谓词假跳转）。当前最痛的不是「机制不够」，而是**覆盖率太低**：在引擎自身 4832 个函数上，只有 42 个被真正虚拟化（≈0.9%）。VMProtect 的核心强度恰恰是「几乎什么都虚拟化得掉」。

因此「全面超过 VMProtect」的主线只有一条：**先把覆盖率拉到接近 100%，再堆抗分析强度**。覆盖率上不去，任何「更强」的机制都只作用在 1% 的代码上。

---

## 1. 覆盖率是第一优先级

### 1.1 现状（来自 STATUS.md 2.3.20–2.3.22 的实测）

| 拒绝原因 | 数量（4832 函数） | 占比 | 状态 |
| --- | --- | --- | --- |
| `no function body before RET` | 2836 | 59% | ✅ 已解决（尾跳 cut + epilogue 岛） |
| `uses RSP/RBP` | 1629 | 34% | ✅ 已解决（prologue 裁剪 + body 虚拟化，见 STATUS 36） |
| `unsupported instruction` | 213 | 4% | 主体转为 SSE/浮点（XMM 文件未做） |
| `8/16-bit` | 6 | <1% | mov/lea 拼接已做；ALU 标志语义待做 |
| 实际虚拟化 | 42 | <1% | ✅ 54.6%（5248 函数实测，见 STATUS 36 表） |

### 1.2 第一刀：查清 `no function body before RET` 为什么占 59%

这是**最大的单一覆盖率损失**。函数扫描区间来自 `.pdata` 的 unwind 边界，但 59% 的区间在第一个 RET 之前就扫描不到 RET。原因大概率是下面几类之一（必须先用 `tools/rtinspect.cpp` + 一个 `.pdata` 区间 dump 工具实测定性，不能猜）：

1. **尾调用（tail-call）结尾**：函数以 `jmp` 结束而非 `ret`（优化器常见）。当前 `vmLowerRegion` 只找 `RET`，不认 `jmp rel32` 结尾 → 整段跳过。修法：把「尾部 `jmp` 落到另一个已识别函数入口」也当作可虚拟化边界（只虚拟化到 jmp 之前）。
2. **noreturn 函数**：`call abort/exit` 后无 RET。这类本来就该跳过，但要能区分，不能和 1 混在一起。
3. **`.pdata` 区间粒度错**：扫描器可能把「两个函数之间的 gap」当成一个函数。需要按 `RUNTIME_FUNCTION` 的 BeginAddress/EndAddress 精确取区间，并对重叠/空洞做合并与去重。
4. **反汇编器在数据字节上卡死**：区间内混入 jump table / 对齐填充，`disassemble` 返回 0 就 break，后面的 RET 永远看不到。修法：失败时跳过 1 字节继续（对齐字节通常是 `CC`/`90`/`00`），而不是整段放弃。

**目标**：2836 → 尽量压缩到「真正的 noreturn + 纯数据区间」。这一步不碰 VM 机制，纯打包器/扫描器改动，风险低、收益最大。

### 1.3 第二刀：栈帧函数（`uses RSP/RBP`，1629 个）

这是**架构性**问题：trampoline 的寄存器保存区位于 guest RSP 之下（`sub rsp,144` 后 `[rsp+slot]`），区域内任何 `push`/`sub rsp,N`/`[rsp-k]` 都会写穿保存区。两条可行路线（STATUS.md 已定位，二选一）：

- **路线 A（推荐，正确性优先）：prologue/epilogue 裁剪 + 只虚拟化 body**。
  1. 识别并保留 prologue（`push rbp; mov rbp,rsp; sub rsp,N`）与 epilogue（`leave; ret` / `add rsp,N; pop rbp; ret`）为原生。
  2. 只虚拟化中间 body。body 内 RSP 稳定、`[rbp-X]` 落在入口 RSP 之上，不与 trampoline 保存区冲突。
  3. 静态验证 body 不改写 RSP、不访问 `[rsp-k]`；违反则回退原生。
- **路线 B：保存区搬离 guest 栈**。放静态区需解决多线程重入；放 TEB/TLS 需先分配内存。工程量大，作为路线 A 之后的可选项。

**目标**：1629 → 大部分可虚拟化。

### 1.4 第三刀：8/16 位寄存器写（`8/16-bit register form`）

wire 寄存器文件没有部分寄存器语义（写 AL 要保留 RAX 高 56 位）。补两个插入操作码即可：

- `WIRE_INSB dst,src`：`r[dst] = (r[dst] & ~0xFF) | (r[src] & 0xFF)`
- `WIRE_INSW dst,src`：`r[dst] = (r[dst] & ~0xFFFF) | (r[src] & 0xFFFF)`

配合已存在的 `MOVZXB/MOVZXW/MOVSXB/MOVSXW`，`mov al,bl`、`mov al,imm`、`add al,bl` 等常见字节/字形式即可翻译。

---

## 2. 抗分析强度（机制已强，继续堆）

### 2.1 每区域 handler 表置换（对照 VMProtect 的「每个 VM 独立 dispatch」）

当前 `np_handlers[]` 是**全局一张表**，虽然已乱序，但所有区域共用同一份 handler 地址。攻击者只要定位一次 `np_vm_run` → 找到 `np_handlers` → 全区域 handler 语义一次摸清。

修法：把 dispatch 从 `np_handlers[op]` 改成 `np_handlers[op ^ regionSalt]`，其中 `regionSalt` 由区域 trailer 携带、每个区域不同；`np_vm_init_handlers` 改为按 salt 生成置换后的表（或把 salt 折叠进 reverse 表）。这样每个区域 handler 布局都不同，单一特征码/断点失效。

### 2.2 不透明谓词强化

已实装假跳转（2.3.10）。可继续加：

- 多态不透明谓词：不止 `shri/shl/andi` 一族，加「二次剩余」「数组指针恒真」等数学恒等式，让谓词本身也随种子变化。
- handler 内联垃圾：在热门 handler（LOADQ/STOREQ/ADD）内部插随机死代码，抬高 handler 特征匹配成本。

### 2.3 反调试污染面（已强，可选增强）

`np_vm_run_stream` 每 4096 条指令重读 PEB 并污染 `r[0]`。可把污染从 `r[0]` 扩散到「随机寄存器 + 随机时机」，并增加 `NtQueryInformationProcess(ProcessDebugPort)` 的轮询（当前只在入口跑）。

---

## 3. 正确性债（必须在加功能前还清）

### 3.1 ✅ 本轮已修：Jcc 条件码错误映射（会造成保护后程序静默算错）

原 `jccWire` 把 `jae`（cc=0x3）降成 `JB`、把 `jbe`/`ja`（cc=0x6/0x7）降成 `JAE`——**分支方向被静默反转**。本轮已修并补齐 6 个条件码（见第 4 节）。

### 3.2 ⚠️ 待修：ADDI/SUBI 不写 OF，签名分支在读陈旧溢出位

`np_h_addi`/`np_h_subi` 只写 zf/sf/cf，不写 of。于是 `add rax,imm; jl` 这类签名分支会读到上一条指令遗留的 OF。修法：给 `np_h_addi`/`np_h_subi` 补上 `of` 计算（公式与 `np_h_add`/`np_h_sub` 一致），并同步到 `tests/vm_engine_test.cpp` 与 `tools/vmdbg.cpp` 的镜像解释器。

### 3.3 ⚠️ 待修：JP/JNP（奇偶标志）分支

wire 只跟踪 zf/cf/sf/of，没有 PF。`jp`/`jnp` 仍会拒绝（这是安全拒绝，不是错误），但会损失覆盖率。修法：给 `NpVmState` 加 `pf`，在写标志的 handler 里算 `pf = popcount(result & 0xFF) ^ 1`，再加 `WIRE_JP`/`WIRE_JNP`。

---

## 4. 本轮已改（2026-11-20）

**主题：补齐条件分支指令集 + 修复 Jcc 静默反转 bug（正确性 + 覆盖率 + 抗分析三赢）。**

新增 6 个 wire 操作码：`WIRE_JA / WIRE_JBE / WIRE_JS / WIRE_JNS / WIRE_JO / WIRE_JNO`，并把 `jccWire` 的错误映射修正为精确映射。

改动文件（全部保持四文件 + 镜像解释器同步）：

| 文件 | 改动 |
| --- | --- |
| `include/vm_isa.h` | 新增 6 操作码；`WIRE_COUNT` 0x55→0x5B；`NP_WIRE_OPCODE_SLOTS` 同步 |
| `include/wire_table.h` | `kWireInfo` 补 6 行；`wireIsBranchOp` 补 6 条件 |
| `src/vm_engine.cpp` | `jccWire` 精确映射（修 JB/JAE/JBE/JA 反置 bug，补 JS/JNS/JO/JNO） |
| `runtime/prot64.c` | `VMO_JA..JNO` 枚举 + 6 个 handler + `np_vm_init_handlers` 注册 |
| `tests/vm_engine_test.cpp` | 镜像解释器补 6 分支 + 3 个新用例（jae/jbe/js，锁定 bug） |
| `tests/vm_obfuscate_test.cpp` | 分支长度表补 6 操作码 |
| `tools/vmdbg.cpp` | 调试解释器补 6 分支 |
| `tools/rtinspect.cpp` | 操作码名表补齐（含先前漏掉的 ADDRADD/ADDRADDI/ADDRSHLI） |

**为什么这个改动是「超过 VMProtect」的第一步而不是自我安慰**：VMProtect 的 VM 对全部 16 个条件码都能精确虚拟化；NovaProtect 此前只能精确处理 11 个、还错算了 2 个。修完之后 x64 条件分支（除奇偶位外）全部精确，且不会再产出「分支被静默反转」的坏镜像。

**验证要求（本机无 MinGW 工具链，未能当场编译）**：

```powershell
cd <repo>
powershell -ExecutionPolicy Bypass -File .\build.ps1 -Prot -Cli   # 重编运行时 blob + 引擎
# 编译并跑 VM 语义测试（新增 3 个用例必须全绿）
g++ -std=c++17 -Iinclude -o tests\vm_engine_test.exe tests\vm_engine_test.cpp tests\np_thunk.S src\vm_engine.cpp
tests\vm_engine_test.exe
# 全量回归
powershell -ExecutionPolicy Bypass -File .\tests\regress.ps1
```

预期：`vm_engine_test` 13 用例全过（原 10 + 新 3），`regress.ps1` 零回归。改前 `jae` 用例会因旧 `jccWire` 反置而 FAIL，这是本轮修复的正向证据。

---

## 5. 建议的落地顺序（按 ROI 排序）

1. **（本轮）** 条件分支补全 + 反置 bug 修复 —— 已完成。
2. 查清并修 `no function body before RET`（59% 覆盖率，最大单点收益）。
3. prologue/epilogue 裁剪，把 1629 个栈帧函数纳入虚拟化。
4. 补 ADDI/SUBI 的 OF、加 PF 标志与 JP/JNP。
5. 补 INSB/INSW，收掉 8/16 位形式。
6. 每区域 handler 表置换（抗分析收尾）。
7. ARM64 loader 与 .NET CLR-aware 重建（能力矩阵补齐，见 `docs/implementation-status.md`）。

每一步都可独立验证（`regress.ps1` + 对应单测 + 真实镜像 `VM-OK`），符合「只写能证明的能力」的项目原则。
