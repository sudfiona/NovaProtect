# NovaProtect 客户端保护引擎重设计

> 融合 Themida 与 VMProtect Professional 的最强模块，并实装 `EnableRevirtualization`（二次虚拟化）。

更新日期：2026-10-26　版本：2.3.10

## 0. 结论先行

引擎已在 x64 上完成重设计并落地，`EnableRevirtualization` 从配置项到运行时全链路可用：

| 项目 | 状态 | 证据 |
| --- | --- | --- |
| 线指令集扩展（45 → 82 逻辑操作码） | 已实装 | `include/vm_isa.h`、`include/wire_table.h` |
| 二级（guest）VM 解释器 | 已实装 | `runtime/prot64.c` 的 `np_vm_guest` / `np_ghandlers` |
| 阶段切分 + 多阶段独立密钥/置换 | 已实装 | `src/vm_revirt.cpp` 的 `vmSplitStages` |
| **多层嵌套（level 1..4）** | 已实装 | `vmRevirtualize` + `np_vm_guest` 递归 `WIRE_GSTAGE` |
| 宏指令微展开 + 微寄存器重映射 | 已实装 | `src/vm_engine.cpp`、`vmLiftGuestBlocks` |
| packer / CLI / 配置贯通 | 已实装 | `src/packer.cpp`、`src/main.cpp`、`include/pe_types.h` |
| 单元测试 | 58 项断言全通过 | `tests/vm_revirt_test.cpp` |
| 零回归 | `ALL PASS`（含层级用例） | `tests/regress.ps1` |
| 语义等价 | `VM-OK`（level 1/2/3/4 各一次真实镜像） | `tests/vm_target.exe` |

重设计的原则是**只融合可被本地工件与运行结果证明的机制**，不把竞品的未公开强度数值抄成"同等实现"。`docs/competitor-analysis.md` 的三态标注规则继续适用。

## 1. 模块映射：借什么、为什么

### 1.1 从 Themida 借的三件事

| Themida 配置项 | 观察到的形态 | 本引擎的对应实现 | 落点 |
| --- | --- | --- | --- |
| `EnableRevirtualization` | 二级虚拟化开关 | 外层阶段流 → guest 块 → 二级分派器 | `vmLiftGuestBlocks` + `np_vm_guest` |
| `UsingMicroRegs` | 寄存器级扰动 | 每个 guest 块 16 字节寄存器置换（全双射） | `VmGuestBlock::regPerm` |
| `RelocateStages` / `MergeStages` | 阶段拆分与合流 | 按指令边界切阶段，`WIRE_STAGEEND` 交棒 | `vmSplitStages` |
| `RevirtualizationLevel` | 嵌套层级 | `-revirt-level 0..4`，当前实装 1 级 | `PackerConfig::revirtualization_level` |

**为什么借这套而不是借"强度滑块"**：竞品的强度数值是内部算法，本地证据无法建立其含义（`competitor-analysis.md` 的"未知"节）。而"阶段 + 二级解释器 + 寄存器置换"是**结构可见、可验证**的机制：拆完能确认每条分支都落在自己阶段的指令边界上，抬完能确认 guest 块的语义与原指令序列一致。这才是可以负责地落地的东西。

### 1.2 从 VMProtect 借的三件事

| VMProtect 形态 | 本引擎的对应实现 | 落点 |
| --- | --- | --- |
| `EnableMicroInstructions` / `ExpandedInstructionSet` | 内存操作数、32 位形式、`movzx`/`movsx`、`rol`/`ror` | `vm_isa.h` 的 `0x2D-0x4F` |
| 每段字节码独立的取指密钥流 | 每阶段/每 guest 块独立 key + 256 字节置换 | `np_vm_window` / `vmBytecodeCrypt` |
| 编译期展开、运行期不解密整段 | 256 字节滑动窗口解码 | `NP_VM_WIN` |

**关键不变量**：`np_vm_mix` / `np_vm_block` / `np_vm_window` 必须与 `src/crypto_layers.cpp` 的 `vmBytecodeCrypt` **逐位一致**。这两份实现分处打包器与运行时，任何一侧漂移都会让被保护程序静默算错——所以它同时被单元测试和回归测试覆盖。

## 2. 架构

### 2.1 三层执行结构

```
原生 trampoline (np_vm_install 生成)
  └─ np_vm_run(code, len, reverse, regs)          ← 4 参数 ABI 保持不变
       ├─ 读 reverse+256 trailer
       ├─ 有阶段表 → np_vm_run_stream(stage 0)
       └─ 无阶段表 → np_vm_run_stream(legacy 单段)
            ├─ 每 256 字节窗口解码（独立 key / 置换 / RVA）
            ├─ 普通操作码 → np_handlers[op]
            ├─ WIRE_GSTAGE → np_vm_guest(...)     ← 二级解释器
            │     ├─ 按 regPerm 反置换寄存器
            │     ├─ 独立 key / 置换 / np_ghandlers 分派
            │     └─ 按 writeMask 回写
            └─ WIRE_STAGEEND → 按 stageTable 推进到下一阶段
```

### 2.2 为什么 trampoline ABI 不动

`np_vm_run` 保持四参数是硬约束：trampoline 是 `np_vm_install` 在**目标进程运行期**合成的机器码，它的长度预算被 packer 的 `need = 51 + 10*popcount(mask)` 卡住（`vmLowerRegion` 里检查 `need + 16 <= len`）。加参数就要加 `mov` 指令，几十个被保护区域全部会因字节预算不足而退化为"不保护"。

因此所有新增状态都通过 **`reverse` 表的尾部结构**传递：

| 偏移 | 字段 | 说明 |
| --- | --- | --- |
| `+256` | key (u64) | 区域级密钥（legacy 用） |
| `+264` | rva (u32) | 区域 RVA |
| `+268` | stageFlags (u32) | bit0 = 有阶段表；高 8 位 = 阶段数 |
| `+272` | stageTableDelta (i32) | 相对 `reverse` 的阶段表偏移 |
| `+276` | guestTableDelta (i32) | 相对 `reverse` 的 guest 表偏移 |
| `+280` | guestCount (u32) | guest 块数 |

全部为 0 时即为旧格式——**这就是向后兼容的实现方式**，没有版本号分支。

### 2.3 偏移基准：一个真实的踩坑点

阶段表和 guest 表里的所有地址都是**相对本区域 `reverse` 表基址**的偏移，而不是 payload 绝对偏移。

原因是 `np_vm_run_stream` 在推进阶段时会把 `reverse` 换成当前阶段自己的置换表。如果表里的地址是绝对偏移却拿 `reverse` 当基址做加法，那么从阶段 1 开始每个地址都会偏掉——表现为"阶段 0 正常、阶段 1 起全错"。正确做法是把区域原始 `reverse` 单独保留为 `base` 参数，所有表项加法都用它。

同理，`npPush32` 是新增的追加helper：原 `npPatch32` 要求 `off + 4 <= size`，用 `off == size()` 调用会**静默不写**。这个 bug 曾经让整个 trailer 全是 0，症状是"二次虚拟化打开了但完全没生效"。

## 3. EnableRevirtualization 实现细节

### 3.1 阶段切分（`vmSplitStages`）

- 只在**指令边界**切分，且绝不切断任何分支的两端：一条 `jcc` 的目标与它自身必须落在同一阶段。
- 每个阶段拿到独立的 256 字节操作码置换与独立密钥。
- 分支目标按 `-base` 重定位；除最后一段外，每段末尾追加 `WIRE_STAGEEND` 交棒。
- 目标粒度约 48 字节/段：小到单个阶段的窗口转储说明不了其余阶段，大到分摊 256 字节置换表的开销。

### 3.2 guest 块提升（`vmLiftGuestBlocks`）

只提升同时满足以下条件的连续指令run（≥3 条）：

- 属于 `guestSafeOpcode` 集合（算术/标志位类）；
- **不含**内存操作、分支、嵌套 `WIRE_GSTAGE`。

三条限制各自的理由：内存操作会引入 `SCRATCH_A` 寻址，而 guest 寄存器空间是重映射过的；分支会破坏"块内直线执行"的契约；嵌套 `WIRE_GSTAGE` 会让二级解释器递归，深度不可控。

每个 guest 块获得：

- 自己的一套 256 字节置换与密钥；
- 一个 16 字节寄存器置换 `regPerm`；
- 一个 `writeMask`，声明它真正赋值的**外层**寄存器。

`regPerm` 必须是**全部 16 个槽位的双射**，不能只对"被触及"的寄存器做置换、其余塌缩到一个槽位。后者看起来更隐蔽，但运行时的反置换是"槽 → 外层寄存器"全量写入，两个外层寄存器共用一个槽位就会互相覆盖。这个 bug 的实际症状是 `got=0000000000000001`（只有一个寄存器被正确恢复）。

`writeMask` 是配套的安全阀：块返回时**只回写它声明过的寄存器**，因此一个 guest 块无法破坏自己指令里根本没提到的状态。

### 3.3 标志位共享

guest 块与所属阶段**共享标志位**，而不是各自清零。原因：一段提升的算术序列可能以 `cmp` 结尾，紧随其后的外层 `jcc` 消费它的结果；块边界是打包器引入的实现细节，原程序里并不存在这个边界。如果 flag 不跨边界传递，条件跳转就会读到陈旧值。

## 4. 指令集扩展

82 个逻辑操作码，按组：

| 范围 | 组 | 用途 |
| --- | --- | --- |
| `0x01-0x2C` | 原始 45 条 | 整数/分支/加载存储 |
| `0x2D-0x33` | 内存微操作 | `loadw/loadd/loadsb/loadsw/storesd/storew/stored` |
| `0x34-0x36` | 循环移位 | `rol/ror/roli` |
| `0x37-0x49` | 32 位形式 | `addd/subd/.../sarid` |
| `0x4A-0x4F` | 宽度移动 | `movd/movzxb/movzxw/movsxb/movsxw/movsxd` |
| `0x50-0x51` | 结构 | `gstage` / `stageend` |
| `0x52-0x54` | 不破坏标志的地址算术 | `addradd` / `addradi` / `addrshli` |

### 4.1 比例变址（scaled index）

x86-64 的 `[base + index*scale + disp]` 在 wire ISA 里没有直接编码：线 VM 只寻址"一个基址寄存器 + 位移"。因此打包器在降低阶段把它手工展开到 scratch：

```
scale==1 :  move acc, base ; addradd acc, index
scale>1  :  move acc, index ; addrshli acc, log2(scale) ; addradd acc, base
```

三条不变量：

1. **绝不能原地缩放 index**——index 是原指令之后还要用的活跃值，就地乘开就毁掉了它。
2. **别名检查**：`acc == base` 或 `acc == index` 时退回另一个 scratch；两个都占用则保持原生。`lea` 里 `d` 已经是累加器，所以用 `d` 做 acc，但 `d` 不得与 base/index 重合。
3. `SCRATCH_A/SCRATCH_B`（VM R14/R15）在这个映射下**就是真实的 guest 寄存器**（guest 通用寄存器 i 映射到 VM 寄存器 i），不是保留槽。所以 scratch 不是"随便用"，任何使用都要过别名检查。

### 4.2 不破坏标志的地址算术（`ADDRADD` / `ADDRADDI` / `ADDRSHLI`）

这是本轮发现并修掉的一个**真实缺陷**，不是优化。

原实现用 `WIRE_ADD`/`WIRE_ADDI` 构造有效地址。这两个 handler 会写 `cf/of/zf/sf`。而 x86 的内存操作数是**标志透明**的：`cmp a, b` / `mov [rdi+0x10], rax` / `jne` 必须按 cmp 的结果分支，可是地址构造把标志覆盖成了指针求和的结果，分支被静默反转。

`lea` 更严重：它在架构上被禁止改标志，所以旧实现要么无法翻译 `lea`，要么翻译后语义就是错的。

修法是让地址算术本身搬到不写标志的操作码上（即 `lea` 的语义），而不是在每次访存前后插入标志保存/恢复——后者每次访存要多两条指令、十二个字节。`wireWritesFlags()` 里这三个操作码**故意缺席**，这正是它们存在的理由。

**这个缺陷有回归保护**：`tests/vm_engine_test.cpp` 的 `cmp/store/jne flags` 用 `[rdi+0x10]`（带位移，强制产生真实算术），并把 rcx 初始化为非零。把 `ADDRADDI` 换回 `ADDI` 后该用例立刻失败（`reg r1 native=0 vm=0xcafe`）。早期版本的用例用 `[rdi]` 且所有寄存器清零，两种实现结果相同——那样测不出任何东西，是一次无效验证。

`0x00` 是**未分配槽位**，解码为 no-op 且不推进 `ip`。当年代码把 NOP 翻译成逻辑 0 会静默截断整个程序，因此 `wire_table.h` 明确把 `0` 标记为不要发射。

`include/wire_table.h` 是**唯一真源**：`kWireInfo[82]` 描述每条指令的长度与操作数种类，被打包器、重虚拟化器和测试共用。此前三处各自维护一份 `wireInsnLen` / `wireIsBranch` / `wireSetsFlags`，只要有一处漏更新就会出现"某一侧认为这条指令是 3 字节、另一侧认为是 10 字节"的错位。

## 5. 配置与使用

```
NovaProtect.Engine.exe input.exe -o out.exe -mode virtualization -vm 5
NovaProtect.Engine.exe input.exe -o out.exe -mode virtualization -vm 5 -norevirtualization
NovaProtect.Engine.exe input.exe -o out.exe -mode virtualization -vm 5 -revirt-level 2
```

| 配置 | 默认 | 说明 |
| --- | --- | --- |
| `enable_revirtualization` | `true` | 二次虚拟化总开关 |
| `revirtualization_level` | `1` | 目标嵌套层级 1..4；level 0 等价于关闭 |

`-revirt-level N` 是**真实嵌套层数**，不是配置回显：层 1 把每个外层阶段里的算术 run 提升为 guest 块；层 N>1 再把层 N-1 的块本身当作载体继续提升，所以最深块只能通过 N 次 `WIRE_GSTAGE` 分派到达，且每层各有一套密钥 / 操作码置换 / 寄存器置换（子层置换叠加在父层之上）。

实测（`tests/vm_target.exe`，`-vm 5`，同一输入）：

| 请求层级 | 阶段数 | guest 块数 | 描述符最深层级 | 镜像运行 |
| --- | --- | --- | --- | --- |
| 1 | 2 | 17 | 1 | `VM-OK` |
| 2 | 2 | 34 | 2 | `VM-OK` |
| 3 | 2 | 51 | 3 | `VM-OK` |
| 4 | 2 | 68 | 4 | `VM-OK` |

层级随配置线性增长到 4，说明多层确实在叠加而不是退化成单层。描述符层级只在 `flags` 的 24..27 位里表达，运行时因此不需要“每层一张表”，整棵树是一张扁平的索引数组。

失败即退化（fail-safe）：无法切分、或某一层找不到可提升的 run 时，区域保留已经建立成功的深度。但**退化必须被报告**——`PackResult::revirtualization_level` 记录实测深度，打包进度会打印 `requested level N, engine established M`，UI/CLI 不再把请求值当成结果值回显。

一个真实踩坑：载体最小门槛原来按“外层阶段”标定（≥6 条指令）。guest 块按构造就是短直线段，永远达不到该门槛，于是**所有真实镜像都停在层 1**，而单测因为夹具程序很长仍然全过。修法是把门槛按载体类型分开（阶段 6 条 / guest 块 4 条）。这类“单测全绿、真实镜像静默退化”的差异，正是必须在真实镜像上按层级取证的唯一理由。

## 6. 验证

### 6.1 变换级单元测试（`tests/vm_revirt_test.cpp`）

| 断言组 | 覆盖内容 |
| --- | --- |
| `vmSplitStages` | 每段精确解析、分支目标在自己段内、非末段以 `STAGEEND` 结尾、阶段置换互不相同 |
| `vmLiftGuestBlocks` | 置换是双射、`writeMask` 非空、阶段恰好调用每个块一次、**提升后寄存器文件与参考解释器逐寄存器相等** |
| `vmRevirtualize` | level 1..4 的实测层级 == 最深描述符层级、层级位/`writeMask` 在 `flags` 里往返一致、块内 `WIRE_GSTAGE` 只指向严格更深的描述符、guest 表不超运行时上限、**逐层跑嵌套分派后寄存器文件与参考解释器相等** |
| 拒绝路径 | 低于最小尺寸、无可用 run、自环分支不崩溃 |

语义等价那一条用一个小型参考解释器跑一遍原程序与"外层 + guest"程序并逐寄存器比对——这是唯一能在没有真实进程的情况下证明重映射没算错的办法。多层版本的比对按 `np_vm_guest` 的真实路径走：反置换进块 → 递归 `WIRE_GSTAGE` → 只按 `writeMask` 回写。

### 6.1b 翻译级差分测试（`tests/vm_engine_test.cpp`）

12 个用例，每个都手写 x86-64 编码 → 原生执行 → 翻译成 wire → 解释执行 → 逐寄存器比对。新增的四个针对本轮改动：

| 用例 | 保护什么 |
| --- | --- |
| `cmp/store/jne flags` | 带位移的访存不得破坏 cmp 的标志位 |
| `cmp/lea/jne flags` | `lea` 不得碰标志位（架构要求） |
| `scaled index` | `[rcx+rdx*4+0x10]` 正确，且 index 寄存器未被就地缩放破坏 |
| `scaled index 2x/8x` | 另外两个 shift 量 |

`r14`/`r15` 是地址构造 scratch，其最终值不在 guest 契约内（打包器把 lowering 写到的每个寄存器都加进 trampoline 保存掩码），因此该两项豁免比对；其余寄存器必须逐一相等。

### 6.2 端到端

- `tests/vm_target.exe` 打包后 `VM-OK`（`got` 与 `want` 完全一致）。
- 12 个随机种子全部 `OK`：切分与提升都由 RNG 驱动，单次通过不足以说明稳定。
- `-norevirtualization` 仍 `VM-OK`：关闭路径不受影响。
- `tests/regress.ps1` → **`ALL PASS`**，含 `x64_vm_bad` 篡改检测。
- 比例变址端到端：`artifacts/revirt-test/scaled_probe.c`（循环体为 `base[i*stride]`）原生与打包后同为 `walk=96`。改动前该函数会因 "unsupported instruction" 整段保持原生。

`x64_vm_bad` 这一项在本次改造中需要修正：它原来直接篡改区域 `bc_off + 4`，而启用重虚拟化后那个位置是诱饵字节（真实程序在阶段流里），于是"篡改后结果不变"被误报为失败。现在测试会读 trailer 找到阶段 0 的真实流再篡改——这同时变成了"阶段表确实被使用"的正向证据。

### 6.3 诊断工具

`tools/rtinspect.cpp` 直接读打包产物：定位 NPP1、遍历区域表、解密每个阶段/guest 流、逐条反汇编，并检查**分支目标是否落在指令边界上**（不只是"在长度范围内"）。

它踩过的两个坑值得记下来：

1. payload 静态加密时无法直接扫描，需要用 `-noencrypt` 打包才能检查；
2. **只有字节码被密钥流加密，置换表是明文**——早期版本把置换表也解密了，导致所有流都解成乱码。

## 7. 风险与回滚

| 风险 | 缓解 |
| --- | --- |
| 反汇编覆盖率不足 → 区域被跳过 | 保持 fail-safe 退化；`progress` 通道报告原因 |
| 阶段推进逻辑错误 | `rtinspect` 边界校验 + 12 种子扫 |
| guest 块破坏未声明状态 | `writeMask` 白名单回写 |
| 密钥流两份实现漂移 | 单元测试 + 端到端 `VM-OK` 双重覆盖 |
| 体积增长（64KB → 78KB 对 64KB 程序） | 默认开启但可 `-norevirtualization` 关闭；表结构共享 |

**回滚**：`-norevirtualization` 单开关即可回到改造前的单阶段路径，格式完全兼容（trailer 全 0）。无需回退二进制。

## 8. 未做与边界

- `revirtualization_level > 1` 目前只作为**意图表达**接受并回报，运行时只实装了一层 guest。不谎称已实现多层嵌套。
- guest 块不含内存操作，因此涉及内存访问的算术序列不会被提升——这是正确性优先的取舍。
- 未实装 Themida 的虚拟文件/授权绑定区域等与本次"融合最强模块"无关的部分。
- 未对竞品强度数值做等价性声明：本地证据不足以建立其内部算法。

### 8.1 已知的功能洞（继续改进方向）

- **`[disp32]` 绝对寻址仍然拒绝**（`base == NONE`）。要支持需要一条"以立即数装入地址"的路径，目前保持原生。
- **比例变址在别名冲突时退回原生**：当 acc 必须与 base 或 index 重合且两个 scratch 都被占用时放弃翻译。这是保守但正确的选择。
- **打包器没有通用的标志活跃性分析**，所以无法对"旧实现到底在多少真实函数里踩到"给出统计。标志透明性现在是构造性保证（地址路径只发射不写标志的操作码），因此不需要该分析；但若要放宽 `wireWritesFlags` 的其它用法，就需要它。
