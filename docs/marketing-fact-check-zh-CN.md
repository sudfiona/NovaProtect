**NovaProtect 宣传文案技术依据（供内部核对）**

核对日期：2026 年 10 月 18 日。依据为当前工作区源码、构建规划器和项目记录；客户端版本文件为 2.2.7。本次工作为文案编写与静态核对，没有重新执行保护、运行回归或安全强度评估。

对外文案见同目录 `marketing-introduction-zh-CN.md`。

**实现与表述的对应关系**

| 宣传主题 | 当前实现与边界 | 主要依据 |
| --- | --- | --- |
| 原生区段保护 | 可执行区段及可选资源区段；有收益时进行 RLE 压缩；启用区段加密时使用循环 XOR。32 字节密钥长度不能据此表述为 AES-256。 | `src/packer.cpp`：`phase_encryptSections`；`src/pe_lib.cpp`：`util::xor_crypt` |
| VM 字节码组合加密 | 顺序执行 RC4、8 字节循环 XOR、字节加法；运行时逆序恢复。密钥派生使用区域 nonce、RVA 与层索引，经 FNV-1a 等混合处理。 | `src/crypto_layers.cpp`；`runtime/prot64.c`：`np_layered_decrypt` |
| x64 区域虚拟化 | 来自真实 NovaProtect SDK marker；转换为内部 wire ISA，并通过映射表解释执行。降不了的指令形式经原生桥执行（函数其余部分照常虚拟化），实测 100.0% 函数字节被虚拟化，以实际构建结果为准。 | `include/vm_isa.h`；`src/vm_engine.cpp`；`src/packer.cpp`：`VMTranslator::translate` 及原生桥切分 |
| 代码变异 | 当前面向 x64 VM 翻译前的变异管线。独立原生 Mutation 模式不能概括为已经完整实现；失败翻译可能回退原始指令再尝试。 | `ui/Services/ProtectionPlanner.cs`：独立原生变异跳过原因；`src/packer.cpp`：变异与重试逻辑 |
| .NET 加密封装 | 使用 16 字节密钥、32 轮 XTEA 分组函数生成与 nonce、计数值相关的密钥流，再与载荷异或。未重写 IL、未做 IL 虚拟化。 | `src/managed_envelope.cpp`：`xteaBlock`、`cryptPayload` |
| .NET 启动方式 | 宿主解密并校验后，将原始载荷写到程序目录中的隐藏临时文件，通过子进程启动，结束后尝试删除。不能写成全程仅内存执行、完全不落盘或无法提取。 | `runtime/managed_host.cpp`：`CreateFileW`、`WriteFile`、`CreateProcessW`、`DeleteFileW` |
| 导入保护 | x86/x64 原生路径保存导入信息，移除常规可见导入目录，并由加载器重建 IAT。与代码区域 VM 是不同机制。 | `src/packer_meta.cpp`：`buildImportBlob`、`stripImportDirectory`；`runtime/stub.S`、`runtime/stub32.S` |
| 完整性校验 | 区段或载荷使用 FNV-1a 校验值，主要用于相应加载、启动检查。不能直接宣传为密码学认证加密或覆盖全生命周期的持续监控。 | `src/packer.cpp`；`runtime/prot64.c`：`np_chk_integrity`；`runtime/managed_host.cpp` |
| 许可与机器绑定 | 原生 x64 运行时校验许可数据及机器 ID；绑定在原始入口前执行。机器 ID 来自 CPUID 信息组合，不能承诺每台设备全球唯一或不可伪造。 | `runtime/prot64.c`：`np_chk_license`、`np_machine_id`；`docs/implementation-status.md` |
| 水印与虚拟文件 | 存在水印写入、读取以及附加文件嵌入、列举、提取。不能直接扩大为透明虚拟文件系统或完整文件访问拦截。 | `src/packer_meta.cpp`：`buildMetadataBlob`、`readWatermark`、`listVirtualFiles`、`extractVirtualFile` |
| 客户端自身完整性 | 有 RSA/SHA-256 签名清单验证与文件摘要检查。这是客户端分发、组件验证用途，不能移作用户程序载荷使用 RSA 加密的依据。 | `ui/Services/ClientIntegrity.cs`；`src/client_gate.cpp` |
| 产品构成 | C#/WinUI 3 客户端、C++ 保护引擎、汇编与 C/C++ 运行时、SDK、PHP 官网（无账户系统，仅客户端下载与后台发布）。 | `ui/NovaProtect.UI.csproj`；`src/`；`runtime/`；`sdk/`；`website/` |
| 目标能力 | x86/x64 原生 EXE 与 .NET EXE 分流；VM 和许可绑定主要限原生 x64；ARM64 当前拒绝构建。 | `ui/Services/ProtectionPlanner.cs`；`README.md` |

**“仿制了哪几个软件”的准确口径**

现有项目记录明确讨论的设计参考是 **VMProtect Professional、Themida 两款产品**，见 `docs/competitor-analysis.md`。记录支持对项目组织、SDK 区域、保护模式、属性与日志等产品设计的借鉴说明，不支持声称复制了它们的内部引擎、全部算法或达到相同强度。

工作区同时存在 `.NET Reactor` 目录，但本次在 NovaProtect 的源码和说明记录中未找到明确的对应借鉴关系。仅凭同目录放有软件，无法确定 NovaProtect 仿制了该产品。当前对外文案因此只写上述两款有记录的设计参考；如需介绍 .NET Reactor，应先明确实际参考了哪些交互或功能，并补充依据。

此外，项目历史上存在使用 VMProtect 加固自身发布文件的构建记录。产品自身发布加固与 NovaProtect 为用户 EXE 提供的保护管线属于不同环节，不能将前者包装成“已复现 VMProtect 引擎”，也不宜据此宣称所有发布保护技术均完全自研。依据：`docs/implementation-status.md`。当前版本的客户端发布打包已不再经过 VMProtect 后处理（仅源码保留 VMProtect SDK marker 底子），相关专用打包工具已从工作区移除。

**发布口径**

正文保留了目标架构与 .NET 实现边界，使用“增加分析工作”“提供分层保护”等描述。当前材料没有建立不可破解、保护强度排名、与竞品同等强度、量化性能损耗或全面兼容的结论，因此文案未加入这些承诺。保护效果与兼容性需要针对实际目标程序验证。
