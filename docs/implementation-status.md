# NovaProtect implementation status

更新时间：2026-10-14

## 已验证能力

- x64：区段加密、`-noencrypt`、导入虚拟化、SDK marker 区域 VM/Ultra、运行时许可、激活绑定。
- x86：loader、区段打包/加密、导入虚拟化；VM、许可和激活绑定明确跳过或拒绝。
- 原生 EXE：重定位裁剪会清空 Base Relocation 目录并清除 `IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE`；导出裁剪会清空 Export 目录。
- 原生 DLL：重定位裁剪和导出裁剪在 CLI 与 UI 规划器中均阻止。
- .NET：识别为 CLR 托管 PE，使用 CLR-safe 加密 EXE envelope；不改写 CLR metadata/IL，不宣称 IL 虚拟化。
- ARM64：识别架构，并在当前核心拒绝构建；没有伪装成 x64 loader 输出。
- 项目文件：保存/导入对象规则、marker 来源/检测器版本、全局配置、激活绑定和区段选项。
- 构建计划：构建前写入独立的 `*.novaprotect-prebuild.json`，最终状态写入 `*.novaprotect-build.json`；两者均包含 PlanId、stage、requested/effective/skipped/conflicts，并生成不可覆盖的本地历史快照。
- 完整架构矩阵：UI 同时横向展示 x86、x64、ARM64、.NET，并单列原生 EXE/DLL 的裁剪边界；当前目标仍显示精确能力列表。

## 对象编辑器边界

对象列表只来自 NovaProtect SDK 的字节 marker：x64 为 `48 8D 0D 00 00 00 00 + 20 个 NOP`，x86 为 `8D 0D 00 00 00 00 + 20 个 NOP`，区域终点为后续 20 个 NOP。每条规则持久化 `Source=NovaProtect SDK marker` 与 `DetectorVersion=novaprotect-sdk-marker-v1`，规划器和执行服务都会校验来源；旧 `novapack-sdk-marker-v1` 只在项目导入时迁移兼容。VMProtect SDK 导入调用、导出表、符号名和反编译结果不会被当作对象。

区域锁定开关表达“该对象要求启用全局激活绑定”。当前 runtime 在进入原始入口点前执行进程级机器 ID 校验，尚未实现独立的每区域授权状态。

## 复现入口

```powershell
cd <repo>
powershell -ExecutionPolicy Bypass -File .\build.ps1 -Stub -Prot -Cli -WinUi
powershell -ExecutionPolicy Bypass -File .\tests\regress.ps1
dotnet run -c Release --project .\tests\planner-smoke\NovaProtect.PlannerSmoke.csproj -- .
```

当前回归结果：`ALL PASS`；planner smoke：`PLANNER-SMOKE-OK`。

## 2.0.3 交付验证

- 五种样本 `C/C++`、`C#`、`VB .NET`、`Rust`、`Golang` 均完成保护和运行验证，结果存于 `artifacts\language-support-2.0.3`。
- 使用 VMProtect Professional `3.10.3 build 2586` 生成兼容 release；开启内存、资源、导入、调试器/虚拟机/内核调试器检查、校验和压缩，`Functions` 保持空集合。
- `NovaProtect.UI.exe` apphost 保持未替换，`NovaProtect.UI.dll` 与 `novaprotect.exe` 使用 VMP 输出；VMP 后 UI 启动、CLI `-machineid` 和 C++ 样本保护运行通过。
- Inno Setup `6.7.3` 生成 `NovaProtect-VMProtect-Setup-2.0.3.exe`；隔离安装后文件完整、CLI 可运行、UI 标题为 `NovaProtect — 代码保护工作台`、文件版本为 `2.0.3.0`。
- 叠加 VMP 后再对复杂 `test_target.exe` 使用 Ultra/导入保护时观察到 `0xC000001B`，保留为兼容性边界，不扩大成功声明。
