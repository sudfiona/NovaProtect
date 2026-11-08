namespace NovaProtect.UI.Services;

/// <summary>
/// The change log that ships inside the application.
///
/// The live list comes from GitHub, but a downloaded installer has to explain
/// itself while offline or behind a firewall, so this copy is baked in and shown
/// whenever the request fails. It is deliberately shorter than CHANGELOG.md: a
/// few lines per version that answer "what does this build do", not the full
/// engineering write-up.
/// </summary>
public static class ChangelogFallback
{
    public static IReadOnlyList<ClientReleaseNote> Releases { get; } =
    [
        new("2.6.0", "对抗与规避接入界面，新增更新日志页",
            """
            引擎补齐 hypervisor 与驱动两层探测，两层都不信任对方自报的标志位：

            · hypervisor 厂商探针改读 CPUID.40000000H 的 leaf 空间——隐藏自身配置的
              hypervisor 能清掉 CPUID.1:ECX[31]，但隐藏不了 leaf 空间回显。
            · exit-cost 探针：16 次串行 CPUID。裸机约 100-200 周期/次，虚拟化下每次都是
              一次 VM exit（1000-5000 周期）。这是改名改不掉的判据。
            · 驱动级看三类 ring-3 可见痕迹：设备对象、驱动服务注册表键、内核模块列表；
              再加 KUSER_SHARED_DATA 的 tick 连续性（15.6ms 节拍，不是毫秒）。
            · 新增 -kernel-driver-out：直接输出可丢进 WDK 的 ring-0 源码。

            客户端：

            · 新增「对抗与规避」页：档位（四档并排对比）、构建签名种子、垃圾指令密度、
              反沙箱级别、内存流式解密、引爆延迟、反挂钩、驱动探针层级、CPUID 退出代价、
              环境闸门阈值与六个硬件下限；两个按钮可直接审计本机 hypervisor 与内核工件。
            · 新增「更新日志」页：与 GitHub Releases 同步，离线时显示随程序打包的记录。
            · 打开默认停在保护项目页（以前停在设置页）。
            · 构建日志与构建计划记录实际命令行与规避参数，可追溯某个产物由哪套参数压出。
            · 设置页新增「数据与诊断」：打开日志/配置目录、恢复默认规避设置。
            · 修复：导航到新页面时崩溃；双击「开始保护」因并发对话框崩溃；档位明细表只看
              得到一列导致每行都像同一个值。
            """,
            "2026-11-04", false),

        new("2.5.1", "稳定性与兼容性修正",
            """
            · 修正 tick 连续性阈值把 15.6ms 时钟节拍当成毫秒的判定错误，该错误会让每台
              真实机器都被判为异常。
            · 延时复测抽查与沙箱检测改为默认成对启用；-no-audit-recheck 保留单独控制。
            · 安装包 PE 版本资源说明同步更新。
            """,
            "2026-11-03", false),

        new("2.5.0", "环境闸门与自隔离",
            """
            · 新增进程自隔离：闸门通过后把自身进程 DACL 置空，拒绝一切新的 OpenProcess
              读取与句柄复制，同时从调试器中隐藏线程。受保护程序本身照常运行。
            · 新增延时复测：每分钟重新比对模块与句柄基线，启动后才附加的监控也会被抓到。
            · 环境闸门支持硬件下限（处理器数、内存、运行时长、屏幕尺寸、显示器数量）。
            """,
            "2026-11-02", false),

        new("2.4.0", "动态规避接入打包管线",
            """
            · 反沙箱加权评分、垃圾指令生成、内存流式解密、API 反挂钩接入打包流程。
            · 静态特征清洗：Rich 头、DOS 存根、时间戳、节区改名、PDB 剥离、节区松弛填充。
            · 构建签名种子化：标签、nonce、节区后缀、填充与探测顺序都由种子派生，两次构建
              不再共享字节特征；固定种子可复现同一构建。
            """,
            "2026-11-02", false)
    ];
}
