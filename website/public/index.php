<?php
declare(strict_types=1);
require dirname(__DIR__) . '/lib/releases.php';
require dirname(__DIR__) . '/lib/layout.php';

$latest = np_latest_release();
$asset = $latest !== null ? np_release_asset($latest) : null;

// Chinese source text is the translation key (see lib/i18n.php), so these
// arrays stay in the authored wording and np_t() runs at the echo site.
$features = [
    ['&#9670;', '三种保护模式', '变异、虚拟化与 Ultra 管线，配合兼容 / 均衡 / 高强度 / Ultra 四档预设，强度参数仍可逐项微调。', '/features/#modes'],
    ['&#9881;', '运行时防护', '反调试、环境检查、反沙箱、反内存转储、交互桌面自检、进程自隔离与延时复测，级别可调。', '/features/#runtime'],
    ['&#9889;', '函数级虚拟化', 'VMP 式函数扫描器一键枚举 x64 函数表，或用 SDK 标记关键区域，逐个勾选进入 VM 保护。', '/features/#functions'],
    ['&#128737;', '对抗与规避', '关闭 / 均衡 / 激进 / 偏执四档策略，构建签名种子可复现，内核与 hypervisor 探针、环境闸门可审计。', '/features/#evasion'],
    ['&#128230;', '输出处理与许可', '区段压缩与加密、调试与重定位裁剪；水印、许可密钥、一机一码硬件绑定与虚拟文件容器。', '/features/#output'],
    ['&#128269;', '检查工具', '只读检查 PE 信息、嵌入水印、虚拟文件清单与本机激活 ID，不修改任何目标文件。', '/features/#inspect'],
    ['&#128200;', '构建可观测', '目标能力矩阵展示请求项与实际生效项，实时进度与日志输出，项目文件可保存、导入与导出。', '/features/#build'],
    ['&#128260;', '在线更新', '客户端直接从 GitHub Releases 检查更新并按摘要校验安装包；运行记录保存在本机。', '/features/#settings'],
];

$steps = [
    ['导入目标', '拖放或选择 C/C++、C#/VB .NET、Rust、Golang 生成的 x86/x64 EXE，客户端立即解析 PE 结构与 SDK 标记。'],
    ['配置策略', '选择保护模式与预设，微调变异强度与 VM 复杂度，按需开启运行时防护、输出处理与许可绑定。'],
    ['查看生效能力', '构建前展示当前目标的能力矩阵：哪些请求会生效、哪些被安全跳过、冲突原因是什么。'],
    ['开始保护', '后台生成受保护版本，实时进度与日志全程可见；中断与取消随时可用。'],
    ['校验输出', '用检查工具读取水印与虚拟文件清单，比对 SHA-256，确认输出与配置一致后发布。'],
];

$modules = [
    ['可视化客户端', 'C# + WinUI 3 工作台：项目配置、区域编辑、深浅色主题、构建进度与日志。'],
    ['原生保护引擎', 'C++ 实现 PE 分析、区段打包、导入处理、虚拟指令转换与输出构建。'],
    ['保护运行时', 'x86/x64 加载器、x64 虚拟指令解释器与 .NET 专用启动宿主，随目标程序运行。'],
    ['SDK 与项目管理', '源码标记关键区域，项目文件与构建快照让配置可复用、可核查、可追溯。'],
];

ob_start();
?>
<section class="hero" data-emil="hero">
    <div class="hero-copy">
        <span class="eyebrow">Windows code protection</span>
        <h1><?= np_t('让关键代码<br><span class="grad-text">更难被读懂</span>') ?></h1>
        <p class="lede"><?= np_t('NovaProtect —— 面向 Windows EXE 的代码保护工作台。') ?></p>
        <p class="support"><?= np_t('支持 C/C++、C#/VB .NET、Rust 与 Golang EXE。用 SDK 标记或函数扫描（.pdata 枚举）圈定要保护的函数与区域，构建前即可看到实际生效的保护项。翻译器覆盖绝大多数编译器产出的 x86-64 代码——同一目标 5266 个函数实测 <strong>100.0% 的函数字节被虚拟化</strong>（chunk 全部可虚拟化、零拒绝桶）。') ?></p>
        <div class="hero-actions">
            <a class="button button-primary button-large" href="/download/"><?= np_e(np_t('下载客户端')) ?></a>
            <a class="button button-secondary button-large" href="/features/"><?= np_e(np_t('全部功能')) ?></a>
            <a class="button button-secondary button-large" href="/sdk/"><?= np_e(np_t('SDK 文档')) ?></a>
        </div>
        <div class="hero-meta">
            <?php if ($latest !== null): ?>
            <span class="pill pill-soft"><span class="dot"></span> <?= np_e(np_t('客户端')) ?> v<?= np_e($latest['version']) ?><?php if ($latest['publishedAt'] !== ''): ?> · <?= np_e($latest['publishedAt']) ?><?php endif; ?></span>
            <span><?= np_e(np_t('每五分钟自动同步 GitHub 版本')) ?></span>
            <?php else: ?>
            <span class="pill pill-muted"><?= np_e(np_t('版本信息暂时不可用')) ?></span>
            <?php endif; ?>
        </div>
    </div>
    <div class="hero-visual">
        <div class="console" aria-hidden="true">
            <div class="console-bar">
                <i></i><i></i><i></i>
                <span class="console-title">novaprotect.project</span>
            </div>
            <div class="console-body">
                <div class="console-row"><span class="k">target</span><span class="v">native-pe / x64</span></div>
                <div class="console-row"><span class="k">marker</span><span class="v">NovaProtect SDK marker</span></div>
                <div class="console-row"><span class="k">mode</span><span class="v">ultra · preset high</span></div>
                <div class="console-row"><span class="k">regions</span><span class="v">4 marked · 3 vm-ready</span></div>
                <div class="console-chips">
                    <span class="chip on"><?= np_e(np_t('虚拟化')) ?></span>
                    <span class="chip on"><?= np_e(np_t('反调试')) ?></span>
                    <span class="chip"><?= np_e(np_t('区段加密')) ?></span>
                    <span class="chip"><?= np_e(np_t('硬件绑定')) ?></span>
                </div>
                <div class="console-row"><span class="k">build</span><span class="v">plan resolved · 0 conflicts</span></div>
                <div class="console-progress"><span></span></div>
            </div>
        </div>
    </div>
</section>

<section class="section-tight">
    <div class="shell">
        <div class="glass strip">
            <div class="strip-item"><strong><?= np_e(np_t('4 种工具链')) ?></strong><span>C/C++ · C# · Rust · Golang</span></div>
            <div class="strip-item"><strong>x86 / x64</strong><span><?= np_e(np_t('原生保护 · .NET 封装')) ?></span></div>
            <div class="strip-item"><strong><?= np_e(np_t('无需账户')) ?></strong><span><?= np_e(np_t('下载与更新全部走 GitHub')) ?></span></div>
            <div class="strip-item"><strong><?= np_e(np_t('构建前可见')) ?></strong><span><?= np_e(np_t('请求项 · 生效项 · 跳过项')) ?></span></div>
        </div>
    </div>
</section>

<section class="section" id="features">
    <div class="shell">
        <div class="section-head reveal">
            <span class="eyebrow">Features</span>
            <h2><?= np_e(np_t('客户端的全部能力')) ?></h2>
            <p><?= np_t('从目标分析、策略配置到构建输出的一体化工作台。每项能力都可在<a href="/features/">功能详解</a>中查看参数与约束。') ?></p>
        </div>
        <div class="grid grid-4">
            <?php foreach ($features as [$icon, $title, $text, $href]): ?>
            <a class="glass feature-card reveal" href="<?= np_e($href) ?>">
                <i class="feature-icon"><?= $icon ?></i>
                <h3><?= np_e(np_t($title)) ?></h3>
                <p><?= np_e(np_t($text)) ?></p>
                <span class="feature-more"><?= np_e(np_t('了解详情 →')) ?></span>
            </a>
            <?php endforeach; ?>
        </div>
    </div>
</section>

<section class="section" id="how">
    <div class="shell">
        <div class="section-head reveal">
            <span class="eyebrow">Workflow</span>
            <h2><?= np_e(np_t('五步完成一次保护构建')) ?></h2>
            <p><?= np_e(np_t('保护对象明确、配置效果透明、过程可追溯——这是 NovaProtect 的三条设计原则。')) ?></p>
        </div>
        <div class="steps">
            <?php foreach ($steps as [$title, $text]): ?>
            <div class="glass step reveal">
                <div>
                    <h3><?= np_e(np_t($title)) ?></h3>
                    <p><?= np_e(np_t($text)) ?></p>
                </div>
            </div>
            <?php endforeach; ?>
        </div>
    </div>
</section>

<section class="section" id="architecture">
    <div class="shell">
        <div class="section-head reveal">
            <span class="eyebrow">Architecture</span>
            <h2><?= np_e(np_t('产品构成')) ?></h2>
            <p><?= np_e(np_t('界面、引擎、运行时与 SDK 协同工作，围绕商业软件中的核心算法与关键业务逻辑提供可配置的保护流程。')) ?></p>
        </div>
        <div class="grid grid-2">
            <?php foreach ($modules as [$title, $text]): ?>
            <div class="glass card reveal">
                <h3 style="margin:0 0 8px;font-size:18px;"><?= np_e(np_t($title)) ?></h3>
                <p style="margin:0;color:var(--ink-2);font-size:15px;"><?= np_e(np_t($text)) ?></p>
            </div>
            <?php endforeach; ?>
        </div>
        <div class="notice" style="margin-top:22px;">
            <?= np_t('<strong>保护原理：</strong>区段打包与 XOR 加密、SDK 标记/函数扫描选中的区域虚拟化为内部虚拟指令（栈帧函数的序言与尾声同样进 VM，多返回与尾调用正确）、VM 字节码全程密文 + 执行期按需解码、Ultra 前置变异与指令混淆、可选 4 层再虚拟化、导入表运行时重建、载荷完整性校验，以及基于 XTEA 的 .NET 加密封装。') ?>
        </div>
    </div>
</section>

<section class="section">
    <div class="shell">
        <div class="glass card card-pad-lg cta-band reveal" style="margin-top:0;">
            <span class="pill pill-grad"><?= np_e(np_t('开始使用')) ?></span>
            <h2><?= np_e(np_t('下载 NovaProtect 客户端')) ?></h2>
            <p><?= np_e(np_t('Windows x64 安装包发布在 GitHub Releases，无需账户。安装包附 SHA-256 摘要，更新器下载后逐字节校验。')) ?></p>
            <div class="hero-actions">
                <a class="button button-primary button-large" href="<?= $asset !== null ? np_e($asset['url']) : 'https://github.com/sudfiona/NovaProtect/releases/latest' ?>"><?= $latest !== null ? np_e(np_t('下载')) . ' v' . np_e($latest['version']) : np_e(np_t('下载最新版')) ?></a>
                <a class="button button-secondary button-large" href="https://github.com/sudfiona/NovaProtect" target="_blank" rel="noopener noreferrer"><?= np_e(np_t('在 GitHub 查看')) ?></a>
            </div>
        </div>
    </div>
</section>
<?php
$body = ob_get_clean();
np_layout(
    np_t('代码保护工具'),
    'home',
    $body,
    np_t('NovaProtect 是面向 Windows EXE 的代码保护工作台，支持 C/C++、C#/VB .NET、Rust、Golang，提供保护模式、运行时防护、函数级虚拟化与 SDK 标记。')
);
