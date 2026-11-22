<?php
declare(strict_types=1);
require dirname(__DIR__, 2) . '/lib/releases.php';
require dirname(__DIR__, 2) . '/lib/layout.php';

$toc = [
    ['overview', '客户端总览', false],
    ['protect', '保护项目', false],
    ['modes', '保护模式与预设', true],
    ['runtime', '运行时防护', true],
    ['output', '输出处理', true],
    ['license', '许可、标识与虚拟文件', true],
    ['functions', '函数与区域保护', true],
    ['build', '构建执行与日志', true],
    ['evasion', '对抗与规避', false],
    ['inspect', '检查工具', false],
    ['activity', '运行记录', false],
    ['settings', '设置与在线更新', false],
    ['tech', '技术要点与适用范围', false],
];

ob_start();
?>
<div class="page-head">
    <div class="row">
        <div>
            <span class="eyebrow">Feature reference</span>
            <h1>客户端功能详解</h1>
            <p class="lede">NovaProtect 客户端的全部页面、参数与约束。所有数值范围与默认值以客户端界面为准，构建前请以「当前目标能力」中的实际生效结果为最终依据。</p>
        </div>
        <a class="button button-primary" href="/download/">下载客户端</a>
    </div>
</div>

<div class="doc-layout">
    <nav class="glass toc" aria-label="本页目录">
        <strong>本页目录</strong>
        <?php foreach ($toc as [$id, $label, $sub]): ?>
        <a href="#<?= np_e($id) ?>"<?= $sub ? ' class="sub"' : '' ?>><?= np_e($label) ?></a>
        <?php endforeach; ?>
    </nav>

    <div class="doc-body">

        <section class="glass panel" id="overview">
            <h2>客户端总览</h2>
            <p class="panel-lede">WinUI 3 桌面工作台，左侧导航包含六个入口；设置页提供外观、数据与诊断、在线更新。</p>
            <div class="table-wrap">
                <table class="data">
                    <thead><tr><th>页面</th><th>作用</th></tr></thead>
                    <tbody>
                        <tr><td><strong>保护项目</strong></td><td>选择目标、配置保护策略、查看能力矩阵、执行构建并观察实时日志。</td></tr>
                        <tr><td><strong>对抗与规避</strong></td><td>静态特征清洗、动态探测强度、内核与 hypervisor 探针、环境闸门阈值。</td></tr>
                        <tr><td><strong>检查工具</strong></td><td>只读检查 PE 信息、水印、虚拟文件清单与本机激活 ID。</td></tr>
                        <tr><td><strong>运行记录</strong></td><td>本机保存的历次运行摘要，可单条删除或清空。</td></tr>
                        <tr><td><strong>更新日志</strong></td><td>与 GitHub Releases 同步的客户端版本说明，每五分钟自动刷新。</td></tr>
                        <tr><td><strong>设置</strong></td><td>外观主题、数据与诊断目录、在线更新检查与安装。</td></tr>
                    </tbody>
                </table>
            </div>
            <p>客户端<b>不需要账户登录</b>；官网仅提供说明与下载入口，安装包与版本元数据全部来自 GitHub Releases。</p>
        </section>

        <section class="glass panel" id="protect">
            <h2>保护项目</h2>
            <p class="panel-lede">选择应用、调整保护策略，然后在后台生成受保护版本。</p>

            <h3 id="target">目标文件</h3>
            <ul>
                <li>支持 <strong>C/C++、C#/VB .NET、Rust、Golang</strong> 生成的 x86/x64 EXE；支持拖放到文件卡片。</li>
                <li>输入文件选择后自动解析 PE 结构、架构与 SDK 标记；输出文件默认生成 <code class="inline">*_protected.exe</code>，可另存为任意路径。</li>
                <li>顶部命令栏支持<b>导入项目</b>、<b>保存项目</b>、<b>导出项目</b>与<b>导出当前构建计划</b>——配置可复用、可核查、可追溯。</li>
            </ul>

            <h3 id="modes">保护模式与预设</h3>
            <p>模式决定代码处理管线；强度参数仍可单独微调。</p>
            <div class="table-wrap">
                <table class="data">
                    <thead><tr><th>模式</th><th>说明</th></tr></thead>
                    <tbody>
                        <tr><td><strong>变异模式</strong></td><td>对适用代码执行 VM 前置指令变异与混淆，不进入虚拟化管线。</td></tr>
                        <tr><td><strong>虚拟化模式</strong></td><td>把可翻译的 SDK 区域 / 函数降级为内部虚拟指令，由 x64 解释器执行。</td></tr>
                        <tr><td><strong>Ultra 模式</strong></td><td>同时启用代码变异与虚拟化，适合需要最高保护等级的 x64 程序。</td></tr>
                    </tbody>
                </table>
            </div>
            <div class="table-wrap">
                <table class="data">
                    <thead><tr><th>参数</th><th>范围</th><th>说明</th></tr></thead>
                    <tbody>
                        <tr><td>预设</td><td>兼容 / 均衡 / 高强度 / Ultra</td><td>预设只调整已实现能力；构建前会显示请求值与实际生效值。</td></tr>
                        <tr><td>变异强度</td><td>0 – 3</td><td>垃圾指令与变异密度的全局档位（低 / 中等 / 高强度…按界面标签显示）。</td></tr>
                        <tr><td>VM 复杂度</td><td>0 – 10</td><td>虚拟指令集与解释路径的复杂度，越高越难静态还原，运行开销也越大。</td></tr>
                        <tr><td>二次虚拟化</td><td>开 / 关</td><td>阶段拆分 + 二级解释器 + 寄存器重映射；<b>仅 x64 生效</b>。</td></tr>
                        <tr><td>嵌套层级</td><td>0 – 4</td><td>二次虚拟化的嵌套深度。</td></tr>
                    </tbody>
                </table>
            </div>

            <h3 id="runtime">运行时防护</h3>
            <p>打包时注入目标运行时的防护开关；只对受支持的架构生效，按需开启避免误杀。</p>
            <div class="table-wrap">
                <table class="data">
                    <thead><tr><th>项</th><th>取值 / 说明</th></tr></thead>
                    <tbody>
                        <tr><td>反调试级别</td><td>关闭 / 基础 / 增强 / 严格</td></tr>
                        <tr><td>环境检查级别</td><td>关闭 / 基础 / 增强</td></tr>
                        <tr><td>内存完整性保护</td><td>按目标架构与配置执行载荷或代码区域完整性校验</td></tr>
                        <tr><td>导入表保护</td><td>保存导入信息、运行时重建导入地址表，改变常规静态导入结构</td></tr>
                        <tr><td>资源区段保护</td><td>加密资源区段时保留程序图标，资源管理器中显示与原文件一致</td></tr>
                        <tr><td>沙箱环境检测</td><td>累计评分 CPU 数、内存、沙箱模块、时序等信号，超阈值拒绝执行</td></tr>
                        <tr><td>反内存转储</td><td>校验 MZ/PE 头、区段表与 PEB 加载基址，拦截 Procdump/Minidump 后处理</td></tr>
                        <tr><td>交互桌面环境自检</td><td>校验 CPU 数、内存、开机时长、屏幕分辨率、显示器数</td></tr>
                        <tr><td>进程自隔离</td><td>拒绝外部读取进程内存</td></tr>
                        <tr><td>延时复测抽查</td><td>随沙箱检测自动开启；延迟后二次校验环境信号</td></tr>
                    </tbody>
                </table>
            </div>

            <h3 id="output">输出处理</h3>
            <div class="table-wrap">
                <table class="data">
                    <thead><tr><th>项</th><th>说明</th></tr></thead>
                    <tbody>
                        <tr><td>区段压缩</td><td>对符合条件的原生代码区段打包，按压缩收益决定是否压缩</td></tr>
                        <tr><td>区段加密</td><td>启用时对打包区段采用 XOR 编码，启动后由对应架构加载器恢复</td></tr>
                        <tr><td>移除调试目录</td><td>输出中不再保留调试信息目录</td></tr>
                        <tr><td>裁剪重定位并关闭 ASLR</td><td>仅原生 EXE；改变常规重定位布局</td></tr>
                        <tr><td>裁剪导出目录</td><td>仅原生 EXE；移除导出表</td></tr>
                    </tbody>
                </table>
            </div>
            <div class="notice">.NET EXE 采用 CLR 安全封装，会跳过破坏 CLR 契约的选项；导入虚拟化在运行时通过 IAT 重建完成。</div>

            <h3 id="license">许可、标识与虚拟文件</h3>
            <ul>
                <li><strong>水印</strong>：可选的产品或构建标识，写入元数据，可用检查工具读取。</li>
                <li><strong>许可密钥</strong>：可选；许可数据由 x64 保护运行时执行校验。</li>
                <li><strong>激活 / 硬件绑定（一机一码）</strong>：填 16 位机器 ID，或 <code class="inline">auto</code> 绑定构建机；本机激活 ID 可在检查工具中读取。</li>
                <li><strong>虚拟文件</strong>：向虚拟文件容器添加任意文件，随受保护文件输出；可列表管理与移除。</li>
            </ul>
            <div class="notice">内部核心不支持直接命令调用；许可与激活绑定的能力边界以运行时实际行为为准。</div>

            <h3 id="functions">函数与区域保护</h3>
            <p><strong>SDK 标记（区域对象编辑器）</strong>：SDK marker 区域直接来自目标文件中的 NovaProtect BEGIN/END 字节模式。每个区域可设置：</p>
            <ul>
                <li>显示名称；对象模式（继承全局 / 跳过此区域 / 虚拟化 / Ultra）；</li>
                <li>VM 复杂度 0–10、变异强度 0–3；</li>
                <li>「此区域要求启用全局激活绑定」开关；右侧显示区域 RVA 范围。</li>
            </ul>
            <p><strong>函数保护（VMP 式扫描）</strong>：扫描目标文件的函数表，勾选加入 VM 保护，无需改源码。</p>
            <ul>
                <li>x64 读取 <code class="inline">.pdata</code> 异常目录枚举运行时函数（含静态函数），按 RVA 排序；</li>
                <li>列表列：名称 / 地址范围 / 所在节 / 大小 / 模式 / 可虚拟化性；</li>
                <li>过滤：全部函数 / 仅可虚拟化 / 仅导出函数 / 仅已勾选；</li>
                <li>批量：全选、反选、<b>添加所有函数</b>（勾选全部可虚拟化函数）、清除勾选；</li>
                <li>批量应用：继承全局模式 / 虚拟化 / Ultra / 仅前置变异 / 跳过，附 VM 复杂度、变异强度与激活锁定。</li>
            </ul>
            <div class="notice">
                <strong>约束：</strong>区域表上限 8192（2.3.20 起放开）；函数级虚拟化覆盖整段函数体——多返回、共享尾声、尾调用与栈帧访问都正确（帧序言与尾声同样进 VM）；降不了的形式经原生桥执行，函数其余部分照常虚拟化。详见 <a href="/sdk/">SDK 文档</a>。
            </div>

            <h3 id="build">构建执行与日志</h3>
            <ul>
                <li><strong>当前目标能力</strong>：构建前逐项展示请求值、生效值、跳过项与冲突原因——状态来自实际核心能力与 PE 类型。</li>
                <li><strong>开始保护</strong>：状态行 + 进度条 + 配置摘要；构建中可取消，完成后输出路径可直接打开。</li>
                <li><strong>实时日志</strong>：完整构建过程输出，可一键清空；日志同时写入本机诊断目录。</li>
            </ul>
        </section>

        <section class="glass panel" id="evasion">
            <h2>对抗与规避</h2>
            <p class="panel-lede">控制静态特征清洗、反分析探测与内核驱动探针。这些设置对保护项目页的每次运行生效。</p>

            <h3>规避档位</h3>
            <div class="table-wrap">
                <table class="data">
                    <thead><tr><th>档位</th><th>取向</th></tr></thead>
                    <tbody>
                        <tr><td><strong>关闭</strong></td><td>不做静态特征清洗与动态探测</td></tr>
                        <tr><td><strong>均衡</strong></td><td>默认。清洗静态特征，加入反沙箱评分、垃圾指令与内存流式解密，误报率与强度平衡</td></tr>
                        <tr><td><strong>激进</strong></td><td>更高探测强度与特征变换，适合对抗意愿明确的分发场景</td></tr>
                        <tr><td><strong>偏执</strong></td><td>最强清洗与探测组合，真实环境误触发概率也最高</td></tr>
                    </tbody>
                </table>
            </div>
            <p>档位展开明细以表格形式列出四个档位在十余个字段上的差异；具体数值请在客户端内展开查看。</p>

            <h3>构建签名种子</h3>
            <ul>
                <li>种子决定标签、nonce、节区后缀、填充与探测顺序；<strong>留空 = 每次从系统熵取新值</strong>，两次构建不共享字节特征。</li>
                <li>填入 1–16 位十六进制可复现同一构建；提供「生成」随机种子与「复制」按钮。</li>
                <li>「每次构建重新随机」开关：已开启时忽略种子、重新取熵。</li>
            </ul>

            <h3>动态对抗</h3>
            <div class="table-wrap">
                <table class="data">
                    <thead><tr><th>参数</th><th>范围 / 默认</th><th>说明</th></tr></thead>
                    <tbody>
                        <tr><td>垃圾指令密度</td><td>0 – 8</td><td>每个注入点插入的垃圾指令块数量，0 表示不插入</td></tr>
                        <tr><td>反沙箱级别</td><td>关闭 / 基础 / 增强 / 严格</td><td>驱动加权沙箱评分，需配合沙箱阈值使用</td></tr>
                        <tr><td>内存流式解密</td><td>驻留 / 1 / 2 / 3 轮</td><td>加密区按需解密的密钥流轮数；轮数越多，内存快照越难直接还原</td></tr>
                        <tr><td>引爆延迟</td><td>0 – 15000 ms（默认 2500）</td><td>执行前等待时长；分析沙箱通常只观察很短时间，真实用户几乎无感</td></tr>
                        <tr><td>API 反挂钩</td><td>开 / 关</td><td>开启时还原磁盘 ntdll 文本并扫描 IAT 重定向</td></tr>
                    </tbody>
                </table>
            </div>

            <h3>内核与 hypervisor</h3>
            <ul>
                <li><strong>驱动探针层级</strong> 0 – 3：驱动级探针深度。</li>
                <li><strong>CPUID 退出代价探测</strong>：用 16 次串行 CPUID 的耗时差判定 hypervisor；关闭时只信 CPUID 厂商叶子。</li>
                <li><strong>审计本机 hypervisor / 内核工件</strong>：只读取本机状态并打印结论，不改动文件、不需要管理员权限。</li>
            </ul>
            <p class="text-muted">两者都不信任对方自报的标志位，改用可测量的行为差异。</p>

            <h3>环境闸门</h3>
            <p>判定是否在沙箱或无头环境中运行，分数达到阈值即拒绝执行。阈值越低越严格，也越容易误杀低配真机。</p>
            <div class="table-wrap">
                <table class="data">
                    <thead><tr><th>参数</th><th>范围 / 默认</th></tr></thead>
                    <tbody>
                        <tr><td>沙箱分数阈值</td><td>0 – 100（默认 40）</td></tr>
                        <tr><td>无头环境分数阈值</td><td>0 – 100（默认 7）</td></tr>
                        <tr><td>硬件下限：逻辑处理器数</td><td>0 = 不检查</td></tr>
                        <tr><td>物理内存 (MB)</td><td>0 = 不检查</td></tr>
                        <tr><td>系统运行时长 (ms)</td><td>0 = 不检查</td></tr>
                        <tr><td>屏幕宽度 / 高度 / 显示器数量</td><td>0 = 不检查</td></tr>
                    </tbody>
                </table>
            </div>
            <div class="notice">环境闸门只在保护项目页开启「沙箱防护」或「环境检查」时生效；否则这些阈值会被记录但不参与判定。</div>
        </section>

        <section class="glass panel" id="inspect">
            <h2>检查工具</h2>
            <p class="panel-lede">读取 PE 信息、嵌入水印和虚拟文件清单，<strong>不修改目标文件</strong>。</p>
            <div class="table-wrap">
                <table class="data">
                    <thead><tr><th>动作</th><th>输出</th></tr></thead>
                    <tbody>
                        <tr><td><strong>PE 信息</strong></td><td>架构、节表、入口与关键头字段等只读解析结果</td></tr>
                        <tr><td><strong>读取水印</strong></td><td>保护时写入的水印 / 构建标识</td></tr>
                        <tr><td><strong>虚拟文件</strong></td><td>虚拟文件容器中的文件清单</td></tr>
                        <tr><td><strong>本机激活 ID</strong></td><td>当前机器的 16 位激活 ID，用于硬件绑定配置</td></tr>
                    </tbody>
                </table>
            </div>
            <p>结果输出在页面下方的等宽文本区，可直接复制。典型用法：保护完成后读取水印与虚拟文件，确认输出与配置一致。</p>
        </section>

        <section class="glass panel" id="activity">
            <h2>运行记录</h2>
            <p class="panel-lede">记录保存在本机，直到你手动删除。</p>
            <ul>
                <li>每条记录包含标题、详情与时间；来自每次保护运行与审计动作。</li>
                <li>支持单条删除与「清空记录」；空状态给出提示。</li>
                <li>记录与规避设置、诊断日志一样，全部保存在本机，<strong>不上传任何服务器</strong>。</li>
            </ul>
        </section>

        <section class="glass panel" id="settings">
            <h2>设置与在线更新</h2>
            <p class="panel-lede">外观设置立即生效；在线更新从 GitHub 读取已发布的客户端版本。</p>

            <h3>外观</h3>
            <p>应用主题：跟随系统 / 浅色 / 深色，默认跟随 Windows 系统设置。</p>

            <h3>数据与诊断</h3>
            <ul>
                <li>运行记录、规避设置与诊断日志都保存在本机，不上传任何服务器；界面可直接打开日志目录与配置目录。</li>
                <li><strong>恢复默认规避设置</strong>：只重置对抗与规避设置，不影响项目文件和历史记录。</li>
            </ul>

            <h3>在线更新</h3>
            <ul>
                <li><strong>检查更新</strong>：直接向 GitHub Releases 查询最新版本；显示当前是否已是最新。</li>
                <li><strong>下载更新</strong>：下载安装包并按 GitHub 提供的 SHA-256 摘要逐字节校验，校验不一致不会进入安装。</li>
                <li><strong>运行安装包</strong>：校验通过后启动安装向导。</li>
            </ul>
            <p class="text-muted">更新过程不经由本站中转；官网只承担说明与下载引导。</p>
        </section>

        <section class="glass panel" id="tech">
            <h2>技术要点与适用范围</h2>
            <p class="panel-lede">保护流程从分析目标文件开始：识别 PE/CLR 格式、处理器架构、区段结构与 SDK 标记，再按目标能力生成构建计划。</p>

            <h3>分层保护原理</h3>
            <ul>
                <li><strong>区段保护</strong>：符合条件的原生代码区段（及可选资源区段）打包，按压缩收益压缩，启用加密时 XOR 编码；启动时由对应架构加载器恢复。</li>
                <li><strong>关键区域虚拟化</strong>：原生 x64 中由 SDK 标记或函数扫描选中的区域转为内部虚拟指令，由随镜像分发的解释器执行。翻译器覆盖绝大多数编译器产出的 x86-64 代码——8/16/32/64 位整数 ALU（宽度精确标志）、SSE 算术与浮点、整数 SIMD、位测试族、x87、字符串指令、CMPXCHG/CPUID/RDTSC、enter/pushfq/popfq、8 位乘除对、128 位乘除、全部条件跳转与调用；同一目标 5266 个函数实测 <strong>100.0% 的函数字节被虚拟化</strong>（chunk 全部可虚拟化、零拒绝桶）。栈帧函数的帧序言与尾声同样进 VM（push/leave/ret 全降低）；降不了的形式（AVX、cmpxchg8b 等）经原生桥执行——多返回、共享尾声、尾调用全部正确。</li>
                <li><strong>字节码执行期解码</strong>：VM 字节码全程保持密文，解释器按 256 字节滑动窗口按需解码（计数器密钥流，第 i 字节只依赖 key/RVA/i>>3），内存转储在任何时刻都拿不到完整 VM 程序。每个区域有独立的物理操作码布局与密钥。</li>
                <li><strong>变异与导入保护</strong>：Ultra 管线在虚拟化前变异并对字节码追加混淆（垃圾指令注入按标志活跃性选点，分支目标在布局确定后回填）；导入保护运行时重建 IAT。<br><strong>再虚拟化</strong>：字节码可再切分为阶段并提升出二级执行块，每层独立操作码置换与密钥，最多 4 层嵌套。</li>
                <li><strong>运行时校验</strong>：按架构与配置执行完整性校验；原生 x64 提供许可数据校验与机器标识绑定。</li>
                <li><strong>.NET 加密封装</strong>：受支持的托管 EXE 使用基于 XTEA 的载荷加密，由专用宿主解密、校验并启动，保留 CLR 元数据与 IL 结构。</li>
            </ul>

            <h3>适用范围</h3>
            <div class="table-wrap">
                <table class="data">
                    <thead><tr><th>目标</th><th>支持情况</th></tr></thead>
                    <tbody>
                        <tr><td>原生 x86/x64 EXE（C/C++、Rust、Golang）</td><td>区段保护与输出处理全覆盖</td></tr>
                        <tr><td>SDK 区域 VM、VM 前置变异、运行时许可与机器绑定</td><td>主要面向原生 x64</td></tr>
                        <tr><td>C# / VB .NET EXE</td><td>加密封装；目前不提供 IL 虚拟化</td></tr>
                        <tr><td>ARM64</td><td>当前用于识别与能力提示，暂不生成保护输出</td></tr>
                    </tbody>
                </table>
            </div>
            <div class="notice">实际支持情况以客户端构建计划与「当前目标能力」为准。产品设计参考 VMProtect 与 Themida 的组织思路，但不复现其全部功能、内部算法或保护强度。</div>

            <div class="download-actions" style="margin-top:20px;">
                <a class="button button-primary" href="/download/">下载客户端</a>
                <a class="button button-secondary" href="/sdk/">SDK 文档</a>
                <a class="button button-secondary" href="/client-updates/">更新日志</a>
            </div>
        </section>

    </div>
</div>
<?php
$body = ob_get_clean();
np_layout('功能详解', 'features', $body, 'NovaProtect 客户端功能详解：保护模式、运行时防护、输出处理、函数与区域保护、对抗与规避、检查工具与在线更新的完整参数说明。');
