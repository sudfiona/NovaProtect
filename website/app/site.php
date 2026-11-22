<?php
declare(strict_types=1);

function np_home(array $release): void
{
    $body = '<main><section class="hero"><div class="hero-copy"><div class="eyebrow">Windows code protection</div><h1>NovaProtect</h1><p class="hero-lede">面向 Windows EXE 的可信代码保护工作台。</p><p class="hero-support">支持 C/C++、C#/VB .NET、Rust 和 Golang EXE。以目标文件中的 NovaProtect SDK marker 作为函数与区域对象的事实来源。</p><div class="hero-actions"><a class="button button-primary" href="/download">下载客户端</a><a class="button button-secondary" href="/client-updates">更新日志</a><a class="button button-secondary" href="/sdk">SDK 文档</a></div><div class="hero-meta"><span class="status-dot"></span> 网站版本 ' . np_e(np_website_version()) . ' · 客户端 ' . np_e($release['clientVersion'] ?? '2.2.3') . '</div></div><div class="hero-console"><div class="console-bar"><span class="console-dot"></span><span class="console-dot"></span><span class="console-dot"></span><span class="console-title">novaprotect.project</span></div><div class="console-body"><div><span class="code-muted">target</span> <span class="code-value">native-pe / x64</span></div><div><span class="code-muted">marker</span> <span class="code-value">NovaProtect SDK marker</span></div><div><span class="code-muted">sections</span> <span class="code-value">encrypted</span></div><div><span class="code-muted">imports</span> <span class="code-value">virtualized</span></div><div><span class="code-muted">activation</span> <span class="code-value">bound</span></div><div class="console-divider"></div><div><span class="code-success">build ready</span> <span class="code-muted">request / effective / conflicts persisted</span></div></div></div></section><section class="section-block"><div class="section-heading"><div><div class="eyebrow">Product surface</div><h2>从项目配置到发布前检查</h2></div><p>官网提供客户端下载与更新日志；保护能力全部在本地客户端内完成。</p></div><div class="feature-grid"><article class="feature-item"><span class="feature-index">01</span><h3>可信对象编辑</h3><p>只展示真实 SDK marker 区域，不把任意符号、导出或反编译结果伪装成函数。</p></article><article class="feature-item"><span class="feature-index">02</span><h3>请求 / 生效 / 冲突</h3><p>统一模型记录请求区域、生效区域与冲突项，导出前即可核对差异。</p></article><article class="feature-item"><span class="feature-index">03</span><h3>发布前检查</h3><p>虚拟化、混淆、加密与校验项在打包前一次跑完，问题就地定位。</p></article></div></section><section class="section-block"><div class="section-heading"><div><div class="eyebrow">Release flow</div><h2>官网只负责分发客户端</h2></div><p>安装包与更新说明由后台发布，客户端启动时自动检查更新。</p></div><div class="feature-grid"><article class="feature-item"><span class="feature-index">04</span><h3>公开下载</h3><p>无需账户，直接下载当前版本安装包，页面提供 SHA-256 校验。</p></article><article class="feature-item"><span class="feature-index">05</span><h3>自动更新</h3><p>客户端按最低可用版本判断是否强制更新，后台可查看发布历史。</p></article><article class="feature-item"><span class="feature-index">06</span><h3>后台发布</h3><p>上传新安装包即自动识别版本、校验哈希并立即对客户端生效。</p></article></div></section></main>';
    np_page('NovaProtect 代码保护工具', $body);
}

function np_client_updates_page(array $releases): never
{
    $items = '';
    foreach ($releases as $release) {
        $notes = trim((string) ($release['releaseNotes'] ?? ''));
        $items .= '<article class="surface announcement"><div class="announcement-meta"><span class="status ' . (($release['forceUpdate'] ?? false) ? 'status-danger' : 'status-ok') . '">' . (($release['forceUpdate'] ?? false) ? '强制更新' : '可选更新') . '</span><time>' . np_e((string) ($release['publishedAt'] ?? '')) . '</time></div><h2>客户端 ' . np_e((string) ($release['clientVersion'] ?? '')) . '</h2><p class="announcement-body">' . nl2br(np_e($notes !== '' ? $notes : '本次版本没有填写更新说明。')) . '</p><p class="field-hint">最低可用版本：' . np_e((string) ($release['minimumClientVersion'] ?? $release['clientVersion'] ?? '')) . '</p></article>';
    }
    np_page('客户端更新日志', '<main class="content-shell"><div class="page-heading"><div><div class="eyebrow">NovaProtect client releases</div><h1>客户端更新日志</h1><p class="lede">查看客户端版本、更新说明和最低可用版本。</p></div><a class="button" href="/download">下载客户端</a></div><div class="announcement-list">' . ($items !== '' ? $items : '<p class="empty-state">暂无客户端更新日志。</p>') . '</div></main>');
}

function np_sdk_page(): never
{
    $body = '<main class="content-shell prose"><div class="page-heading"><div><div class="eyebrow">NovaProtect SDK</div><h1>函数 / 区域加密 SDK</h1><p class="lede">在应用源码里标记需要虚拟化或混淆的函数，再用 NovaProtect 客户端打包，标记区域即被降级为 VM 字节码。</p></div><a class="button" href="/download">下载客户端</a></div><section class="surface"><h2>快速开始</h2><ol><li>把 <code>sdk/include/novaprotect_sdk.h</code> 放进你的工程。</li><li>用 <code>NOVAPROTECT_BEGIN(&quot;名称&quot;)</code> 和 <code>NOVAPROTECT_END()</code> 包住一个函数体。</li><li>正常编译出 EXE——标记在未保护版本里是无副作用的 NOP。</li><li>在 NovaProtect 客户端选择该 EXE，模式设为虚拟化或 Ultra，开始保护。</li><li>客户端会扫描 BEGIN/END 字节边界、在对象编辑器列出每个区域，并把可翻译区域降级为 VM 字节码。</li></ol></section><section class="surface"><h2>手动添加函数保护（无需改源码）</h2><p>除 SDK 标记外，客户端「保护」页内置 <strong>VMP 式函数扫描器</strong>：对 x64 目标读取 .pdata 异常目录枚举全部运行时函数（含静态函数），逐个勾选或一键「添加所有函数」即可对整个函数体 做 VM 保护。列表显示名称 / 地址 / 节 / 大小 / 可虚拟化性，支持批量设置模式、VM 复杂度、变异强度与激活锁定。</p><ul><li>函数级虚拟化覆盖整段函数体（含多返回与栈帧访问），降不了的指令形式经原生桥执行。</li><li>区域表上限 8192，超出按 RVA 顺序取前 8192 个，其余保持原生。</li><li>实测同一目标 100.0% 的函数字节被虚拟化。</li></ul></section><section class="surface"><h2>标记示例（C/C++）</h2><pre><code>#include &quot;novaprotect_sdk.h&quot;

int secret_calc(int x)
{
    NOVAPROTECT_BEGIN(&quot;secret_calc&quot;);
    int a = x + 3;
    int b = x - 7;
    int c = (a ^ b) * 0x9E3779B9 + a;
    NOVAPROTECT_END();
    return c;
}</code></pre></section><section class="surface"><h2>完整虚拟化的约束</h2><p>VM 解释器把整段函数体翻译成 wire 指令集执行，帧序言与尾声同样进 VM；同一目标 5266 个函数实测 100.0% 的函数字节被虚拟化（chunk 全部可虚拟化、零拒绝桶）。降不了的指令形式（AVX、cmpxchg8b 等）经原生桥执行，函数其余部分照常虚拟化。</p></section><section class="surface"><h2>反沙箱 / 反转储 / 环境自检</h2><p>打包时可在客户端独立开启三项运行时防护：</p><ul><li><strong>反沙箱检测</strong>：累计评分 CPU 数、物理内存、已知沙箱模块与监控组件、RDTSCP 时序、CPU 核掩码、睡眠压缩与桌面/用户名模板，超过阈值即终止。</li><li><strong>反内存转储</strong>：校验 MZ/PE 头、区段表与 PEB 加载基址，拦截 Procdump/Minidump 后处理。</li><li><strong>交互桌面环境自检</strong>：校验 CPU 数、内存、开机时长、屏幕分辨率、显示器数。</li></ul><p>这些只对原生 x64 生效，且默认关闭，按需开启避免误杀。</p></section><section class="surface"><h2>与商业 VMProtect 的关系</h2><p>客户端自身与 NovaProtect 核心运行时使用商业 VMProtect SDK 做启动级虚拟化与防篡改（构建时自动链接 VMProtectSDK64.a，发布时附带 VMProtectSDK64.dll）。这是对 NovaProtect 自有 VM 引擎的补充。</p></section><section class="surface"><h2>兼容性</h2><p>旧版 NOVAPACK_BEGIN/NOVAPACK_END 继续可用，字节模式不变。x86 与 x64 都支持 marker 扫描；VM 翻译仅 x64。</p></section></main>';
    np_page('SDK 文档', $body);
}

function np_admin_login_page(string $error = ''): never
{
    np_page('管理员登录', '<main class="auth-shell"><section class="auth-panel"><div class="eyebrow">NovaProtect administration</div><h1>管理员登录</h1><p class="lede">网站没有用户账户系统；此处仅用于发布客户端与网站升级。</p>' . np_form_error($error) . '<form method="post" class="stack-form" action="/admin/login">' . np_hidden_csrf() . '<div class="field"><label for="password">管理员口令</label><input id="password" name="password" type="password" autocomplete="current-password" required autofocus></div><button class="button button-primary button-wide" type="submit">登录后台</button></form></section></main>');
}

function np_handle_admin_login(): never
{
    if (!np_check_csrf()) np_admin_login_page('表单已过期，请刷新后重试。');
    if (!np_admin_login_allowed()) { http_response_code(429); np_admin_login_page('尝试次数过多，请五分钟后再试。'); }
    $password = is_string($_POST['password'] ?? null) ? $_POST['password'] : '';
    $hash = np_admin_password_hash();
    if ($hash === null || strlen($password) > 128 || !np_verify_password($password, $hash)) np_admin_login_page('口令不正确。');
    np_admin_sign_in();
    np_redirect('/admin');
}

function np_install_page(string $error = ''): void
{
    $checks = array(
        'PHP ' . PHP_VERSION . '（要求 8.4+）' => version_compare(PHP_VERSION, '8.4.0', '>='),
        'JSON / session / hash 扩展' => function_exists('json_encode') && function_exists('session_start') && function_exists('hash_pbkdf2'),
        '安装包 SHA-256 校验' => np_release_file(true) !== null,
        'OpenSSL/随机数' => function_exists('random_bytes'),
        '可写数据目录：' . np_data_dir() => is_dir(np_data_dir()) && is_writable(np_data_dir())
    );
    $rows = '';
    foreach ($checks as $label => $ok) $rows .= '<li class="' . ($ok ? 'check-ok' : 'check-fail') . '">' . ($ok ? '✓ ' : '✗ ') . np_e($label) . '</li>';
    np_page('安装向导', '<main class="auth-shell"><section class="auth-panel"><div class="eyebrow">NovaProtect setup</div><h1>安装向导</h1><div class="setup-steps" aria-label="安装步骤"><span>01 环境检查</span><span>02 设置管理员口令</span><span>03 锁定安装</span></div><p class="lede">完成一次初始化后，网站会锁定安装入口；该口令用于登录后台发布客户端与网站升级。</p><ul class="setup-checks">' . $rows . '</ul>' . np_form_error($error) . '<form method="post" class="stack-form">' . np_hidden_csrf() . '<div class="field"><label for="setup_token">安装口令</label><input id="setup_token" name="setup_token" autocomplete="off" type="password" required><small>安装脚本在终端显示的一次性口令。</small></div><div class="field"><label for="password">管理员口令</label><input id="password" name="password" type="password" minlength="10" maxlength="128" autocomplete="new-password" required><small>10 到 128 字节；用于登录 /admin 后台。</small></div><div class="field"><label for="confirm_password">确认管理员口令</label><input id="confirm_password" name="confirm_password" type="password" minlength="10" maxlength="128" autocomplete="new-password" required></div><button class="button button-primary button-wide" type="submit">完成安装</button></form><p class="notice">安装目录：' . np_e(np_data_dir()) . '<br>网站不保存任何用户账户；后台仅使用这一个管理员口令。</p></section></main>');
}

function np_handle_install(): void
{
    if (np_installed()) np_redirect('/admin');
    if (!np_check_csrf()) np_install_page('表单已过期，请刷新后重试。');
    if (!np_rate_limit('setup', $_SERVER['REMOTE_ADDR'] ?? 'local', 8, 300)) { http_response_code(429); np_install_page('安装尝试过多，请五分钟后再试。'); }
    $token = $_POST['setup_token'] ?? null;
    $setup = np_read_json(np_data_dir() . '/setup.json');
    $tokenHash = np_setup_token_hash();
    $expiresAt = is_string($setup['expiresAt'] ?? null) ? strtotime($setup['expiresAt']) : false;
    if ($tokenHash === null || $expiresAt === false || $expiresAt < time() || !is_string($token) || strlen($token) > 128 || !hash_equals($tokenHash, hash('sha256', $token))) np_install_page('安装口令不正确或已过期。请使用安装脚本终端显示的口令重新部署。');
    $password = is_string($_POST['password'] ?? null) ? $_POST['password'] : '';
    $confirm = is_string($_POST['confirm_password'] ?? null) ? $_POST['confirm_password'] : '';
    if (strlen($password) < 10 || strlen($password) > 128 || $password !== $confirm) np_install_page('管理员口令需要 10 到 128 字节，且两次输入必须一致。');
    if (np_release_file(true) === null) np_install_page('安装包缺失或校验失败，请重新上传完整发布包。');
    $done = np_transaction('installation', static function (string $path) use ($password): bool {
        if ((np_read_json($path)['installed'] ?? false) === true) return false;
        np_set_admin_password($password);
        np_atomic_write($path, ['installed' => true, 'websiteVersion' => np_website_version(), 'installedAt' => gmdate('c')]);
        return true;
    });
    if (!$done) np_install_page('安装已完成；原数据保持不变。');
    np_migrate(); np_remove_setup_token(); np_admin_sign_in(); np_redirect('/admin');
}
