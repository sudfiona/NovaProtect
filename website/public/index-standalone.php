<?php
declare(strict_types=1);

// NovaProtect 官网 - PHP 8.3+ 兼容版
// 开箱即用，无外部依赖

header('Content-Type: text/html; charset=utf-8');
http_response_code(200);

$lang = $_GET['lang'] ?? 'zh';
$theme = $_GET['theme'] ?? 'light';

// 从 HTML 获取数据
$features = [
    ['icon' => '◆', 'title' => '三种保护模式', 'desc' => '变异、虚拟化与 Ultra 管线，强度可调'],
    ['icon' => '⚙', 'title' => '运行时防护', 'desc' => '反调试、反沙箱、进程自隔离'],
    ['icon' => '⚡', 'title' => '函数级虚拟化', 'desc' => 'VMP 式函数扫描器一键枚举'],
    ['icon' => '🛡', 'title' => '对抗与规避', 'desc' => '四档策略应对各类检测'],
    ['icon' => '📦', 'title' => '输出处理与许可', 'desc' => '区段加密、水印、硬件绑定'],
    ['icon' => '🔍', 'title' => '检查工具', 'desc' => '只读检查，不修改目标文件'],
];

$canvasClass = $theme === 'blackhole' ? 'blackhole-flow' : 'hidden';
?>
<!DOCTYPE html>
<html lang="<?php echo htmlspecialchars($lang); ?>" data-theme="<?php echo htmlspecialchars($theme); ?>">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="description" content="NovaProtect - 专业的代码保护与混淆平台">
    <meta name="keywords" content="代码保护,代码混淆,PE保护,虚拟化,反调试">
    <title>NovaProtect - 专业的代码保护与混淆平台</title>
    
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        :root {
            --primary: #2563eb;
            --secondary: #64748b;
            --background: #ffffff;
            --foreground: #0f172a;
            --border: #e2e8f0;
        }

        html[data-theme="dark"] {
            --background: #0f172a;
            --foreground: #f1f5f9;
        }

        html[data-theme="blackhole"] {
            --background: #0a0e27;
            --foreground: #e0f2fe;
            --primary: #06b6d4;
        }

        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            background-color: var(--background);
            color: var(--foreground);
            line-height: 1.6;
            transition: background-color 0.3s, color 0.3s;
        }

        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 0 20px;
        }

        header {
            padding: 20px 0;
            border-bottom: 1px solid var(--border);
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        .logo {
            font-size: 24px;
            font-weight: bold;
            color: var(--primary);
        }

        nav {
            display: flex;
            gap: 30px;
            align-items: center;
        }

        nav a {
            text-decoration: none;
            color: var(--foreground);
            transition: color 0.3s;
        }

        nav a:hover {
            color: var(--primary);
        }

        .theme-selector {
            display: flex;
            gap: 10px;
        }

        .theme-btn {
            padding: 8px 12px;
            border: 1px solid var(--border);
            background: var(--background);
            color: var(--foreground);
            border-radius: 4px;
            cursor: pointer;
            transition: all 0.3s;
            font-size: 12px;
        }

        .theme-btn:hover,
        .theme-btn.active {
            background: var(--primary);
            color: white;
            border-color: var(--primary);
        }

        .hero {
            padding: 80px 0;
            text-align: center;
            position: relative;
            min-height: 500px;
            display: flex;
            flex-direction: column;
            justify-content: center;
            align-items: center;
        }

        .blackhole-scene {
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            z-index: 1;
        }

        canvas.blackhole-flow {
            width: 100%;
            height: 100%;
            display: block;
        }

        canvas.hidden {
            display: none;
        }

        .hero-content {
            position: relative;
            z-index: 10;
        }

        h1 {
            font-size: 48px;
            margin-bottom: 20px;
            font-weight: 700;
        }

        .subtitle {
            font-size: 20px;
            color: var(--secondary);
            margin-bottom: 40px;
        }

        .cta-button {
            display: inline-block;
            padding: 12px 32px;
            background: var(--primary);
            color: white;
            text-decoration: none;
            border-radius: 4px;
            transition: transform 0.3s, box-shadow 0.3s;
            font-weight: 600;
        }

        .cta-button:hover {
            transform: translateY(-2px);
            box-shadow: 0 10px 20px rgba(37, 99, 235, 0.2);
        }

        .features {
            padding: 60px 0;
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 30px;
        }

        .feature-card {
            padding: 30px;
            border: 1px solid var(--border);
            border-radius: 8px;
            transition: all 0.3s;
        }

        .feature-card:hover {
            border-color: var(--primary);
            box-shadow: 0 10px 30px rgba(37, 99, 235, 0.1);
        }

        .feature-icon {
            font-size: 32px;
            margin-bottom: 15px;
        }

        .feature-title {
            font-size: 18px;
            font-weight: 600;
            margin-bottom: 10px;
            color: var(--foreground);
        }

        .feature-desc {
            font-size: 14px;
            color: var(--secondary);
        }

        footer {
            padding: 40px 0;
            border-top: 1px solid var(--border);
            text-align: center;
            color: var(--secondary);
            font-size: 14px;
        }

        @media (max-width: 768px) {
            h1 {
                font-size: 32px;
            }

            nav {
                gap: 15px;
            }

            .features {
                grid-template-columns: 1fr;
            }
        }

        .motion-paused * {
            animation-play-state: paused !important;
        }
    </style>
</head>
<body>
    <!-- 黑洞背景 -->
    <div class="blackhole-scene">
        <canvas class="<?php echo $canvasClass; ?>"></canvas>
    </div>

    <!-- 页面内容 -->
    <header class="container" style="position: relative; z-index: 100;">
        <div class="logo">NovaProtect</div>
        <nav>
            <a href="#features">功能</a>
            <a href="#about">关于</a>
            <a href="#contact">联系</a>
            <div class="theme-selector">
                <button class="theme-btn <?php echo $theme === 'light' ? 'active' : ''; ?>" onclick="switchTheme('light')">Light</button>
                <button class="theme-btn <?php echo $theme === 'dark' ? 'active' : ''; ?>" onclick="switchTheme('dark')">Dark</button>
                <button class="theme-btn <?php echo $theme === 'blackhole' ? 'active' : ''; ?>" onclick="switchTheme('blackhole')">Black Hole</button>
            </div>
        </nav>
    </header>

    <main>
        <!-- 英雄部分 -->
        <section class="hero container">
            <div class="hero-content">
                <h1>专业的代码保护与混淆平台</h1>
                <p class="subtitle">NovaProtect 提供企业级的代码保护、混淆与虚拟化解决方案</p>
                <a href="#" class="cta-button">立即开始</a>
            </div>
        </section>

        <!-- 功能部分 -->
        <section id="features" class="container">
            <div class="features">
                <?php foreach ($features as $feature): ?>
                <div class="feature-card">
                    <div class="feature-icon"><?php echo htmlspecialchars($feature['icon']); ?></div>
                    <div class="feature-title"><?php echo htmlspecialchars($feature['title']); ?></div>
                    <div class="feature-desc"><?php echo htmlspecialchars($feature['desc']); ?></div>
                </div>
                <?php endforeach; ?>
            </div>
        </section>
    </main>

    <footer class="container">
        <p>&copy; 2026 NovaProtect. All rights reserved.</p>
    </footer>

    <!-- 黑洞系统 -->
    <script type="module" defer src="/blackhole-system/bootstrap.js"></script>

    <!-- 主题切换 -->
    <script>
        function switchTheme(theme) {
            document.documentElement.dataset.theme = theme;
            const url = new URL(window.location);
            url.searchParams.set('theme', theme);
            window.history.replaceState({}, '', url);
            
            // 更新按钮状态
            document.querySelectorAll('.theme-btn').forEach(btn => {
                btn.classList.remove('active');
            });
            event?.target?.classList.add('active');
        }
    </script>
</body>
</html>
