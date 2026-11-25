<?php
declare(strict_types=1);

header('Content-Type: text/html; charset=utf-8');
http_response_code(200);

$theme = $_GET['theme'] ?? 'light';
?>
<!DOCTYPE html>
<html lang="zh" data-theme="<?php echo htmlspecialchars($theme); ?>">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="description" content="NovaProtect - 专业的代码保护与混淆平台">
    <title>NovaProtect - 专业的代码保护与混淆平台</title>
    
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        :root {
            --bg: #ffffff;
            --fg: #0f172a;
            --primary: #2563eb;
            --secondary: #64748b;
            --accent: #ec4899;
            --border: #e2e8f0;
        }

        html[data-theme="dark"] {
            --bg: #0f172a;
            --fg: #f1f5f9;
            --border: #1e293b;
            --secondary: #cbd5e1;
        }

        html[data-theme="blackhole"] {
            --bg: linear-gradient(135deg, #0a0e27 0%, #0f1b4d 50%, #1a0f3f 100%);
            --fg: #e0f2fe;
            --primary: #06b6d4;
            --accent: #0ea5e9;
            --border: #164e63;
        }

        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: var(--bg);
            color: var(--fg);
            line-height: 1.6;
            overflow-x: hidden;
        }

        html[data-theme="blackhole"] body {
            background: var(--bg);
        }

        .stars {
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            pointer-events: none;
            z-index: -1;
        }

        html[data-theme="blackhole"] .star {
            position: absolute;
            width: 2px;
            height: 2px;
            background: #e0f2fe;
            border-radius: 50%;
            animation: twinkle 3s infinite;
        }

        @keyframes twinkle {
            0%, 100% { opacity: 0.3; }
            50% { opacity: 1; }
        }

        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 0 20px;
        }

        header {
            padding: 20px 0;
            display: flex;
            justify-content: space-between;
            align-items: center;
            position: relative;
            z-index: 100;
            border-bottom: 1px solid var(--border);
            backdrop-filter: blur(10px);
            background: rgba(255,255,255,0.8);
        }

        html[data-theme="dark"] header,
        html[data-theme="blackhole"] header {
            background: rgba(15,23,42,0.8);
        }

        .logo {
            font-size: 28px;
            font-weight: 900;
            background: linear-gradient(135deg, var(--primary), var(--accent));
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
            letter-spacing: -1px;
        }

        nav {
            display: flex;
            gap: 30px;
            align-items: center;
        }

        nav a {
            text-decoration: none;
            color: var(--fg);
            transition: all 0.3s;
            position: relative;
        }

        nav a:hover {
            color: var(--primary);
        }

        nav a::after {
            content: '';
            position: absolute;
            bottom: -5px;
            left: 0;
            width: 0;
            height: 2px;
            background: var(--primary);
            transition: width 0.3s;
        }

        nav a:hover::after {
            width: 100%;
        }

        .theme-selector {
            display: flex;
            gap: 8px;
            padding: 4px;
            background: var(--border);
            border-radius: 8px;
        }

        .theme-btn {
            padding: 6px 12px;
            border: none;
            background: transparent;
            color: var(--fg);
            cursor: pointer;
            border-radius: 6px;
            transition: all 0.3s;
            font-size: 12px;
            font-weight: 600;
        }

        .theme-btn.active {
            background: var(--primary);
            color: white;
            box-shadow: 0 4px 12px rgba(37, 99, 235, 0.3);
        }

        .hero {
            padding: 120px 0;
            text-align: center;
            position: relative;
            min-height: 600px;
            display: flex;
            flex-direction: column;
            justify-content: center;
            align-items: center;
            overflow: hidden;
        }

        .hero::before {
            content: '';
            position: absolute;
            top: -50%;
            right: -20%;
            width: 500px;
            height: 500px;
            background: radial-gradient(circle, var(--primary), transparent);
            opacity: 0.1;
            border-radius: 50%;
            animation: float 20s infinite ease-in-out;
        }

        .hero::after {
            content: '';
            position: absolute;
            bottom: -50%;
            left: -10%;
            width: 400px;
            height: 400px;
            background: radial-gradient(circle, var(--accent), transparent);
            opacity: 0.1;
            border-radius: 50%;
            animation: float 25s infinite ease-in-out reverse;
        }

        @keyframes float {
            0%, 100% { transform: translate(0, 0); }
            50% { transform: translate(30px, -50px); }
        }

        .hero-content {
            position: relative;
            z-index: 10;
        }

        h1 {
            font-size: 64px;
            font-weight: 900;
            margin-bottom: 20px;
            background: linear-gradient(135deg, var(--primary) 0%, var(--accent) 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
            animation: slideUp 0.8s ease-out;
        }

        @keyframes slideUp {
            from { 
                opacity: 0;
                transform: translateY(30px);
            }
            to { 
                opacity: 1;
                transform: translateY(0);
            }
        }

        .subtitle {
            font-size: 20px;
            color: var(--secondary);
            margin-bottom: 50px;
            animation: slideUp 0.8s ease-out 0.1s both;
        }

        .cta-buttons {
            display: flex;
            gap: 15px;
            justify-content: center;
            flex-wrap: wrap;
            animation: slideUp 0.8s ease-out 0.2s both;
        }

        .btn {
            padding: 14px 32px;
            border-radius: 8px;
            font-weight: 600;
            text-decoration: none;
            border: 2px solid;
            transition: all 0.3s;
            cursor: pointer;
            font-size: 16px;
        }

        .btn-primary {
            background: var(--primary);
            color: white;
            border-color: var(--primary);
        }

        .btn-primary:hover {
            transform: translateY(-2px);
            box-shadow: 0 12px 24px rgba(37, 99, 235, 0.4);
        }

        .btn-secondary {
            background: transparent;
            color: var(--primary);
            border-color: var(--primary);
        }

        .btn-secondary:hover {
            background: var(--primary);
            color: white;
        }

        .features {
            padding: 100px 0;
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(320px, 1fr));
            gap: 30px;
        }

        .feature-card {
            padding: 40px;
            border: 1px solid var(--border);
            border-radius: 12px;
            background: rgba(255,255,255,0.5);
            backdrop-filter: blur(10px);
            transition: all 0.3s;
            position: relative;
            overflow: hidden;
        }

        html[data-theme="dark"] .feature-card,
        html[data-theme="blackhole"] .feature-card {
            background: rgba(15,23,42,0.5);
        }

        .feature-card::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 3px;
            background: linear-gradient(90deg, var(--primary), var(--accent));
            transform: scaleX(0);
            transform-origin: left;
            transition: transform 0.3s;
        }

        .feature-card:hover::before {
            transform: scaleX(1);
        }

        .feature-card:hover {
            transform: translateY(-10px);
            border-color: var(--primary);
            box-shadow: 0 20px 40px rgba(37, 99, 235, 0.15);
        }

        .feature-icon {
            font-size: 40px;
            margin-bottom: 15px;
            animation: bounce 2s infinite;
        }

        .feature-card:nth-child(2) .feature-icon {
            animation-delay: 0.2s;
        }

        .feature-card:nth-child(3) .feature-icon {
            animation-delay: 0.4s;
        }

        .feature-card:nth-child(4) .feature-icon {
            animation-delay: 0.6s;
        }

        .feature-card:nth-child(5) .feature-icon {
            animation-delay: 0.8s;
        }

        .feature-card:nth-child(6) .feature-icon {
            animation-delay: 1s;
        }

        @keyframes bounce {
            0%, 100% { transform: translateY(0); }
            50% { transform: translateY(-10px); }
        }

        .feature-title {
            font-size: 18px;
            font-weight: 700;
            margin-bottom: 10px;
            color: var(--fg);
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
            position: relative;
            z-index: 100;
        }

        @media (max-width: 768px) {
            h1 {
                font-size: 40px;
            }

            .subtitle {
                font-size: 16px;
            }

            nav {
                gap: 15px;
            }

            .cta-buttons {
                flex-direction: column;
            }

            .btn {
                width: 100%;
            }
        }

        .blackhole-scene {
            position: fixed;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            z-index: 1;
            pointer-events: none;
        }

        canvas.blackhole-flow {
            width: 100%;
            height: 100%;
            display: block !important;
        }

        canvas.hidden {
            display: none !important;
        }

        /* 黑洞主题时显示 Canvas */
        html[data-theme="blackhole"] .blackhole-flow {
            display: block !important;
        }

        html[data-theme="light"] canvas,
        html[data-theme="dark"] canvas {
            display: none !important;
        }
    </style>
</head>
<body>
    <!-- 黑洞背景 -->
    <div class="blackhole-scene">
        <canvas class="<?php echo $theme === 'blackhole' ? 'blackhole-flow' : 'hidden'; ?>"></canvas>
        <div class="stars" id="stars"></div>
    </div>

    <!-- 页面内容 -->
    <header class="container">
        <div class="logo">◆ NovaProtect</div>
        <nav>
            <a href="#features">功能</a>
            <a href="#about">关于</a>
            <a href="#contact">联系</a>
            <div class="theme-selector">
                <button class="theme-btn <?php echo $theme === 'light' ? 'active' : ''; ?>" onclick="switchTheme('light')">Light</button>
                <button class="theme-btn <?php echo $theme === 'dark' ? 'active' : ''; ?>" onclick="switchTheme('dark')">Dark</button>
                <button class="theme-btn <?php echo $theme === 'blackhole' ? 'active' : ''; ?>" onclick="switchTheme('blackhole')">◆ Hole</button>
            </div>
        </nav>
    </header>

    <main>
        <!-- 英雄部分 -->
        <section class="hero container">
            <div class="hero-content">
                <h1>专业的代码保护与混淆平台</h1>
                <p class="subtitle">NovaProtect 提供企业级的代码保护、混淆与虚拟化解决方案</p>
                <div class="cta-buttons">
                    <a href="#" class="btn btn-primary">立即开始</a>
                    <a href="#" class="btn btn-secondary">了解更多</a>
                </div>
            </div>
        </section>

        <!-- 功能部分 -->
        <section id="features" class="container">
            <div class="features">
                <div class="feature-card">
                    <div class="feature-icon">◆</div>
                    <div class="feature-title">三种保护模式</div>
                    <div class="feature-desc">变异、虚拟化与 Ultra 管线，强度可调</div>
                </div>
                <div class="feature-card">
                    <div class="feature-icon">⚙</div>
                    <div class="feature-title">运行时防护</div>
                    <div class="feature-desc">反调试、反沙箱、进程自隔离</div>
                </div>
                <div class="feature-card">
                    <div class="feature-icon">⚡</div>
                    <div class="feature-title">函数级虚拟化</div>
                    <div class="feature-desc">VMP 式函数扫描器一键枚举</div>
                </div>
                <div class="feature-card">
                    <div class="feature-icon">🛡</div>
                    <div class="feature-title">对抗与规避</div>
                    <div class="feature-desc">四档策略应对各类检测</div>
                </div>
                <div class="feature-card">
                    <div class="feature-icon">📦</div>
                    <div class="feature-title">输出处理与许可</div>
                    <div class="feature-desc">区段加密、水印、硬件绑定</div>
                </div>
                <div class="feature-card">
                    <div class="feature-icon">🔍</div>
                    <div class="feature-title">检查工具</div>
                    <div class="feature-desc">只读检查，不修改目标文件</div>
                </div>
            </div>
        </section>
    </main>

    <footer class="container">
        <p>&copy; 2026 NovaProtect. All rights reserved. | Powered by WebGL Black Hole System</p>
    </footer>

    <!-- 黑洞系统 -->
    <script type="module" defer src="./blackhole-system/bootstrap.js"></script>

    <!-- 主题切换和效果 -->
    <script>
        // 生成星星背景
        function generateStars() {
            const starsContainer = document.getElementById('stars');
            if (!starsContainer) return;
            
            const count = window.innerWidth < 768 ? 50 : 150;
            for (let i = 0; i < count; i++) {
                const star = document.createElement('div');
                star.className = 'star';
                star.style.left = Math.random() * 100 + '%';
                star.style.top = Math.random() * 100 + '%';
                star.style.animationDelay = Math.random() * 3 + 's';
                starsContainer.appendChild(star);
            }
        }

        // 主题切换
        function switchTheme(theme) {
            document.documentElement.dataset.theme = theme;
            const url = new URL(window.location);
            url.searchParams.set('theme', theme);
            window.history.replaceState({}, '', url);
            
            document.querySelectorAll('.theme-btn').forEach(btn => {
                btn.classList.remove('active');
            });
            event?.target?.classList.add('active');
        }

        // 初始化
        document.addEventListener('DOMContentLoaded', generateStars);
    </script>
</body>
</html>
