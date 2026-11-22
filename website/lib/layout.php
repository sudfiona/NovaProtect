<?php
declare(strict_types=1);

/** HTML-escape for every dynamic value that reaches a page. */
function np_e(string $value): string
{
    return htmlspecialchars($value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

function np_format_bytes(int $bytes): string
{
    if ($bytes >= 1048576) {
        return number_format($bytes / 1048576, 1) . ' MB';
    }
    if ($bytes >= 1024) {
        return number_format($bytes / 1024, 1) . ' KB';
    }
    return $bytes . ' B';
}

/**
 * Byte-budget UTF-8 truncation without mbstring (not guaranteed on every host).
 */
function np_truncate(string $value, int $maxBytes): string
{
    if (strlen($value) <= $maxBytes) {
        return $value;
    }
    $cut = substr($value, 0, $maxBytes);
    while ($cut !== '' && !preg_match('//u', $cut)) {
        $cut = substr($cut, 0, -1);
    }
    return $cut;
}

function np_canonical(string $active): string
{
    return match ($active) {
        'home' => 'https://nova.fbi.plus/',
        'features' => 'https://nova.fbi.plus/features/',
        'download' => 'https://nova.fbi.plus/download/',
        'sdk' => 'https://nova.fbi.plus/sdk/',
        'updates' => 'https://nova.fbi.plus/client-updates/',
        'privacy' => 'https://nova.fbi.plus/privacy/',
        default => 'https://nova.fbi.plus/',
    };
}

/**
 * Full HTML shell.
 *
 * Themes (data-theme on <html>):
 *   glass — Liquid Glass (default)
 *   pop   — Neo Pop
 *   lab   — Dark Lab
 * Layout skeleton is shared; only tokens + decorative rules change.
 *
 * @param string $active nav key: home|features|download|sdk|updates|privacy|''
 */
function np_layout(string $title, string $active, string $main, string $description): void
{
    if (!headers_sent()) {
        // Version lists come from GitHub on every render; never let a proxy
        // pin the HTML — otherwise a new Release stays invisible until purge.
        header('Cache-Control: no-cache, no-store, must-revalidate, max-age=0');
        header('Pragma: no-cache');
        header('Expires: 0');
        header('X-Content-Type-Options: nosniff');
        header('X-Frame-Options: DENY');
        header('Referrer-Policy: strict-origin-when-cross-origin');
        header('Permissions-Policy: camera=(), microphone=(), geolocation=()');
        header("Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'");
    }

    $latest = np_latest_release();
    $nav = [
        'features' => ['功能', '/features/'],
        'download' => ['下载', '/download/'],
        'sdk' => ['SDK 文档', '/sdk/'],
        'updates' => ['更新日志', '/client-updates/'],
    ];
    ?>
<!doctype html>
<html lang="zh-CN" data-theme="glass">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<meta http-equiv="Content-Security-Policy" content="default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'">
<meta name="description" content="<?= np_e($description) ?>">
<meta name="theme-color" content="#F3F7FF" id="theme-color-meta">
<meta name="color-scheme" content="light">
<meta name="apple-mobile-web-app-capable" content="yes">
<link rel="canonical" href="<?= np_e(np_canonical($active)) ?>">
<link rel="icon" href="/favicon.ico">
<link rel="stylesheet" href="/css/site.css?v=themes-1">
<title><?= np_e($title) ?> · NovaProtect</title>
<script src="/js/vendor/motion.js"></script>
<script>
/* Set theme before first paint to avoid flash */
(function () {
  try {
    document.documentElement.classList.add('js');
    var t = localStorage.getItem('np-theme');
    if (t === 'glass' || t === 'pop' || t === 'lab') {
      document.documentElement.setAttribute('data-theme', t);
    } else {
      document.documentElement.setAttribute('data-theme', 'glass');
    }
  } catch (e) {
    document.documentElement.setAttribute('data-theme', 'glass');
  }
})();

</script>
</head>
<body>
<a class="skip-link" href="#main-content">跳转到主要内容</a>
<div class="aurora" aria-hidden="true">
    <span class="orb orb-blue"></span>
    <span class="orb orb-cyan"></span>
    <span class="orb orb-violet"></span>
    <span class="orb orb-rose"></span>
</div>

<header class="site-header">
    <nav class="nav-shell" aria-label="主导航">
        <a class="brand" href="/">
            <img src="/assets/novaprotect.png" alt="" width="30" height="30">
            <span class="brand-name">NovaProtect</span>
            <?php if ($latest !== null): ?>
            <span class="pill pill-soft" title="最新客户端版本">v<?= np_e($latest['version']) ?></span>
            <?php endif; ?>
        </a>

        <button class="nav-toggle" type="button"
                aria-expanded="false" aria-controls="primary-nav"
                aria-label="打开菜单" data-nav-toggle>
            <span class="bars" aria-hidden="true"><span></span><span></span><span></span></span>
        </button>

        <div class="nav-links" id="primary-nav" data-nav-panel>
            <?php foreach ($nav as $key => [$label, $href]): ?>
            <a href="<?= np_e($href) ?>"<?= $active === $key ? ' class="active" aria-current="page"' : '' ?>><?= np_e($label) ?></a>
            <?php endforeach; ?>
            <a class="nav-github" href="https://github.com/sudfiona/NovaProtect" target="_blank" rel="noopener noreferrer">GitHub</a>
            <a class="button button-primary button-small nav-cta" href="/download/">下载客户端</a>

            <!-- Theme chips: end of nav cluster (desktop); drawer footer (mobile) -->
            <div class="theme-switch" role="group" aria-label="视觉主题">
                <button type="button" class="theme-btn" data-theme-set="glass" aria-pressed="true" title="液态玻璃">玻璃</button>
                <button type="button" class="theme-btn" data-theme-set="pop" aria-pressed="false" title="新波普">波普</button>
                <button type="button" class="theme-btn" data-theme-set="lab" aria-pressed="false" title="暗色实验室">实验室</button>
            </div>
        </div>
    </nav>
</header>

<main id="main-content" tabindex="-1">
<?= $main ?>
</main>

<footer class="site-footer">
    <div class="footer-inner">
        <div class="footer-brand">
            <img src="/assets/novaprotect.png" alt="" width="26" height="26">
            <div>
                <strong>NovaProtect</strong>
                <p>面向 Windows EXE 的代码保护工作台</p>
            </div>
        </div>
        <div class="footer-links">
            <a href="/features/">功能</a>
            <a href="/download/">下载</a>
            <a href="/sdk/">SDK 文档</a>
            <a href="/client-updates/">更新日志</a>
            <a href="/privacy/">隐私</a>
            <a href="https://github.com/sudfiona/NovaProtect" target="_blank" rel="noopener noreferrer">GitHub</a>
        </div>
        <div class="footer-note">
            <p>客户端版本与更新说明每五分钟自动同步自 <a href="https://github.com/sudfiona/NovaProtect/releases" target="_blank" rel="noopener noreferrer">GitHub Releases</a>。</p>
            <p>© 2026 NovaProtect</p>
        </div>
    </div>
</footer>

<script>
(function () {
    /* ---- Theme switcher ---- */
    var root = document.documentElement;
    var meta = document.getElementById('theme-color-meta');
    var colors = { glass: '#F3F7FF', pop: '#FFF8E7', lab: '#0B0F1A' };
    var buttons = document.querySelectorAll('[data-theme-set]');

    function applyTheme(name) {
        if (name !== 'glass' && name !== 'pop' && name !== 'lab') name = 'glass';
        root.setAttribute('data-theme', name);
        try { localStorage.setItem('np-theme', name); } catch (e) {}
        if (meta) meta.setAttribute('content', colors[name] || colors.glass);
        buttons.forEach(function (b) {
            b.setAttribute('aria-pressed', b.getAttribute('data-theme-set') === name ? 'true' : 'false');
        });
    }

    buttons.forEach(function (btn) {
        btn.addEventListener('click', function () {
            applyTheme(btn.getAttribute('data-theme-set'));
        });
        // pointer feedback without waiting for hover paint
        function press(el, on) {
            var s = on ? 0.97 : 1;
            if (window.Motion && Motion.animate) {
                Motion.animate(el, { scale: s }, {
                    type: 'spring',
                    stiffness: 520,
                    damping: 32,
                    mass: 0.6
                });
            } else {
                el.style.transform = on ? 'scale(0.97)' : '';
            }
        }
        btn.addEventListener('pointerdown', function () { press(btn, true); });
        btn.addEventListener('pointerup', function () { press(btn, false); });
        btn.addEventListener('pointerleave', function () { press(btn, false); });
    });

    /* init aria-pressed from current theme */
    applyTheme(root.getAttribute('data-theme') || 'glass');

    /* ---- Mobile nav ---- */
    var toggle = document.querySelector('[data-nav-toggle]');
    var panel = document.querySelector('[data-nav-panel]');
    if (!toggle || !panel) return;

    function setOpen(open) {
        toggle.setAttribute('aria-expanded', open ? 'true' : 'false');
        toggle.setAttribute('aria-label', open ? '关闭菜单' : '打开菜单');
        panel.classList.toggle('is-open', open);
    }

    toggle.addEventListener('click', function () {
        setOpen(toggle.getAttribute('aria-expanded') !== 'true');
    });
    panel.querySelectorAll('a').forEach(function (link) {
        link.addEventListener('click', function () { setOpen(false); });
    });
    document.addEventListener('keydown', function (e) {
        if (e.key === 'Escape') setOpen(false);
    });
    document.addEventListener('click', function (e) {
        if (!panel.classList.contains('is-open')) return;
        if (panel.contains(e.target) || toggle.contains(e.target)) return;
        setOpen(false);
    });
    var mq = window.matchMedia('(min-width: 721px)');
    function onMq() { if (mq.matches) setOpen(false); }
    if (mq.addEventListener) mq.addEventListener('change', onMq);
    else if (mq.addListener) mq.addListener(onMq);
})();
</script>

<script>
(function () {
  'use strict';
  document.documentElement.classList.add('js');
  var reduce = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

  function revealAll() {
    var els = document.querySelectorAll('.reveal');
    for (var i = 0; i < els.length; i++) els[i].classList.add('is-in');
  }

  // Scroll reveal — run after DOM (this script is at end of body)
  if (reduce || !('IntersectionObserver' in window)) {
    revealAll();
  } else {
    var io = new IntersectionObserver(function (entries) {
      for (var i = 0; i < entries.length; i++) {
        var e = entries[i];
        if (e.isIntersecting) {
          e.target.classList.add('is-in');
          io.unobserve(e.target);
        }
      }
    }, { rootMargin: '0px 0px -8% 0px', threshold: 0.08 });
    var els = document.querySelectorAll('.reveal');
    for (var j = 0; j < els.length; j++) {
      if (!els[j].hasAttribute('data-reveal-delay')) {
        els[j].setAttribute('data-reveal-delay', String((j % 4) + 1));
      }
      io.observe(els[j]);
    }
    // Failsafe: anything in viewport must show even if IO misbehaves
    setTimeout(function () {
      for (var k = 0; k < els.length; k++) {
        var r = els[k].getBoundingClientRect();
        if (r.top < window.innerHeight && r.bottom > 0) {
          els[k].classList.add('is-in');
        }
      }
    }, 80);
    // Ultimate failsafe: never leave content hidden
    setTimeout(revealAll, 1500);
  }

  // Header elevation on scroll
  var header = document.querySelector('.site-header');
  if (header) {
    var ticking = false;
    window.addEventListener('scroll', function () {
      if (ticking) return;
      ticking = true;
      requestAnimationFrame(function () {
        header.classList.toggle('is-scrolled', window.scrollY > 8);
        ticking = false;
      });
    }, { passive: true });
  }

  // Hero entrance spring (Motion) — from current value, interruptible
  if (!reduce && window.Motion && Motion.animate) {
    var copy = document.querySelectorAll('.hero-copy > *');
    for (var i = 0; i < copy.length; i++) {
      (function (el, idx) {
        Motion.animate(el,
          { opacity: [0, 1], transform: ['translateY(14px) scale(0.98)', 'translateY(0px) scale(1)'] },
          { type: 'spring', stiffness: 260, damping: 28, mass: 0.8, delay: idx * 0.05 });
      })(copy[i], i);
    }
  }

  // Hero parallax (desktop pointer only)
  if (!reduce) {
    var hero = document.querySelector('.hero-visual');
    var root = document.documentElement;
    var px = 0, py = 0, tx = 0, ty = 0, raf = 0;
    function tick() {
      px += (tx - px) * 0.12;
      py += (ty - py) * 0.12;
      root.style.setProperty('--px', px.toFixed(2) + 'px');
      root.style.setProperty('--py', py.toFixed(2) + 'px');
      if (Math.abs(tx - px) > 0.05 || Math.abs(ty - py) > 0.05) {
        raf = requestAnimationFrame(tick);
      } else {
        raf = 0;
      }
    }
    window.addEventListener('pointermove', function (e) {
      if (e.pointerType === 'touch') return;
      var w = window.innerWidth || 1;
      var h = window.innerHeight || 1;
      tx = ((e.clientX / w) - 0.5) * 14;
      ty = ((e.clientY / h) - 0.5) * 10;
      if (!raf) raf = requestAnimationFrame(tick);
    }, { passive: true });
    if (hero) {
      hero.addEventListener('pointerleave', function () {
        tx = 0; ty = 0;
        if (!raf) raf = requestAnimationFrame(tick);
      });
    }
  }
})();
</script>
</body>
</html>
    <?php
}
