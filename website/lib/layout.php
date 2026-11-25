<?php
declare(strict_types=1);

require_once __DIR__ . '/i18n.php';

// Resolve the language before anything can be written: the switch sets a
// cookie, which needs headers, and a page that already echoed has spent them.
np_lang();

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
 *   lab       — Dark Lab
 *   blackhole — Gravitational lensing
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
        'features' => [np_t('功能'), '/features/'],
        'download' => [np_t('下载'), '/download/'],
        'sdk' => [np_t('SDK 文档'), '/sdk/'],
        'updates' => [np_t('更新日志'), '/client-updates/'],
    ];
    ?>
<!doctype html>
<html lang="<?= np_e(np_html_lang()) ?>" data-theme="blackhole">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<meta http-equiv="Content-Security-Policy" content="default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'">
<meta name="description" content="<?= np_e($description) ?>">
<meta name="theme-color" content="#050506" id="theme-color-meta">
<meta name="apple-mobile-web-app-capable" content="yes">
<link rel="canonical" href="<?= np_e(np_canonical($active)) ?>">
<link rel="icon" href="/favicon.ico">
<script>
/* Restore preferences before the first stylesheet is applied. */
(function () {
  var root = document.documentElement;
  try {
    var theme = localStorage.getItem('np-theme');
    if (theme === 'glass' || theme === 'pop' || theme === 'lab' || theme === 'blackhole') {
      root.setAttribute('data-theme', theme);
    }
    root.classList.toggle('motion-paused', localStorage.getItem('np-motion-paused') === 'true');
  } catch (e) {}
})();
</script>
<link rel="stylesheet" href="/css/site.css?v=themes-i18n-event-horizon-5">
<link rel="stylesheet" href="/css/theme-motion.css?v=photon-ring-1">
<link rel="stylesheet" href="/css/theme-layout.css?v=photon-ring-1">
<title><?= np_e($title) ?> · NovaProtect</title>
</head>
<body>
<a class="skip-link" href="#main-content"><?= np_e(np_t('跳转到主要内容')) ?></a>
<div class="aurora" aria-hidden="true">
    <span class="orb orb-blue"></span>
    <span class="orb orb-cyan"></span>
    <span class="orb orb-violet"></span>
    <span class="orb orb-rose"></span>
</div>

<header class="site-header">
    <nav class="nav-shell" aria-label="<?= np_e(np_t('主导航')) ?>">
        <a class="brand" href="/">
            <img src="/assets/novaprotect.png" alt="" width="30" height="30">
            <span class="brand-name">NovaProtect</span>
            <?php if ($latest !== null): ?>
            <span class="pill pill-soft" title="<?= np_e(np_t('最新客户端版本')) ?>">v<?= np_e(np_release_display_version($latest)) ?></span>
            <?php endif; ?>
        </a>

        <button class="nav-toggle" type="button"
                aria-expanded="false" aria-controls="primary-nav"
                aria-label="<?= np_e(np_t('打开菜单')) ?>" data-nav-toggle>
            <span class="bars" aria-hidden="true"><span></span><span></span><span></span></span>
        </button>

        <div class="nav-links" id="primary-nav" data-nav-panel>
            <?php foreach ($nav as $key => [$label, $href]): ?>
            <a href="<?= np_e($href) ?>"<?= $active === $key ? ' class="active" aria-current="page"' : '' ?>><?= np_e($label) ?></a>
            <?php endforeach; ?>
            <a class="nav-github" href="https://github.com/sudfiona/NovaProtect" target="_blank" rel="noopener noreferrer">GitHub</a>
            <a class="button button-primary button-small nav-cta" href="/download/"><?= np_e(np_t('下载客户端')) ?></a>

            <!-- Theme chips: end of nav cluster (desktop); drawer footer (mobile) -->
            <div class="theme-switch" role="group" aria-label="<?= np_e(np_t('视觉主题')) ?>">
                <button type="button" class="theme-btn" data-theme-set="blackhole" aria-pressed="false" title="<?= np_e(np_t('引力透镜')) ?>"><?= np_e(np_t('黑洞')) ?></button>
                <button type="button" class="theme-btn" data-theme-set="glass" aria-pressed="false" title="<?= np_e(np_t('液态玻璃')) ?>"><?= np_e(np_t('玻璃')) ?></button>
                <button type="button" class="theme-btn" data-theme-set="pop" aria-pressed="false" title="<?= np_e(np_t('新波普')) ?>"><?= np_e(np_t('波普')) ?></button>
                <button type="button" class="theme-btn" data-theme-set="lab" aria-pressed="false" title="<?= np_e(np_t('暗色实验室')) ?>"><?= np_e(np_t('实验室')) ?></button>
                <button type="button" class="theme-btn motion-toggle" data-motion-toggle aria-pressed="false" title="<?= np_e(np_t('暂停动效')) ?>"><?= np_e(np_t('暂停动效')) ?></button>
            </div>

            <?= np_lang_switch() ?>
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
                <p><?= np_e(np_t('面向 Windows EXE 的代码保护工作台')) ?></p>
            </div>
        </div>
        <div class="footer-links">
            <a href="/features/"><?= np_e(np_t('功能')) ?></a>
            <a href="/download/"><?= np_e(np_t('下载')) ?></a>
            <a href="/sdk/"><?= np_e(np_t('SDK 文档')) ?></a>
            <a href="/client-updates/"><?= np_e(np_t('更新日志')) ?></a>
            <a href="/privacy/"><?= np_e(np_t('隐私')) ?></a>
            <a href="https://github.com/sudfiona/NovaProtect" target="_blank" rel="noopener noreferrer">GitHub</a>
        </div>
        <div class="footer-note">
            <p><?= np_t('客户端版本与更新说明每分钟自动同步自 <a href="https://github.com/sudfiona/NovaProtect/releases" target="_blank" rel="noopener noreferrer">GitHub Releases</a>。') ?></p>
            <p>© 2026 NovaProtect</p>
        </div>
    </div>
</footer>

<script>
(function () {
    /* ---- Theme switcher ---- */
    var root = document.documentElement;
    var meta = document.getElementById('theme-color-meta');
    var colors = { blackhole: '#050506', glass: '#F3F7FF', pop: '#FFF8E7', lab: '#0B0F1A' };
    var buttons = document.querySelectorAll('[data-theme-set]');
    var motionToggle = document.querySelector('[data-motion-toggle]');
    var motionPaused = root.classList.contains('motion-paused');
    function syncMotionControl() {
        root.classList.toggle('motion-paused', motionPaused);
        document.dispatchEvent(new Event('np-motion-change'));
        if (!motionToggle) return;
        motionToggle.setAttribute('aria-pressed', motionPaused ? 'true' : 'false');
        var label = motionPaused
            ? <?= json_encode(np_t('恢复动效'), JSON_UNESCAPED_UNICODE | JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT) ?>
            : <?= json_encode(np_t('暂停动效'), JSON_UNESCAPED_UNICODE | JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT) ?>;
        motionToggle.textContent = label;
        motionToggle.title = label;
    }
    syncMotionControl();
    if (motionToggle) motionToggle.addEventListener('click', function () {
        motionPaused = !motionPaused;
        syncMotionControl();
        try { localStorage.setItem('np-motion-paused', motionPaused ? 'true' : 'false'); } catch (e) {}
    });

    function applyTheme(name) {
        if (name !== 'blackhole' && name !== 'glass' && name !== 'pop' && name !== 'lab') name = 'blackhole';
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
    });

    /* init aria-pressed from current theme */
    applyTheme(root.getAttribute('data-theme') || 'blackhole');

    /* ---- Mobile nav ---- */
    var toggle = document.querySelector('[data-nav-toggle]');
    var panel = document.querySelector('[data-nav-panel]');
    if (!toggle || !panel) return;

    var openLabel = <?= json_encode(np_t('打开菜单'), JSON_UNESCAPED_UNICODE | JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT) ?>;
    var closeLabel = <?= json_encode(np_t('关闭菜单'), JSON_UNESCAPED_UNICODE | JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT) ?>;

    function setOpen(open) {
        toggle.setAttribute('aria-expanded', open ? 'true' : 'false');
        toggle.setAttribute('aria-label', open ? closeLabel : openLabel);
        panel.classList.toggle('is-open', open);
    }

    toggle.addEventListener('click', function () {
        setOpen(toggle.getAttribute('aria-expanded') !== 'true');
    });
    panel.querySelectorAll('a').forEach(function (link) {
        link.addEventListener('click', function () { setOpen(false); });
    });
    document.addEventListener('keydown', function (e) {
        if (e.key !== 'Escape' || !panel.classList.contains('is-open')) return;
        setOpen(false);
        if (panel.contains(document.activeElement) || panel.contains(e.target)) toggle.focus();
    });
    document.addEventListener('click', function (e) {
        if (!panel.classList.contains('is-open')) return;
        if (panel.contains(e.target) || toggle.contains(e.target)) return;
        setOpen(false);
    });
    var mq = window.matchMedia('(width > 1180px)');
    function onMq() { if (mq.matches) setOpen(false); }
    if (mq.addEventListener) mq.addEventListener('change', onMq);
    else if (mq.addListener) mq.addListener(onMq);
})();
</script>

<script>
(function () {
  'use strict';
  var root = document.documentElement;
  var animations = new Map();
  var pressed = new Set();
  function motionDisabled() {
    return root.classList.contains('motion-paused');
  }
  function animate(el, keyframes, options) {
    var previous = animations.get(el);
    if (previous) previous.cancel();
    var animation = el.animate(keyframes, options);
    animations.set(el, animation);
    animation.onfinish = function () {
      if (animations.get(el) !== animation || pressed.has(el)) return;
      animation.cancel();
      animations.delete(el);
    };
  }
  document.querySelectorAll('[data-theme-set]').forEach(function (btn) {
    function press(on) {
      if (motionDisabled()) return;
        if (on) pressed.add(btn);
      else if (!pressed.delete(btn)) return;
      if (btn.animate) {
        var from = getComputedStyle(btn).scale || '1';
        animate(btn, { scale: [from === 'none' ? '1' : from, on ? '0.97' : '1'] }, {
          duration: 180, easing: 'cubic-bezier(.2,.8,.2,1)', fill: 'both'
        });
      }
    }
    btn.addEventListener('pointerdown', function () { press(true); });
    ['pointerup', 'pointerleave', 'pointercancel'].forEach(function (event) {
      btn.addEventListener(event, function () { press(false); });
    });
  });
  var io;

  function revealAll() {
    var els = document.querySelectorAll('.reveal');
    for (var i = 0; i < els.length; i++) els[i].classList.add('is-in');
  }

  // Scroll reveal — run after DOM (this script is at end of body)
  if (motionDisabled() || !('IntersectionObserver' in window)) {
    revealAll();
  } else {
    root.classList.add('js');
    io = new IntersectionObserver(function (entries) {
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

  // Hero entrance uses cancelable effects without writing inline styles.
  if (!motionDisabled() && Element.prototype.animate) {
    document.querySelectorAll('.hero-copy > *').forEach(function (el, index) {
      animate(el,
        { opacity: [0, 1], transform: ['translateY(14px) scale(0.98)', 'translateY(0px) scale(1)'] },
        { duration: 540, easing: 'cubic-bezier(.2,.8,.2,1)', delay: index * 50, fill: 'both' });
    });
  }

  // Hero parallax (desktop pointer only)
  var hero = document.querySelector('.hero-visual');
  var px = 0, py = 0, tx = 0, ty = 0, raf = 0;
  function resetParallax() {
    if (raf) cancelAnimationFrame(raf);
    raf = px = py = tx = ty = 0;
    root.style.removeProperty('--px');
    root.style.removeProperty('--py');
  }
  if (hero) {
    function tick() {
      if (motionDisabled()) {
        resetParallax();
        return;
      }
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
      if (e.pointerType === 'touch' || motionDisabled()) return;
      var w = window.innerWidth || 1;
      var h = window.innerHeight || 1;
      tx = ((e.clientX / w) - 0.5) * 14;
      ty = ((e.clientY / h) - 0.5) * 10;
      if (!raf) raf = requestAnimationFrame(tick);
    }, { passive: true });
    hero.addEventListener('pointerleave', function () {
      if (motionDisabled()) return;
      tx = 0; ty = 0;
      if (!raf) raf = requestAnimationFrame(tick);
    });
  }

  function stopMotion() {
    if (!motionDisabled()) return;
    root.classList.remove('js');
    if (io) io.disconnect();
    revealAll();
    pressed.clear();
    animations.forEach(function (animation) { animation.cancel(); });
    animations.clear();
    resetParallax();
  }
  document.addEventListener('np-motion-change', stopMotion);
})();
</script>
</body>
</html>
    <?php
}
