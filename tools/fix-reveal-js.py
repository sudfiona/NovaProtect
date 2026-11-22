# -*- coding: utf-8 -*-
"""Fix reveal JS: run after DOM, set html.js gate, move to body end."""
from pathlib import Path
import re

p = Path(r"D:\工作区\NovaProtect\NovaProtect-main\website\lib\layout.php")
t = p.read_text(encoding="utf-8")

# 1) Remove broken in-head Apple helpers block (from comment to before </script> of first script)
start = t.find("    /* ---- Apple fluid helpers")
if start < 0:
    start = t.find("/* ---- Apple fluid helpers")
end = t.find("    })();\n</script>", start)
if start >= 0 and end >= 0:
    end += len("    })();\n")
    t = t[:start] + t[end:]
    print("removed head apple block")
else:
    print("head block not found", start, end)

# 2) Add html.js at start of theme script
t = t.replace(
    "/* Set theme before first paint to avoid flash */\n(function () {\n  try {",
    "/* Set theme before first paint to avoid flash */\n(function () {\n  try {\n    document.documentElement.classList.add('js');",
)

# 3) Append robust body-end script
apple = """
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
"""

# insert before </body>
if "Apple fluid helpers" not in t.split("</head>")[-1]:
    t = t.replace("</body>", apple + "</body>")
    print("body-end script added")
else:
    print("apple already after head")

p.write_bytes(t.encode("utf-8"))
print("layout bytes", len(t))
