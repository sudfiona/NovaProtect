# -*- coding: utf-8 -*-
"""Apple fluid + Emil polish: CSS motion system rewrite (append/replace core tokens)."""
from pathlib import Path
import re

css = Path(r"D:\工作区\NovaProtect\NovaProtect-main\website\public\css\site.css")
c = css.read_text(encoding="utf-8-sig")

# --- Motion tokens ---
if "--ease-spring-css" not in c:
    c = c.replace(
        "--ease-spring: cubic-bezier(0.23, 1, 0.32, 1);",
        """--ease-spring: cubic-bezier(0.23, 1, 0.32, 1);
    --ease-spring-css: cubic-bezier(0.23, 1, 0.32, 1);
    --ease-exit: cubic-bezier(0.4, 0, 1, 1);
    --spring-bounce: cubic-bezier(0.34, 1.4, 0.64, 1);
    --mat-nav: blur(20px) saturate(1.8);
    --mat-sheet: blur(28px) saturate(1.6);""",
    )

# --- Header: vibrancy (heavier text over blur) ---
c = re.sub(
    r"\.site-header \{[^}]+\}",
    """.site-header {
    position: sticky; top: 0; z-index: 50;
    backdrop-filter: var(--mat-nav);
    -webkit-backdrop-filter: var(--mat-nav);
    background: var(--header-bg);
    border-bottom: 1px solid var(--line-soft);
    /* vibrancy: slightly heavier type over blur */
    font-weight: 550;
}""",
    c,
    count=1,
)

# --- Buttons: Apple press + hover from current value ---
c = re.sub(
    r"\.button:hover \{[^}]+\}",
    """.button:hover {
    text-decoration: none;
    transform: translateY(-1px);
    /* start from current, never jump */
    transition-duration: 220ms;
}""",
    c,
    count=1,
)

# --- Feature cards: springy lift + icon parallax ---
c = c.replace(
    """.feature-card:hover {
    transform: translateY(-4px); box-shadow: var(--shadow-lift); text-decoration: none;
}
.feature-card:active { transform: translateY(-1px) scale(0.99); }""",
    """.feature-card:hover {
    transform: translateY(-3px) scale(1.01);
    box-shadow: var(--shadow-lift);
    text-decoration: none;
    transition: transform 280ms var(--spring-bounce), box-shadow 280ms var(--ease-out);
}
.feature-card:active {
    transform: translateY(0) scale(0.985);
    transition-duration: 90ms;
}
.feature-card:hover .feature-icon {
    transform: scale(1.08) rotate(-3deg) translateY(-2px);
    transition: transform 320ms var(--spring-bounce);
}""",
)

# --- Console: hover lift ---
c = re.sub(
    r"\.console \{",
    """.console {
    transition: transform 320ms var(--ease-out), box-shadow 320ms var(--ease-out);
}
.console:hover {
    transform: translateY(-2px) scale(1.005);
}
.console""",
    c,
    count=1,
)

# --- Scroll reveal (IO) ---
reveal = '''

/* ---------- Scroll reveal (rAF + IO, interruptible opacity) ---------- */
.reveal {
    opacity: 0;
    transform: translateY(18px) scale(0.985);
    transition:
        opacity 620ms var(--ease-out),
        transform 620ms var(--ease-out);
    will-change: opacity, transform;
}
.reveal.is-in {
    opacity: 1;
    transform: translateY(0) scale(1);
    will-change: auto;
}
.reveal[data-reveal-delay="1"] { transition-delay: 60ms; }
.reveal[data-reveal-delay="2"] { transition-delay: 120ms; }
.reveal[data-reveal-delay="3"] { transition-delay: 180ms; }
.reveal[data-reveal-delay="4"] { transition-delay: 240ms; }

/* Eased gradient edge on glass (extra stops ≈ eased fade) */
.card::after {
    content: "";
    position: absolute;
    inset: 0;
    border-radius: inherit;
    pointer-events: none;
    background:
        linear-gradient(180deg,
            rgba(255,255,255,0.22) 0%,
            rgba(255,255,255,0.08) 18%,
            rgba(255,255,255,0) 42%);
    opacity: 0.9;
}
[data-theme="pop"] .card::after { display: none; }
[data-theme="lab"] .card::after {
    background: linear-gradient(180deg, rgba(255,255,255,0.06), transparent 50%);
}

/* Hero visual: light parallax + inertia feel */
.hero-visual {
    transform: translate3d(var(--px, 0), var(--py, 0), 0);
    transition: transform 900ms var(--ease-out);
    will-change: transform;
}
.blob {
    transform: translate3d(calc(var(--px, 0) * -1.4), calc(var(--py, 0) * -1.4), 0);
    transition: transform 1200ms var(--ease-out);
}

/* Nav drawer: iOS-like drawer curve */
@media (max-width: 720px) {
    .nav-links {
        transition:
            opacity 280ms var(--ease-drawer),
            transform 320ms var(--ease-drawer),
            visibility 320ms var(--ease-drawer);
    }
    .nav-links.is-open {
        transform: translateY(0) scale(1);
    }
}

/* Theme chips: spring scale on press */
.theme-btn {
    transition:
        transform 180ms var(--spring-bounce),
        background-color 160ms ease,
        color 160ms ease,
        border-color 160ms ease,
        box-shadow 180ms var(--ease-out);
}

/* Progress bar: glow pulse (rare / status — OK to animate) */
.console-progress span {
    transition: width 400ms var(--ease-out);
}

/* Sticky header shadow on scroll (class set by JS) */
.site-header.is-scrolled {
    box-shadow: 0 8px 28px rgba(31, 45, 90, 0.08);
    border-bottom-color: transparent;
}

/* Pointer-pressure: interactive cards */
.feature-card,
.step,
.release-card {
    cursor: pointer;
}

/* Reduced motion: cross-fade only */
@media (prefers-reduced-motion: reduce) {
    .reveal {
        opacity: 0;
        transform: none;
        transition: opacity 200ms linear;
    }
    .reveal.is-in {
        opacity: 1;
    }
    .hero-visual, .blob {
        transform: none !important;
        transition: none !important;
    }
    .console:hover,
    .feature-card:hover {
        transform: none !important;
    }
}
'''

if "Scroll reveal (rAF + IO" not in c:
    c = c + reveal

css.write_bytes(b"\xef\xbb\xbf" + c.encode("utf-8"))
print("css apple ok", len(c))
