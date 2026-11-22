# -*- coding: utf-8 -*-
"""NovaProtect HyperOS logo — shield-forward, frosted glass, no extra decoration."""
from __future__ import annotations

import math
import struct
from io import BytesIO
from pathlib import Path

from PIL import Image, ImageDraw, ImageFilter

ROOT = Path(r"D:\工作区\NovaProtect\NovaProtect-main")
SIZE = 1024


def lerp_color(c1, c2, t):
    return tuple(int(round(c1[i] + (c2[i] - c1[i]) * t)) for i in range(3))


def rounded_rect_mask(size: int, radius: int) -> Image.Image:
    ss = 4
    m = Image.new("L", (size * ss, size * ss), 0)
    d = ImageDraw.Draw(m)
    d.rounded_rectangle([0, 0, size * ss - 1, size * ss - 1], radius=radius * ss, fill=255)
    return m.resize((size, size), Image.Resampling.LANCZOS)


def draw_gradient(size: int) -> Image.Image:
    n = 256
    small = Image.new("RGB", (n, n))
    px = small.load()
    c0 = (0x5A, 0xA9, 0xFF)
    c1 = (0x2E, 0x7C, 0xF6)
    c2 = (0x7B, 0x61, 0xFF)
    for y in range(n):
        for x in range(n):
            t = (x + y) / (2 * (n - 1))
            if t < 0.55:
                px[x, y] = lerp_color(c0, c1, t / 0.55)
            else:
                px[x, y] = lerp_color(c1, c2, (t - 0.55) / 0.45)
    return small.resize((size, size), Image.Resampling.BICUBIC)


def soft_orb(size: int, radius: int) -> Image.Image:
    layer = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    d = ImageDraw.Draw(layer)
    cx = cy = size // 2
    steps = 32
    for i in range(steps, 0, -1):
        r = int(radius * i / steps)
        a = int(110 * ((steps - i + 1) / steps) ** 2.2)
        d.ellipse([cx - r, cy - r, cx + r, cy + r], fill=(255, 255, 255, a))
    core = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    cd = ImageDraw.Draw(core)
    cr = int(radius * 0.5)
    for i in range(20, 0, -1):
        r = int(cr * i / 20)
        a = int(95 * (1 - i / 20) ** 1.4)
        cd.ellipse([cx - r, cy - r, cx + r, cy + r], fill=(255, 255, 255, a))
    layer = Image.alpha_composite(layer, core)
    return layer.filter(ImageFilter.GaussianBlur(radius * 0.12))


def shield_path(size: int, inset: float = 0.0) -> list[tuple[float, float]]:
    """Classic shield outline, slightly softened bottom point."""
    cx = size / 2
    top = size * (0.16 + inset)
    bot = size * (0.86 - inset)
    half_w = size * (0.30 - inset * 0.6)
    shoulder = size * (0.48 - inset * 0.25)
    tip = size * (0.86 - inset)
    # rounded shoulders
    return [
        (cx - half_w, top),
        (cx + half_w, top),
        (cx + half_w, shoulder),
        (cx + half_w * 0.92, shoulder + (bot - shoulder) * 0.42),
        (cx + half_w * 0.55, tip * 0.985),
        (cx, tip),
        (cx - half_w * 0.55, tip * 0.985),
        (cx - half_w * 0.92, shoulder + (bot - shoulder) * 0.42),
        (cx - half_w, shoulder),
    ]


def draw_shield_filled(size: int) -> Image.Image:
    """Soft glass shield silhouette (main protection mark)."""
    layer = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    d = ImageDraw.Draw(layer)
    pts = shield_path(size, inset=0.0)
    d.polygon(pts, fill=(255, 255, 255, 52))
    # inner shield highlight ring
    inner = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    idr = ImageDraw.Draw(inner)
    idr.polygon(shield_path(size, inset=0.018), outline=(255, 255, 255, 70), width=max(3, size // 90))
    layer = Image.alpha_composite(layer, inner.filter(ImageFilter.GaussianBlur(1)))
    return layer


def draw_n_in_shield(size: int) -> Image.Image:
    """Bold geometric N centered in the shield."""
    layer = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    d = ImageDraw.Draw(layer)
    white = (255, 255, 255, 255)
    cx, cy = size / 2, size * 0.50
    sw = int(size * 0.082)
    left = cx - size * 0.125
    right = cx + size * 0.125
    top = cy - size * 0.155
    bottom = cy + size * 0.155

    d.rounded_rectangle([left - sw / 2, top, left + sw / 2, bottom], radius=sw / 2, fill=white)
    d.rounded_rectangle([right - sw / 2, top, right + sw / 2, bottom], radius=sw / 2, fill=white)

    x0, y0 = left, top + sw / 2
    x1, y1 = right, bottom - sw / 2
    dx, dy = x1 - x0, y1 - y0
    length = math.hypot(dx, dy) or 1
    nx, ny = -dy / length * (sw / 2), dx / length * (sw / 2)
    d.polygon([(x0 + nx, y0 + ny), (x1 + nx, y1 + ny), (x1 - nx, y1 - ny), (x0 - nx, y0 - ny)], fill=white)
    for px, py in ((x0, y0), (x1, y1)):
        d.ellipse([px - sw / 2, py - sw / 2, px + sw / 2, py + sw / 2], fill=white)
    return layer


def draw_gloss(size: int) -> Image.Image:
    hl = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    hd = ImageDraw.Draw(hl)
    hd.ellipse([size * 0.06, -size * 0.08, size * 0.72, size * 0.42], fill=(255, 255, 255, 55))
    hl = hl.filter(ImageFilter.GaussianBlur(size * 0.05))
    vig = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    vd = ImageDraw.Draw(vig)
    vd.ellipse([size * 0.12, size * 0.58, size * 1.08, size * 1.18], fill=(22, 42, 96, 32))
    vig = vig.filter(ImageFilter.GaussianBlur(size * 0.06))
    return Image.alpha_composite(hl, vig)


def compose_icon(size: int = SIZE) -> Image.Image:
    # More HyperOS-like squircle
    radius = int(size * 0.26)
    mask = rounded_rect_mask(size, radius)
    bg = draw_gradient(size).convert("RGBA")

    # Frosted glass disc (stronger)
    disc = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    dd = ImageDraw.Draw(disc)
    pad = int(size * 0.07)
    dd.ellipse([pad, pad, size - pad, size - pad], fill=(255, 255, 255, 58))
    disc = disc.filter(ImageFilter.GaussianBlur(size * 0.035))
    bg = Image.alpha_composite(bg, disc)

    # Soft orb glow behind mark
    bg = Image.alpha_composite(bg, soft_orb(size, int(size * 0.30)))

    # Glass light-edge ring
    ring = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    rd = ImageDraw.Draw(ring)
    rd.rounded_rectangle([1, 1, size - 2, size - 2], radius=radius - 1,
                         outline=(255, 255, 255, 78), width=max(3, size // 110))
    bg = Image.alpha_composite(bg, ring)

    # Shield + N (no cyan bar, no extra chips)
    bg = Image.alpha_composite(bg, draw_shield_filled(size))
    bg = Image.alpha_composite(bg, draw_n_in_shield(size))
    bg = Image.alpha_composite(bg, draw_gloss(size))

    pure = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    pure.paste(bg, (0, 0), mask)
    return pure


def make_ico(img: Image.Image, path: Path, sizes=(16, 24, 32, 48, 64, 128, 256)) -> None:
    images = [img.resize((s, s), Image.Resampling.LANCZOS) for s in sizes]
    count = len(images)
    entries = []
    blob = b""
    offset = 6 + 16 * count
    for im in images:
        buf = BytesIO()
        im.save(buf, format="PNG", optimize=True)
        data = buf.getvalue()
        w = im.width if im.width < 256 else 0
        h = im.height if im.height < 256 else 0
        entries.append((w, h, len(data), offset))
        blob += data
        offset += len(data)
    out = struct.pack("<HHH", 0, 1, count)
    for w, h, size, off in entries:
        out += struct.pack("<BBBBHHII", w, h, 0, 0, 1, 32, size, off)
    out += blob
    path.write_bytes(out)


def main() -> None:
    icon = compose_icon(SIZE)
    ui_png = ROOT / "ui" / "Assets" / "NovaProtect.png"
    web_png = ROOT / "website" / "public" / "assets" / "novaprotect.png"
    art_png = ROOT / "artifacts" / "website-release" / "public" / "assets" / "novaprotect.png"
    for p in (ui_png, web_png, art_png):
        p.parent.mkdir(parents=True, exist_ok=True)
        icon.save(p, "PNG", optimize=True)

    ico_targets = [
        ROOT / "ui" / "Assets" / "NovaProtect.ico",
        ROOT / "website" / "public" / "favicon.ico",
        ROOT / "artifacts" / "website-release" / "public" / "favicon.ico",
    ]
    for p in ico_targets:
        p.parent.mkdir(parents=True, exist_ok=True)
        make_ico(icon, p)

    preview = icon.resize((512, 512), Image.Resampling.LANCZOS)
    preview_path = ROOT / "docs" / "logo-hyperos-preview.png"
    preview_path.parent.mkdir(parents=True, exist_ok=True)
    preview.save(preview_path, "PNG")

    board = Image.new("RGB", (720, 720), (0xF5, 0xF7, 0xFC))
    sm = icon.resize((420, 420), Image.Resampling.LANCZOS)
    board.paste(sm, (150, 150), sm)
    board.save(ROOT / "docs" / "logo-hyperos-on-light.png", "PNG")

    print("PNG", ui_png.stat().st_size)
    print("ICO", ico_targets[0].stat().st_size)


if __name__ == "__main__":
    main()
