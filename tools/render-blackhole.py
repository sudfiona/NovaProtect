"""Render the black-hole hero from a seeded star field and bent emission bands.

Geometry uses half the image height as its unit, matching event-horizon.js.
Requires NumPy and Pillow. No network or source photographs are needed.
"""
from pathlib import Path

import numpy as np
from PIL import Image

WIDTH, HEIGHT = 1600, 1000
OUTPUT = Path(__file__).resolve().parents[1] / 'website/public/assets/event-horizon.webp'
TILT = np.deg2rad(-27)
RING = .400


def smooth(x):
    x = np.clip(x, 0, 1)
    return x * x * (3 - 2 * x)


def noise(x, y, grid):
    # Periodic interpolation on a fixed lattice. Using cos/sin for polar
    # coordinates keeps the approaching and receding halves joined at ±pi.
    xi, yi = np.floor(x).astype(int), np.floor(y).astype(int)
    fx, fy = smooth(x - xi), smooth(y - yi)
    n = grid.shape[0]
    a = grid[yi % n, xi % n] * (1 - fx) + grid[yi % n, (xi + 1) % n] * fx
    b = grid[(yi + 1) % n, xi % n] * (1 - fx) + grid[(yi + 1) % n, (xi + 1) % n] * fx
    return a * (1 - fy) + b * fy


def render():
    rng = np.random.default_rng(52715)
    grid = rng.random((128, 128), dtype=np.float32)
    y, x = np.mgrid[:HEIGHT, :WIDTH].astype(np.float32)
    x = (x + .5 - WIDTH / 2) / (HEIGHT / 2)
    y = (y + .5 - HEIGHT / 2) / (HEIGHT / 2)
    u = np.cos(TILT) * x + np.sin(TILT) * y
    v = -np.sin(TILT) * x + np.cos(TILT) * y
    radius = np.hypot(u, v / .91)
    angle = np.arctan2(v / .91, u)
    edge = radius - RING
    image = np.zeros((HEIGHT, WIDTH, 3), np.float32) + (3., 5., 8.)

    def emit(field, color):
        image[:] += field[..., None] * color

    def gaussian(x, width):
        return np.exp(-(x / width)**2)

    # Small unresolved stars, with soft point-spread profiles and very rare
    # diffraction spikes. Nearby backgrounds stay subdued behind the hero type.
    for _ in range(1050):
        sx, sy = rng.uniform(8, WIDTH - 8), rng.uniform(8, HEIGHT - 8)
        yy, xx = np.mgrid[-7:8, -7:8]
        dx, dy = xx + int(sx) - sx, yy + int(sy) - sy
        size = rng.uniform(.43, 1.05)
        flux = 9 + 190 * rng.random()**8
        psf = gaussian(np.hypot(dx, dy), size * 1.3)
        if flux > 150:
            psf += .16 * gaussian(np.hypot(dx, dy), size * 2.9)
            psf += .17 * (gaussian(dx, .48) * gaussian(dy, 3.8) + gaussian(dy, .48) * gaussian(dx, 3.8))
        color = np.array((.79, .88, 1.)) if rng.random() < .68 else np.array((.94, .95, 1.))
        image[int(sy)-7:int(sy)+8, int(sx)-7:int(sx)+8] += psf[..., None] * flux * color

    # Rotate texture with radius to sweep irregular clouds into long wisps.
    def turbulence(r, theta):
        phase = theta + 2.8 * r + .14 * np.sin(theta * 2 + 7 * r)
        p, q = r * np.cos(phase), r * np.sin(phase)
        return (.52 * noise(8*p, 8*q, grid) + .29 * noise(20*p-15, 20*q, grid)
                + .14 * noise(45*p, 45*q+17, grid) + .05 * noise(96*p, 96*q, grid))

    disk_r = np.hypot(u, (v - .024) / .65)
    disk_a = np.arctan2((v - .024) / .65, u)
    flow = turbulence(disk_r, disk_a)
    swept = disk_r + .023 * np.sin(2*disk_a + 6*disk_r) + .036 * flow
    strands = (.50 + .50 * np.cos(119*swept + 2*disk_a)) ** 3
    dust = gaussian(disk_r - .61, .31) * (.42 + .58 * strands) * (flow**2)
    dust *= .55 + .45 * np.cos(disk_a - 2.35)
    emit(dust, (96, 123, 158))

    # A broad, turbulent crescent outside the narrow, sharper photon rim.
    boost = (.5 + .5 * np.cos(angle - 2.20))**2.6
    detail = turbulence(radius, angle)
    width = .021 + .049 * boost
    crest = gaussian(edge - .023, width) * (.11 + .89 * boost) * (.22 + 1.45 * detail**1.5)
    emit(crest, (120, 157, 191))
    emit(gaussian(edge - .010, .022) * (.17 + .83 * boost), (38, 53, 77))
    emit(gaussian(edge - .003, .0047) * (.28 + .72 * boost), (166, 179, 183))
    # Two discontinuous caustics curled around the wider, faint disk.
    for i, offset in enumerate((.048, .092)):
        trace = edge - offset * (1 + .43 * np.cos(angle + .3)) - .006 * np.sin(3*angle+i)
        patch = (.5 + .5 * np.cos(angle - 2.52 + i*.52))**3 * (.19 + detail)
        emit(gaussian(trace, .004 + .002*i) * patch, (50, 67, 88))

    # Occlude even the background stars in the shadow. A tiny spill of lens
    # light at the limb preserves the dark centre without a hard matte edge.
    image *= (.10 + .90 * smooth((edge + .012) / .014))[..., None]
    emission_fade = smooth((1.60 - abs(x)) / .30) * smooth((1 - abs(y)) / .22)
    image = image * emission_fade[..., None] + np.array((3,5,8)) * (1-emission_fade[..., None])
    image += rng.uniform(-.58, .58, (HEIGHT, WIDTH, 1))
    return Image.fromarray(np.uint8(np.clip(image, 0, 255)))


if __name__ == '__main__':
    render().save(OUTPUT, quality=91, method=6)
