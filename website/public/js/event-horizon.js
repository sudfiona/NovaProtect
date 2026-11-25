(() => {
    'use strict';

    const canvas = document.querySelector('.blackhole-flow');
    if (!canvas || !('IntersectionObserver' in window)) return;

    const root = document.documentElement;
    const scene = canvas.closest('.blackhole-scene');
    const TAU = Math.PI * 2;
    const SAMPLES = 256;
    const tilt = -27 * Math.PI / 180;
    const cosTilt = Math.cos(tilt), sinTilt = Math.sin(tilt);
    const wave = (index) => ((Math.imul(index + 1, 2654435761) >>> 0) / 4294967296);

    let context;
    let streams;
    let isOnScreen = false;
    let frame = null;
    let previous = null;
    let time = 0;

    // Sample the rim and both outer caustics of tools/render-blackhole.py.
    // The opaque shadow and photographic plate stay perfectly stationary.
    function point(angle, band) {
        const offset = band === 1 ? .048 : .092;
        const radius = band === 0 ? .403 : .4 + offset * (1 + .43 * Math.cos(angle + .3))
            + .006 * Math.sin(3 * angle + band - 1);
        const u = radius * Math.cos(angle);
        const v = radius * .91 * Math.sin(angle);
        return {
            x: (.5 + (cosTilt * u - sinTilt * v) / 3.2) * canvas.width,
            y: (.5 + (sinTilt * u + cosTilt * v) / 2) * canvas.height,
            light: .12 + .88 * (.5 + .5 * Math.cos(angle - 2.2)) ** 2,
        };
    }

    function buildStreams() {
        const bands = Array.from({ length: 3 }, (_, band) => Array.from(
            { length: SAMPLES }, (_, index) => point(index * TAU / SAMPLES, band)));
        return Array.from({ length: 12 }, (_, i) => {
            const band = i % bands.length;
            return {
                samples: bands[band],
                speed: (SAMPLES / TAU) * (.74 - .13 * band),
                phase: wave(i * 7) * SAMPLES,
                tail: 10 + Math.round(wave(i * 3) * 20),
                strength: (.57 - band * .08) * (.75 + wave(i * 11) * .25),
                color: ['#e3effa', '#a8c5df', '#7c9fbd'][band],
                width: .9 + wave(i * 5) * .9,
            };
        });
    }

    function draw() {
        context.clearRect(0, 0, canvas.width, canvas.height);
        context.lineCap = 'round';
        for (const stream of streams) {
            const head = stream.phase + time * stream.speed;
            const direction = Math.sign(stream.speed);
            context.strokeStyle = stream.color;
            for (let i = 0; i < stream.tail; i++) {
                const position = head - i * direction;
                const lower = Math.floor(position);
                const fraction = position - lower;
                const sample = stream.samples[lower & (SAMPLES - 1)];
                const next = stream.samples[(lower + 1) & (SAMPLES - 1)];
                const end = stream.samples[(lower + direction) & (SAMPLES - 1)];
                const endNext = stream.samples[(lower + direction + 1) & (SAMPLES - 1)];
                const alpha = Math.min(sample.light, next.light, end.light, endNext.light)
                    * stream.strength * Math.sin(Math.PI * (i + .5) / stream.tail) ** 1.5;
                if (alpha <= .012) continue;
                context.beginPath();
                context.moveTo(sample.x + (next.x - sample.x) * fraction, sample.y + (next.y - sample.y) * fraction);
                context.lineTo(end.x + (endNext.x - end.x) * fraction, end.y + (endNext.y - end.y) * fraction);
                context.globalAlpha = alpha * .20;
                context.lineWidth = stream.width * 5;
                context.stroke();
                context.globalAlpha = alpha * .68;
                context.lineWidth = stream.width;
                context.stroke();
            }
        }
    }

    function canPlay() {
        return root.dataset.theme === 'blackhole' && !root.classList.contains('motion-paused')
            && !document.hidden && isOnScreen;
    }

    function tick(now) {
        frame = null;
        if (!canPlay()) {
            previous = null;
            return;
        }
        if (previous === null || now - previous >= 1000 / 60 - 1) {
            if (previous !== null) time += Math.min(.05, (now - previous) / 1000);
            previous = now;
            draw();
        }
        frame = requestAnimationFrame(tick);
    }

    function sync() {
        if (!canPlay()) {
            if (frame !== null) cancelAnimationFrame(frame);
            frame = null;
            previous = null;
            return;
        }
        if (frame !== null) return;
        if (!context) {
            context = canvas.getContext('2d');
            if (!context) return;
            streams = buildStreams();
        }
        frame = requestAnimationFrame(tick);
    }

    new IntersectionObserver(([entry]) => {
        isOnScreen = entry.isIntersecting;
        sync();
    }).observe(scene);
    new MutationObserver(sync).observe(root, { attributes: true, attributeFilter: ['data-theme', 'class'] });
    document.addEventListener('visibilitychange', sync);
})();
