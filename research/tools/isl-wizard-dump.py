import subprocess, time, os, sys, ctypes
from ctypes import wintypes

user32 = ctypes.windll.user32
try:
    ctypes.windll.shcore.SetProcessDpiAwareness(2)
except Exception:
    pass

EnumWindowsProc = ctypes.WINFUNCTYPE(ctypes.c_bool, wintypes.HWND, wintypes.LPARAM)


def window_text(hwnd):
    n = user32.GetWindowTextLengthW(hwnd)
    buf = ctypes.create_unicode_buffer(n + 1)
    user32.GetWindowTextW(hwnd, buf, n + 1)
    return buf.value


def class_name(hwnd):
    buf = ctypes.create_unicode_buffer(256)
    user32.GetClassNameW(hwnd, buf, 256)
    return buf.value


def enum_all():
    out = []

    def cb(h, l):
        out.append((h, window_text(h), class_name(h), bool(user32.IsWindowVisible(h))))
        return True

    user32.EnumWindows(EnumWindowsProc(cb), 0)
    return out


def enum_children(hwnd):
    out = []

    def cb(h, l):
        out.append((h, window_text(h), class_name(h)))
        return True

    user32.EnumChildWindows(hwnd, EnumWindowsProc(cb), 0)
    return out


exe = sys.argv[1] if len(sys.argv) > 1 else r"C:\npbuild\artifacts\isl-test\isl-test.exe"
outdir = os.path.dirname(exe)

print("launching", exe)
proc = subprocess.Popen([exe], cwd=outdir)
time.sleep(7.0)

cands = [w for w in enum_all() if w[3] and ("NovaProtect" in w[1] or "安装" in w[1] or "Setup" in w[1])]
print("candidate top-level windows:")
for h, t, c, v in cands:
    print(f"  hwnd={h} class={c!r} title={t!r}")

if not cands:
    print("no installer window; all visible windows:")
    for h, t, c, v in enum_all():
        if v:
            print(f"  hwnd={h} class={c!r} title={t!r}")
    proc.kill()
    sys.exit(2)

hwnd = cands[0][0]
user32.SetForegroundWindow(hwnd)
time.sleep(1.0)

# Inno's wizard is a custom-drawn form; the child controls still carry the
# rendered strings.  Dump them for each page as we click "Next".
for step in range(6):
    print(f"\n=== page {step} ===")
    kids = enum_children(hwnd)
    texts = [(t, c) for _, t, c in kids if t and t.strip()]
    for t, c in texts:
        print(f"   [{c}] {t!r}")

    # Click the Next button (Inno uses id 1 for Next/Install).
    import ctypes.wintypes as wt
    BM_CLICK = 0x00F5
    nxt = user32.GetDlgItem(hwnd, 1)
    if nxt:
        user32.SendMessageW(nxt, BM_CLICK, 0, 0)
    else:
        # fall back: find a child with text 安装/下一步
        for h, t, c in kids:
            if t.strip() in ("下一步", "&下一步", "Next", "&Next", "安装", "&安装"):
                user32.SendMessageW(h, BM_CLICK, 0, 0)
                break
    time.sleep(2.0)

print("\nfinal title:", window_text(hwnd))
proc.kill()
