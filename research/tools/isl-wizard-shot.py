import subprocess, time, os, sys
import ctypes
from ctypes import wintypes

user32 = ctypes.windll.user32
try:
    ctypes.windll.shcore.SetProcessDpiAwareness(2)
except Exception:
    pass

user32.SetProcessDPIAware()

EnumWindows = user32.EnumWindows
EnumWindowsProc = ctypes.WINFUNCTYPE(ctypes.c_bool, wintypes.HWND, wintypes.LPARAM)

titles = []


def cb(hwnd, lparam):
    if not user32.IsWindowVisible(hwnd):
        return True
    length = user32.GetWindowTextLengthW(hwnd)
    if length == 0:
        return True
    buf = ctypes.create_unicode_buffer(length + 1)
    user32.GetWindowTextW(hwnd, buf, length + 1)
    titles.append((hwnd, buf.value))
    return True


exe = sys.argv[1] if len(sys.argv) > 1 else r"C:\npbuild\artifacts\isl-test\isl-test.exe"
print("launching", exe)
proc = subprocess.Popen([exe, "/LANG=chinese"], cwd=os.path.dirname(exe))
time.sleep(6.0)

found = []
EnumWindows(EnumWindowsProc(cb), 0)
for hwnd, title in titles:
    print(f"  hwnd={hwnd} title={title!r}")
    if "NovaProtect" in title or "安装" in title or "Setup" in title:
        found.append((hwnd, title))

if not found:
    print("NO INSTALLER WINDOW FOUND")
    # capture the whole screen anyway
    import PIL  # may not exist
    sys.exit(2)

hwnd = found[0][0]
user32.SetForegroundWindow(hwnd)
time.sleep(1.0)

# Screenshot the installer window.
import ctypes.wintypes as w
rect = wintypes.RECT()
user32.GetWindowRect(hwnd, ctypes.byref(rect))
w_, h_ = rect.right - rect.left, rect.bottom - rect.top
print("window rect", rect.left, rect.top, w_, h_)

try:
    from PIL import ImageGrab
    img = ImageGrab.grab(bbox=(rect.left, rect.top, rect.right, rect.bottom))
    out = r"C:\npbuild\artifacts\isl-test\wizard-1.png"
    img.save(out)
    print("saved", out)
except ImportError:
    print("PIL not available")
