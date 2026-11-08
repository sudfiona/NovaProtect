"""Render the marketing DOCX to page rasters using a portable renderer.

The original version of this script pointed at absolute paths inside the
maintainer's machine (a Codex runtime cache and one pinned plugin version), so it
only ran on that one box. It now resolves the renderer from the environment:

    NP_RENDER_DOCX   full path to render_docx.py
    NP_POPPLER_BIN   directory containing pdftoppm.exe

Both are optional. When they are unset the script falls back to whatever is on
PATH, which is what a normal LibreOffice + poppler install provides.
"""

from pathlib import Path
import importlib.util
import os
import shutil
import sys

BASE = Path(__file__).resolve().parent
PREVIEW = BASE / 'render' / 'native-preview.pdf'
DOCX = BASE.parents[1] / 'marketing-source' / 'product-copy.docx'


def load_renderer():
    script = os.environ.get('NP_RENDER_DOCX')
    if script and Path(script).is_file():
        spec = importlib.util.spec_from_file_location('render_docx', script)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module
    return None


def main():
    poppler = os.environ.get('NP_POPPLER_BIN')
    if poppler and Path(poppler).is_dir():
        os.environ['PATH'] = poppler + os.pathsep + os.environ.get('PATH', '')
    elif shutil.which('pdftoppm') is None:
        print('pdftoppm not found: install poppler or set NP_POPPLER_BIN', file=sys.stderr)
        return 2

    if not DOCX.is_file():
        print(f'marketing source document missing: {DOCX}', file=sys.stderr)
        return 2
    if not (PREVIEW.is_file() and PREVIEW.stat().st_size > 0):
        print(f'rendered preview missing: {PREVIEW}', file=sys.stderr)
        return 2

    renderer = load_renderer()
    if renderer is None:
        print('render_docx.py not available: set NP_RENDER_DOCX', file=sys.stderr)
        return 2

    # The Windows runtime has no LibreOffice. WPS exports the real DOCX through
    # its native layout engine; the packaged renderer is kept for DPI and raster
    # QA only, so the PDF conversion step is bypassed.
    def native_conversion(*args, **kwargs):
        return str(PREVIEW), 'Native WPS ExportAsFixedFormat PDF'

    renderer.convert_to_pdf = native_conversion
    dpi = renderer.calc_dpi_via_ooxml_docx(str(DOCX), 1600, 2100)
    for path in renderer.rasterize(str(DOCX), str(BASE / 'render'), dpi, False, False):
        print(path)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
