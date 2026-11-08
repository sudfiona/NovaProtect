import sys
from pypdf import PdfReader

path = sys.argv[1]
reader = PdfReader(path)
print(f"PAGES {len(reader.pages)}")
for i, page in enumerate(reader.pages):
    text = page.extract_text() or ""
    print(f"\n===== PAGE {i + 1} =====")
    print(text)
