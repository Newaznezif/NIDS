"""Minimal, dependency-free PDF writer (PDF 1.4, text-only, multi-page).

Produces a valid, professional-looking text report without third-party
libraries so the platform stays deployable offline.
"""


def _escape(text: str) -> str:
    return (text or "").replace("\\", r"\\").replace("(", r"\(").replace(")", r"\)")


class PDFDocument:
    PAGE_W = 612   # US Letter portrait
    PAGE_H = 792
    MARGIN = 54

    def __init__(self, title: str = "Report"):
        self.title = title
        self.pages = []
        self._current = []
        self._y = self.PAGE_H - self.MARGIN

    def _new_page(self):
        if self._current:
            self.pages.append(self._current)
        self._current = []
        self._y = self.PAGE_H - self.MARGIN

    def _ensure(self, height: float):
        if self._y - height < self.MARGIN:
            self._new_page()

    def line(self, text: str, size: int = 10, bold: bool = False, indent: int = 0, gap: float = 4):
        text = text or ""
        # naive wrap at ~95 chars for 10pt
        width = 95 if size <= 10 else int(95 * 10 / size)
        chunks = [text[i:i + width] for i in range(0, len(text), width)] or [""]
        for chunk in chunks:
            self._ensure(size + gap)
            font = "/F2" if bold else "/F1"
            self._current.append(
                f"BT {font} {size} Tf 1 0 0 1 {self.MARGIN + indent} {self._y:.2f} Tm "
                f"({_escape(chunk)}) Tj ET"
            )
            self._y -= size + gap
        if not self._current:
            self._current = []

    def spacer(self, pts: float = 8):
        self._y -= pts

    def rule(self):
        self._ensure(6)
        self._current.append(
            f"0.75 w {self.MARGIN} {self._y:.2f} m {self.PAGE_W - self.MARGIN} {self._y:.2f} l S"
        )
        self._y -= 8

    def heading(self, text: str, size: int = 14):
        self.spacer(6)
        self.line(text, size=size, bold=True)
        self.rule()

    def render(self) -> bytes:
        if self._current:
            self.pages.append(self._current)
        if not self.pages:
            self.pages = [["BT /F1 10 Tf 1 0 0 1 54 738 Tm (Empty report) Tj ET"]]

        objs = []  # (obj_number, body)
        # 1 catalog, 2 pages, 3 F1, 4 F2, then per page: page obj + content obj
        page_obj_nums = []
        num = 5
        for _ in self.pages:
            page_obj_nums.append((num, num + 1))
            num += 2

        catalog = f"<< /Type /Catalog /Pages 2 0 R >>"
        kids = " ".join(f"{p} 0 R" for p, _ in page_obj_nums)
        pages = f"<< /Type /Pages /Kids [{kids}] /Count {len(self.pages)} >>"
        f1 = "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>"
        f2 = "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >>"
        objs.append((1, catalog))
        objs.append((2, pages))
        objs.append((3, f1))
        objs.append((4, f2))

        for (pnum, cnum), content in zip(page_obj_nums, self.pages):
            stream = "\n".join(content)
            objs.append((pnum, f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 {self.PAGE_W} {self.PAGE_H}] "
                               f"/Resources << /Font << /F1 3 0 R /F2 4 0 R >> >> /Contents {cnum} 0 R >>"))
            objs.append((cnum, f"<< /Length {len(stream.encode('latin-1', errors='replace'))} >>\nstream\n{stream}\nendstream"))

        objs.sort(key=lambda o: o[0])
        out = bytearray(b"%PDF-1.4\n")
        offsets = {}
        for onum, body in objs:
            offsets[onum] = len(out)
            out += f"{onum} 0 obj\n{body}\nendobj\n".encode("latin-1", errors="replace")
        xref_start = len(out)
        maxobj = max(offsets) + 1
        out += f"xref\n0 {maxobj}\n".encode()
        out += b"0000000000 65535 f \n"
        for i in range(1, maxobj):
            off = offsets.get(i, 0)
            out += f"{off:010d} 00000 n \n".encode()
        out += (f"trailer\n<< /Size {maxobj} /Root 1 0 R >>\nstartxref\n{xref_start}\n%%EOF\n").encode()
        return bytes(out)
