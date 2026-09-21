"""Dependency-free PDF writer (PDF 1.4) for professional investigation reports.

Adds the capabilities a serious report needs while staying offline-installable:
colour, vector brand logo, a branded cover, running header + footer with
"Page X of Y", auto section numbering, wrapping tables that never overflow the
page, severity/provenance badges and consistent typography.

The public surface used by reports.py is intentionally small: cover(), section(),
subheading(), line(), label_value(), table(), badge_line(), rule(), spacer(),
render().
"""
from . import branding


def _escape(text):
    text = text or ""
    # Transliterate common Unicode to latin-1-safe equivalents so user-supplied
    # text (notes, provider data) never renders as '?' or breaks encoding.
    text = (text.replace("\u2014", "-").replace("\u2013", "-")
                .replace("\u2022", "-").replace("\u2026", "...")
                .replace("\u2018", "'").replace("\u2019", "'")
                .replace("\u201c", '"').replace("\u201d", '"')
                .replace("\u00a0", " "))
    text = text.encode("latin-1", "replace").decode("latin-1")
    return text.replace("\\", r"\\").replace("(", r"\(").replace(")", r"\)")


def _blend(hex_color, factor):
    """Blend a hex colour toward white by `factor` (0..1). Returns hex."""
    h = (hex_color or "#000000").lstrip("#")
    r, g, b = int(h[0:2], 16), int(h[2:4], 16), int(h[4:6], 16)
    r = int(r + (255 - r) * factor)
    g = int(g + (255 - g) * factor)
    b = int(b + (255 - b) * factor)
    return f"#{r:02x}{g:02x}{b:02x}"


class PDFDocument:
    PAGE_W = 612    # US Letter portrait
    PAGE_H = 792
    MARGIN = 54
    TOP = 58
    BOTTOM = 62
    CONTENT_W = PAGE_W - 2 * MARGIN  # 504

    def __init__(self, title="Report"):
        self.title = title
        self.pages = []
        self._current = []
        self._y = self.PAGE_H - self.TOP
        self._section = 0
        self.meta = {"case_id": "", "generated": "", "classification": "", "doc_id": ""}

    # ---------- low-level ----------
    def _op(self, s):
        self._current.append(s)

    def _new_page(self):
        if self._current:
            self.pages.append(self._current)
        self._current = []
        self._y = self.PAGE_H - self.TOP

    def _ensure(self, h):
        if self._y - h < self.BOTTOM:
            self._new_page()

    @staticmethod
    def _cw(size, bold):
        return size * (0.545 if bold else 0.505)

    def _wrap(self, text, max_w, size, bold):
        text = "" if text is None else str(text)
        cw = self._cw(size, bold)
        max_chars = max(4, int(max_w / cw))
        lines = []
        for para in text.split("\n"):
            words = para.split(" ")
            cur = ""
            for w in words:
                while len(w) > max_chars:        # hard-split very long tokens
                    if cur:
                        lines.append(cur); cur = ""
                    lines.append(w[:max_chars]); w = w[max_chars:]
                trial = (cur + " " + w).strip()
                if len(trial) <= max_chars:
                    cur = trial
                else:
                    if cur:
                        lines.append(cur)
                    cur = w
            lines.append(cur)
        return lines or [""]

    def _text_op(self, x, y, s, size, bold=False, color=None, italic=False):
        font = "/F2" if bold else ("/F3" if italic else "/F1")
        col = branding.rgb(color or branding.INK)
        return (f"BT {col} rg {font} {size} Tf 1 0 0 1 {x:.2f} {y:.2f} Tm "
                f"({_escape(s)}) Tj ET")

    def _text_width(self, s, size, bold):
        return len(s or "") * self._cw(size, bold)

    # ---------- content helpers ----------
    def line(self, text, size=10, bold=False, indent=0, gap=3.5,
             color=None, italic=False, align="left"):
        max_w = self.CONTENT_W - indent
        for ln in self._wrap(text, max_w, size, bold):
            self._ensure(size + gap)
            x = self.MARGIN + indent
            if align == "right":
                x = self.MARGIN + self.CONTENT_W - self._text_width(ln, size, bold)
            elif align == "center":
                x = self.MARGIN + (self.CONTENT_W - self._text_width(ln, size, bold)) / 2
            self._op(self._text_op(x, self._y, ln, size, bold, color, italic))
            self._y -= size + gap

    def spacer(self, pts=8):
        self._y -= pts

    def rule(self, color=None, width=0.75, pad=6):
        self._ensure(pad + 2)
        c = branding.rgb(color or branding.BORDER)
        self._op(f"{c} RG {width} w {self.MARGIN} {self._y:.2f} m "
                 f"{self.MARGIN + self.CONTENT_W} {self._y:.2f} l S")
        self._y -= pad

    def section(self, title):
        """Numbered top-level section heading in brand colour."""
        self._section += 1
        self.spacer(8)
        self._ensure(26)
        label = f"{self._section}. {title}"
        self._op(self._text_op(self.MARGIN, self._y, label, 13, True, branding.BRAND))
        self._y -= 17
        self.rule(color=branding.BRAND, width=1.0, pad=7)
        return self._section

    def subheading(self, text):
        self._ensure(18)
        self.spacer(3)
        self._op(self._text_op(self.MARGIN, self._y, text, 11, True, branding.INK))
        self._y -= 15

    def label_value(self, pairs, label_w=140, size=9.5):
        for label, value in pairs:
            vlines = self._wrap(value, self.CONTENT_W - label_w - 6, size, False)
            block_h = max(len(vlines), 1) * (size + 3)
            self._ensure(block_h + 2)
            top = self._y
            self._op(self._text_op(self.MARGIN, top, str(label), size, True, branding.MUTED))
            yy = top
            for vl in vlines:
                self._op(self._text_op(self.MARGIN + label_w, yy, vl, size, False, branding.INK))
                yy -= size + 3
            self._y = top - block_h - 1

    def badge(self, x, y, label, color, size=8):
        """Draw a tinted pill badge with its baseline at y; returns its width."""
        pad_x, pad_y = 5, 2.5
        w = self._text_width(label, size, True) + 2 * pad_x
        h = size + 2 * pad_y
        bg = branding.rgb(_blend(color, 0.82))
        fg = branding.rgb(color)
        self._op(f"{bg} rg {x:.2f} {y - pad_y:.2f} {w:.2f} {h:.2f} re f")
        self._op(self._text_op(x + pad_x, y, label, size, True, color))
        return w

    def badge_line(self, label, color, prefix="", size=9.5):
        """A line that starts with an optional text prefix then a colour badge."""
        self._ensure(size + 6)
        x = self.MARGIN
        if prefix:
            self._op(self._text_op(x, self._y, prefix, size, False, branding.INK))
            x += self._text_width(prefix, size, False) + 6
        w = self.badge(x, self._y, label.upper(), color, size=8)
        self._y -= size + 6
        return w

    # ---------- tables ----------
    def _table_header(self, headers, widths, size, pad, line_h):
        wrapped = [self._wrap(headers[i], widths[i] - 2 * pad, size, True) for i in range(len(headers))]
        nlines = max(1, max(len(w) for w in wrapped))
        h = nlines * line_h + 2 * pad
        if self._y - h < self.BOTTOM:
            self._new_page()
        top = self._y
        self._op(f"{branding.rgb(branding.LIGHT)} rg {self.MARGIN} {top - h:.2f} "
                 f"{self.CONTENT_W} {h:.2f} re f")
        x = self.MARGIN
        for i, cell in enumerate(wrapped):
            yy = top - pad - size
            for ln in cell:
                self._op(self._text_op(x + pad, yy, ln, size, True, branding.INK))
                yy -= line_h
            x += widths[i]
        # borders
        self._op(f"{branding.rgb(branding.BRAND)} RG 1 w {self.MARGIN} {top - h:.2f} m "
                 f"{self.MARGIN + self.CONTENT_W} {top - h:.2f} l S")
        self._y = top - h

    def table(self, headers, rows, widths, size=9, aligns=None, zebra=True):
        if not widths:
            return
        # normalise widths to the content box
        total = sum(widths)
        widths = [w * self.CONTENT_W / total for w in widths]
        aligns = aligns or ["left"] * len(headers)
        pad, line_h = 5, size + 3

        def cell_parts(raw):
            """Return (text, color, is_badge) for a cell that may be a plain
            value, a (text, color) tuple, or a {text,color,badge} dict."""
            color, is_badge = branding.INK, False
            if isinstance(raw, dict):
                text = raw.get("text", "")
                color = raw.get("color", branding.INK)
                is_badge = bool(raw.get("badge"))
            elif isinstance(raw, (tuple, list)):
                text = raw[0] if raw else ""
                if len(raw) > 1 and raw[1]:
                    color = raw[1]
                if len(raw) > 2:
                    is_badge = bool(raw[2])
            else:
                text = raw
            return ("" if text is None else str(text)), color, is_badge

        self._table_header(headers, widths, size, pad, line_h)
        if not rows:
            self._ensure(line_h + 2 * pad)
            self._op(self._text_op(self.MARGIN + pad, self._y - pad - size,
                                   "No records.", size, False, branding.MUTED))
            self._y -= line_h + 2 * pad
            return
        for r_i, row in enumerate(rows):
            parts = [cell_parts(row[i] if i < len(row) else "") for i in range(len(widths))]
            wrapped = [self._wrap(parts[i][0], widths[i] - 2 * pad, size, False) for i in range(len(widths))]
            nlines = max(1, max(len(w) for w in wrapped))
            row_h = nlines * line_h + 2 * pad
            if self._y - row_h < self.BOTTOM:
                self._new_page()
                self._table_header(headers, widths, size, pad, line_h)
            top = self._y
            if zebra and r_i % 2 == 1:
                self._op(f"{branding.rgb('#f8fafc')} rg {self.MARGIN} {top - row_h:.2f} "
                         f"{self.CONTENT_W} {row_h:.2f} re f")
            x = self.MARGIN
            for i, cell in enumerate(wrapped):
                _, color, is_badge = parts[i]
                yy = top - pad - size
                if is_badge and len(cell) <= 1:
                    self.badge(x + pad, yy, (cell[0] if cell else "").upper(), color, size=7.5)
                else:
                    for ln in cell:
                        if aligns[i] == "right":
                            tx = x + widths[i] - pad - self._text_width(ln, size, False)
                        elif aligns[i] == "center":
                            tx = x + (widths[i] - self._text_width(ln, size, False)) / 2
                        else:
                            tx = x + pad
                        self._op(self._text_op(tx, yy, ln, size, False, color))
                        yy -= line_h
                x += widths[i]
            # row bottom border + column separators
            self._op(f"{branding.rgb(branding.BORDER)} RG 0.5 w {self.MARGIN} {top - row_h:.2f} m "
                     f"{self.MARGIN + self.CONTENT_W} {top - row_h:.2f} l S")
            cx = self.MARGIN
            for i in range(len(widths) - 1):
                cx += widths[i]
                self._op(f"{branding.rgb(branding.BORDER)} RG 0.5 w {cx:.2f} {top:.2f} m "
                         f"{cx:.2f} {top - row_h:.2f} l S")
            self._y = top - row_h
        self.spacer(4)

    # ---------- cover ----------
    def cover(self, c):
        self.meta["case_id"] = c.get("case_id", "")
        self.meta["generated"] = c.get("date", "")
        self.meta["classification"] = c.get("classification", "") or ""
        self.meta["doc_id"] = c.get("case_id", "")

        # top brand band
        self._op(f"{branding.rgb(branding.BRAND)} rg 0 {self.PAGE_H - 6:.2f} {self.PAGE_W} 6 re f")
        # logo + product name
        logo_size = 40
        logo_y = self.PAGE_H - self.TOP - logo_size
        for op in branding.logo_ops(self.MARGIN, logo_y, logo_size):
            self._op(op)
        tx = self.MARGIN + logo_size + 12
        self._op(self._text_op(tx, logo_y + logo_size - 16, branding.PRODUCT_NAME, 15, True, branding.INK))
        self._op(self._text_op(tx, logo_y + 6, "Threat Investigation & Intelligence Reporting", 9, False, branding.MUTED))

        self._y = logo_y - 18
        # report title
        self._op(self._text_op(self.MARGIN, self._y, branding.REPORT_TITLE.upper(), 20, True, branding.BRAND))
        self._y -= 24
        self._op(self._text_op(self.MARGIN, self._y, c.get("title", "") or "", 13, False, branding.INK))
        self._y -= 20
        self.rule(color=branding.BRAND, width=1.0, pad=10)

        # classification banner (only if configured)
        if self.meta["classification"]:
            label = self.meta["classification"].upper()
            w = self._text_width(label, 8.5, True) + 16
            bx = self.MARGIN + self.CONTENT_W - w
            self._op(f"{branding.rgb(_blend(branding.BRAND, 0.85))} rg {bx:.2f} {self._y - 2:.2f} {w:.2f} 16 re f")
            self._op(self._text_op(bx + 8, self._y + 2, label, 8.5, True, branding.BRAND))
            self._y -= 22

        # metadata grid
        self.label_value([
            ("Investigation ID", c.get("case_id", "") or "Unavailable"),
            ("Report type", c.get("report_type", "Case investigation report")),
            ("Generated", c.get("date", "") or "Unavailable"),
            ("Analyst", c.get("analyst", "") or "Unavailable"),
            ("Status", c.get("status", "") or "Unavailable"),
            ("Priority", c.get("priority", "") or "Unavailable"),
        ], label_w=120, size=9.5)
        self.spacer(6)

    # ---------- running header / footer (injected at render) ----------
    def _running_header_ops(self):
        ops = []
        size = 16
        y = self.PAGE_H - 34 - size
        for op in branding.logo_ops(self.MARGIN, y, size):
            ops.append(op)
        ops.append(self._text_op(self.MARGIN + size + 8, y + 4, branding.PRODUCT_NAME, 9, True, branding.MUTED))
        right = self.meta["case_id"] or ""
        if right:
            ops.append(self._text_op(self.MARGIN + self.CONTENT_W - self._text_width(right, 9, False),
                                     y + 4, right, 9, False, branding.MUTED))
        ops.append(f"{branding.rgb(branding.BORDER)} RG 0.75 w {self.MARGIN} {self.PAGE_H - 56:.2f} m "
                   f"{self.MARGIN + self.CONTENT_W} {self.PAGE_H - 56:.2f} l S")
        return ops

    def _footer_ops(self, page_no, total):
        ops = []
        fy = self.BOTTOM - 20
        ops.append(f"{branding.rgb(branding.BORDER)} RG 0.75 w {self.MARGIN} {fy + 12:.2f} m "
                   f"{self.MARGIN + self.CONTENT_W} {fy + 12:.2f} l S")
        left = branding.PRODUCT_NAME
        if self.meta["case_id"]:
            left += f"  \u00b7  Investigation ID: {self.meta['case_id']}"
        if self.meta["generated"]:
            left += f"  \u00b7  Generated: {self.meta['generated']}"
        # keep footer left within the box (drop the generated part if too long)
        if self._text_width(left, 7.5, False) > self.CONTENT_W - 70:
            left = branding.PRODUCT_NAME + (f"  \u00b7  {self.meta['case_id']}" if self.meta["case_id"] else "")
        ops.append(self._text_op(self.MARGIN, fy, left, 7.5, False, branding.MUTED))
        page_txt = f"Page {page_no} of {total}"
        ops.append(self._text_op(self.MARGIN + self.CONTENT_W - self._text_width(page_txt, 7.5, True),
                                 fy, page_txt, 7.5, True, branding.INK))
        return ops

    # ---------- assembly ----------
    def render(self):
        if self._current:
            self.pages.append(self._current)
            self._current = []
        if not self.pages:
            self.pages = [[]]
        total = len(self.pages)
        final = []
        for i, body in enumerate(self.pages):
            ops = []
            if i > 0:
                ops += self._running_header_ops()
            ops += body
            ops += self._footer_ops(i + 1, total)
            final.append("\n".join(ops))

        objs = []
        page_obj_nums = []
        num = 6
        for _ in final:
            page_obj_nums.append((num, num + 1))
            num += 2

        objs.append((1, "<< /Type /Catalog /Pages 2 0 R >>"))
        kids = " ".join(f"{p} 0 R" for p, _ in page_obj_nums)
        objs.append((2, f"<< /Type /Pages /Kids [{kids}] /Count {len(final)} >>"))
        objs.append((3, "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>"))
        objs.append((4, "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >>"))
        objs.append((5, "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Oblique >>"))

        info_num = num
        for (pnum, cnum), stream in zip(page_obj_nums, final):
            objs.append((pnum, f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 {self.PAGE_W} {self.PAGE_H}] "
                               f"/Resources << /Font << /F1 3 0 R /F2 4 0 R /F3 5 0 R >> >> "
                               f"/Contents {cnum} 0 R >>"))
            objs.append((cnum, f"<< /Length {len(stream.encode('latin-1', errors='replace'))} >>\n"
                               f"stream\n{stream}\nendstream"))
        objs.append((info_num, f"<< /Title ({_escape(self.title)}) /Producer ({_escape(branding.PRODUCT_NAME)}) "
                               f"/Creator ({_escape(branding.PRODUCT_NAME)}) >>"))

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
            out += f"{offsets.get(i, 0):010d} 00000 n \n".encode()
        out += (f"trailer\n<< /Size {maxobj} /Root 1 0 R /Info {info_num} 0 R >>\n"
                f"startxref\n{xref_start}\n%%EOF\n").encode()
        return bytes(out)
