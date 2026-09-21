"""Report branding: product identity, brand palette and the logo mark.

The logo geometry mirrors the web application's shield mark (Frontend LOGO_SVG /
workbench.html) so the PDF report is visually consistent with the product. It is
emitted as vector PDF operators — no raster asset, no external dependency, and
no invented artwork. If a real logo asset is later supplied, only `logo_ops`
needs to change; the rest of the PDF system is untouched.
"""

PRODUCT_NAME = "Cybersecurity Analyst Platform"
REPORT_TITLE = "Investigation Report"

# Brand palette (matches the web light theme: accent #0e7490, slate neutrals).
BRAND = "#0e7490"      # primary brand teal
INK = "#0f172a"        # dark neutral (body text)
MUTED = "#64748b"      # secondary text
LIGHT = "#f1f5f9"      # light neutral (table header fill)
BORDER = "#cbd5e1"     # hairlines / table borders
PAPER = "#ffffff"

# Semantic severity scale — identical to the web design system.
SEVERITY = {
    "CRITICAL": "#ef4444",
    "HIGH": "#f97316",
    "MEDIUM": "#f59e0b",
    "LOW": "#22c55e",
    "INFO": "#3b82f6",
}
# Provenance accent colours (for the small provenance pills in tables).
PROVENANCE = {
    "OBSERVED": "#2563eb",
    "CALCULATED": "#16a34a",
    "EXTRACTED": "#16a34a",
    "EXTERNAL INTELLIGENCE": "#7c3aed",
    "INFERRED": "#7c3aed",
    "USER PROVIDED": "#d97706",
    "USER-PROVIDED": "#d97706",
    "UNAVAILABLE": "#94a3b8",
}


def _hex_to_rgb(h):
    h = (h or "#000000").lstrip("#")
    if len(h) == 3:
        h = "".join(c * 2 for c in h)
    r, g, b = int(h[0:2], 16), int(h[2:4], 16), int(h[4:6], 16)
    return r / 255.0, g / 255.0, b / 255.0


def rgb(h):
    """Return a PDF 'r g b' triplet string for a hex colour."""
    r, g, b = _hex_to_rgb(h)
    return f"{r:.3f} {g:.3f} {b:.3f}"


def logo_ops(x, y, size):
    """Vector operators drawing the shield logo mark.

    (x, y) is the BOTTOM-LEFT corner of the size x size box (PDF y-up space).
    """
    s = float(size)
    brand = rgb(BRAND)
    ops = []
    # Brand tile
    ops.append(f"{brand} rg {x:.2f} {y:.2f} {s:.2f} {s:.2f} re f")
    # White shield (hexagon-ish) centred in the tile
    def p(fx, fy):
        return f"{x + fx * s:.2f} {y + fy * s:.2f}"
    shield = [
        (0.50, 0.82), (0.80, 0.68), (0.80, 0.44),
        (0.50, 0.18), (0.20, 0.44), (0.20, 0.68),
    ]
    # Build the shield path explicitly (first point moveto, rest lineto, close, fill)
    d = f"{p(*shield[0])} m " + " ".join(f"{p(fx, fy)} l" for fx, fy in shield[1:]) + " h f"
    ops.append(f"1 1 1 rg {d}")
    # Check mark in brand colour
    ops.append(f"{brand} RG {max(1.0, s * 0.09):.2f} w "
               f"{p(0.36, 0.50)} m {p(0.46, 0.40)} l {p(0.66, 0.62)} l S")
    return ops
