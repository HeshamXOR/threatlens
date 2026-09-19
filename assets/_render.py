"""Render the threatlens logo/icon to PNG with Pillow (no cairo needed).

Throwaway helper — draws the same mark as logo.svg / icon.svg at high
resolution and downsamples for crisp anti-aliasing.
"""
from PIL import Image, ImageDraw, ImageFont

BG = (12, 12, 13, 255)
GLASS = (20, 20, 22, 255)
RING = (250, 95, 2, 255)
RING_HI = (255, 143, 77, 255)
CROSS = (250, 95, 2, 235)
THREAT = (255, 45, 85, 255)
INK = (250, 250, 250, 255)
DIM = (154, 154, 163, 255)
ACCENT = (250, 95, 2, 255)

SS = 4  # supersample factor


def _font(size, bold=True):
    names = (["segoeuib.ttf", "arialbd.ttf"] if bold else ["segoeui.ttf", "arial.ttf"])
    for n in names:
        try:
            return ImageFont.truetype(n, size)
        except OSError:
            continue
    return ImageFont.load_default()


def draw_lens(d, cx, cy, r, ring_w, cross_w):
    # lens ring
    d.ellipse([cx - r, cy - r, cx + r, cy + r], fill=GLASS, outline=RING, width=ring_w)
    # handle
    off = r * 0.79
    d.line([cx + off, cy + off, cx + off + r * 0.62, cy + off + r * 0.62],
           fill=RING, width=int(ring_w * 1.7))
    d.ellipse([cx - r, cy - r, cx + r, cy + r], outline=RING, width=ring_w)  # redraw ring over handle
    # crosshair
    inner, outer = r * 0.36, r
    for (x1, y1, x2, y2) in [
        (cx - outer, cy, cx - inner, cy), (cx + inner, cy, cx + outer, cy),
        (cx, cy - outer, cx, cy - inner), (cx, cy + inner, cx, cy + outer),
    ]:
        d.line([x1, y1, x2, y2], fill=CROSS, width=cross_w)
    # threat diamond (rotated square) + centre dot
    dr = r * 0.24
    d.polygon([(cx, cy - dr), (cx + dr, cy), (cx, cy + dr), (cx - dr, cy)],
              outline=THREAT, width=cross_w)
    d.ellipse([cx - cross_w, cy - cross_w, cx + cross_w, cy + cross_w], fill=THREAT)


def render_logo(path):
    W, H = 520 * SS, 130 * SS
    img = Image.new("RGBA", (W, H), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    draw_lens(d, 65 * SS, 65 * SS, 38 * SS, 7 * SS, max(2, round(2.5 * SS)))
    f1 = _font(46 * SS, bold=True)
    f2 = _font(15 * SS, bold=False)
    x = 132 * SS
    y = 52 * SS
    d.text((x, y), "threat", font=f1, fill=INK)
    w = d.textlength("threat", font=f1)
    d.text((x + w, y), "lens", font=f1, fill=ACCENT)
    d.text((x + 2 * SS, 82 * SS), "malicious URL & executable detection", font=f2, fill=DIM)
    img.resize((520, 130), Image.LANCZOS).save(path)


def render_icon(path, size=256):
    S = size * SS
    img = Image.new("RGBA", (S, S), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    rad = int(S * 0.22)
    d.rounded_rectangle([0, 0, S, S], radius=rad, fill=BG)
    draw_lens(d, int(S * 0.44), int(S * 0.42), int(S * 0.27), max(2, int(S * 0.055)), max(2, int(S * 0.02)))
    img.resize((size, size), Image.LANCZOS).save(path)


if __name__ == "__main__":
    render_logo("assets/logo.png")
    render_icon("assets/icon.png")
    print("rendered logo.png + icon.png")
