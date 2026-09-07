"""
Decoy image generator.

Produces an image that reads as something a real person would actually send —
a screenshot of a generic chat, a meme with a caption, a photographed
receipt, a whiteboard photo — not an obvious placeholder. Deliberately never
generates faces or people: nothing here should ever read as a fabricated
photo of a real individual.

Everything derives from a seed (pass the media_id): the same file must
always produce the same decoy — one that changes between openings is a tell.
"""

import hashlib
import io
import random
from datetime import datetime, timedelta
from typing import Optional, Tuple

from PIL import Image, ImageDraw, ImageFont

IMAGE_DECOY_KINDS = ("meme", "screenshot", "receipt", "whiteboard")

_CAPTIONS_TOP = ["WHEN YOU FINALLY", "ME AFTER", "NOBODY:", "THAT MOMENT WHEN", "EVERYONE ELSE:"]
_CAPTIONS_BOTTOM = [
    "FIX THE BUG", "THE MEETING GOT MOVED AGAIN", "ABSOLUTELY NOTHING",
    "IT WORKS ON MY MACHINE", "MONDAY MORNING", "FRIDAY AT 5PM",
]

_APP_NAMES = ["Notes", "Messages", "Reminders", "Weather", "Calendar"]
_CHAT_LINES = [
    "ok sounds good", "see you then", "thanks!", "np", "will do", "got it",
    "sure thing", "on my way", "let me check", "sounds fine to me",
]

_STORES = ["Lagoon Mart", "Northgate Store", "Riverside Grocers", "Crestview Pharmacy", "City Center Shop"]
_ITEMS = [
    ("Bread", 850), ("Milk 1L", 1200), ("Eggs (dozen)", 1800), ("Rice 5kg", 6500),
    ("Cooking oil 1L", 3200), ("Sugar 1kg", 1100), ("Soap", 650), ("Toothpaste", 900),
]

_WB_LABELS = ["Q3 Goals", "Action Items", "Timeline", "Budget", "Next Steps", "Ideas"]


def _rng(seed: Optional[str]) -> random.Random:
    if seed is None:
        return random.Random()
    return random.Random(int(hashlib.sha256(seed.encode()).hexdigest()[:16], 16))


def _font(size: int):
    for path in (
        "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
        "/System/Library/Fonts/Helvetica.ttc",
        "/System/Library/Fonts/SFNSDisplay-Bold.otf",
        "C:\\Windows\\Fonts\\arialbd.ttf",
    ):
        try:
            return ImageFont.truetype(path, size)
        except (OSError, AttributeError, TypeError):
            continue
    return ImageFont.load_default()


def _draw_meme(rng: random.Random) -> Image.Image:
    w, h = 720, 720
    bg = rng.choice([(30, 30, 40), (20, 60, 90), (80, 30, 60), (40, 70, 40)])
    img = Image.new("RGB", (w, h), bg)
    draw = ImageDraw.Draw(img)
    font = _font(48)
    draw.text((w / 2, 60), rng.choice(_CAPTIONS_TOP), fill="white", font=font, anchor="mm", stroke_width=3, stroke_fill="black")
    draw.text((w / 2, h - 60), rng.choice(_CAPTIONS_BOTTOM), fill="white", font=font, anchor="mm", stroke_width=3, stroke_fill="black")
    accent = tuple(min(255, c + 50) for c in bg)
    for _ in range(4):
        x0, y0 = rng.randint(0, w), rng.randint(150, h - 150)
        size = rng.randint(60, 180)
        draw.ellipse([x0, y0, x0 + size, y0 + size], outline=accent, width=4)
    return img


def _draw_screenshot(rng: random.Random) -> Image.Image:
    w, h = 720, 1280
    img = Image.new("RGB", (w, h), (245, 245, 247))
    draw = ImageDraw.Draw(img)
    draw.rectangle([0, 0, w, 90], fill=(20, 20, 22))
    draw.text((w / 2, 45), rng.choice(_APP_NAMES), fill="white", font=_font(32), anchor="mm")
    y = 140
    for _ in range(rng.randint(6, 9)):
        mine = rng.random() > 0.5
        text = rng.choice(_CHAT_LINES)
        bw = 80 + len(text) * 12
        bh = 60
        x = w - 40 - bw if mine else 40
        color = (0, 122, 255) if mine else (230, 230, 232)
        text_color = "white" if mine else "black"
        draw.rounded_rectangle([x, y, x + bw, y + bh], radius=18, fill=color)
        draw.text((x + bw / 2, y + bh / 2), text, fill=text_color, font=_font(22), anchor="mm")
        y += bh + 24
    return img


def _draw_receipt(rng: random.Random) -> Image.Image:
    w = 480
    items = rng.sample(_ITEMS, k=rng.randint(4, 6))
    h = 260 + len(items) * 36
    img = Image.new("RGB", (w, h), (250, 248, 240))
    draw = ImageDraw.Draw(img)
    font_h = _font(28)
    font_b = _font(20)
    draw.text((w / 2, 40), rng.choice(_STORES), fill="black", font=font_h, anchor="mm")
    date = (datetime.now() - timedelta(days=rng.randint(0, 20))).strftime("%d/%m/%Y %H:%M")
    draw.text((w / 2, 75), date, fill=(80, 80, 80), font=_font(16), anchor="mm")
    draw.line([(30, 100), (w - 30, 100)], fill=(180, 180, 180), width=2)
    y = 130
    total = 0
    for name, price in items:
        qty = rng.randint(1, 3)
        line_total = price * qty
        total += line_total
        draw.text((30, y), f"{name} x{qty}", fill="black", font=font_b, anchor="lm")
        draw.text((w - 30, y), f"NGN {line_total:,}", fill="black", font=font_b, anchor="rm")
        y += 36
    draw.line([(30, y + 10), (w - 30, y + 10)], fill=(180, 180, 180), width=2)
    draw.text((30, y + 40), "TOTAL", fill="black", font=font_h, anchor="lm")
    draw.text((w - 30, y + 40), f"NGN {total:,}", fill="black", font=font_h, anchor="rm")
    return img


def _draw_whiteboard(rng: random.Random) -> Image.Image:
    w, h = 960, 720
    img = Image.new("RGB", (w, h), (250, 250, 250))
    draw = ImageDraw.Draw(img)
    ink_colors = [(30, 30, 160), (160, 30, 30), (20, 120, 60)]
    labels = rng.sample(_WB_LABELS, k=min(4, len(_WB_LABELS)))
    for i, label in enumerate(labels):
        x = 60 + (i % 2) * 460
        y = 60 + (i // 2) * 300
        color = rng.choice(ink_colors)
        draw.rectangle([x, y, x + 380, y + 220], outline=color, width=4)
        draw.text((x + 20, y + 20), label, fill=color, font=_font(30))
        for _ in range(rng.randint(2, 4)):
            lx0, ly0 = x + rng.randint(20, 300), y + rng.randint(70, 190)
            lx1, ly1 = lx0 + rng.randint(30, 120), ly0 + rng.randint(-20, 20)
            draw.line([(lx0, ly0), (lx1, ly1)], fill=color, width=3)
    return img


_GENERATORS = {
    "meme": _draw_meme,
    "screenshot": _draw_screenshot,
    "receipt": _draw_receipt,
    "whiteboard": _draw_whiteboard,
}


def generate_decoy_image(
    seed: Optional[str] = None,
    target_size: Optional[int] = None,
    kind: Optional[str] = None,
) -> Tuple[bytes, str]:
    """
    Returns (jpeg_bytes, kind_used). `seed` (the media_id) makes the result
    reproducible. `target_size`, when given, nudges JPEG quality so the
    decoy's byte size doesn't give away that it isn't the real file.
    """
    rng = _rng(seed)
    chosen_kind = kind if kind in _GENERATORS else rng.choice(list(_GENERATORS.keys()))
    img = _GENERATORS[chosen_kind](rng)

    quality = 85
    buf = io.BytesIO()
    img.save(buf, format="JPEG", quality=quality)
    data = buf.getvalue()

    if target_size and target_size > 0:
        for _ in range(4):
            if abs(len(data) - target_size) < target_size * 0.15:
                break
            if len(data) < target_size and quality < 95:
                quality = min(95, quality + 5)
            elif len(data) > target_size and quality > 40:
                quality = max(40, quality - 10)
            else:
                break
            buf = io.BytesIO()
            img.save(buf, format="JPEG", quality=quality)
            data = buf.getvalue()

    return data, chosen_kind
