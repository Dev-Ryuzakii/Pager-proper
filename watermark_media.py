"""
Leak-detection watermarks for media (images, PDFs, documents).

Adds up to 5 watermarks per file so leaked content can be traced to the recipient.
No new endpoints: applied inside existing upload flows.
"""
from __future__ import annotations

import io
import logging
from typing import Optional

logger = logging.getLogger(__name__)

# Max number of watermark instances per media (e.g. 5 positions or 5 pages)
WATERMARKS_PER_MEDIA = 5

# Payload format: short code to identify recipient + media (for leak lookup)
def _payload(recipient_id: int, media_id: str) -> str:
    short_id = (media_id.replace("-", "")[:8]) if media_id else ""
    return f"R{recipient_id}#{short_id}"


def _watermark_image(data: bytes, content_type: str, payload_text: str) -> Optional[bytes]:
    """Add up to WATERMARKS_PER_MEDIA text watermarks to image bytes. Returns None on failure."""
    try:
        from PIL import Image
    except ImportError:
        logger.warning("Pillow not installed; image watermarking skipped")
        return None

    try:
        img = Image.open(io.BytesIO(data)).convert("RGBA")
        w, h = img.size
    except Exception as e:
        logger.debug("Image open failed (not an image?): %s", e)
        return None

    try:
        from PIL import ImageDraw, ImageFont
    except ImportError:
        return None

    # Positions for up to 5 watermarks (corners + center)
    positions = [
        (w // 10, h // 10),
        (w - w // 10, h // 10),
        (w // 2, h // 2),
        (w // 10, h - h // 10),
        (w - w // 10, h - h // 10),
    ][:WATERMARKS_PER_MEDIA]

    overlay = Image.new("RGBA", img.size, (255, 255, 255, 0))
    draw = ImageDraw.Draw(overlay)
    font_size = max(8, min(w, h) // 60)
    try:
        font = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", font_size)
    except (OSError, AttributeError):
        try:
            font = ImageFont.truetype("/System/Library/Fonts/Helvetica.ttc", font_size)
        except (OSError, AttributeError):
            font = ImageFont.load_default()

    for x, y in positions:
        draw.text((x, y), payload_text, fill=(128, 128, 128, 80), font=font)

    try:
        out = Image.alpha_composite(img, overlay)
        buf = io.BytesIO()
        fmt = "PNG" if content_type in ("image/png", "image/x-png") else "JPEG"
        if fmt == "JPEG":
            out = out.convert("RGB")
        out.save(buf, format=fmt, quality=92)
        return buf.getvalue()
    except Exception as e:
        logger.warning("Image watermark failed: %s", e)
        return None


def _watermark_pdf(data: bytes, payload_text: str) -> Optional[bytes]:
    """Add watermark to first WATERMARKS_PER_MEDIA pages of PDF. Returns None on failure."""
    try:
        from pypdf import PdfReader, PdfWriter, Transformation
    except ImportError:
        logger.warning("pypdf not installed; PDF watermarking skipped")
        return None

    try:
        from PIL import Image
    except ImportError:
        logger.warning("Pillow not installed; PDF watermarking skipped")
        return None

    try:
        reader = PdfReader(io.BytesIO(data))
        n_pages = len(reader.pages)
        if n_pages == 0:
            return None
    except Exception as e:
        logger.debug("PDF read failed: %s", e)
        return None

    try:
        # Create a small watermark image (text), then as single-page PDF
        img = Image.new("RGBA", (200, 40), (255, 255, 255, 0))
        try:
            from PIL import ImageDraw, ImageFont
            draw = ImageDraw.Draw(img)
            font = ImageFont.load_default()
            draw.text((5, 5), payload_text, fill=(180, 180, 180, 120), font=font)
        except Exception:
            pass
        wm_buf = io.BytesIO()
        img.convert("RGB").save(wm_buf, "PDF")
        wm_buf.seek(0)
        wm_reader = PdfReader(wm_buf)
        wm_page = wm_reader.pages[0]

        writer = PdfWriter()
        pages_to_mark = min(WATERMARKS_PER_MEDIA, n_pages)
        for i in range(n_pages):
            page = reader.pages[i]
            if i < pages_to_mark:
                page.merge_transformed_page(wm_page, Transformation().scale(0.3), over=True)
            writer.add_page(page)

        out = io.BytesIO()
        writer.write(out)
        return out.getvalue()
    except Exception as e:
        logger.warning("PDF watermark failed: %s", e)
        return None


def apply_watermark(
    data: bytes,
    content_type: str,
    filename: str,
    recipient_id: int,
    media_id: str,
) -> bytes:
    """
    Apply up to WATERMARKS_PER_MEDIA leak-detection watermarks to media bytes.
    Supported: images (JPEG, PNG, etc.) and PDF. Others returned unchanged.
    """
    if not data:
        return data
    payload_text = _payload(recipient_id, media_id)
    ct = (content_type or "").lower()
    fn = (filename or "").lower()

    # Images
    if ct.startswith("image/") or fn.endswith((".jpg", ".jpeg", ".png", ".gif", ".webp", ".bmp")):
        out = _watermark_image(data, ct, payload_text)
        if out is not None:
            return out
    # PDF
    if ct == "application/pdf" or fn.endswith(".pdf"):
        out = _watermark_pdf(data, payload_text)
        if out is not None:
            return out

    return data
