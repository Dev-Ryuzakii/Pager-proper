"""
Web-sourced decoy photos for locked image/video attachments — a more
convincing stand-in than the procedurally-drawn generator in decoy_image.py
("a real photo someone might send" vs. an obvious meme/receipt template),
pulled from free, license-safe stock sources instead of scraping arbitrary
sites (which would be a copyright and ToS problem for redistributed content).

Sources, tried in order, each with a short timeout:
  1. Openverse (api.openverse.org) — keyless, CC-licensed/public-domain images.
     No signup needed; this is the only source active until a free API key is
     added for the ones below.
  2. Pexels (api.pexels.com) — free-signup key (PEXELS_API_KEY), stock photos
     explicitly licensed for this kind of reuse.
  3. Pixabay (pixabay.com/api) — free-signup key (PIXABAY_API_KEY), same deal.

Every candidate is screened with OpenCV's bundled Haar-cascade face detector
before being accepted — this is the actual enforcement of the same rule
decoy_image.py's generator follows by construction (it never draws people):
no web-sourced decoy may contain a real, identifiable face. A candidate with
a detected face is rejected and the next one is tried.

Video: none of the keyless/free-tier sources reliably serve raw, directly
downloadable video files (Openverse's video results mostly point at external
platforms like YouTube, which can't be scraped without violating their own
terms). So today this module only produces images — a locked video still
gets a still-photo decoy (same as before), just now sourced from here when
available instead of always falling back to the local generator. Pexels/
Pixabay both do offer real stock video search once a key exists; wiring that
in is a small follow-up once one is added, not a redesign.

If every source fails or times out (offline, blocked, no results, no faces
found in the tried candidates), this returns None and the caller falls back
to decoy_image.py's local generator — decoy generation itself must never
fail just because the network did.
"""

import hashlib
import io
import logging
import os
import random
from typing import Optional, Tuple

import httpx
from PIL import Image

logger = logging.getLogger(__name__)

REQUEST_TIMEOUT = 4.0
CANDIDATES_TO_TRY = 6
MAX_DIMENSION = 1600
# Some source CDNs (Flickr in particular, which backs a lot of Openverse
# results) 502 requests with no browser-like User-Agent at all.
_HEADERS = {"User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36"}

# Deliberately mundane object/scene queries — not portrait photography — so
# most results are already unlikely to contain people before the face
# detector even runs.
_QUERY_TERMS = [
    "coffee cup", "city street", "office desk", "mountain landscape",
    "food plate", "bookshelf", "parking lot", "sunset sky",
    "kitchen counter", "garden flowers", "laptop desk", "rainy window",
    "forest path", "beach shore", "old car", "bicycle street",
]

_face_cascade = None


def _get_face_cascade():
    global _face_cascade
    if _face_cascade is not None:
        return _face_cascade
    try:
        import cv2
        path = cv2.data.haarcascades + "haarcascade_frontalface_default.xml"
        cascade = cv2.CascadeClassifier(path)
        _face_cascade = cascade if not cascade.empty() else False
    except Exception as e:
        logger.warning(f"Face detector unavailable, web decoys disabled: {e}")
        _face_cascade = False
    return _face_cascade


def _contains_face(jpeg_bytes: bytes) -> bool:
    cascade = _get_face_cascade()
    if not cascade:
        # No detector available — refuse to trust an unscreened web image
        # rather than silently skip the safety check.
        return True
    try:
        import cv2
        import numpy as np
        arr = np.frombuffer(jpeg_bytes, dtype=np.uint8)
        img = cv2.imdecode(arr, cv2.IMREAD_GRAYSCALE)
        if img is None:
            return True
        faces = cascade.detectMultiScale(img, scaleFactor=1.1, minNeighbors=5, minSize=(40, 40))
        return len(faces) > 0
    except Exception as e:
        logger.warning(f"Face check failed, rejecting candidate: {e}")
        return True


def _rng(seed: Optional[str]) -> random.Random:
    if seed is None:
        return random.Random()
    return random.Random(int(hashlib.sha256(seed.encode()).hexdigest()[:16], 16))


def _recompress(raw: bytes, target_size: Optional[int]) -> bytes:
    img = Image.open(io.BytesIO(raw)).convert("RGB")
    img.thumbnail((MAX_DIMENSION, MAX_DIMENSION))
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
    return data


def _try_openverse(client: httpx.Client, term: str, rng: random.Random) -> list:
    """Returns a list of candidate image URLs, best-effort."""
    try:
        res = client.get(
            "https://api.openverse.org/v1/images/",
            params={"q": term, "license_type": "commercial,modification", "mature": "false", "page_size": 20},
            timeout=REQUEST_TIMEOUT,
        )
        if res.status_code != 200:
            return []
        results = res.json().get("results", [])
        urls = [r.get("url") for r in results if r.get("url")]
        rng.shuffle(urls)
        return urls
    except Exception as e:
        logger.info(f"Openverse decoy fetch failed: {e}")
        return []


def _try_pexels(client: httpx.Client, term: str, rng: random.Random) -> list:
    key = os.getenv("PEXELS_API_KEY")
    if not key:
        return []
    try:
        res = client.get(
            "https://api.pexels.com/v1/search",
            params={"query": term, "per_page": 20},
            headers={"Authorization": key},
            timeout=REQUEST_TIMEOUT,
        )
        if res.status_code != 200:
            return []
        photos = res.json().get("photos", [])
        urls = [p.get("src", {}).get("large") for p in photos if p.get("src", {}).get("large")]
        rng.shuffle(urls)
        return urls
    except Exception as e:
        logger.info(f"Pexels decoy fetch failed: {e}")
        return []


def _try_pixabay(client: httpx.Client, term: str, rng: random.Random) -> list:
    key = os.getenv("PIXABAY_API_KEY")
    if not key:
        return []
    try:
        res = client.get(
            "https://pixabay.com/api/",
            params={"key": key, "q": term, "image_type": "photo", "safesearch": "true", "per_page": 20},
            timeout=REQUEST_TIMEOUT,
        )
        if res.status_code != 200:
            return []
        hits = res.json().get("hits", [])
        urls = [h.get("largeImageURL") for h in hits if h.get("largeImageURL")]
        rng.shuffle(urls)
        return urls
    except Exception as e:
        logger.info(f"Pixabay decoy fetch failed: {e}")
        return []


def fetch_web_decoy_image(seed: Optional[str] = None, target_size: Optional[int] = None) -> Optional[Tuple[bytes, str]]:
    """Returns (jpeg_bytes, source_name) or None if nothing usable was found —
    callers must fall back to decoy_image.py's local generator on None."""
    if _get_face_cascade() is False:
        return None

    rng = _rng(seed)
    term = rng.choice(_QUERY_TERMS)

    try:
        with httpx.Client(follow_redirects=True, headers=_HEADERS) as client:
            candidate_urls = (
                _try_openverse(client, term, rng)
                + _try_pexels(client, term, rng)
                + _try_pixabay(client, term, rng)
            )
            for url in candidate_urls[:CANDIDATES_TO_TRY]:
                try:
                    resp = client.get(url, timeout=REQUEST_TIMEOUT)
                    if resp.status_code != 200 or not resp.content:
                        continue
                    if _contains_face(resp.content):
                        continue
                    jpeg = _recompress(resp.content, target_size)
                    return jpeg, url.split("/")[2] if "//" in url else "web"
                except Exception as e:
                    logger.info(f"Web decoy candidate failed: {e}")
                    continue
    except Exception as e:
        logger.info(f"Web decoy fetch aborted: {e}")

    return None
