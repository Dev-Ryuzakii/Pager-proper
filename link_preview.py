"""
Link preview — server-side URL unfurling.

Fetches the URL from THIS server, never the viewer's device, so opening a
shared link never reveals the viewer's IP/user-agent/timing to whatever
site is linked — the same reasoning WhatsApp/Signal use server-side
unfurling instead of a client-side fetch.

SSRF-hardened, because this endpoint fetches an arbitrary user-supplied URL
from the server's own network:
  - http(s) only, no other schemes (file://, gopher://, etc.)
  - hostname resolved and checked BEFORE connecting; rejects anything that
    resolves to a private/loopback/link-local/reserved address, which
    covers the VPS's own internal network and the cloud metadata endpoint
    (169.254.169.254)
  - redirects are followed manually (max 3 hops), re-validating the host
    at every hop — a same-origin-looking link can't 302 its way to an
    internal address after the first check passes
  - bounded timeout and response size; only text/html is parsed

Known residual limitation: the safety check and the actual connection are
two separate DNS lookups. An attacker controlling DNS with a very short TTL
could theoretically flip the answer between them ("DNS rebinding"). This
blocks the common case (a link that's simply internal/localhost/metadata)
but is not a complete defense against a determined, DNS-controlling
attacker — closing that fully would need IP-pinned connections with manual
TLS SNI handling, which is a larger change than this pass covers.
"""

import ipaddress
import logging
import socket
from html.parser import HTMLParser
from typing import Optional
from urllib.parse import urljoin, urlparse

import httpx

logger = logging.getLogger(__name__)

_MAX_BYTES = 512 * 1024  # enough for <head>, no reason to pull a whole page
_TIMEOUT = 6.0
_MAX_REDIRECTS = 3
_USER_AGENT = "Mozilla/5.0 (compatible; DilarionLinkPreview/1.0)"


class _MetaParser(HTMLParser):
    """Pulls <title> and og:*/twitter:* meta tags."""

    def __init__(self):
        super().__init__()
        self.title: Optional[str] = None
        self.tags: dict = {}
        self._in_title = False

    def handle_starttag(self, tag, attrs):
        if tag == "title":
            self._in_title = True
        elif tag == "meta":
            d = dict(attrs)
            prop = d.get("property") or d.get("name")
            content = d.get("content")
            if prop and content and (prop.startswith("og:") or prop.startswith("twitter:")):
                self.tags.setdefault(prop, content)

    def handle_endtag(self, tag):
        if tag == "title":
            self._in_title = False

    def handle_data(self, data):
        if self._in_title and self.title is None:
            self.title = data.strip()


def _is_safe_host(hostname: str) -> bool:
    """False for anything resolving to non-public address space."""
    try:
        infos = socket.getaddrinfo(hostname, None)
    except socket.gaierror:
        return False
    if not infos:
        return False
    for info in infos:
        addr = info[4][0]
        try:
            ip = ipaddress.ip_address(addr)
        except ValueError:
            continue
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved or ip.is_unspecified:
            return False
    return True


def _validate_url(url: str) -> Optional[str]:
    """Returns the URL if it's http(s) with a public host, else None."""
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        return None
    if not _is_safe_host(parsed.hostname):
        logger.warning(f"[link-preview] rejected non-public host: {parsed.hostname}")
        return None
    return url


async def fetch_link_preview(url: str) -> Optional[dict]:
    """
    Returns {"url", "title", "description", "image", "site_name"}, or None
    if the URL is unsafe, unreachable, not HTML, or has no usable metadata.
    """
    current = _validate_url(url)
    if current is None:
        return None

    body = b""
    encoding = "utf-8"
    try:
        async with httpx.AsyncClient(follow_redirects=False, timeout=_TIMEOUT) as client:
            for _ in range(_MAX_REDIRECTS + 1):
                async with client.stream("GET", current, headers={"User-Agent": _USER_AGENT}) as resp:
                    if resp.status_code in (301, 302, 303, 307, 308):
                        location = resp.headers.get("location")
                        if not location:
                            return None
                        next_url = urljoin(current, location)
                        validated = _validate_url(next_url)
                        if validated is None:
                            logger.warning(f"[link-preview] redirect to unsafe URL rejected: {next_url}")
                            return None
                        current = validated
                        continue

                    if resp.status_code != 200:
                        return None
                    content_type = resp.headers.get("content-type", "")
                    if "text/html" not in content_type:
                        return None
                    encoding = resp.encoding or "utf-8"

                    async for chunk in resp.aiter_bytes():
                        body += chunk
                        if len(body) >= _MAX_BYTES:
                            break
                    break
            else:
                return None  # exhausted redirect budget
    except Exception as e:
        logger.warning(f"[link-preview] fetch failed: {type(e).__name__}: {e}")
        return None

    if not body:
        return None

    try:
        html = body.decode(encoding, errors="ignore")
    except (LookupError, TypeError):
        html = body.decode("utf-8", errors="ignore")

    parser = _MetaParser()
    try:
        parser.feed(html)
    except Exception:
        pass  # a malformed head is still worth returning whatever we got

    title = parser.tags.get("og:title") or parser.title
    description = parser.tags.get("og:description") or parser.tags.get("twitter:description")
    image = parser.tags.get("og:image") or parser.tags.get("twitter:image")
    site_name = parser.tags.get("og:site_name") or urlparse(current).hostname

    if not title and not description and not image:
        return None

    return {
        "url": current,
        "title": (title or "").strip()[:200] or None,
        "description": (description or "").strip()[:400] or None,
        "image": image,
        "site_name": site_name,
    }
