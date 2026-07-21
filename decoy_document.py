"""
Decoy document generator.

Produces a document that reads as a real one: an invoice whose line items add up
to its stated total, a delivery note whose dates run in order, meeting minutes
whose attendees are named consistently throughout. Lorem ipsum or Markov noise
fails the moment someone actually opens the file, which is exactly when a decoy
has to hold.

Output is PDF built directly — PDF is a text format, so no reportlab/fpdf
dependency is needed.

Everything derives from a seed (pass the media_id): the same file must always
produce the same decoy. A document that changes between openings is a tell.
"""

import hashlib
import random
from datetime import datetime, timedelta
from typing import List, Optional, Tuple

_FIRST = ["Adebayo", "Chinelo", "Emeka", "Fatima", "Ibrahim", "Ngozi", "Olumide",
          "Sade", "Tunde", "Yemi", "Amaka", "Bello", "Chidi", "Halima", "Kunle"]
_LAST = ["Adeyemi", "Balogun", "Chukwu", "Danjuma", "Eze", "Ibrahim", "Lawal",
         "Musa", "Nwachukwu", "Okafor", "Okonkwo", "Salami", "Uche", "Yusuf"]

_COMPANIES = ["Lagoon Trading Ltd", "Northgate Supplies", "Riverside Logistics",
              "Meridian Services Ltd", "Crestview Enterprises", "Harbour Point Co",
              "Silverline Distributors", "Greenfield Holdings"]

_CITIES = ["Lagos", "Abuja", "Ibadan", "Port Harcourt", "Kano", "Enugu", "Benin City"]

_GOODS = [
    ("Office paper A4, 80gsm", "ream", 3200),
    ("Printer toner cartridge", "unit", 28500),
    ("Desk lamp, LED", "unit", 9500),
    ("Filing cabinet, 3-drawer", "unit", 62000),
    ("Whiteboard markers", "pack", 2800),
    ("Ethernet cable, 5m", "unit", 4200),
    ("Bottled water, 75cl", "carton", 2400),
    ("Cleaning supplies", "set", 15600),
    ("Safety helmets", "unit", 7800),
    ("Extension cord, 4-way", "unit", 6500),
]

_AGENDA = [
    "Review of outstanding action items",
    "Quarterly budget position",
    "Staffing and shift coverage",
    "Supplier contract renewal",
    "Health and safety walkthrough",
    "Vehicle maintenance schedule",
    "Warehouse stock reconciliation",
    "Customer complaints summary",
]


def _rng(seed: Optional[str]) -> random.Random:
    if seed is None:
        return random.Random()
    return random.Random(int(hashlib.sha256(seed.encode()).hexdigest()[:16], 16))


def _person(rng: random.Random) -> str:
    return f"{rng.choice(_FIRST)} {rng.choice(_LAST)}"


def _people(rng: random.Random, count: int) -> List[str]:
    """Distinct names — repeated first or last names read as generated."""
    firsts = rng.sample(_FIRST, count)
    lasts = rng.sample(_LAST, count)
    return [f"{f} {l}" for f, l in zip(firsts, lasts)]


def _money(amount: int) -> str:
    return f"{amount:,}"


# ── Document bodies ───────────────────────────────────────────────────────────

def _invoice(rng: random.Random) -> Tuple[str, List[str]]:
    company = rng.choice(_COMPANIES)
    issued = datetime.now() - timedelta(days=rng.randint(3, 40))
    due = issued + timedelta(days=30)
    number = f"INV-{issued.year}-{rng.randint(1000, 9999)}"

    items = rng.sample(_GOODS, rng.randint(3, 5))
    lines, subtotal = [], 0
    for name, unit, price in items:
        qty = rng.randint(2, 24)
        total = qty * price
        subtotal += total
        lines.append(f"  {name:<34}{qty:>4} {unit:<8}{_money(price):>10}{_money(total):>12}")

    vat = round(subtotal * 0.075)
    grand = subtotal + vat

    body = [
        company,
        f"{rng.randint(4, 180)} {rng.choice(['Marina', 'Awolowo', 'Broad', 'Herbert Macaulay'])} Road, {rng.choice(_CITIES)}",
        "",
        f"INVOICE {number}",
        f"Date issued: {issued:%d %B %Y}      Payment due: {due:%d %B %Y}",
        "",
        f"Bill to: {_person(rng)}, {rng.choice(_COMPANIES)}",
        "",
        f"  {'Description':<34}{'Qty':>4} {'Unit':<8}{'Rate':>10}{'Amount':>12}",
        "  " + "-" * 66,
    ]
    body += lines
    body += [
        "  " + "-" * 66,
        f"  {'Subtotal':<56}{_money(subtotal):>12}",
        f"  {'VAT at 7.5%':<56}{_money(vat):>12}",
        f"  {'Total due (NGN)':<56}{_money(grand):>12}",
        "",
        "Payment by bank transfer within 30 days of the date above.",
        f"Queries: accounts@{company.split()[0].lower()}.example",
    ]
    return f"Invoice {number}", body


def _delivery_note(rng: random.Random) -> Tuple[str, List[str]]:
    company = rng.choice(_COMPANIES)
    dispatched = datetime.now() - timedelta(days=rng.randint(1, 21))
    delivered = dispatched + timedelta(days=rng.randint(1, 4))
    number = f"DN-{rng.randint(10000, 99999)}"
    driver = _person(rng)
    receiver = _person(rng)

    items = rng.sample(_GOODS, rng.randint(3, 6))
    lines = []
    for name, unit, _ in items:
        qty = rng.randint(1, 40)
        lines.append(f"  {name:<40}{qty:>5} {unit}")

    return f"Delivery Note {number}", [
        company,
        f"Depot: {rng.choice(_CITIES)}",
        "",
        f"DELIVERY NOTE {number}",
        f"Dispatched: {dispatched:%d %B %Y}     Delivered: {delivered:%d %B %Y}",
        f"Driver: {driver}     Vehicle: {rng.choice(['LAG', 'ABJ', 'KAN'])}-{rng.randint(100, 999)}-{rng.choice('ABCDEFGH')}{rng.choice('ABCDEFGH')}",
        "",
        f"  {'Item':<40}{'Qty':>5} Unit",
        "  " + "-" * 55,
        *lines,
        "  " + "-" * 55,
        "",
        f"Received in good condition by: {receiver}",
        "Signature: ______________________    Date: ______________",
        "",
        "Discrepancies must be reported within 48 hours of delivery.",
    ]


def _minutes(rng: random.Random) -> Tuple[str, List[str]]:
    when = datetime.now() - timedelta(days=rng.randint(2, 30))
    attendees = _people(rng, rng.randint(4, 6))
    chair = attendees[0]
    secretary = attendees[1]
    agenda = rng.sample(_AGENDA, rng.randint(3, 5))

    body = [
        rng.choice(_COMPANIES),
        "",
        "MINUTES OF OPERATIONS MEETING",
        f"Held {when:%d %B %Y} at {rng.randint(9, 16)}:{rng.choice(['00', '15', '30'])}, {rng.choice(_CITIES)} office",
        "",
        f"Chair: {chair}",
        f"Minutes: {secretary}",
        "Present: " + ", ".join(attendees),
        "",
    ]
    for i, item in enumerate(agenda, 1):
        owner = rng.choice(attendees)
        body += [
            f"{i}. {item}",
            f"   {owner} presented the current position. The meeting noted progress",
            f"   since the last review and agreed no further escalation is required",
            f"   at this stage.",
            f"   Action: {owner} to circulate an update by {(when + timedelta(days=rng.randint(5, 20))):%d %B}.",
            "",
        ]
    body += [
        f"Next meeting: {(when + timedelta(days=rng.choice([7, 14, 28]))):%d %B %Y}.",
        f"There being no other business, the chair closed the meeting at "
        f"{rng.randint(10, 18)}:{rng.choice(['05', '20', '40', '55'])}.",
    ]
    return "Meeting Minutes", body


def _memo(rng: random.Random) -> Tuple[str, List[str]]:
    when = datetime.now() - timedelta(days=rng.randint(1, 25))
    author = _person(rng)
    subject = rng.choice([
        "Revised office opening hours",
        "Vehicle booking procedure",
        "Stock count scheduling",
        "Updated visitor sign-in process",
        "Annual leave requests",
    ])
    return "Internal Memo", [
        rng.choice(_COMPANIES),
        "",
        "INTERNAL MEMORANDUM",
        "",
        f"To:      All staff, {rng.choice(_CITIES)} office",
        f"From:    {author}, Operations",
        f"Date:    {when:%d %B %Y}",
        f"Subject: {subject}",
        "",
        "Following the review completed last month, the arrangements set out",
        "below take effect from the start of next week. They replace the",
        "previous guidance issued at the beginning of the year.",
        "",
        f"1. Requests should be submitted at least {rng.randint(3, 10)} working days in advance.",
        "2. Line managers will confirm approval in writing.",
        "3. Where cover cannot be arranged, the request may be deferred.",
        "",
        "Department heads should ensure their teams are briefed. Questions may",
        f"be directed to {author.split()[0]} in the first instance.",
        "",
        f"{author}",
        "Operations",
    ]


_GENERATORS = [_invoice, _delivery_note, _minutes, _memo]


# ── PDF assembly ──────────────────────────────────────────────────────────────

def _escape(s: str) -> str:
    return s.replace("\\", r"\\").replace("(", r"\(").replace(")", r"\)")


def _build_pdf(lines: List[str], title: str, pad_to: Optional[int] = None) -> bytes:
    """A single-page PDF in Courier, assembled by hand. No third-party library."""
    drawn = "\n".join(f"({_escape(l)}) Tj 0 -14 Td" for l in lines[:52])
    content = f"BT /F1 9 Tf 48 792 Td\n{drawn}\nET".encode("latin-1", "replace")

    objs = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] "
        b"/Resources << /Font << /F1 5 0 R >> >> /Contents 4 0 R >>",
        b"<< /Length " + str(len(content)).encode() + b" >>\nstream\n" + content + b"\nendstream",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Courier >>",
        b"<< /Title (" + _escape(title).encode("latin-1", "replace") + b") >>",
    ]

    out = bytearray(b"%PDF-1.4\n")
    offsets = []
    for i, obj in enumerate(objs, 1):
        offsets.append(len(out))
        out += str(i).encode() + b" 0 obj\n" + obj + b"\nendobj\n"

    xref_at = len(out)
    out += b"xref\n0 " + str(len(objs) + 1).encode() + b"\n0000000000 65535 f \n"
    for off in offsets:
        out += f"{off:010d} 00000 n \n".encode()
    out += (b"trailer\n<< /Size " + str(len(objs) + 1).encode() +
            b" /Root 1 0 R /Info 6 0 R >>\nstartxref\n" +
            str(xref_at).encode() + b"\n%%EOF\n")

    # Pad towards the original's size: a 3 KB decoy for a 900 KB document is
    # obvious in any file listing. Comment bytes after %%EOF are ignored by
    # every reader.
    if pad_to and len(out) < pad_to:
        filler = pad_to - len(out)
        if filler > 2:
            out += b"%" + b"0" * (filler - 2) + b"\n"

    return bytes(out)


def generate_decoy_document(
    seed: Optional[str] = None,
    target_size: Optional[int] = None,
    kind: Optional[str] = None,
) -> Tuple[bytes, str]:
    """
    Build a decoy PDF.

    `seed` — pass the media_id so the same file always decoys identically.
    `target_size` — the real file's size in bytes; the decoy is padded towards it.
    `kind` — force one of invoice/delivery/minutes/memo, otherwise chosen by seed.

    Returns (pdf_bytes, suggested_filename).
    """
    rng = _rng(seed)
    by_name = {"invoice": _invoice, "delivery": _delivery_note,
               "minutes": _minutes, "memo": _memo}
    generator = by_name.get(kind or "", rng.choice(_GENERATORS))
    title, lines = generator(rng)

    pdf = _build_pdf(lines, title, pad_to=target_size)
    filename = title.lower().replace(" ", "_") + ".pdf"
    return pdf, filename
