"""Browser pages for the end of the Google Calendar link flow.

Google redirects the user's browser to /calendar/google/callback, so these are
the pages a person actually sees. They follow the landing page's look
(dilarion-app/web): near-black background, red accent, Inter Tight headings.
Everything is inline so the page works with no other files.
"""
import html
from typing import Optional

WEB_APP_URL = "https://web-dilarion.eibstratoc.com"

_ICONS = {
    "success": '<path d="M5 12.5l4.2 4.2L19 7" />',
    "warning": '<path d="M12 8v5" /><path d="M12 16.5v.01" />',
    "error": '<path d="M8 8l8 8" /><path d="M16 8l-8 8" />',
}

_TONES = {
    # icon colour, glow colour, kicker text
    "success": ("#3ccf7a", "60,207,122", "Calendar connected"),
    "warning": ("#f4b13f", "244,177,63", "Not connected"),
    "error": ("#ff5a36", "255,90,54", "Something went wrong"),
}

_CSS = """
:root{--red:#d83428;--red-hot:#ff5a36;--bg:#070505;--card:#130e0e;--line:rgba(255,255,255,.08);
--line-2:rgba(255,255,255,.14);--text:#f6f1ef;--muted:#a59894;--faint:#6f6461;color-scheme:dark}
*{box-sizing:border-box}
html,body{height:100%}
body{margin:0;background:var(--bg);color:var(--text);font-family:'Inter',system-ui,-apple-system,'Segoe UI',sans-serif;
-webkit-font-smoothing:antialiased;display:flex;flex-direction:column;min-height:100vh;overflow-x:hidden}
.glow{position:fixed;inset:-20% -10% auto;height:70vh;pointer-events:none;
background:radial-gradient(60% 60% at 50% 0%,rgba(216,52,40,.28),transparent 70%)}
.grid{position:fixed;inset:0;pointer-events:none;opacity:.35;
background-image:linear-gradient(var(--line) 1px,transparent 1px),linear-gradient(90deg,var(--line) 1px,transparent 1px);
background-size:56px 56px;mask-image:radial-gradient(70% 55% at 50% 30%,#000 30%,transparent 80%)}
header{position:relative;height:72px;display:flex;align-items:center;padding:0 clamp(16px,4vw,48px)}
.brand{display:flex;align-items:center;gap:10px;font-family:'Inter Tight',sans-serif;font-weight:700;font-size:18px;
letter-spacing:-.02em;color:var(--text);text-decoration:none}
.mark{width:30px;height:30px;border-radius:9px;display:grid;place-items:center;background:var(--red);color:#fff;
font-size:15px;box-shadow:0 8px 22px -8px rgba(216,52,40,.9),inset 0 1px 0 rgba(255,255,255,.25)}
main{position:relative;flex:1;display:grid;place-items:center;padding:24px 16px 64px}
.card{width:100%;max-width:480px;background:linear-gradient(180deg,rgba(255,255,255,.04),rgba(255,255,255,.01)),var(--card);
border:1px solid var(--line-2);border-radius:28px;padding:40px 32px 32px;text-align:center;
box-shadow:0 40px 80px -40px rgba(0,0,0,.8)}
.badge{width:72px;height:72px;margin:0 auto 22px;border-radius:22px;display:grid;place-items:center;
background:rgba(var(--tone-rgb),.12);border:1px solid rgba(var(--tone-rgb),.35);
box-shadow:0 16px 40px -14px rgba(var(--tone-rgb),.7)}
.badge svg{width:34px;height:34px;stroke:var(--tone);stroke-width:2.4;fill:none;stroke-linecap:round;stroke-linejoin:round}
.kicker{font-family:'JetBrains Mono',ui-monospace,monospace;font-size:11px;letter-spacing:.12em;text-transform:uppercase;color:var(--tone)}
h1{font-family:'Inter Tight',sans-serif;font-size:clamp(26px,5vw,32px);letter-spacing:-.025em;line-height:1.15;margin:10px 0 12px}
p{color:var(--muted);font-size:15px;line-height:1.6;margin:0 auto;max-width:380px}
.account{display:inline-flex;align-items:center;gap:10px;margin:22px auto 0;padding:10px 16px;border-radius:999px;
background:rgba(255,255,255,.05);border:1px solid var(--line-2);font-size:14px;max-width:100%}
.account span{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.dot{width:8px;height:8px;border-radius:50%;background:var(--tone);flex:none;box-shadow:0 0 0 4px rgba(var(--tone-rgb),.15)}
.detail{margin-top:18px;font-family:'JetBrains Mono',ui-monospace,monospace;font-size:12px;color:var(--faint);word-break:break-word}
.actions{display:flex;flex-direction:column;gap:10px;margin-top:28px}
.button{border:0;border-radius:999px;padding:14px 22px;font:600 15px 'Inter',system-ui,sans-serif;cursor:pointer;
text-decoration:none;display:inline-flex;align-items:center;justify-content:center;gap:10px;transition:transform .25s,background .25s}
.button:hover{transform:translateY(-1px)}
.primary{background:var(--red);color:#fff;box-shadow:0 10px 30px -10px rgba(216,52,40,.8),inset 0 1px 0 rgba(255,255,255,.25)}
.primary:hover{background:#e8402f}
.glass{background:rgba(255,255,255,.06);color:var(--text);border:1px solid var(--line-2)}
.glass:hover{background:rgba(255,255,255,.11)}
.hint{margin-top:16px;font-size:13px;color:var(--faint)}
footer{position:relative;text-align:center;padding:0 16px 28px;font-size:12px;color:var(--faint)}
footer a{color:var(--muted)}
@media (max-width:480px){.card{padding:32px 20px 24px;border-radius:24px}}
"""


def calendar_page(
    tone: str,
    title: str,
    message: str,
    *,
    account: Optional[str] = None,
    detail: Optional[str] = None,
) -> str:
    """A full HTML page. tone is "success", "warning" or "error". All text is
    escaped here, so callers can pass values that came from the query string."""
    colour, rgb, kicker = _TONES.get(tone, _TONES["error"])
    icon = _ICONS.get(tone, _ICONS["error"])
    esc = html.escape
    account_html = (
        f'<div class="account"><i class="dot"></i><span>{esc(account)}</span></div>' if account else ""
    )
    detail_html = f'<div class="detail">{esc(detail)}</div>' if detail else ""
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="theme-color" content="#070505">
<meta name="robots" content="noindex">
<title>{esc(title)} · Dilarion</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Inter+Tight:wght@600;700&family=Inter:wght@400;500;600&family=JetBrains+Mono:wght@500&display=swap" rel="stylesheet">
<style>{_CSS}</style>
</head>
<body style="--tone:{colour};--tone-rgb:{rgb}">
<div class="glow"></div><div class="grid"></div>
<header><a class="brand" href="{WEB_APP_URL}"><span class="mark">D</span>Dilarion</a></header>
<main>
  <section class="card" role="status">
    <div class="badge"><svg viewBox="0 0 24 24" aria-hidden="true">{icon}</svg></div>
    <div class="kicker">{esc(kicker)}</div>
    <h1>{esc(title)}</h1>
    <p>{esc(message)}</p>
    {account_html}
    {detail_html}
    <div class="actions">
      <button class="button primary" onclick="window.close()">Close this tab</button>
      <a class="button glass" href="{WEB_APP_URL}">Open Dilarion on the web</a>
    </div>
    <div class="hint">If the tab doesn't close, switch back to the Dilarion app.</div>
  </section>
</main>
<footer>Dilarion · <a href="https://www.dilarion.xyz/privacy">Privacy</a></footer>
</body>
</html>"""
