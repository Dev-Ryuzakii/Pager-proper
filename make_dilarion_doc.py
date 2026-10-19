#!/usr/bin/env python3
"""Generate Dilarion-Overview.docx — a narrative, portrait feature literature."""
from docx import Document
from docx.shared import Pt, RGBColor, Inches
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.oxml.ns import qn
from docx.oxml import OxmlElement

BRAND = RGBColor(0x6F, 0x10, 0x24)
INK = RGBColor(0x24, 0x19, 0x1B)
GREY = RGBColor(0x60, 0x60, 0x60)

doc = Document()

normal = doc.styles['Normal']
normal.font.name = 'Calibri'
normal.font.size = Pt(11)
normal.font.color.rgb = INK
normal.paragraph_format.space_after = Pt(8)
normal.paragraph_format.line_spacing = 1.18

for section in doc.sections:
    section.page_height = Inches(11)
    section.page_width = Inches(8.5)
    section.top_margin = Inches(1)
    section.bottom_margin = Inches(1)
    section.left_margin = Inches(1)
    section.right_margin = Inches(1)


def heading(text, size=18, color=BRAND, space_before=16, space_after=6):
    p = doc.add_paragraph()
    p.paragraph_format.space_before = Pt(space_before)
    p.paragraph_format.space_after = Pt(space_after)
    p.paragraph_format.keep_with_next = True
    r = p.add_run(text)
    r.bold = True
    r.font.size = Pt(size)
    r.font.color.rgb = color
    return p


def feature(title):
    p = doc.add_paragraph()
    p.paragraph_format.space_before = Pt(11)
    p.paragraph_format.space_after = Pt(2)
    p.paragraph_format.keep_with_next = True
    r = p.add_run(title)
    r.bold = True
    r.font.size = Pt(12.5)
    r.font.color.rgb = INK
    return p


def body(text, italic=False):
    p = doc.add_paragraph()
    r = p.add_run(text)
    r.italic = italic
    return p


def rule(color='6F1024'):
    p = doc.add_paragraph()
    pPr = p._p.get_or_add_pPr()
    pbdr = OxmlElement('w:pBdr')
    bottom = OxmlElement('w:bottom')
    bottom.set(qn('w:val'), 'single')
    bottom.set(qn('w:sz'), '6')
    bottom.set(qn('w:space'), '1')
    bottom.set(qn('w:color'), color)
    pbdr.append(bottom)
    pPr.append(pbdr)
    return p


# ── Cover ────────────────────────────────────────────────────────────────────
for _ in range(6):
    doc.add_paragraph()
t = doc.add_paragraph(); t.alignment = WD_ALIGN_PARAGRAPH.CENTER
r = t.add_run('DILARION'); r.bold = True; r.font.size = Pt(46); r.font.color.rgb = BRAND
s = doc.add_paragraph(); s.alignment = WD_ALIGN_PARAGRAPH.CENTER
r = s.add_run('The Secure Communication Platform for Organizations'); r.font.size = Pt(15); r.font.color.rgb = GREY
d = doc.add_paragraph(); d.alignment = WD_ALIGN_PARAGRAPH.CENTER
r = d.add_run('Product Story & Feature Compendium'); r.italic = True; r.font.size = Pt(12.5)
doc.add_page_break()

# ── 1. Executive summary ─────────────────────────────────────────────────────
heading('1. Executive Summary')
body(
    'Dilarion is a private, end-to-end encrypted communication platform built for '
    'organizations that need to control who communicates, on what devices, and under '
    'what policy. Where most teams stitch together a consumer chat app, a separate '
    'video tool, and a spreadsheet of who-has-access, Dilarion brings secure '
    'messaging, voice and video calling, group calls, meetings, a collaborative '
    'whiteboard and an AI copilot into a single product that runs natively on iOS, '
    'Android, Windows and macOS, and in any modern browser.'
)
body(
    'The defining idea is that the organization, not the individual, owns the '
    'communication. Staff accounts are provisioned centrally, every person activates '
    'privately inside the app, and administrators keep the oversight, device policy, '
    'monitoring and emergency controls an enterprise depends on — all while the '
    'platform relays encrypted content rather than reading it in the course of normal '
    'operation. The result is a tool that feels as immediate as the apps people '
    'already know, but behaves like infrastructure a serious organization can stand '
    'behind.'
)

# ── 2. Why Dilarion ──────────────────────────────────────────────────────────
heading('2. Why Dilarion')
body(
    'Consider how most organizations actually communicate today. Work conversations '
    'live in personal WhatsApp or Telegram accounts. There is no central way to create '
    'or remove access, no record of who signed in from where, no policy over which '
    'apps run on a work device, and no switch to pull when a phone is lost or a person '
    'leaves. The convenience is real, but so is the exposure: the moment a device is '
    'compromised or an account is shared, the organization has no visibility and no '
    'recourse.'
)
body(
    'Dilarion was built to keep the convenience and remove the exposure. It starts '
    'from a different assumption — that communication is an organizational asset that '
    'must be provisioned, governed and observable — and then works hard to make that '
    'governance invisible in daily use. People still send a message, tap to call, drop '
    'into a group. Behind that familiar surface sits encryption, single-device '
    'identity, device policy, and a live view of the platform’s health.'
)
feature('The principles that shape every feature')
body(
    'Private by default: every message is end-to-end encrypted, and the server stores '
    'ciphertext, never plaintext. Organization-controlled: accounts, devices, policy '
    'and lifecycle belong to the organization. Accountable: one person maps to one '
    'active device, every sign-in is attributed, and access can be revoked instantly. '
    'Everywhere: the same capabilities on phone, desktop and browser. Observable: the '
    'health of every feature and endpoint is visible in real time, so issues are seen '
    'rather than guessed at.'
)

# ── 3. Differentiators ───────────────────────────────────────────────────────
heading('3. What Makes Dilarion Different')
body(
    'Many products claim to be secure. Dilarion’s difference is in the specific, '
    'deliberate decisions that favour the organization’s control and the user’s '
    'safety at the same time.'
)
feature('Encryption with lawful, auditable oversight')
body(
    'End-to-end encryption usually forces a choice: either the provider can read '
    'everything, or the organization can recover nothing. Dilarion resolves this by '
    'wrapping each message key for a controlled administrative key alongside the '
    'recipient’s. Messages stay encrypted in transit and at rest, yet the '
    'organization can meet lawful and compliance obligations when it must. It is a '
    'documented, intentional capability — not a hidden backdoor into a plaintext '
    'database, because no such database exists.'
)
feature('Proof that the right person answered')
body(
    'When a Dilarion call is answered, the owner’s master token is required. A found '
    'or borrowed phone cannot silently pick up a sensitive call. The token is verified '
    'once per session and then reused, so the protection does not become a nuisance — '
    'the owner proves identity, and answering stays a single tap thereafter.'
)
feature('One identity, one device, fully attributed')
body(
    'Each account has exactly one active device. Every sign-in captures the device '
    'name, approximate location and time and alerts the owner, and a second sign-in '
    'attempt elsewhere is blocked rather than quietly allowed. Account sharing and '
    'quiet takeovers — the most common real-world failure of consumer tools — simply '
    'do not work here.'
)
feature('Policy that reaches the device')
body(
    'On organization-owned desktops, an optional device policy can detect disallowed '
    'applications running and capture a screenshot as evidence for administrators to '
    'review. Governance stops being a document nobody reads and becomes something the '
    'platform can actually observe.'
)
feature('Protection for the moment things go wrong')
body(
    'If a device is left unattended it logs out on its own; if a user is coerced, a '
    'decoy image can stand in for the real screen. And if a device is lost or an '
    'account compromised, administrators have remote wipe, a kill switch and data '
    'purge to respond decisively.'
)
feature('You can see the platform working')
body(
    'Dilarion traces the health of every feature and the uptime of every endpoint in '
    'real time, drillable from an organization down to a single user. When someone '
    'reports a problem, support confirms it with evidence instead of guessing.'
)

# ── 4. Platforms ─────────────────────────────────────────────────────────────
heading('4. Platforms & Clients')
body(
    'Dilarion meets people on whatever they already carry or sit in front of, and the '
    'experience is deliberately consistent across all of them.'
)
feature('iOS and Android')
body(
    'Native mobile apps deliver the full experience — messaging, calls, groups and '
    'meetings — with push notifications so a call or message still reaches the user '
    'when the app is closed. The Android client uses modern Jetpack Compose and '
    'LiveKit-powered calling; the iOS client uses Apple Push Notifications for '
    'wake-from-closed alerts.'
)
feature('Windows and macOS desktop')
body(
    'The desktop app installs natively on Windows and macOS and opens each call in its '
    'own window, so a conversation can run alongside the user’s other work rather '
    'than taking over the screen.'
)
feature('Web, installable as an app')
body(
    'The same application runs in the browser and can be installed to a phone’s home '
    'screen as a Progressive Web App, giving an app-like launch without an app-store '
    'download. On the web build, calling is intentionally disabled with a clear '
    'message, so expectations are never ambiguous.'
)
feature('Two management surfaces')
body(
    'Beyond the end-user clients, organizations get a browser portal to manage their '
    'own staff, and Dilarion operators get a dedicated administration console for '
    'platform-wide oversight.'
)

# ── 5. Messaging ─────────────────────────────────────────────────────────────
heading('5. Secure Messaging')
body(
    'Messaging is the heart of the product, and every part of it is built around the '
    'rule that content belongs to the people in the conversation.'
)
feature('End-to-end encryption')
body(
    'A message is encrypted on the sender’s device before it ever leaves. The server '
    'relays and stores only ciphertext, so even a full view of the database reveals no '
    'conversation content. For compliance, each message key is additionally wrapped '
    'for the organization’s controlled administrative key — oversight by design, '
    'not plaintext by accident.'
)
feature('Rich, encrypted media')
body(
    'Images, documents and voice notes travel with the same encryption as text. The '
    'composer also has GIF and stock-image search built in, so expression is easy '
    'without leaving the secure channel.'
)
feature('Control over what you have said')
body(
    'Users can delete a message, hide a message, and set messages to disappear '
    'automatically after a chosen time. Reactions, read receipts and delivery status '
    'make conversations feel alive, while the disappearing and deletion controls keep '
    'sensitive exchanges from lingering longer than intended.'
)
feature('Time you can trust')
body(
    'Every timestamp is stored in a single, unambiguous universal time and displayed '
    'in each viewer’s real local time — so a message sent in Lagos reads correctly '
    'as West Africa Time, and the order of a conversation is never in doubt across '
    'devices or regions.'
)

# ── 6. Calls ─────────────────────────────────────────────────────────────────
heading('6. Voice & Video Calls')
body(
    'Calling in Dilarion is designed to be both effortless and verifiably private.'
)
feature('Direct and group calls')
body(
    'One-to-one audio and video calls are encrypted end to end. For more people, '
    'Dilarion moves to a LiveKit-powered room that scales to group and conference '
    'calls without the quality collapse of a simple mesh. A managed TURN relay keeps '
    'media flowing even behind strict firewalls and mobile networks.'
)
feature('Answered by the right person, once')
body(
    'Answering requires the owner’s master token, proving the account owner is the '
    'one picking up. Because the session token is reused, the owner enters it a single '
    'time rather than on every call, and the on-screen prompt invites a simple press '
    'of Enter to answer.'
)
feature('No more phantom ringing')
body(
    'When a call is answered on one device, every other device the user owns stops '
    'ringing immediately — for direct calls and group calls alike. Call history then '
    'records the duration of each call and clearly marks the ones that were picked up '
    'on another device.'
)

# ── 7. Meetings etc ──────────────────────────────────────────────────────────
heading('7. Meetings, Whiteboard & AI Copilot')
feature('Meetings')
body(
    'Users schedule meetings, invite participants, and are reminded before each one '
    'begins, so the right people arrive on time without a separate calendar tool.'
)
feature('Whiteboard')
body(
    'A shared canvas turns a call into a working session — sketching an idea, mapping '
    'a plan, or marking up a diagram together in real time.'
)
feature('AI Copilot')
body(
    'An in-app assistant helps draft and think through messages and content, presented '
    'as a draggable widget that stays out of the way until it is needed.'
)

# ── 8. Groups ────────────────────────────────────────────────────────────────
heading('8. Groups & Self-Service')
body(
    'Teams form and dissolve constantly, so Dilarion lets people organize themselves '
    'without waiting on an administrator.'
)
feature('Create and manage your own groups')
body(
    'A user can create a group, give it a name and description, and manage it directly '
    '— no ticket, no approval queue.'
)
feature('Joining made simple')
body(
    'Each group offers an invite link and a QR code, so bringing someone in is as easy '
    'as a scan or a tap.'
)
feature('Conversations that clean up after themselves')
body(
    'A group can be set to automatically delete messages after a chosen number of '
    'hours, keeping a busy channel from becoming a permanent record.'
)

# ── 9. Onboarding ────────────────────────────────────────────────────────────
heading('9. Organizations & Onboarding')
body(
    'Access to Dilarion is intentional from the very first step; nobody simply signs '
    'up for an organization’s workspace.'
)
feature('Request and review')
body(
    'An organization submits a request with its details; a Dilarion administrator '
    'reviews it and either approves or declines, with email notifications at each '
    'stage so the requester is never left wondering.'
)
feature('Activation that happens in the app')
body(
    'Approved staff receive a one-time activation code by email and SMS. The account '
    'is activated, and the private login token chosen, inside the Dilarion app itself '
    '— never on a public web page. During first run, the new user completes a profile '
    'and captures a photo, so the roster is real from day one.'
)

# ── 10. Org portal ───────────────────────────────────────────────────────────
heading('10. Organization Portal')
body(
    'The organization portal gives each organization a focused, browser-based home for '
    'managing its own people — powerful enough to run day-to-day, bounded so that the '
    'riskier actions stay with Dilarion administrators.'
)
feature('See and grow the team')
body(
    'Organizations view their full staff roster and status at a glance, and invite new '
    'staff either one at a time or in bulk by uploading an Excel or CSV spreadsheet. '
    'A downloadable template and flexible column matching mean an existing HR export '
    'usually just works; the parsed rows are shown for review before anything is sent.'
)
feature('Keep access healthy')
body(
    'Pending invitations can be re-issued with a fresh code. An activated staff '
    'member’s login can be reset, which signs them out everywhere and sends a new '
    'setup code — ideal when a device is lost. And the organization’s own portal '
    'account has a self-service forgot-password flow that delivers a one-time code to '
    'the organization’s contact address.'
)
body(
    'By design the portal is view-and-invite: organizations manage growth and access, '
    'while editing and suspending individual staff remain with Dilarion '
    'administrators.', italic=True,
)

# ── 11. Admin console ────────────────────────────────────────────────────────
heading('11. Administration Console')
body(
    'The administration console is the control room of the platform. It is role-aware '
    'and assignable page by page, so a superadmin can give each operator exactly the '
    'surface they need and nothing more.'
)
feature('Everyday operations')
body(
    'Operators approve and create organizations and invite their staff — including by '
    'spreadsheet — manage user accounts, resend invitations, restore accounts, and '
    'oversee groups across the whole platform.'
)
feature('Response and recordings')
body(
    'Emergency response and live field operations place active devices on a map; '
    'administrators review and approve remote device wipes, process account-deletion '
    'and password-reset requests, and access call and meeting recordings where '
    'applicable.'
)
feature('Superadmin authority')
body(
    'A kill switch can disable a single user or every user at once, a data-purge '
    'capability clears platform data, and a complete, assignable audit view records '
    'administrative activity for accountability.'
)

# ── 12. Security ─────────────────────────────────────────────────────────────
heading('12. Security & Privacy Controls')
body(
    'Security in Dilarion is not a single wall but a set of layered, practical '
    'controls aimed at the ways real accounts are actually compromised.'
)
feature('Identity and sign-in')
body(
    'One active device per account closes the door on shared logins. Each sign-in is '
    'attributed with device name, approximate location and time and announced to the '
    'owner, and a competing sign-in attempt is blocked outright. The master token, '
    'optionally protected by two-factor authentication and stored only as a secure '
    'hash, proves ownership for sensitive actions such as answering a call.'
)
feature('Protecting the device itself')
body(
    'The app logs out automatically after a period of inactivity, so an unattended '
    'screen does not become an open door. A decoy image can replace the real interface '
    'to protect a user who is being watched or coerced. On organization devices, the '
    'optional device policy detects disallowed desktop applications and screenshots '
    'them as evidence.'
)
feature('Decisive response')
body(
    'When prevention is not enough, remote wipe, the kill switch and data purge let '
    'administrators act immediately on a lost device or a compromised account.'
)

# ── 13. Monitoring ───────────────────────────────────────────────────────────
heading('13. Monitoring, Reliability & Audit')
body(
    'A platform people trust with their communication has to prove it is working. '
    'Dilarion traces the health of thirteen channels in real time: authentication, '
    'calls, conference, messages, media, meetings, whiteboard, copilot, encryption, '
    'decryption, webhooks, devices and uptime.'
)
feature('Service Health, from the whole platform down to one person')
body(
    'A live feed shows successes and errors for every feature. The view begins with a '
    'card for each organization, opens into that organization’s users, and finally '
    'into a single person’s history — so a vague "calls aren’t working" becomes a '
    'precise record of which feature failed, for whom, and when.'
)
feature('Uptime')
body(
    'Scheduled probes check configured endpoints, while live traffic metrics cover '
    'every API route the platform serves. Together they distinguish a platform-wide '
    'outage from a problem affecting a single user — the first question any support '
    'conversation needs answered.'
)
feature('Audit')
body(
    'An assignable audit view records administrative activity, so sensitive actions '
    'are always accountable.'
)

# ── 14. Notifications ────────────────────────────────────────────────────────
heading('14. Notifications & Reminders')
body(
    'Dilarion makes sure the right alert reaches the right person through whatever '
    'channel is available.'
)
feature('Real-time and push')
body(
    'A persistent connection delivers in-app notifications instantly, and Apple Push '
    'Notifications wake iOS users to calls and messages even when the app is fully '
    'closed.'
)
feature('Reminders across channels')
body(
    'Meeting and task reminders are delivered in-app, by push and by email, so an '
    'upcoming meeting or a due task is hard to miss. An optional Google Calendar '
    'connection ties Dilarion scheduling into the calendar people already live in.'
)

# ── 15. Comms infra ──────────────────────────────────────────────────────────
heading('15. Communications Infrastructure')
feature('Email built for the inbox')
body(
    'Transactional email is sent over SMTP/Resend using a branded template with an '
    'inline logo, structured for deliverability so activation codes and notices land '
    'in the inbox rather than the spam folder.'
)
feature('SMS that understands local numbers')
body(
    'SMS is delivered through Sendchamp, with automatic number normalization that '
    'handles both local and international formats so codes reach the phone reliably.'
)

# ── 16. Architecture ─────────────────────────────────────────────────────────
heading('16. Architecture')
body(
    'Under the surface, Dilarion is a FastAPI backend over a PostgreSQL database, with '
    'a WebSocket presence layer keyed by user and device that powers real-time events '
    'such as calls, typing and delivery. Group media runs on LiveKit for scale, with a '
    'TURN server for relay. The clients are Tauri + React for desktop and web, Kotlin '
    'with Jetpack Compose for Android, and Swift for iOS — native where it matters, '
    'shared where it helps.'
)

# ── 17. Deployment ───────────────────────────────────────────────────────────
heading('17. Deployment & Hosting')
body(
    'Dilarion ships as native installers for Windows and macOS and as Android and iOS '
    'builds, while the web version is hosted as a static site and installs to a '
    'phone’s home screen as a Progressive Web App. A production environment and a '
    'separate testing environment are selected purely by build configuration, so the '
    'same code is promoted from test to production without change.'
)

# ── 18. Conclusion ───────────────────────────────────────────────────────────
heading('18. Conclusion')
body(
    'Dilarion takes the immediacy people expect from modern communication — messaging, '
    'calls, group calls, meetings and AI assistance — and places it inside an '
    'organization-controlled, end-to-end encrypted platform with the provisioning, '
    'device policy, monitoring and administrative authority that serious organizations '
    'require. It is private by default, accountable by design, observable in real '
    'time, and available on every platform its people work from. That combination — '
    'consumer ease with organizational control — is what makes Dilarion different.'
)
rule()
tag = doc.add_paragraph(); tag.alignment = WD_ALIGN_PARAGRAPH.CENTER
r = tag.add_run('Dilarion — secure communication, under your organization’s control.')
r.italic = True; r.font.color.rgb = BRAND

doc.save('Dilarion-Overview.docx')
print('saved Dilarion-Overview.docx')
