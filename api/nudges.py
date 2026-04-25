from __future__ import annotations

from django.conf import settings


def build_inactivity_nudge_email(*, name: str, days_inactive: int, app_url: str | None = None) -> tuple[str, str, str]:
    display_name = (name or '').strip() or 'there'
    url = (app_url or getattr(settings, 'PADLUPP_APP_URL', '') or 'https://app.padlupp.com').rstrip('/')

    subject = 'We miss you at Padlupp'
    text = (
        f'Hi {display_name},\n\n'
        f'It has been {days_inactive} days since we last saw you on Padlupp, and we wanted to check in.\n\n'
        'Your progress still matters here. If life has been full, busy, or a little heavy lately, that is completely okay. '\
        'You do not need a perfect plan to come back. Just one small step is enough to start again.\n\n'
        'Whenever you are ready, we would love to welcome you back and help you pick up the thread.\n\n'
        f'Come back gently when it feels right: {url}\n\n'
        'Warmly,\n'
        'The Padlupp team'
    )
    html = (
        '<html><body style="font-family:Arial,sans-serif;line-height:1.6;color:#1f2937;">'
        f'<p>Hi {display_name},</p>'
        f'<p>It has been <strong>{days_inactive} days</strong> since we last saw you on Padlupp, and we wanted to check in.</p>'
        '<p>Your progress still matters here. If life has been full, busy, or a little heavy lately, that is completely okay. '
        'You do not need a perfect plan to come back. Just one small step is enough to start again.</p>'
        '<p>Whenever you are ready, we would love to welcome you back and help you pick up the thread.</p>'
        f'<p><a href="{url}" style="display:inline-block;padding:12px 18px;border-radius:999px;background:#17384a;color:#ffffff;text-decoration:none;font-weight:700;">Come back to Padlupp</a></p>'
        '<p>Warmly,<br>The Padlupp team</p>'
        '</body></html>'
    )
    return subject, text, html
