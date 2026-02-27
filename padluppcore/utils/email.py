import logging
from typing import Iterable, Optional

import requests
from django.conf import settings

logger = logging.getLogger(__name__)


class EmailSendError(RuntimeError):
    pass


def send_mailgun_email(
    *,
    to_email: str,
    subject: str,
    text: str,
    html: Optional[str] = None,
    tags: Optional[Iterable[str]] = None,
    timeout_seconds: int = 10,
) -> None:
    """Send an email via Mailgun HTTP API.

    Requires settings:
    - MAILGUN_API_KEY
    - MAILGUN_DOMAIN
    - MAILGUN_API_BASE_URL (defaults to https://api.mailgun.net/v3)
    - MAILGUN_FROM_EMAIL
    """

    api_key = getattr(settings, 'MAILGUN_API_KEY', '')
    domain = getattr(settings, 'MAILGUN_DOMAIN', '')
    base_url = getattr(settings, 'MAILGUN_API_BASE_URL', 'https://api.mailgun.net/v3').rstrip('/')
    from_email = getattr(settings, 'MAILGUN_FROM_EMAIL', '')

    if not api_key or not domain or not from_email:
        print("Mailgun email settings are not properly configured. Skipping email send.")
        raise EmailSendError('Mailgun is not configured (missing API key, domain, or from email).')

    url = f"{base_url}/{domain}/messages"

    # Mailgun expects form-encoded data. Tags are sent as repeated `o:tag` keys.
    data_items: list[tuple[str, str]] = [
        ('from', from_email),
        ('to', to_email),
        ('subject', subject),
        ('text', text),
    ]
    if html:
        data_items.append(('html', html))
    if tags:
        for tag in tags:
            t = str(tag).strip()
            if t:
                data_items.append(('o:tag', t))

    try:
        resp = requests.post(
            url,
            auth=('api', api_key),
            data=data_items,
            timeout=timeout_seconds,
        )
        try:
            resp.raise_for_status()
        except requests.HTTPError as exc:
            detail = (resp.text or '').strip()
            msg = f"Mailgun HTTP {resp.status_code}"
            if detail:
                msg = f"{msg}: {detail}"
            raise EmailSendError(msg) from exc
    except EmailSendError:
        logger.exception('Failed sending Mailgun email')
        raise
    except Exception as exc:
        logger.exception('Failed sending Mailgun email')
        raise EmailSendError(str(exc)) from exc
