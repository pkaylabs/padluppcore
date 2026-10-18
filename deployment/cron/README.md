# Cron jobs (server)

This project exposes three scheduler-only endpoints. Production requires the
`X-Padlupp-Cron-Secret` header and Nginx denies public access to `/api-v1/cron/`:

- `POST /api-v1/cron/nudge-inactive-users/`
- `POST /api-v1/cron/checkin-reminders/`
- `POST /api-v1/cron/community-cycles/`

The existing `checkin` runner mode also invokes community cycles. Run `community`
hourly as shown below for due prompts, pre-deadline reminders, missed check-ins
and 28-day inactivity reviews. It never removes members automatically. All
community jobs are idempotent. Completed, archived and frozen pods are excluded.
Pod deadlines use UTC calendar days; an unanswered check-in gets its final
reminder from 20:00 UTC and is marked missed after that UTC day ends. Existing
personal-goal reminder timing is unchanged.
Check-in evidence no longer expires automatically; authorized internal admins
can remove sensitive evidence through audited moderation actions.

On the server, the simplest/most reliable approach is to call Daphne directly over localhost (no DNS/TLS):

- `http://127.0.0.1:8000/api-v1/...`

The runner sends the trusted local HTTPS proxy header for loopback requests and
requires a 2xx response. A redirect is an error, not a successful scheduler run.

## 1) Quick manual test (on the server)

From the repo root:

```bash
bash deployment/cron/run_cron_endpoints.sh nudge
bash deployment/cron/run_cron_endpoints.sh checkin
```

Or with curl:

```bash
curl -sS --fail-with-body -X POST -H "X-Padlupp-Cron-Secret: $PADLUPPCORE_CRON_SECRET" http://127.0.0.1:8000/api-v1/cron/nudge-inactive-users/
curl -sS --fail-with-body -X POST -H "X-Padlupp-Cron-Secret: $PADLUPPCORE_CRON_SECRET" http://127.0.0.1:8000/api-v1/cron/checkin-reminders/
```

## 2) Add crontab entries

Create a root-readable secret file and log directory:

```bash
sudo mkdir -p /var/log/padluppcore
sudo mkdir -p /etc/padluppcore
printf 'PADLUPPCORE_CRON_SECRET=%s\n' 'replace-with-the-Django-CRON_SHARED_SECRET' | sudo tee /etc/padluppcore/cron.env >/dev/null
sudo chmod 600 /etc/padluppcore/cron.env
sudo chown -R root:root /var/log/padluppcore

# Optional (avoids confusion when tailing before the first run)
sudo touch /var/log/padluppcore/cron-checkin.log /var/log/padluppcore/cron-nudge.log
```

Edit root’s crontab:

```bash
sudo crontab -e
```

Example schedule (09:00 Europe/London):

```cron
CRON_TZ=Europe/London
SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

# Daily check-in reminders
0 9 * * * /bin/bash /padlupp/padluppcore/deployment/cron/run_cron_endpoints.sh checkin >> /var/log/padluppcore/cron-checkin.log 2>&1

# Hourly pod cycles, deadline reminders and membership reviews
0 * * * * /bin/bash /padlupp/padluppcore/deployment/cron/run_cron_endpoints.sh community >> /var/log/padluppcore/cron-community.log 2>&1

# Daily inactivity nudges
0 9 * * * /bin/bash /padlupp/padluppcore/deployment/cron/run_cron_endpoints.sh nudge >> /var/log/padluppcore/cron-nudge.log 2>&1
```

If your repo is deployed somewhere else, update the paths accordingly.

## 3) Notes

- Keep `CRON_SHARED_SECRET` and `PADLUPPCORE_CRON_SECRET` identical and rotate both together.
- These cron endpoints call `send_mailgun_email()` directly and currently do **not** honor `EMAIL_NOTIFICATIONS_ENABLED`. If Mailgun is configured, they will attempt to send.
- If emails aren’t sending, verify Mailgun env vars are present on the server (`MAILGUN_API_KEY`, `MAILGUN_DOMAIN`, `MAILGUN_FROM_EMAIL`).

### Lock down cron URLs in Nginx

If you are proxying publicly via Nginx, anyone on the internet can call these cron endpoints unless you restrict them.
One simple approach is to deny external access to `/api-v1/cron/` at the Nginx layer and only allow localhost.

Example snippet:

```nginx
location ^~ /api-v1/cron/ {
	allow 127.0.0.1;
	deny all;

	proxy_pass http://padlupp_app_asgi;
	proxy_http_version 1.1;
	proxy_set_header Host $host;
	proxy_set_header X-Real-IP $remote_addr;
	proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
	proxy_set_header X-Forwarded-Proto $scheme;
}
```

After updating: `nginx -t` then `systemctl reload nginx`.
