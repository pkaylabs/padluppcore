# Padlupp API deployment

The production API runs Django ASGI through Uvicorn on `127.0.0.1:8000`.
Nginx terminates TLS, serves Django static/media files, and proxies HTTP and
WebSocket traffic to Uvicorn.

## Service

Install the committed systemd unit and restart the application:

```bash
sudo cp deployment/websocket/padluppcore-daphne.service /etc/systemd/system/padluppcore-daphne.service
sudo systemctl daemon-reload
sudo systemctl enable padluppcore-daphne
sudo systemctl restart padluppcore-daphne
sudo systemctl status padluppcore-daphne
```

The historical service name contains `daphne`, but the unit intentionally runs
Uvicorn. Production secrets are loaded from `/etc/padluppcore/app.env`; they are
never stored in this repository.

## Nginx

Install and validate the API virtual host before reloading Nginx:

```bash
sudo cp deployment/websocket/nginx.conf /etc/nginx/sites-available/padluppcore
sudo ln -sfn /etc/nginx/sites-available/padluppcore /etc/nginx/sites-enabled/padluppcore
sudo nginx -t
sudo systemctl reload nginx
```

The configuration serves:

- `/static/` from `/padlupp/padluppcore/staticfiles/`
- `/assets/` from `/var/lib/padlupp/assets/`
- check-in evidence only through its authenticated API endpoint
- `/ws/` through Uvicorn with WebSocket upgrade headers
- cron endpoints only from the local host

## Community rollout prerequisites

Back up the database and both media directories before applying the community
migrations. Use a maintenance window for the file backfill. Migration `0034`
copies existing chat attachments and check-in evidence into private storage,
then removes their public copies after a successful transaction. Reversing the
database migration alone does not move these files back; recovery requires the
matching database and file backups.

Set `PRIVATE_MEDIA_ROOT=/var/lib/padlupp/private-media` in the service environment
and provision that directory for the application account before migration:

```bash
sudo install -d -m 0700 -o padlupp-app -g www-data /var/lib/padlupp/private-media
```

Keep private storage outside every Nginx alias and public media directory. Do
not expose it through a CDN or static file server. Preserve and back it up
across application releases. The committed Nginx rules deny legacy attachment
and evidence URLs; install those rules as part of the same rollout. Avatars and
group images remain public media, while attachments, pod covers, retained report
evidence and check-in evidence require authenticated API access.

Apply all current migrations, restart the HTTP/WebSocket workers, and enable
the hourly `community` scheduler alongside the existing `checkin` cron runner. See
`deployment/cron/README.md`. Before reopening traffic, verify an authenticated
attachment loads, an unauthenticated request fails, and an old public attachment
URL returns 404. Run the PostgreSQL-only concurrency tests against a disposable
PostgreSQL database before production promotion; SQLite skips those tests.

## Application update

From `/padlupp/padluppcore`:

```bash
sudo /padlupp/padluppcore/venv/bin/python -m pip install -r requirements.txt
sudo -u padlupp-app env DJANGO_ENV_FILE=/etc/padluppcore/app.env /padlupp/padluppcore/venv/bin/python manage.py migrate --noinput
sudo env DJANGO_ENV_FILE=/etc/padluppcore/app.env /padlupp/padluppcore/venv/bin/python manage.py collectstatic --noinput
sudo systemctl restart padluppcore-daphne
```

Always run `sudo nginx -t` before reloading Nginx.
