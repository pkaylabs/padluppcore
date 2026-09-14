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

## Application update

From `/padlupp/padluppcore`:

```bash
sudo /padlupp/padluppcore/venv/bin/python -m pip install -r requirements.txt
sudo -u padlupp-app /padlupp/padluppcore/venv/bin/python manage.py migrate --noinput
sudo -u padlupp-app /padlupp/padluppcore/venv/bin/python manage.py collectstatic --noinput
sudo systemctl restart padluppcore-daphne
```

Always run `sudo nginx -t` before reloading Nginx.
