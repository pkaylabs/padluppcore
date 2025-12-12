import subprocess
import sys

from django.core.management.base import BaseCommand


class Command(BaseCommand):
    help = "Deploy: pull, migrate, collectstatic, restart Daphne/nginx services."

    def handle(self, *args, **options):
        python_executable = sys.executable

        self.stdout.write(self.style.NOTICE("[DEPLOY] Pulling latest code from origin/main..."))
        subprocess.run(["git", "pull", "origin", "main"], check=True)

        self.stdout.write(self.style.NOTICE("[DEPLOY] Making migrations..."))
        subprocess.run([python_executable, "manage.py", "makemigrations"], check=True)

        self.stdout.write(self.style.NOTICE("[DEPLOY] Applying migrations..."))
        subprocess.run([python_executable, "manage.py", "migrate"], check=True)

        self.stdout.write(self.style.NOTICE("[DEPLOY] Collecting static files..."))
        subprocess.run([python_executable, "manage.py", "collectstatic", "--noinput"], check=True)

        self.stdout.write(self.style.NOTICE("[DEPLOY] Restarting Daphne and nginx services..."))
        try:
            subprocess.run(["systemctl", "restart", "padluppcore-daphne"], check=True)
            subprocess.run(["systemctl", "reload", "nginx"], check=True)
        except Exception as e:
            self.stdout.write(self.style.WARNING(f"[DEPLOY] Could not restart one or more services: {e}"))

        self.stdout.write(self.style.SUCCESS("[DEPLOY] Deployment complete."))
