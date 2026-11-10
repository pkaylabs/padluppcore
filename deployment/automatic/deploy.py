#!/usr/bin/env python3
"""Root-owned, commit-pinned releases. Never replace or restore application data."""

import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import signal
import subprocess
import sys
import tarfile
import time
from urllib.error import HTTPError
from urllib.request import urlopen
import uuid

ROOT = Path("/var/lib/padlupp-deploy")
BACKUPS = Path("/var/backups/padlupp-auto")
LOGS = Path("/var/log/padlupp-deploy")
LEGACY_PYTHON = "/padlupp/padluppcore/venv/bin/python"
HELPERS = Path("/usr/local/libexec/padlupp-deploy")
MAX_ARCHIVE_BYTES = 256 * 1024 * 1024
TARGETS = {
    "web": ("padlupp", "https://app.padlupp.com"),
    "backend": ("padluppcore", "https://api.padlupp.com"),
    "marketing": ("padlupp-web-00", "https://www.padlupp.com"),
}


class DeploymentError(RuntimeError):
    pass


def digest(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def validate_manifest(manifest, target, commit):
    expected = {
        "remote": "padlupp",
        "repository": f"https://github.com/padlup001/{TARGETS[target][0]}.git",
        "branch": "main",
        "commit": commit,
    }
    if manifest != expected:
        raise DeploymentError("Artifact provenance does not match the authorized repository/commit")


def validate_members(members, target):
    if len(members) > 25000 or sum(member.size for member in members) > 1024 ** 3:
        raise DeploymentError("Artifact exceeds extraction limits")
    forbidden = {".git", "venv", "node_modules"}
    if target == "backend":
        forbidden |= {"assets", "media", "private_media", "private-media", "db.sqlite3", "staticfiles"}
    seen = set()
    for member in members:
        path = PurePosixPath(member.name)
        if path.is_absolute() or ".." in path.parts or "\\" in member.name:
            raise DeploymentError("Unsafe artifact path")
        if not (member.isfile() or member.isdir()):
            raise DeploymentError("Links and special files are not accepted in artifacts")
        if path.parts and path.parts[0] in forbidden:
            raise DeploymentError("Artifacts must not contain live data, environments or dependencies")
        if any(part == ".env" or (part.startswith(".env.") and part != ".env.example") for part in path.parts):
            raise DeploymentError("Environment credentials are not accepted in artifacts")
        if member.isfile() and path in seen:
            raise DeploymentError("Duplicate artifact file")
        seen.add(path)


def bounded_members(archive):
    members = []
    total = 0
    for member in archive:
        total += member.size
        if len(members) >= 25000 or total > 1024 ** 3:
            raise DeploymentError("Artifact exceeds extraction limits")
        members.append(member)
    return members


def write_json(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + "." + uuid.uuid4().hex)
    temporary.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")
    temporary.chmod(0o600)
    os.replace(temporary, path)


def switch_link(target, destination):
    link = ROOT / "current" / target
    if not link.is_symlink():
        raise DeploymentError("Current release must be an explicitly initialized symlink")
    temporary = link.with_name(target + "." + uuid.uuid4().hex)
    temporary.symlink_to(destination, target_is_directory=True)
    os.replace(temporary, link)


def fetch(url):
    try:
        with urlopen(url, timeout=15) as response:
            return response.status, response.read()
    except HTTPError as error:
        return error.code, error.read()


class Deployer:
    def __init__(self, target, commit):
        self.target = target
        self.commit = commit
        self.identifier = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime()) + "-" + target + "-" + commit[:12]
        LOGS.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.log_path = LOGS / (self.identifier + ".log")
        self.log_file = self.log_path.open("ab", buffering=0)
        self.log_path.chmod(0o600)
        self.backup = BACKUPS / self.identifier
        self.previous = (ROOT / "current" / target).resolve(strict=True)

    def log(self, message):
        self.log_file.write((str(message) + "\n").encode())
        try:
            print(str(message), flush=True)
        except BrokenPipeError:
            pass

    def run(self, args, *, user=None, production=False, cwd=None, stdin=None, stdout=None, timeout=600):
        command = list(map(str, args))
        if production:
            command = ["env", "DJANGO_ENV_FILE=/etc/padluppcore/app.env",
                       "DJANGO_SETTINGS_MODULE=padluppcore.settings", "PYTHONDONTWRITEBYTECODE=1", *command]
        if user:
            command = ["runuser", "-u", user, *(["-g", "www-data"] if user == "padlupp-app" else []), "--", *command]
        result = subprocess.run(command, cwd=cwd, stdin=stdin, stdout=stdout or subprocess.PIPE,
                                stderr=subprocess.PIPE, timeout=timeout, check=False,
                                umask=0o022 if user == "padlupp-app" else -1)
        if result.returncode:
            self.log_file.write(result.stderr or b"")
            if stdout is None:
                self.log_file.write(result.stdout or b"")
            raise DeploymentError(f"{Path(str(args[0])).name} failed; see protected server log {self.log_path}")
        return result.stdout

    def backup_database_and_uploads(self):
        self.check_backup_capacity()
        self.log("Creating a consistent PostgreSQL snapshot and verified restore")
        self.backup.mkdir(mode=0o700, parents=True, exist_ok=False)
        holder = subprocess.Popen(
            ["runuser", "-u", "postgres", "--", LEGACY_PYTHON, str(HELPERS / "db_snapshot.py"), "hold"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=self.log_file,
        )
        dump_path = self.backup / "database.dump"
        try:
            snapshot = json.loads(holder.stdout.readline())
            write_json(self.backup / "snapshot-counts.json", snapshot["counts"])
            with dump_path.open("wb") as output:
                self.run(["pg_dump", "--format=custom", "--snapshot=" + snapshot["snapshot"], "padlupp"],
                         user="postgres", stdout=output)
        finally:
            if holder.stdin:
                try:
                    holder.stdin.write(b"finished\n")
                    holder.stdin.flush()
                except BrokenPipeError:
                    pass
                try:
                    holder.stdin.close()
                except BrokenPipeError:
                    pass
            try:
                holder.wait(timeout=30)
            except subprocess.TimeoutExpired:
                holder.terminate()
                holder.wait(timeout=10)
        if holder.returncode:
            raise DeploymentError("PostgreSQL snapshot holder failed")
        with dump_path.open("rb") as stream, (self.backup / "database-contents.txt").open("wb") as output:
            self.run(["pg_restore", "--list"], user="postgres", stdin=stream, stdout=output)
        scratch = "padlupp_verify_" + uuid.uuid4().hex[:12]
        created = False
        try:
            self.run(["createdb", "--template=template0", scratch], user="postgres")
            created = True
            with dump_path.open("rb") as stream:
                self.run(["pg_restore", "--exit-on-error", "--no-owner", "--no-privileges", "--dbname=" + scratch],
                         user="postgres", stdin=stream)
            restored = json.loads(self.run([LEGACY_PYTHON, HELPERS / "db_snapshot.py", "counts", scratch], user="postgres"))
            if restored != snapshot["counts"]:
                raise DeploymentError("Restored backup table counts differ from the exact dump snapshot")
        finally:
            if created:
                # This name is generated here, never a production database or caller input.
                self.run(["dropdb", "--force", scratch], user="postgres")
        self.log("Database restore verified: every table matches the backup snapshot")
        self.run(["tar", "-czf", self.backup / "uploads.tar.gz", "-C", "/var/lib/padlupp", "."])
        self.run(["tar", "-czf", self.backup / "runtime-config.tar.gz", "-C", "/etc/padluppcore", "."])
        write_json(self.backup / "checksums.json", {
            "database.dump": digest(dump_path),
            "uploads.tar.gz": digest(self.backup / "uploads.tar.gz"),
            "runtime-config.tar.gz": digest(self.backup / "runtime-config.tar.gz"),
            "restore_verified": True,
        })

    def check_backup_capacity(self):
        database_size = int(self.run([
            "psql", "-XAt", "-d", "padlupp", "-c", "SELECT pg_database_size(current_database())",
        ], user="postgres").strip())
        data_size = sum(int(self.run(["du", "-sb", path]).split()[0])
                        for path in ["/var/lib/padlupp", "/etc/padluppcore"])
        required = 2 * 1024 ** 3 + data_size + database_size * 3
        available = min(shutil.disk_usage(path).free
                        for path in [ROOT, BACKUPS, "/var/lib/postgresql"])
        if available < required:
            raise DeploymentError("Backup blocked: insufficient capacity for data, restore verification and 2 GiB reserve")

    def prepare_backend(self, release):
        import pwd
        import grp

        account = pwd.getpwnam("padlupp-app")
        group = grp.getgrnam("www-data").gr_gid
        ownership(release, 0, group)
        # Keep source root-owned. Only build outputs are writable by the runtime user.
        for name in ("venv", "staticfiles"):
            directory = release / name
            directory.mkdir(mode=0o755)
            os.chown(directory, account.pw_uid, group)
        self.run(["/usr/bin/python3.12", "-m", "venv", release / "venv"], user="padlupp-app")
        python = release / "venv/bin/python"
        self.run([python, "-m", "pip", "install", "--disable-pip-version-check", "--no-cache-dir", "-r", release / "requirements.txt"],
                 user="padlupp-app", timeout=900)
        audit = json.loads(self.run([python, HELPERS / "runtime_audit.py"], user="padlupp-app", production=True, cwd=release))
        if audit != {"debug": False, "engine": "postgresql", "database": "padlupp", "media": "/var/lib/padlupp/assets",
                     "private_media": "/var/lib/padlupp/private-media"}:
            raise DeploymentError("Candidate database/storage settings differ from persistent production storage")
        manage = [python, release / "manage.py"]
        self.run([*manage, "check", "--deploy"], user="padlupp-app", production=True, cwd=release)
        self.run([*manage, "makemigrations", "--check", "--dry-run"], user="padlupp-app", production=True, cwd=release)
        self.run([*manage, "safe_deploy_migrate"], user="padlupp-app", production=True, cwd=release)
        self.run([*manage, "collectstatic", "--noinput"], user="padlupp-app", production=True, cwd=release)
        self.backup_database_and_uploads()
        self.run([*manage, "safe_deploy_migrate", "--apply"], user="padlupp-app", production=True, cwd=release)
        self.run([*manage, "migrate", "--check", "--noinput"], user="padlupp-app", production=True, cwd=release)

    def health(self, release):
        base = TARGETS[self.target][1]
        last_error = None
        for _ in range(30):
            try:
                if self.target == "backend":
                    if fetch(base + "/api-v1/messages/")[0] != 401:
                        raise DeploymentError("API authentication health check failed")
                    self.run(["systemctl", "is-active", "--quiet", "padluppcore-daphne"], timeout=15)
                else:
                    paths = ["/signin", "/messages", "/pods", "/community"] if self.target == "web" else ["/"]
                    expected = digest(release / "index.html")
                    for path in paths:
                        status, body = fetch(base + path)
                        if status != 200 or hashlib.sha256(body).hexdigest() != expected:
                            raise DeploymentError("Published HTML does not match the verified release")
                return
            except Exception as error:
                last_error = error
                time.sleep(1)
        raise DeploymentError(f"Release health check failed: {last_error}")

    def activate(self, release):
        if self.target != "backend":
            self.backup.mkdir(mode=0o700, parents=True, exist_ok=False)
            config = "/etc/nginx/sites-available/" + ("padlupp" if self.target == "web" else "padluppsite")
            shutil.copy2(config, self.backup / "nginx.conf")
        write_json(self.backup / "previous-release.json", {"path": str(self.previous)})
        self.run(["nginx", "-t"])
        switch_link(self.target, release)
        try:
            self.run(["systemctl", "restart" if self.target == "backend" else "reload",
                      "padluppcore-daphne" if self.target == "backend" else "nginx"], timeout=60)
            self.health(release)
        except BaseException:
            self.log("Health failed: restoring previous code, leaving database and uploads untouched")
            switch_link(self.target, self.previous)
            self.run(["systemctl", "restart" if self.target == "backend" else "reload",
                      "padluppcore-daphne" if self.target == "backend" else "nginx"], timeout=60)
            self.health(self.previous)
            raise


def ownership(root, uid, gid):
    for directory, dirs, files in os.walk(root, followlinks=False):
        for path in [Path(directory), *(Path(directory) / name for name in dirs + files)]:
            os.chown(path, uid, gid, follow_symlinks=False)
            if not path.is_symlink():
                path.chmod(0o755 if path.is_dir() or path.stat().st_mode & 0o111 else 0o644)


def preserve_assets(previous, release):
    old = previous / "assets"
    if old.is_symlink() or not old.is_dir():
        return
    for directory, dirs, files in os.walk(old, followlinks=False):
        dirs[:] = [name for name in dirs if not (Path(directory) / name).is_symlink()]
        for name in files:
            source = Path(directory) / name
            destination = release / "assets" / source.relative_to(old)
            if not source.is_symlink() and not destination.exists():
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(source, destination)


def main():
    import grp

    if os.geteuid() != 0:
        raise DeploymentError("Run using the restricted deployment entry point")
    os.umask(0o077)
    signal.signal(signal.SIGHUP, signal.SIG_IGN)
    import fcntl
    with open("/var/lock/padlupp-release.lock", "a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        if sys.argv[1:] == ["--backup-only"]:
            deployer = Deployer("backend", "0" * 40)
            deployer.backup_database_and_uploads()
            deployer.log("Protected baseline backup: " + str(deployer.backup))
            return
        if len(sys.argv) != 4:
            raise DeploymentError("Expected target, commit and archive checksum")
        target, commit, expected = sys.argv[1:]
        if target not in TARGETS or not re.fullmatch(r"[0-9a-f]{40}", commit) or not re.fullmatch(r"[0-9a-f]{64}", expected):
            raise DeploymentError("Invalid deployment request")
        if shutil.disk_usage(ROOT).free < 2 * 1024 ** 3:
            raise DeploymentError("Deployment blocked: retain at least 2 GiB free disk space")
        incoming = ROOT / "incoming" / (uuid.uuid4().hex + ".tar.gz")
        incoming.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        try:
            with incoming.open("xb") as output:
                total = 0
                while chunk := sys.stdin.buffer.read(1024 * 1024):
                    total += len(chunk)
                    if total > MAX_ARCHIVE_BYTES:
                        raise DeploymentError("Artifact exceeds upload limit")
                    output.write(chunk)
            if digest(incoming) != expected:
                raise DeploymentError("Artifact checksum mismatch")
            deployer = Deployer(target, commit)
            with tarfile.open(incoming, "r:gz") as archive:
                members = bounded_members(archive)
                validate_members(members, target)
                manifests = [member for member in members if PurePosixPath(member.name).name == ".deployment-source.json"
                             and len(PurePosixPath(member.name).parts) == 1 and member.isfile()]
                if len(manifests) != 1:
                    raise DeploymentError("Exactly one root artifact provenance file is required")
                validate_manifest(json.load(archive.extractfile(manifests[0])), target, commit)
                release = ROOT / "releases" / target / commit
                if deployer.previous == release:
                    deployer.health(release)
                    deployer.log("Commit is already active and healthy: " + commit)
                    return
                if release.exists():
                    raise DeploymentError("Candidate already exists; preserve it for review and retry with a new commit")
                release.mkdir(mode=0o755, parents=True, exist_ok=False)
                archive.extractall(release, members=members, filter="data")
            if target == "backend":
                deployer.prepare_backend(release)
            else:
                if not (release / "index.html").is_file():
                    raise DeploymentError("Static artifact is missing index.html")
                preserve_assets(deployer.previous, release)
                ownership(release, 0, grp.getgrnam("www-data").gr_gid)
            deployer.activate(release)
            write_json(ROOT / "state" / (target + ".json"), {
                "commit": commit, "repository": f"https://github.com/padlup001/{TARGETS[target][0]}.git",
                "branch": "main", "archive_sha256": expected, "release": str(release),
                "previous": str(deployer.previous), "backup": str(deployer.backup), "status": "healthy",
                "data_rollback": "never automatic; shared database and uploads are preserved",
            })
            deployer.log(f"Production {target} deployment healthy: {commit}")
        finally:
            incoming.unlink(missing_ok=True)


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(f"Deployment failed safely: {error}", file=sys.stderr)
        raise SystemExit(1)
