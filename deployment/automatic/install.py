#!/usr/bin/env python3
"""Administrator-only bootstrap. Never executed by an application deployment."""

import argparse
import grp
import json
import os
from pathlib import Path
import pwd
import re
import shutil
import signal
import subprocess
import time

ROOT = Path("/var/lib/padlupp-deploy")
BACKUPS = Path("/var/backups/padlupp-auto")
HELPERS = Path("/usr/local/libexec/padlupp-deploy")
USER = "padlupp-deploy"
HOME = Path("/var/lib/padlupp-deployer")


def run(*args):
    subprocess.run(list(map(str, args)), check=True)


def install(source, destination, mode=0o755):
    destination = Path(destination)
    destination.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    destination.write_bytes(Path(source).read_bytes().replace(b"\r\n", b"\n"))
    os.chown(destination, 0, 0)
    destination.chmod(mode)


def current_web_root():
    content = Path("/etc/nginx/sites-available/padlupp").read_text()
    roots = re.findall(r"^\s*root\s+([^;]+);\s*$", content, flags=re.MULTILINE)
    if len(roots) != 1:
        raise SystemExit("Expected exactly one web root")
    root = Path(roots[0]).resolve(strict=True)
    if not str(root).startswith("/var/www/padlupp-releases/"):
        raise SystemExit("Unexpected legacy web release")
    return root


def prepare(source):
    directories = [HELPERS.parent, ROOT, ROOT / "current", ROOT / "releases", ROOT / "releases/web",
                   ROOT / "releases/backend", HELPERS]
    for directory in directories:
        directory.mkdir(mode=0o755, parents=True, exist_ok=True)
        directory.chmod(0o755)
    for directory in [BACKUPS, Path("/var/log/padlupp-deploy"), ROOT / "incoming", ROOT / "state"]:
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        directory.chmod(0o700)
    for name in ["db_snapshot.py", "runtime_audit.py", "ssh_entry.py"]:
        install(source / name, HELPERS / name)
    install(source / "deploy.py", "/usr/local/sbin/padlupp-deploy")
    links = {"web": current_web_root(), "backend": Path("/padlupp/padluppcore")}
    for target, destination in links.items():
        link = ROOT / "current" / target
        if link.is_symlink():
            if link.resolve() != destination:
                raise SystemExit("Refusing to reset an already initialized release link")
        elif link.exists():
            raise SystemExit("Refusing to replace a non-link current directory")
        else:
            link.symlink_to(destination, target_is_directory=True)
    print("Controller prepared; no application activation, SSH credentials or marketing configuration changed.")


def sha(path):
    import hashlib
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def authorize_ssh(baseline):
    authorized = (HOME / ".ssh/authorized_keys").read_text().splitlines()
    if len(authorized) != 2 or any(
        not line.startswith(f'restrict,command="/usr/bin/python3 {HELPERS}/ssh_entry.py {target}" ssh-ed25519 ')
        for target, line in zip(("web", "backend"), authorized)
    ):
        raise SystemExit("Restricted web/backend keys must exist before SSH allowlisting")
    hardening = Path("/etc/ssh/sshd_config.d/00-padlupp-hardening.conf")
    content = hardening.read_text()
    matches = list(re.finditer(r"^([ \t]*AllowUsers[ \t]+)([^\r\n]*)$", content, flags=re.MULTILINE))
    if len(matches) != 1:
        raise SystemExit("Expected one existing explicit SSH AllowUsers rule")
    match = matches[0]
    entries, separator, comment = match.group(2).partition("#")
    users = entries.split()
    if USER in users:
        return
    users.append(USER)
    replacement = match.group(1) + " ".join(users) + (" #" + comment if separator else "")
    previous = baseline / "bootstrap-config/ssh-hardening.conf"
    if previous.exists():
        raise SystemExit("Refusing to overwrite the original SSH policy backup")
    shutil.copy2(hardening, previous)
    try:
        hardening.write_text(content[:match.start()] + replacement + content[match.end():])
        run("sshd", "-t")
        run("systemctl", "reload", "ssh")
    except BaseException:
        shutil.copy2(previous, hardening)
        run("sshd", "-t")
        run("systemctl", "reload", "ssh")
        raise


def enable(keys, baseline):
    baseline = baseline.resolve(strict=True)
    if baseline.parent != BACKUPS or time.time() - baseline.stat().st_mtime > 86400:
        raise SystemExit("A current baseline backup is required")
    checks = json.loads((baseline / "checksums.json").read_text())
    if checks.get("restore_verified") is not True:
        raise SystemExit("A successful full database restore verification is required")
    for name in ["database.dump", "uploads.tar.gz", "runtime-config.tar.gz"]:
        if sha(baseline / name) != checks[name]:
            raise SystemExit("Baseline backup checksum does not match")
    for name in ["web", "backend"]:
        public = (keys / (name + ".pub")).read_text().strip()
        if not re.fullmatch(r"ssh-ed25519 [A-Za-z0-9+/]+={0,3}(?: [^\r\n]+)?", public):
            raise SystemExit("Expected one ed25519 public key per active repository")
    authorized = HOME / ".ssh/authorized_keys"
    sudoers = Path("/etc/sudoers.d/padlupp-deploy")
    if authorized.exists() or sudoers.exists():
        raise SystemExit("Refusing to replace existing deployment credentials or sudo policy")
    try:
        account = pwd.getpwnam(USER)
    except KeyError:
        account = None
    if account is not None and account.pw_dir != str(HOME):
        raise SystemExit("Existing deployment account has an unexpected home")
    run("nginx", "-t")
    backup = baseline / "bootstrap-config"
    backup.mkdir(mode=0o700)
    web = Path("/etc/nginx/sites-available/padlupp")
    api = Path("/etc/nginx/sites-available/padluppcore")
    for path in [web, api]:
        shutil.copy2(path, backup / path.name)
    dropin = Path("/etc/systemd/system/padluppcore-daphne.service.d/20-automatic-release.conf")
    if dropin.exists():
        raise SystemExit("Automatic deployment drop-in already exists; review instead of overwriting")
    web_content = web.read_text()
    new_web, count = re.subn(r"^(\s*root\s+)[^;]+;", r"\g<1>/var/lib/padlupp-deploy/current/web;",
                             web_content, flags=re.MULTILINE)
    if count != 1:
        raise SystemExit("Expected one web root")
    api_content = api.read_text()
    old_alias = "alias /padlupp/padluppcore/staticfiles/;"
    if api_content.count(old_alias) != 1:
        raise SystemExit("Expected original backend static alias")
    new_api = api_content.replace(old_alias, "alias /var/lib/padlupp-deploy/current/backend/staticfiles/;")
    proposed_sudoers = backup / "sudoers.proposed"
    proposed_sudoers.write_text(
        "Defaults:padlupp-deploy !requiretty\n"
        "padlupp-deploy ALL=(root) NOPASSWD: /usr/local/sbin/padlupp-deploy web *, "
        "/usr/local/sbin/padlupp-deploy backend *\n"
    )
    run("visudo", "-cf", proposed_sudoers)
    run("sshd", "-t")
    created_keys = False
    created_policy = False
    try:
        web.write_text(new_web)
        api.write_text(new_api)
        dropin.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
        dropin.write_text(
            "[Service]\nWorkingDirectory=/var/lib/padlupp-deploy/current/backend\n"
            "Environment=PYTHONDONTWRITEBYTECODE=1\nExecStart=\n"
            "ExecStart=/var/lib/padlupp-deploy/current/backend/venv/bin/python -m uvicorn "
            "padluppcore.asgi:application --host 127.0.0.1 --port 8000 --proxy-headers "
            "--forwarded-allow-ips=127.0.0.1 --no-access-log --log-level warning\n"
        )
        dropin.chmod(0o644)
        run("nginx", "-t")
        run("systemctl", "daemon-reload")
        run("systemctl", "reload", "nginx")
        if account is None:
            run("useradd", "--no-create-home", "--home-dir", HOME, "--shell", "/bin/bash", USER)
            account = pwd.getpwnam(USER)
        if account.pw_dir != str(HOME):
            raise SystemExit("Existing deployment account has an unexpected home")
        group = account.pw_gid
        for directory in [HOME, HOME / ".ssh"]:
            directory.mkdir(mode=0o750, parents=True, exist_ok=True)
            os.chown(directory, 0, group)
            directory.chmod(0o750)
        with authorized.open("x", encoding="utf-8") as stream:
            created_keys = True
            stream.write("".join(
                f'restrict,command="/usr/bin/python3 {HELPERS}/ssh_entry.py {name}" '
                + (keys / (name + ".pub")).read_text().strip() + "\n"
                for name in ["web", "backend"]
            ))
        os.chown(authorized, 0, group)
        authorized.chmod(0o640)
        with sudoers.open("xb") as stream:
            created_policy = True
            stream.write(proposed_sudoers.read_bytes())
        os.chown(sudoers, 0, 0)
        sudoers.chmod(0o440)
        run("sshd", "-t")
        authorize_ssh(baseline)
    except BaseException:
        if created_policy:
            sudoers.unlink(missing_ok=True)
        if created_keys:
            authorized.unlink(missing_ok=True)
        shutil.copy2(backup / web.name, web)
        shutil.copy2(backup / api.name, api)
        dropin.unlink(missing_ok=True)
        run("systemctl", "daemon-reload")
        run("nginx", "-t")
        run("systemctl", "reload", "nginx")
        raise
    print("Web/backend forced-command deployment access enabled after verified baseline backup.")
    print("Marketing is unchanged and has no deployment key or sudo target.")


def main():
    if os.geteuid() != 0:
        raise SystemExit("Administrator privileges are required")
    os.umask(0o077)
    signal.signal(signal.SIGHUP, signal.SIG_IGN)
    parser = argparse.ArgumentParser()
    parser.add_argument("phase", choices=["prepare", "enable", "authorize-host"])
    parser.add_argument("--source", type=Path)
    parser.add_argument("--keys", type=Path)
    parser.add_argument("--baseline", type=Path)
    args = parser.parse_args()
    import fcntl
    with open("/var/lock/padlupp-release.lock", "a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        if args.phase == "prepare":
            prepare(args.source.resolve(strict=True))
        elif args.phase == "enable":
            enable(args.keys.resolve(strict=True), args.baseline)
        else:
            authorize_ssh(args.baseline.resolve(strict=True))


if __name__ == "__main__":
    main()
