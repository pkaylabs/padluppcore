"""Release preflight for the canonical backend repository."""

import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[2]


def git(*args):
    return subprocess.check_output(["git", *args], cwd=ROOT, text=True).strip()


def main():
    source = json.loads((ROOT / "deployment-source.json").read_text(encoding="utf-8"))
    assert source == {"remote": "padlupp", "repository": "https://github.com/padlup001/padluppcore.git", "branch": "main"}
    if git("status", "--porcelain") or git("branch", "--show-current") != "main":
        raise SystemExit("Release requires a clean main checkout")
    if git("remote", "get-url", "padlupp") != source["repository"]:
        raise SystemExit("The padlupp remote must identify the canonical backend repository")
    git("fetch", "--no-tags", "padlupp", "refs/heads/main:refs/remotes/padlupp/main")
    commit = git("rev-parse", "HEAD")
    if commit != git("rev-parse", "refs/remotes/padlupp/main"):
        raise SystemExit("Release requires the latest padlupp/main commit")
    print("Canonical backend source verified: " + commit)


if __name__ == "__main__":
    main()
