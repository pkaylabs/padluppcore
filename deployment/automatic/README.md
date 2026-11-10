# Automatic Production Releases

Canonical sources are `padlup001/padlupp` (web) and `padlup001/padluppcore`
(backend), both `main`. Their production workflows run on main pushes and manual
dispatches on main. Mirror repositories cannot deploy. Marketing and mobile
releases are not enabled by this setup.

The production environment permits only the main branch. Pinned official GitHub
Actions run tests before sending a checksum-verified artifact through a dedicated
SSH key. Each key is forced to exactly one deployment target; it cannot run a
shell, forward connections, choose another application or access root credentials.
The production controller and SSH entry are root-owned and installed separately
by an administrator. Application deployments do not update privileged tools.

## Data And Rollback

- Database credentials remain in `/etc/padluppcore/app.env`, never in GitHub.
- PostgreSQL and `/var/lib/padlupp` uploads are shared persistent data, outside
  immutable code/virtual-environment release directories.
- Backend releases first take a consistent PostgreSQL dump and restore it into
  an isolated temporary database. Every table count must match the exact dump
  snapshot. Only that newly created verification database is dropped afterward.
- Uploads and runtime configuration are archived privately before backend deployment. Backups are root-only
  in `/var/backups/padlupp-auto`; previous code releases are retained.
- The migration gate permits only forward atomic CreateModel, AddIndex and
  backward-compatible AddField operations (nullable or persistent database
  default). Destructive, data-code and other schema operations fail for manual
  review. A Python-only default is not sufficient for rollback compatibility.
- A global release lock serializes deployments across the active repositories.
  Running deployments are not cancelled by newer main pushes. Superseded queued
  commits skip deployment; artifacts include repository/branch/commit metadata.
- Activation changes an atomic code symlink. Failed health checks restore the
  previous code and restart/reload its service. Rollback NEVER restores a database
  dump, reverses migrations, flushes records or replaces uploads, which would
  discard writes made after a backup.
- No automatic release/backup pruning is configured. New deployment is blocked
  below 2 GiB free disk space. Backups additionally require room for the current
  uploads/configuration and three times the database size (including restore
  verification), plus that reserve. Operators must monitor capacity and review retention.

Schema allowlisting protects against accidental destructive migrations, not
untrusted application code. Main-branch write access remains production-code
deployment authority. Review model changes and production environment access.

## Operations

`/usr/local/sbin/padlupp-deploy` is the installed controller. Its fixed SSH entry
accepts only `deploy <40-character-commit> <64-character-archive-SHA256>`.
Active code links and last-success records are under `/var/lib/padlupp-deploy`;
protected logs are under `/var/log/padlupp-deploy`. A root operator can run
`padlupp-deploy --backup-only` to verify a fresh database/upload backup.

For a data incident, stop and investigate before any manual database restore.
Preserve the current database and uploads first. Code rollback is deliberately
independent of data recovery. Never run a database restore or reverse migration
as an automatic deployment fallback.

Environment secrets per active repository: `PADLUPP_DEPLOY_HOST`,
`PADLUPP_DEPLOY_USER`, `PADLUPP_DEPLOY_SSH_KEY`, `PADLUPP_DEPLOY_KNOWN_HOSTS`.
The web environment also needs the public `VITE_GOOGLE_OAUTH2_CLIENT_ID` variable.
Private keys, application environments and database/upload backups must never be
committed, published as workflow artifacts or printed in Actions logs.
