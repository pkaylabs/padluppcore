import io
import base64
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch, call

from deployment.automatic import deploy, ssh_entry

# The installer is Linux-only; filesystem/command doubles keep its unit tests
# portable and never create real users, configuration files or authorization.
with patch.dict(sys.modules, {} if os.name == 'posix' else {'grp': Mock(), 'pwd': Mock()}):
    from deployment.automatic import install as installer


SHA = "a" * 40
DIGEST = "b" * 64


def member(name, kind=tarfile.REGTYPE):
    value = tarfile.TarInfo(name)
    value.type = kind
    return value


class ArtifactSafetyTests(unittest.TestCase):
    def test_accepts_regular_static_and_backend_source(self):
        deploy.validate_members([member("./", tarfile.DIRTYPE), member("./index.html")], "web")
        deploy.validate_members([member("manage.py"), member(".env.example")], "backend")

    def test_rejects_paths_that_could_escape_release(self):
        for path in ["/etc/passwd", "../assets", "files/../../database", "..\\database"]:
            with self.subTest(path=path), self.assertRaises(deploy.DeploymentError):
                deploy.validate_members([member(path)], "web")

    def test_rejects_links_devices_and_duplicates(self):
        for kind in [tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.CHRTYPE, tarfile.FIFOTYPE]:
            with self.subTest(kind=kind), self.assertRaises(deploy.DeploymentError):
                deploy.validate_members([member("asset", kind)], "web")
        with self.assertRaises(deploy.DeploymentError):
            deploy.validate_members([member("./index.html"), member("index.html")], "web")

    def test_never_accepts_live_data_or_credentials_in_backend_artifact(self):
        for path in ["assets/avatar.png", "private-media/evidence", "media/file", "db.sqlite3", ".env",
                     "padluppcore/.env", ".env.production", "venv/bin/python", ".git/config", "staticfiles/admin.css"]:
            with self.subTest(path=path), self.assertRaises(deploy.DeploymentError):
                deploy.validate_members([member(path)], "backend")

    def test_enforces_extraction_limit(self):
        large = member("large")
        large.size = 1024 ** 3 + 1
        with self.assertRaises(deploy.DeploymentError):
            deploy.validate_members([large], "web")

    def test_header_limit_stops_reading_before_an_unbounded_member_list_is_built(self):
        visited = []
        def headers():
            for index in range(30000):
                visited.append(index)
                yield member(str(index))
        with self.assertRaisesRegex(deploy.DeploymentError, 'extraction limits'):
            deploy.bounded_members(headers())
        self.assertEqual(len(visited), 25001)

    def test_data_filter_strips_archive_ownership_and_setid_before_extraction(self):
        payload = b'synthetic release file'
        buffer = io.BytesIO()
        info = member('regular.txt')
        info.size = len(payload)
        info.uid, info.gid = 12345, 23456
        info.uname, info.gname = 'untrusted-owner', 'untrusted-group'
        info.mode = 0o6777
        with tarfile.open(fileobj=buffer, mode='w:gz') as archive:
            archive.addfile(info, io.BytesIO(payload))
        buffer.seek(0)
        with tempfile.TemporaryDirectory() as directory, tarfile.open(fileobj=buffer, mode='r:gz') as archive:
            members = archive.getmembers()
            deploy.validate_members(members, 'backend')
            seen = []

            def record_owner(member, *args):
                seen.append((member.uid, member.gid, member.uname, member.gname))

            with patch.object(tarfile.TarFile, 'chown', side_effect=record_owner):
                archive.extractall(directory, members=members, filter='data')
            self.assertEqual((Path(directory) / 'regular.txt').read_bytes(), payload)
            self.assertEqual(seen, [(None, None, None, None)])
            if os.name == 'posix':
                self.assertEqual((Path(directory) / 'regular.txt').stat().st_mode & 0o6022, 0)

    def test_preserve_assets_never_overwrites_new_release_assets(self):
        with tempfile.TemporaryDirectory() as directory:
            previous, release = Path(directory) / 'old', Path(directory) / 'new'
            (previous / 'assets').mkdir(parents=True)
            (release / 'assets').mkdir(parents=True)
            (previous / 'assets/shared.js').write_bytes(b'old code')
            (previous / 'assets/old-hash.js').write_bytes(b'cached old asset')
            (release / 'assets/shared.js').write_bytes(b'new code')
            deploy.preserve_assets(previous, release)
            self.assertEqual((release / 'assets/shared.js').read_bytes(), b'new code')
            self.assertEqual((release / 'assets/old-hash.js').read_bytes(), b'cached old asset')

    def test_preserve_assets_does_not_publish_files_from_a_symlinked_assets_root(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            previous, release, private = root / 'old', root / 'new', root / 'private'
            previous.mkdir()
            release.mkdir()
            private.mkdir()
            (private / 'private-evidence.txt').write_bytes(b'synthetic private evidence')
            try:
                (previous / 'assets').symlink_to(private, target_is_directory=True)
            except OSError as error:
                self.skipTest(f'Temporary symlink creation unavailable: {error}')
            try:
                deploy.preserve_assets(previous, release)
            except deploy.DeploymentError:
                pass  # Rejecting the candidate is also a safe refusal.
            self.assertFalse((release / 'assets/private-evidence.txt').exists())

    def test_manifest_must_name_correct_repo_branch_and_commit(self):
        good = {"remote": "padlupp", "repository": "https://github.com/padlup001/padlupp.git",
                "branch": "main", "commit": SHA}
        deploy.validate_manifest(good, "web", SHA)
        for bad in [{**good, "repository": "https://github.com/pkaylabs/padlupp.git"},
                    {**good, "branch": "feature"}, {**good, "commit": "c" * 40}, {**good, "extra": True}]:
            with self.subTest(bad=bad), self.assertRaises(deploy.DeploymentError):
                deploy.validate_manifest(bad, "web", SHA)

    def test_ssh_key_cannot_select_another_target_or_run_shell_commands(self):
        self.assertEqual(ssh_entry.parse_command("web", f"deploy {SHA} {DIGEST}")[-3:], ["web", SHA, DIGEST])
        for command in ["bash", f"deploy backend {SHA} {DIGEST}", f"deploy {SHA} {DIGEST}; id",
                        f"deploy {SHA} {DIGEST}\nid", f"deploy {SHA}", ""]:
            with self.subTest(command=command), self.assertRaises(ValueError):
                ssh_entry.parse_command("web", command)
        with self.assertRaises(ValueError):
            ssh_entry.parse_command("unknown", f"deploy {SHA} {DIGEST}")

    def test_failed_backend_health_restores_only_code_not_database_or_uploads(self):
        with tempfile.TemporaryDirectory() as directory:
            runner = deploy.Deployer.__new__(deploy.Deployer)
            runner.target = "backend"
            runner.backup = Path(directory)
            runner.previous = Path(directory) / "previous"
            runner.run = Mock()
            runner.log = Mock()
            runner.health = Mock(side_effect=[deploy.DeploymentError("unhealthy"), None])
            candidate = Path(directory) / "candidate"
            with patch.object(deploy, "switch_link") as switch:
                with self.assertRaisesRegex(deploy.DeploymentError, "unhealthy"):
                    runner.activate(candidate)
                self.assertEqual(switch.call_args_list, [call("backend", candidate), call("backend", runner.previous)])
            self.assertEqual(runner.run.call_args_list, [
                call(["nginx", "-t"]),
                call(["systemctl", "restart", "padluppcore-daphne"], timeout=60),
                call(["systemctl", "restart", "padluppcore-daphne"], timeout=60),
            ])

    @unittest.skipUnless(os.name == "posix", "Production atomic links require POSIX")
    def test_release_switch_is_atomic_and_preserves_previous_directory(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(deploy, "ROOT", Path(directory)):
            current = Path(directory) / "current"
            current.mkdir()
            old = Path(directory) / "old"
            new = Path(directory) / "new"
            old.mkdir()
            new.mkdir()
            (old / "preserved").write_text("original", encoding="utf-8")
            (current / "web").symlink_to(old, target_is_directory=True)
            deploy.switch_link("web", new)
            self.assertEqual((current / "web").resolve(), new)
            self.assertEqual((old / "preserved").read_text(encoding="utf-8"), "original")


class BackupSafetyTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.runner = deploy.Deployer.__new__(deploy.Deployer)
        self.runner.target = 'backend'
        self.runner.backup = self.root / 'backup'
        self.runner.log_file = io.BytesIO()
        self.runner.log = Mock()
        self.counts = {'accounts_user': 7, 'api_message': 23, 'django_migrations': 45}
        self.snapshot = {'snapshot': '00000003-0000002A-1', 'counts': self.counts}
        self.holder = Mock(returncode=0)
        self.holder.stdout = io.BytesIO(json.dumps(self.snapshot).encode() + b'\n')
        self.holder.wait.return_value = 0
        process_patch = patch.object(deploy.subprocess, 'Popen', return_value=self.holder)
        self.popen = process_patch.start()
        self.addCleanup(process_patch.stop)
        self.runner.run = Mock(side_effect=self.simulate_command)
        disk_patch = patch.object(deploy.shutil, 'disk_usage', return_value=SimpleNamespace(free=10 * 1024 ** 3))
        self.disk = disk_patch.start()
        self.addCleanup(disk_patch.stop)
        self.failure = None
        self.restored_counts = self.counts.copy()

    def simulate_command(self, args, **options):
        args = list(map(str, args))
        executable = Path(args[0]).name
        if self.failure == executable or (self.failure == 'restore' and executable == 'pg_restore' and '--list' not in args):
            raise deploy.DeploymentError('synthetic command failure: ' + executable)
        if executable == 'pg_dump':
            options['stdout'].write(b'synthetic verified dump')
        elif executable == 'pg_restore' and '--list' in args:
            options['stdout'].write(b'synthetic archive table of contents')
        elif executable == 'tar':
            Path(args[2]).write_bytes(b'synthetic upload archive')
        elif 'counts' in args:
            return json.dumps(self.restored_counts).encode()
        elif executable == 'psql':
            return b'16000000\n'
        elif executable == 'du':
            return b'91000000\t/persistent-data\n'
        return b''

    def commands(self, executable):
        return [list(map(str, item.args[0])) for item in self.runner.run.call_args_list
                if Path(str(item.args[0][0])).name == executable]

    def assert_only_generated_scratch_dropped(self):
        drops = self.commands('dropdb')
        self.assertEqual(len(drops), 1)
        self.assertEqual(drops[0][:2], ['dropdb', '--force'])
        self.assertRegex(drops[0][2], r'^padlupp_verify_[0-9a-f]{12}$')
        self.assertNotEqual(drops[0][2], 'padlupp')
        self.assertEqual(self.commands('createdb')[0][-1], drops[0][2])
        return drops[0][2]

    def test_full_restore_uses_exact_exported_snapshot_and_only_generated_scratch_database(self):
        self.runner.backup_database_and_uploads()
        dump = self.commands('pg_dump')
        self.assertEqual(dump, [[
            'pg_dump', '--format=custom', '--snapshot=' + self.snapshot['snapshot'], 'padlupp',
        ]])
        scratch = self.assert_only_generated_scratch_dropped()
        self.assertEqual(self.commands('pg_restore')[1], [
            'pg_restore', '--exit-on-error', '--no-owner', '--no-privileges', '--dbname=' + scratch,
        ])
        count_calls = [item for item in self.runner.run.call_args_list if 'counts' in item.args[0]]
        self.assertEqual(len(count_calls), 1)
        self.assertEqual(str(count_calls[0].args[0][-1]), scratch)
        self.assertEqual(json.loads((self.runner.backup / 'snapshot-counts.json').read_text()), self.counts)
        checksums = json.loads((self.runner.backup / 'checksums.json').read_text())
        self.assertIs(checksums['restore_verified'], True)
        for name in ('database.dump', 'uploads.tar.gz', 'runtime-config.tar.gz'):
            self.assertEqual(checksums[name], deploy.digest(self.runner.backup / name))
        self.assertTrue(any(args[-3:] == ['-C', '/var/lib/padlupp', '.'] for args in self.commands('tar')))
        self.holder.wait.assert_called_once_with(timeout=30)

    def test_restore_count_mismatch_never_marks_backup_verified_but_drops_own_scratch(self):
        self.restored_counts['api_message'] -= 1
        with self.assertRaisesRegex(deploy.DeploymentError, 'exact dump snapshot'):
            self.runner.backup_database_and_uploads()
        self.assert_only_generated_scratch_dropped()
        self.assertFalse((self.runner.backup / 'checksums.json').exists())
        self.assertEqual(self.commands('tar'), [])

    def test_restore_failure_still_only_drops_own_scratch_and_never_uploads_or_verifies(self):
        self.failure = 'restore'
        with self.assertRaisesRegex(deploy.DeploymentError, 'pg_restore'):
            self.runner.backup_database_and_uploads()
        self.assert_only_generated_scratch_dropped()
        self.assertFalse((self.runner.backup / 'checksums.json').exists())
        self.assertEqual(self.commands('tar'), [])

    def test_failed_createdb_never_drops_a_database_it_did_not_create(self):
        self.failure = 'createdb'
        with self.assertRaisesRegex(deploy.DeploymentError, 'createdb'):
            self.runner.backup_database_and_uploads()
        self.assertEqual(self.commands('dropdb'), [])
        self.assertEqual(len(self.commands('pg_restore')), 1)  # List only, no restore.
        self.assertFalse((self.runner.backup / 'checksums.json').exists())

    def test_holder_pipe_close_does_not_mask_original_dump_failure_and_process_is_reaped(self):
        self.failure = 'pg_dump'
        self.holder.stdin.write.side_effect = BrokenPipeError('synthetic write failure')
        self.holder.stdin.close.side_effect = BrokenPipeError('synthetic close failure')
        with self.assertRaisesRegex(deploy.DeploymentError, 'pg_dump'):
            self.runner.backup_database_and_uploads()
        self.holder.stdin.close.assert_called_once_with()
        self.holder.wait.assert_called_once_with(timeout=30)
        self.assertEqual(self.commands('createdb'), [])
        self.assertEqual(self.commands('dropdb'), [])

    def test_holder_pipe_close_does_not_mask_empty_snapshot_error(self):
        self.holder.stdout = io.BytesIO(b'')
        self.holder.returncode = 1
        self.holder.stdin.close.side_effect = BrokenPipeError('synthetic close failure')
        with self.assertRaises((json.JSONDecodeError, deploy.DeploymentError)) as caught:
            self.runner.backup_database_and_uploads()
        self.assertNotIsInstance(caught.exception, BrokenPipeError)
        self.holder.wait.assert_called_once_with(timeout=30)
        self.assertTrue(all(Path(str(item.args[0][0])).name in {'psql', 'du'}
                            for item in self.runner.run.call_args_list))

    def test_insufficient_capacity_blocks_before_snapshot_or_any_backup_writes(self):
        self.disk.return_value = SimpleNamespace(free=2 * 1024 ** 3)
        with self.assertRaisesRegex(deploy.DeploymentError, 'insufficient capacity'):
            self.runner.backup_database_and_uploads()
        self.popen.assert_not_called()
        self.assertFalse(self.runner.backup.exists())

    def test_nonzero_holder_exit_blocks_restore_even_after_a_successful_dump(self):
        self.holder.returncode = 1
        with self.assertRaisesRegex(deploy.DeploymentError, 'snapshot holder failed'):
            self.runner.backup_database_and_uploads()
        self.assertEqual(self.commands('createdb'), [])
        self.assertEqual(self.commands('pg_restore'), [])
        self.assertFalse((self.runner.backup / 'checksums.json').exists())

    def test_upload_archive_failure_never_marks_backup_verified(self):
        self.failure = 'tar'
        with self.assertRaisesRegex(deploy.DeploymentError, 'tar'):
            self.runner.backup_database_and_uploads()
        self.assert_only_generated_scratch_dropped()
        self.assertFalse((self.runner.backup / 'checksums.json').exists())


class BackendPreparationTests(unittest.TestCase):
    audit = {'debug': False, 'engine': 'postgresql', 'database': 'padlupp', 'media': '/var/lib/padlupp/assets',
             'private_media': '/var/lib/padlupp/private-media'}

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.release = Path(temporary.name) / 'candidate'
        self.release.mkdir()
        self.runner = deploy.Deployer.__new__(deploy.Deployer)
        self.runner.target = 'backend'
        self.events = []
        self.runner.run = Mock(side_effect=self.run_command)
        self.runner.backup_database_and_uploads = Mock(side_effect=lambda: self.events.append('backup'))
        modules = {
            'pwd': SimpleNamespace(getpwnam=Mock(return_value=SimpleNamespace(pw_uid=12345))),
            'grp': SimpleNamespace(getgrnam=Mock(return_value=SimpleNamespace(gr_gid=33))),
        }
        for patcher in (patch.dict(sys.modules, modules), patch.object(deploy.os, 'chown', create=True),
                        patch.object(deploy, 'ownership', side_effect=lambda *_: self.events.append('ownership'))):
            patcher.start()
            self.addCleanup(patcher.stop)

    def run_command(self, args, **options):
        args = list(map(str, args))
        if any(Path(item).name == 'runtime_audit.py' for item in args):
            return json.dumps(self.audit).encode()
        if 'safe_deploy_migrate' in args:
            self.events.append('apply' if '--apply' in args else 'preflight')
        return b''

    def test_root_owned_source_app_user_pip_and_verified_backup_precede_migration_apply(self):
        self.runner.prepare_backend(self.release)
        self.assertEqual(self.events, ['ownership', 'preflight', 'backup', 'apply'])
        pip = [item for item in self.runner.run.call_args_list if 'pip' in item.args[0]]
        self.assertEqual(len(pip), 1)
        self.assertEqual(pip[0].kwargs['user'], 'padlupp-app')
        for item in self.runner.run.call_args_list:
            self.assertEqual(item.kwargs['user'], 'padlupp-app')
            if 'migrate' in item.args[0]:
                self.assertIn('--check', item.args[0])
        applies = [item for item in self.runner.run.call_args_list if '--apply' in item.args[0]]
        self.assertEqual(len(applies), 1)
        self.assertIn('safe_deploy_migrate', applies[0].args[0])

    def test_unverified_backup_never_reaches_apply_or_activation(self):
        self.runner.backup_database_and_uploads.side_effect = deploy.DeploymentError('restore failed')
        with self.assertRaisesRegex(deploy.DeploymentError, 'restore failed'):
            self.runner.prepare_backend(self.release)
        self.assertNotIn('apply', self.events)
        self.assertFalse(any('--apply' in item.args[0] for item in self.runner.run.call_args_list))

    def test_storage_or_database_drift_blocks_before_backup_or_migrations(self):
        for key, value in (('debug', True), ('engine', 'sqlite'), ('database', 'wrong-db'),
                           ('media', '/tmp/assets'), ('private_media', '/tmp/evidence')):
            with self.subTest(key=key):
                candidate = self.release / key
                candidate.mkdir()
                self.audit = {**type(self).audit, key: value}
                with self.assertRaisesRegex(deploy.DeploymentError, 'persistent production storage'):
                    self.runner.prepare_backend(candidate)
                self.runner.backup_database_and_uploads.assert_not_called()
                self.assertNotIn('preflight', self.events)
                self.assertNotIn('apply', self.events)


class InstallerSafetyTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.sandbox = Path(temporary.name)
        self.root = self.sandbox / 'controller'
        self.home = self.sandbox / 'deployer'
        self.backups = self.sandbox / 'backups'
        self.baseline = self.backups / 'verified-baseline'
        self.baseline.mkdir(parents=True)
        checks = {'restore_verified': True}
        for name in ('database.dump', 'uploads.tar.gz', 'runtime-config.tar.gz'):
            path = self.baseline / name
            path.write_bytes(b'synthetic verified backup')
            checks[name] = deploy.digest(path)
        (self.baseline / 'checksums.json').write_text(json.dumps(checks))
        self.keys = self.sandbox / 'keys'
        self.keys.mkdir()
        key_blob = b'\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20' + b'\x01' * 32
        public = 'ssh-ed25519 ' + base64.b64encode(key_blob).decode() + ' synthetic-test-only\n'
        for target in ('web', 'backend'):
            (self.keys / (target + '.pub')).write_text(public)
        self.web = self.host_path('/etc/nginx/sites-available/padlupp')
        self.api = self.host_path('/etc/nginx/sites-available/padluppcore')
        self.marketing = self.host_path('/etc/nginx/sites-available/padluppsite')
        self.dropin = self.host_path('/etc/systemd/system/padluppcore-daphne.service.d/20-automatic-release.conf')
        self.authorized = self.home / '.ssh/authorized_keys'
        self.sudoers = self.host_path('/etc/sudoers.d/padlupp-deploy')
        self.sudoers.parent.mkdir(parents=True)
        self.web.parent.mkdir(parents=True)
        self.web.write_text('server {\n root /var/www/padlupp-releases/legacy;\n}\n')
        self.api.write_text('location /static/ { alias /padlupp/padluppcore/staticfiles/; }\n')
        self.marketing.write_text('deferred marketing configuration -- must not change\n')
        self.marketing_link = self.root / 'current/marketing'
        self.marketing_link.parent.mkdir(parents=True)
        self.marketing_link.write_text('untouched marketing link sentinel')
        self.account = SimpleNamespace(pw_dir=str(self.home), pw_gid=12345, pw_uid=12345)
        for patcher in (patch.object(installer, 'Path', side_effect=self.host_path),
                        patch.object(installer, 'ROOT', self.root),
                        patch.object(installer, 'HOME', self.home),
                        patch.object(installer, 'BACKUPS', self.backups),
                        patch.object(installer, 'HELPERS', self.sandbox / 'helpers'),
                        patch.object(installer.os, 'chown', create=True),
                        patch.object(installer.pwd, 'getpwnam', return_value=self.account)):
            patcher.start()
            self.addCleanup(patcher.stop)
        command_patch = patch.object(installer, 'run')
        self.run = command_patch.start()
        self.addCleanup(command_patch.stop)
        ssh_patch = patch.object(installer, 'authorize_ssh')
        ssh_patch.start()
        self.addCleanup(ssh_patch.stop)
        if os.name != 'posix':
            # Windows chmod(0440) sets a read-only attribute that prevents unlink;
            # POSIX root can unlink that file. Native mode checks remain for CI.
            mode_patch = patch.object(Path, 'chmod', autospec=True)
            mode_patch.start()
            self.addCleanup(mode_patch.stop)

    def host_path(self, value):
        value = os.fspath(value)
        candidate = Path(value)
        if candidate == self.sandbox or self.sandbox in candidate.parents:
            return candidate
        if value.startswith('/'):
            return self.sandbox / 'host' / value.lstrip('/')
        return candidate

    def state(self):
        paths = (self.web, self.api, self.dropin, self.authorized, self.sudoers,
                 self.marketing, self.marketing_link)
        return {str(path.relative_to(self.sandbox)): path.read_bytes() if path.is_file() else None for path in paths}

    def test_enable_success_scopes_keys_and_sudo_to_web_backend_and_leaves_marketing_untouched(self):
        marketing_before = self.marketing.read_bytes(), self.marketing_link.read_bytes()
        installer.enable(self.keys, self.baseline)
        authorized = self.authorized.read_text().splitlines()
        self.assertEqual(len(authorized), 2)
        for line, target in zip(authorized, ('web', 'backend')):
            self.assertTrue(line.startswith('restrict,command='))
            self.assertIn(f'/ssh_entry.py {target}" ', line)
            self.assertNotIn('marketing', line)
        sudoers = self.sudoers.read_text()
        self.assertIn('/usr/local/sbin/padlupp-deploy web *', sudoers)
        self.assertIn('/usr/local/sbin/padlupp-deploy backend *', sudoers)
        self.assertNotIn('marketing', sudoers)
        self.assertEqual((self.marketing.read_bytes(), self.marketing_link.read_bytes()), marketing_before)
        self.assertFalse((self.keys / 'marketing.pub').exists())

    def test_invalid_baseline_or_missing_runtime_backup_blocks_before_config_or_auth_changes(self):
        checks_path = self.baseline / 'checksums.json'
        original_checks = json.loads(checks_path.read_text())
        cases = [
            {**original_checks, 'restore_verified': False},
            {**original_checks, 'database.dump': '0' * 64},
            {**original_checks, 'uploads.tar.gz': '0' * 64},
            {**original_checks, 'runtime-config.tar.gz': '0' * 64},
        ]
        original = self.state()
        for checks in cases:
            with self.subTest(checks=checks):
                checks_path.write_text(json.dumps(checks))
                with self.assertRaises(SystemExit):
                    installer.enable(self.keys, self.baseline)
                self.assertEqual(self.state(), original)
                self.run.assert_not_called()
        checks_path.write_text(json.dumps(original_checks))
        (self.baseline / 'runtime-config.tar.gz').unlink()
        with self.assertRaises((SystemExit, FileNotFoundError)):
            installer.enable(self.keys, self.baseline)
        self.assertEqual(self.state(), original)
        self.run.assert_not_called()

    def assert_failed_enable_restores_state(self, executable, occurrence=1):
        original = self.state()
        seen = 0

        def run(*args):
            nonlocal seen
            if str(args[0]) == executable:
                seen += 1
                if seen == occurrence:
                    raise subprocess.CalledProcessError(1, args)

        self.run.side_effect = run
        with self.assertRaises(subprocess.CalledProcessError):
            installer.enable(self.keys, self.baseline)
        self.assertEqual(self.state(), original)

    def test_visudo_failure_restores_configs_and_removes_new_privileges(self):
        self.assert_failed_enable_restores_state('visudo')

    def test_sshd_failure_restores_configs_and_removes_new_privileges(self):
        # First sshd check is prevalidation; fail the check after keys/policy exist.
        self.assert_failed_enable_restores_state('sshd', occurrence=2)

    def test_authorized_key_ownership_failure_removes_partial_keys_and_restores_configs(self):
        original = self.state()

        def chown(path, *args, **kwargs):
            if path == self.authorized:
                raise PermissionError('synthetic authorized-key ownership failure')

        with patch.object(installer.os, 'chown', side_effect=chown, create=True):
            with self.assertRaisesRegex(PermissionError, 'authorized-key ownership'):
                installer.enable(self.keys, self.baseline)
        self.assertEqual(self.state(), original)

    def test_partial_sudo_install_failure_removes_new_policy_and_keys_and_restores_configs(self):
        original = self.state()

        def finish_policy(path, *args, **kwargs):
            if path == self.sudoers:
                self.assertTrue(path.exists())
                raise PermissionError('synthetic sudo policy install failure')

        with patch.object(installer.os, 'chown', side_effect=finish_policy, create=True):
            with self.assertRaisesRegex(PermissionError, 'sudo policy install'):
                installer.enable(self.keys, self.baseline)
        self.assertEqual(self.state(), original)

    def test_existing_authorized_keys_are_preserved_without_any_activation_changes(self):
        self.authorized.parent.mkdir(parents=True)
        self.authorized.write_text('preexisting keys must remain unchanged\n')
        original = self.state()
        with self.assertRaises(SystemExit):
            installer.enable(self.keys, self.baseline)
        self.assertEqual(self.state(), original)

    def test_existing_sudo_policy_is_preserved_without_creating_keys_or_changing_live_configs(self):
        self.sudoers.write_text('preexisting sudo policy must remain unchanged\n')
        original = self.state()
        with self.assertRaises(SystemExit):
            installer.enable(self.keys, self.baseline)
        self.assertEqual(self.state(), original)

    def test_unexpected_existing_account_home_blocks_before_config_changes(self):
        self.account.pw_dir = str(self.sandbox / 'unexpected-home')
        original = self.state()
        with self.assertRaises(SystemExit):
            installer.enable(self.keys, self.baseline)
        self.assertEqual(self.state(), original)

    def test_prepare_does_not_touch_marketing_or_create_any_deployment_authorization(self):
        source = self.sandbox / 'source'
        source.mkdir()
        for name in ('db_snapshot.py', 'runtime_audit.py', 'ssh_entry.py', 'deploy.py'):
            (source / name).write_text('# synthetic helper, never executed\n')
        original = self.state()
        with patch.object(installer, 'current_web_root', return_value=self.sandbox / 'legacy-web'), \
                patch.object(Path, 'symlink_to', autospec=True) as links:
            installer.prepare(source)
        self.assertEqual(self.state(), original)
        self.assertEqual({item.args[0].name for item in links.call_args_list}, {'web', 'backend'})
        self.run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
