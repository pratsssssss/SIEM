"""ECS normalization, through the aggregator's real transform. All events are synthetic fixtures."""
import unittest

from helpers import get, normalize_transforms, opened, run_transforms

SUDO, SU, USERADD, USERMOD, CRON, SYSTEMD, SSHD = '/usr/bin/sudo', '/usr/bin/su', '/usr/sbin/useradd', '/usr/sbin/usermod', '/usr/sbin/cron', '/usr/lib/systemd/systemd', '/usr/sbin/sshd'
LINE = ' alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/id -u'
CASES = {
    'sudo ran': (opened('sudo', LINE, SUDO), {'event.dataset': 'linux.auth', 'event.action': 'sudo-command', 'event.outcome': 'success', 'event.category': ['process'], 'user.name': 'alice', 'user.effective.name': 'root', 'process.command_line': '/usr/bin/id -u'}),
    'sudo bad password': (opened('sudo', 'alice : 3 incorrect password attempts ; TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/bin/ls', SUDO), {'event.action': 'sudo-auth-failed', 'event.outcome': 'failure', 'event.type': ['denied'], 'user.name': 'alice'}),
    'sudo refused': (opened('sudo', 'bob : user NOT in sudoers ; TTY=pts/1 ; PWD=/ ; USER=root ; COMMAND=/bin/ls', SUDO), {'event.action': 'sudo-not-permitted', 'event.outcome': 'failure'}),
    'su': (opened('su', '(to root) alice on pts/0', SU), {'event.action': 'su-session', 'event.outcome': 'success', 'user.name': 'alice', 'user.effective.name': 'root'}),
    'su failed': (opened('su', 'FAILED SU (to root) alice on pts/0', SU), {'event.action': 'su-failed', 'event.outcome': 'failure'}),
    'session opened': (opened('su', 'pam_unix(su:session): session opened for user root(uid=0) by alice(uid=1000)', SU), {'event.action': 'session-opened', 'event.category': ['session'], 'user.name': 'alice', 'user.effective.name': 'root', 'user.id': '0'}),
    'session closed': (opened('su', 'pam_unix(su:session): session closed for user root', SU), {'event.action': 'session-closed', 'event.type': ['end'], 'user.effective.name': 'root'}),
    'pam failure': (opened('sudo', 'pam_unix(sudo:auth): authentication failure; logname=alice uid=1000 euid=0 tty=/dev/pts/0 ruser=alice rhost=  user=alice', SUDO), {'event.action': 'pam-auth-failed', 'event.outcome': 'failure', 'user.name': 'alice', 'user.target.name': 'alice', 'source.ip': None}),
    'pam failure remote': (opened('sshd', 'pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=192.0.2.9  user=bob', SSHD), {'event.action': 'pam-auth-failed', 'source.ip': '192.0.2.9', 'user.target.name': 'bob'}),
    'user created': (opened('useradd', 'new user: name=mallory, UID=1001, GID=1001, home=/home/mallory, shell=/bin/bash, from=none', USERADD), {'event.action': 'user-created', 'event.category': ['iam'], 'event.type': ['creation'], 'user.target.name': 'mallory', 'user.id': '1001'}),
    'user deleted': (opened('userdel', "delete user 'mallory'", '/usr/sbin/userdel'), {'event.action': 'user-deleted', 'user.target.name': 'mallory'}),
    'group created': (opened('groupadd', 'new group: name=ops, GID=1005', '/usr/sbin/groupadd'), {'event.action': 'group-created', 'group.name': 'ops'}),
    'added to group': (opened('usermod', "add 'mallory' to group 'sudo'", USERMOD), {'event.action': 'group-member-added', 'user.target.name': 'mallory', 'group.name': 'sudo'}),
    'removed from group': (opened('usermod', "delete 'mallory' from group 'sudo'", USERMOD), {'event.action': 'group-member-removed', 'group.name': 'sudo'}),
    'gpasswd': (opened('gpasswd', 'user mallory added by root to group sudo', '/usr/bin/gpasswd'), {'event.action': 'group-member-added', 'user.name': 'root', 'user.target.name': 'mallory', 'group.name': 'sudo'}),
    'password changed': (opened('passwd', 'password changed for alice', '/usr/bin/passwd'), {'event.action': 'password-changed', 'user.target.name': 'alice'}),
    'ssh accepted': (opened('sshd', 'Accepted publickey for alice from 192.0.2.7 port 50022 ssh2: ED25519 SHA256:abc', SSHD), {'event.action': 'ssh-login', 'event.outcome': 'success', 'user.name': 'alice', 'source.ip': '192.0.2.7', 'source.port': 50022}),
    'ssh failed': (opened('sshd', 'Failed password for invalid user admin from 2001:db8::5 port 2222 ssh2', SSHD), {'event.action': 'ssh-login-failed', 'event.outcome': 'failure', 'user.name': 'admin', 'source.ip': '2001:db8::5'}),
    'ssh bad address': (opened('sshd', 'Failed password for root from not-an-address port 99999 ssh2', SSHD), {'event.action': 'ssh-login-failed', 'source.ip': None, 'source.port': None}),
    'cron ran': (opened('CRON', '(root) CMD (test -x /usr/sbin/anacron)', CRON), {'event.dataset': 'linux.cron', 'event.action': 'scheduled-task-run', 'user.name': 'root', 'process.command_line': 'test -x /usr/sbin/anacron'}),
    'crontab replaced': (opened('crontab', '(alice) REPLACE (alice)', '/usr/bin/crontab'), {'event.dataset': 'linux.cron', 'event.action': 'crontab-replaced', 'user.name': 'alice', 'user.target.name': 'alice'}),
    'crontab with no exe': (opened('crontab', '(root) REPLACE (alice)', None), {'event.action': 'crontab-replaced', 'user.target.name': 'alice', 'labels.attribution': 'process-name', 'journald.exe_verified': False}),
    'crontab listed': (opened('crontab', '(alice) LIST (alice)', '/usr/bin/crontab'), {'event.action': 'crontab-listed', 'event.type': ['access']}),
    'service started': (opened('systemd', 'Started ssh.service', SYSTEMD, {'TargetUnit': 'ssh.service', 'JobType': 'start', 'JobResult': 'done'}), {'event.dataset': 'linux.system', 'event.action': 'service-started', 'service.name': 'ssh'}),
    'service stopped': (opened('systemd', 'Stopped x.service', SYSTEMD, {'TargetUnit': 'x.service', 'JobType': 'stop', 'JobResult': 'done'}), {'event.action': 'service-stopped', 'event.type': ['end']}),
    'service failed': (opened('systemd', "x.service: Failed with result 'signal'.", SYSTEMD, {'TargetUnit': 'x.service', 'UnitResult': 'signal'}, level='4'), {'event.action': 'service-failed', 'event.outcome': 'failure', 'service.name': 'x', 'log.level': 'warning'}),
    'session by logind': (opened('systemd-logind', 'New session 42 of user alice.', '/usr/lib/systemd/systemd-logind'), {'event.action': 'session-opened', 'user.name': 'alice'}),
    'kernel': (opened('kernel', 'oom-killer invoked', None, {'Transport': 'kernel'}, level='3'), {'event.dataset': 'linux.kernel', 'event.action': 'log-entry', 'log.level': 'error'}),
    'ordinary program': (opened('someapp', 'hello', '/usr/bin/someapp'), {'event.dataset': 'linux.system', 'event.action': 'log-entry', 'labels.attribution': None}),
    'package installed': (opened('dpkg', '2026-11-01 10:00:00 install sl:amd64 <none> 5.02-1', None, channel='linux-package'), {'event.dataset': 'linux.package', 'event.action': 'package-installed', 'event.type': ['installation'], 'package.name': 'sl:amd64', 'package.version': '5.02-1'}),
    'package upgraded': (opened('dpkg', '2026-11-01 10:00:00 upgrade curl:amd64 8.5.0-1 8.5.0-2', None, channel='linux-package'), {'event.action': 'package-upgraded', 'package.previous_version': '8.5.0-1'}),
    'package removed': (opened('dpkg', '2026-11-01 10:00:00 remove sl:amd64 5.02-1 <none>', None, channel='linux-package'), {'event.action': 'package-removed', 'event.type': ['deletion']}),
    'package line unreadable': (opened('dpkg', 'garbled', None, channel='linux-package'), {'event.dataset': 'linux.package', 'event.action': 'log-entry'}),
    'no message': (opened('someapp', None, '/usr/bin/x'), {'event.action': 'log-entry', 'message': None}),
    'event data absent': ({**opened('x', 'y'), 'event_data': None}, {'event.action': 'log-entry', 'process.pid': None}),
    'bad time keeps the event': (opened('x', 'y', '/usr/bin/x', timestamp=None), {'event.action': 'log-entry'}),
    'multiline text': (opened('app', 'first\nsecond\nthird', '/usr/bin/app'), {'message': 'first\nsecond\nthird'}),
}
SPOOFS = {
    'sudo from logger': opened('sudo', LINE, '/usr/bin/logger'),
    'sudo with no exe': opened('sudo', LINE, None),
    'useradd from a script': opened('useradd', 'new user: name=x, UID=0, GID=0', '/usr/bin/python3'),
    'group add from bash': opened('usermod', "add 'x' to group 'sudo'", '/usr/bin/bash'),
    'ssh from logger': opened('sshd', 'Accepted password for root from 192.0.2.1 port 22 ssh2', '/usr/bin/logger'),
    'service failed from a user': opened('systemd', 'vector.service: Failed', '/usr/bin/logger', {'TargetUnit': 'vector.service', 'UnitResult': 'signal'}),
    'cron from logger': opened('CRON', '(root) CMD (x)', '/usr/bin/logger'),
    'crontab from nc': opened('crontab', '(root) REPLACE (root)', '/usr/bin/nc'),
    'crontab name from logger': opened('crontab', '(root) REPLACE (root)', None, {'Comm': 'logger'}),
}


class Normalize(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cases = list(CASES.values())
        spoofs = list(SPOOFS.values())
        out = run_transforms(normalize_transforms(), ['normalize_linux'], [c[0] for c in cases] + spoofs)
        cls.by_id = {e['event']['id']: e for e in out}
        cls.cases = cases
        cls.spoofs = spoofs

    def test_every_case(self):
        for name, (event, expected) in CASES.items():
            found = self.by_id.get(event['event_uid'])
            self.assertIsNotNone(found, f'{name}: no output')
            for path, value in expected.items():
                self.assertEqual(get(found, path), value, f'{name}: {path}')

    def test_common_fields(self):
        event = self.by_id[CASES['sudo ran'][0]['event_uid']]
        self.assertEqual(event['@timestamp'], '2026-11-01T10:00:00.000Z')
        self.assertEqual(event['siem_index'], '2026.11.01')
        self.assertEqual(get(event, 'host.name'), 'testhost-wsl')
        self.assertEqual(get(event, 'host.id'), 'cd' * 16)
        self.assertEqual(get(event, 'host.os.name'), 'Ubuntu')
        self.assertEqual(get(event, 'host.os.version'), '24.04')
        self.assertEqual(get(event, 'host.os.type'), 'linux')
        self.assertEqual(get(event, 'event.kind'), 'event')
        self.assertEqual(get(event, 'event.module'), 'linux')
        self.assertEqual(get(event, 'event.provider'), 'sudo')
        self.assertEqual(get(event, 'process.pid'), 4242)
        self.assertEqual(get(event, 'process.executable'), '/usr/bin/sudo')
        self.assertEqual(get(event, 'labels.source_role'), 'wsl_infrastructure')
        self.assertEqual(get(event, 'journald.exe_verified'), True)
        self.assertEqual(get(event, 'siem.kafka.offset'), 7)

    def test_os_labels_do_not_stay_in_labels(self):
        labels = self.by_id[CASES['su'][0]['event_uid']]['labels']
        self.assertNotIn('os_name', labels)

    def test_unavailable_fields_are_absent_not_invented(self):
        event = self.by_id[CASES['su'][0]['event_uid']]
        for path in ('process.parent.pid', 'source.ip', 'destination.ip', 'event.code', 'user.domain'):
            self.assertIsNone(get(event, path), path)

    def test_a_program_cannot_claim_to_be_another(self):
        for name, event in SPOOFS.items():
            found = self.by_id[event['event_uid']]
            self.assertEqual(get(found, 'event.action'), 'unverified-log-entry', name)
            self.assertEqual(get(found, 'labels.attribution'), 'unverified', name)
            self.assertEqual(get(found, 'journald.exe_verified'), False, name)
            self.assertEqual(get(found, 'event.outcome'), 'unknown', name)
            for path in ('user.name', 'user.target.name', 'group.name', 'source.ip', 'service.name'):
                self.assertIsNone(get(found, path), f'{name}: {path}')

    def test_text_cannot_inject_fields_into_a_real_sudo_line(self):
        crafted = ' alice : TTY=pts/0 ; PWD=/tmp/x ; USER=nobody ; COMMAND=/bin/ls ; USER=root ; COMMAND=/bin/fake'
        out = run_transforms(normalize_transforms(), ['normalize_linux'], [opened('sudo', crafted, SUDO)])
        self.assertEqual(get(out[0], 'user.effective.name'), 'nobody')
        self.assertEqual(get(out[0], 'user.name'), 'alice')

    def test_windows_transform_is_not_given_linux_events(self):
        import yaml
        from helpers import AGGREGATOR
        routes = yaml.safe_load(AGGREGATOR.read_text())['transforms']['sort_events']['route']
        self.assertIn('!starts_with', routes['good'])
        self.assertIn('siem-windows-{{ siem_index }}', AGGREGATOR.read_text())


if __name__ == '__main__':
    unittest.main()
