"""`siem-dashboard-admin`: the root-only command for the dashboard administrator.

There is no setup page and no recovery route over the network: an account can only come from here. Passwords are read
from the terminal with no echo, or from standard input with --password-stdin. They are never accepted as an argument, so
they stay out of shell history and process lists. This is a dashboard account, and it is unrelated to any Linux account.
"""
import argparse
import getpass
import grp
import json
import os
import pwd
import sys

from .auth import Auth, AuthError
from .config import ConfigError, load

SERVICE_USER = 'siem-dashboard'


def read_password(args, confirm=True):
    if args.password_stdin:
        return sys.stdin.readline().rstrip('\r\n')
    first = getpass.getpass('New dashboard password: ')
    if confirm and first != getpass.getpass('Again: '):
        raise AuthError('the passwords do not match')
    return first


def keep_owner(path):
    """Root ran this, so the service must still own its file afterwards."""
    try:
        user = pwd.getpwnam(SERVICE_USER)
        group = grp.getgrnam(SERVICE_USER)
        os.chown(path, user.pw_uid, group.gr_gid)
    except (KeyError, FileNotFoundError):
        pass


def main(argv=None):
    parser = argparse.ArgumentParser(prog='siem-dashboard-admin', description='Root-only administration of the single dashboard account.')
    parser.add_argument('--config', default='/home/linux/siem/config/dashboard/dashboard.yaml')
    commands = parser.add_subparsers(dest='command', required=True)
    create = commands.add_parser('create', help='create the administrator')
    create.add_argument('username')
    create.add_argument('--password-stdin', action='store_true')
    reset = commands.add_parser('reset-password', help='replace the password, and end every session')
    reset.add_argument('--password-stdin', action='store_true')
    for name, text in (('status', 'show the state of sign-in'), ('revoke-sessions', 'end every session'), ('disable', 'refuse all sign-in'), ('enable', 'allow sign-in again'), ('unlock', 'clear sign-in throttling'), ('remove', 'delete the account. The audit trail stays'), ('verify-audit', 'check the audit chain')):
        commands.add_parser(name, help=text)
    args = parser.parse_args(argv)
    if os.geteuid() != 0:
        print('siem-dashboard-admin: run this as root, on the server', file=sys.stderr)
        return 2
    try:
        config = load(args.config)
        auth = Auth(config['state_file'], config)
        keep_owner(config['state_file'])
        if args.command == 'create':
            auth.create(args.username, read_password(args))
            print('Administrator created. This account is for the dashboard only.')
        elif args.command == 'reset-password':
            auth.set_password(read_password(args), 'root-local')
            print('Password replaced, and every session ended.')
        elif args.command == 'status':
            print(json.dumps(auth.status(), indent=1))
        elif args.command == 'revoke-sessions':
            print(f'{auth.revoke_all()} sessions ended.')
        elif args.command == 'disable':
            auth.set_disabled(True)
            print('Sign-in disabled, and every session ended.')
        elif args.command == 'enable':
            auth.set_disabled(False)
            print('Sign-in enabled.')
        elif args.command == 'unlock':
            auth.unlock()
            print('Throttling cleared.')
        elif args.command == 'remove':
            auth.remove()
            print('Administrator removed. The audit trail stays.')
        elif args.command == 'verify-audit':
            result = auth.audit_verify()
            print(json.dumps(result, indent=1))
            return 0 if result['intact'] else 1
        keep_owner(config['state_file'])
        return 0
    except (AuthError, ConfigError) as error:
        print(f'siem-dashboard-admin: {error}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
