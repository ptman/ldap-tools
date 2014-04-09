#!/usr/bin/env python
# coding: utf-8
# vim: set ts=4 sts=4 sw=4 si ai et ft=python:
#
# Copyright (c) 2014, ZenRobotics Ltd.
# Author: Paul Tötterman <paul.totterman@zenrobotics.com>
#
# Permission to use, copy, modify, and/or distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

"""OpenSSH AuthorizedKeysCommand + LDAP helper.

To run tests:
    python -m doctest sshldapauthkey.py
"""

import ldap
import ldap.filter
import logging
import logging.handlers
import re
import sys

BINDDN = '...'
BINDPW = ''
DEFAULT_OPTIONS = {'no-agent-forwarding': None,
                   'no-port-forwarding': None,
                   'no-pty': None,
                   'no-user-rc': None,
                   'no-X11-forwarding': None}
IGNORE_USERS = ['root']
LDAP_CONF = '/etc/ldap/ldap.conf'
PUBKEY_RE = re.compile(r'''^((?P<options>.*) )?'''
                       r'''(?P<type>ssh-(dss|rsa|ed25519)'''
                       r'''|ecdsa-sha2-nistp(256|384|521)) '''
                       r'''(?P<key>[^ ]*)( (?P<comment>.*))?$''')


def parse_ldap_base():
    """Parse LDAP base from ldap.conf(5)."""
    # pylint: disable-msg=W0141
    ldap_conf = open(LDAP_CONF, 'rb')
    pattern = re.compile(r'^\s*[bB][aA][sS][eE]\s+(.+)\s*$')
    matches = [pattern.search(x) for x in
               ldap_conf.readlines()]
    base = filter(None, matches)[0].group(1)
    return base


def get_ldap_base(conn, persist={}):
    """Find out LDAP base."""
    # pylint: disable-msg=W0102
    if 'base' in persist:
        return persist['base']

    entries = conn.search_s('', ldap.SCOPE_BASE, 'objectClass=*', ('+',))
    attrs = entries[0][1]
    if len(attrs['namingContexts']) == 1:
        base = attrs['namingContexts'][0]
    else:
        base = parse_ldap_base()

    persist['base'] = base

    return base


def format_options(options):
    """Format options dict for authorized_keys entry.

    >>> format_options({'no-pty': None, 'command': '/bin/sh -i'})
    'command="/bin/sh -i",no-pty'
    """
    def format_option(option):
        """Format a single option."""
        if options[option] is None:
            return option
        return '%s="%s"' % (option, options[option])
    return ','.join([format_option(option) for option in options])


def parse_options(options):
    """Parse authorizes_keys entry options into python dict.

    >>> parse_options('command="/bin/sh -i",no-pty,environment="SHELL=/bin/sh"')
    {'environment': 'SHELL=/bin/sh', 'command': '/bin/sh -i', 'no-pty': None}

    Known bugs:

    >>> parse_options('environment="SHELL=bin/sh",environment="HOME=/"')
    {'environment': 'HOME=/'}

    >>> parse_options('command="/bin/echo \\\\"haha\\\\""')
    {'command': '/bin/echo \\\\"haha\\\\'}
    """
    result = {}
    if options is None:
        return result

    for option in options.split(','):
        if '=' in option:
            key, val = option.split('=', 1)
            result[key.lower()] = val.strip('"')
        else:
            result[option] = None

    return result


def main(args):
    """Main function."""
    # pylint: disable-msg=R0914
    logging.getLogger().setLevel(logging.INFO)
    logging.getLogger().addHandler(logging.StreamHandler(sys.stderr))
    loghandler = logging.handlers.SysLogHandler(address='/dev/log',
            facility=logging.handlers.SysLogHandler.LOG_AUTH)
    loghandler.setFormatter(logging.Formatter('sshldapauthkey %(levelname)-9s'
                                              '%(message)s'))
    logging.getLogger().addHandler(loghandler)

    if len(args) != 1:
        logging.critical('Usage: sshauthkey <USERNAME>')
        sys.exit(1)

    uid = args[0]

    if uid in IGNORE_USERS:
        return

    conn = ldap.initialize(ldap.get_option(ldap.OPT_URI))
    base = get_ldap_base(conn)
    conn.simple_bind_s(BINDDN, BINDPW)

    filterstr = ldap.filter.filter_format('(&(uid=%s)'
                                          '(objectClass=posixAccount)'
                                          '(objectClass=shadowAccount)'
                                          '(objectClass=ldapPublicKey))',
                                          (uid,))
    results = conn.search_s(base, ldap.SCOPE_SUBTREE, filterstr,
                            ('sshPublicKey',))

    if len(results) != 1:
        logging.error('too many results for uid=%s', uid)
        sys.exit(2)

    for result in results:
        dname, attrs = result

        if 'sshPublicKey' in attrs:
            pubkeys = attrs['sshPublicKey']
            for pubkey in pubkeys:
                match = PUBKEY_RE.match(pubkey)
                if not match:
                    logging.warning('Could not parse ssh key in dn %s: %s',
                                    dname, pubkey)
                    continue

                parts = match.groupdict()
                typ = parts['type']
                key = parts['key']
                comment = parts['comment']

                if typ == 'ssh-dss':
                    logging.error('DSA key type is no longer secure')
                    continue

                options = parse_options(parts['options'])

                options.update(DEFAULT_OPTIONS)

                if options is None:
                    print '%s %s %s' % (typ, key, comment)
                else:
                    print '%s %s %s %s' % (format_options(options), typ, key,
                                           comment)


if __name__ == '__main__':
    main(sys.argv[1:])
