#!/usr/bin/env python
# coding: utf-8
#
# Copyright (c) 2009, Paul Tötterman <paul.totterman@iki.fi>
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

'''chsh(1) implementation for LDAP user database'''

import getpass
import ldap
import optparse
import re

ADDUSER_CONF = '/etc/adduser.conf'
SHELLS = '/etc/shells'
LDAP_CONF = '/etc/ldap/ldap.conf'
USERDN = 'uid=%s,ou=People,%s'

def get_default_shell():
    '''Get the default shell for users on this system from adduser.conf(5)'''
    # pylint: disable-msg=W0141
    adduser_conf = open(ADDUSER_CONF, 'rb')
    pattern = re.compile(r'''^\s*DSHELL\s*=\s*(\S+)\s*$''')
    matches = [ pattern.search(x) for x in adduser_conf.readlines() ]
    shell = filter(None, matches)[0].group(1)
    return shell

def get_old_shell(user):
    '''Get the current shell of a user from LDAP'''
    ldapconn = ldap.initialize(ldap.get_option(ldap.OPT_URI))
    userdn = USERDN % (user, get_ldap_base())
    try:
        result = ldapconn.search_s(userdn, ldap.SCOPE_BASE)
        shell = result[0][1]['loginShell'][0]
        return shell
    except ldap.NO_SUCH_OBJECT:
        return None

def is_shell_ok(shell):
    '''Is the shell allowed in shells(5)'''
    # pylint: disable-msg=W0141
    shells = [ x.rstrip() for x in open(SHELLS, 'rb').readlines() ]
    shells = filter(lambda s: s[0] != '#', shells)
    return any(map(lambda s: s == shell, shells))

def get_ldap_base(persist={}):
    '''Get LDAP base from ldap.conf(5)'''
    # pylint: disable-msg=W0141
    if 'base' in persist:
        return persist['base']

    ldap_conf = open(LDAP_CONF, 'rb')
    pattern = re.compile(r'''^\s*[bB][aA][sS][eE]\s+(.+)\s*$''')
    matches = [ pattern.search(x) for x in ldap_conf.readlines() ]
    base = filter(None, matches)[0].group(1)

    persist['base'] = base
    return base

def ldap_connect(binddn, passwd):
    '''Connect to the LDAP server'''
    ldapconn = ldap.initialize(ldap.get_option(ldap.OPT_URI))
    ldapconn.simple_bind_s(binddn, passwd)
    return ldapconn

def change_shell(ldapconn, user, shell):
    '''Change the shell of the specified user'''
    userdn = USERDN % (user, get_ldap_base())
    ldapconn.modify_s(userdn, [(ldap.MOD_REPLACE, 'loginShell', shell)])

def parse_args():
    '''Parse the arguments using optparse'''
    parser = optparse.OptionParser()
    parser.add_option('-s', '--shell', action='store', dest='loginShell',
                      help='new login shell for the user account')
    parser.add_option('-D', '-b', '--bind', '--binddn', action='store',
                      dest='binddn', help='LDAP bind DN')

    try:
        import optcomplete
        optcomplete.autocomplete(parser)
    except ImportError:
        pass

    return parser.parse_args()

def run():
    '''The main function'''
    (opts, args) = parse_args()

    if args:
        user = args[0]
    else:
        user = getpass.getuser()

    default_shell = get_old_shell(user)

    if opts.binddn:
        binddn = opts.binddn
    else:
        binddn = USERDN % (user, get_ldap_base())

    if opts.loginShell:
        new_shell = opts.loginShell
    else:
        print 'Changing the login shell for %s' % user
        print 'Enter the new value, or press ENTER for the default'
        new_shell = raw_input('\tLogin Shell [%s]: ' % default_shell)

    if new_shell == '':
        new_shell = default_shell

    if not is_shell_ok(new_shell):
        print '%s not found in %s' % (new_shell, SHELLS)
        return

    passwd = getpass.getpass('LDAP bind password:')

    ldapconn = ldap_connect(binddn, passwd)
    change_shell(ldapconn, user, new_shell)

if __name__ == '__main__':
    run()
