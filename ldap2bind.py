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

'''Generate bind9 zone file from ldap.'''

import ldap
import optparse
import re

LDAP_CONF = '/etc/ldap/ldap.conf'
NS_RE = re.compile('ns\d+')
RECORD = '%(name)s\t%(ttl)s\t%(class)s\t%(type)s\t%(data)s'

def get_ldap_base(persist={}):
    '''Get LDAP base from ldap.conf(5)'''
    # pylint: disable-msg=W0141,W0102
    if 'base' in persist:
        return persist['base']

    ldap_conf = open(LDAP_CONF, 'rb')
    pattern = re.compile(r'''^\s*[bB][aA][sS][eE]\s+(.+)\s*$''')
    matches = [ pattern.search(x) for x in ldap_conf.readlines() ]
    base = filter(None, matches)[0].group(1)

    persist['base'] = base
    return base

def output_header(zone, ttl):
    '''Output zonefile header.'''
    print '; autogenerated bind zone file by ldap2zone.py'
    print '; vim: set filetype=bindzone:'
    print '$ORIGIN %s.' % zone
    print '$TTL\t%s' % ttl

def output_record(values):
    '''Output a single DNS record.'''
    default_values = {'ttl': '', 'class': 'IN'}
    out_values = default_values.copy()
    out_values.update(values)
    print RECORD % out_values

def generate_zonefile(ds, base, zone):
    '''Generates the zonefile from ldap. Does the actual work.'''
    # pylint: disable-msg=C0103
    hosts = ds.search_s(base,
                        ldap.SCOPE_SUBTREE,
                        '(objectClass=ipHost)',
                        ['ipHostNumber', 'cn'])

    output_header(zone, 60)
    output_record({'name': '@',
                   'type': 'SOA',
                   'data': ('ns1.%(zone)s. hostmaster.%(zone)s. (1 1200 180 '
                            '1209600 60)' % {'zone': zone})})

    for host in hosts:
        dn = [rdn.split('=') for rdn in host[0].split(',')]
        dncn = [v for k, v in dn if k == 'cn'][0]
        attrs = host[1]
        output_record({'name': dncn,
                       'type': 'A',
                       'data': attrs['ipHostNumber'][0]})
        for cn in attrs['cn']:
            if cn == dncn:
                continue
            if cn == '@':
                output_record({'name': cn,
                               'type': 'A',
                               'data': attrs['ipHostNumber'][0]})
            elif NS_RE.match(cn):
                output_record({'name': '@',
                               'type': 'NS',
                               'data': cn})
                output_record({'name': cn,
                               'type': 'A',
                               'data': attrs['ipHostNumber'][0]})
            else:
                output_record({'name': cn,
                               'type': 'CNAME',
                               'data': dncn})

def run():
    '''The main function'''
    parser = optparse.OptionParser()
    parser.add_option('-D',
                      '--binddn',
                      action='store',
                      dest='binddn',
                      help='LDAP bind DN')
    parser.add_option('-w',
                      '--bindpw',
                      action='store',
                      dest='bindpw',
                      help='LDAP bind password')
    parser.add_option('-H',
                      '--uri',
                      action='store',
                      dest='uri',
                      help='LDAP URI')
    parser.add_option('-b',
                      '--base',
                      action='store',
                      dest='base',
                      help='LDAP search base')
    parser.add_option('-z',
                      '--zone',
                      action='store',
                      dest='zone',
                      help='Name of the zone')

    try:
        import optcomplete
        optcomplete.autocomplete(parser)
    except ImportError:
        pass

    (opts, _) = parser.parse_args()

    uri = ldap.get_option(ldap.OPT_URI)
    if opts.uri:
        uri = opts.uri

    base = 'ou=Hosts,%s' % get_ldap_base()
    if opts.base:
        base = opts.base

    # pylint: disable-msg=C0103
    dn = [rdn.split('=') for rdn in base.split(',')]
    dcs = [v for k, v in dn if k == 'dc']
    zone = '.'.join(dcs)

    ds = ldap.initialize(uri)

    if opts.binddn:
        ds.simple_bind_s(opts.binddn, opts.bindpw)

    generate_zonefile(ds, base, zone)

if __name__ == '__main__':
    run()