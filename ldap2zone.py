#!/usr/bin/env python
# coding: utf-8
#
# Copyright (c) 2011, Paul Tötterman <paul.totterman@iki.fi>
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
import time

LDAP_CONF = '/etc/ldap/ldap.conf'
NS_RE = re.compile('ns\d+')
RECORD = '%(name)s\t%(ttl)s\t%(type)s\t%(data)s'
RECORD_ATTRIBUTES = ['a6Record',
                     'aAAARecord',
                     'aFSDBRecord',
                     'aPLRecord',
                     'aRecord',
                     'cERTRecord',
                     'cNAMERecord',
                     'dHCIDRecord',
                     'dLVRecord',
                     'dNAMERecord',
                     'dNSKEYRecord',
                     'dSRecord',
                     'hINFORecord',
                     'hIPRecord',
                     'iPSECKEYRecord',
                     'kEYRecord',
                     'kXRecord',
                     'lOCRecord',
                     'mDRecord',
                     'mINFORecord',
                     'mXRecord',
                     'nAPTRRecord',
                     'nSEC3PARAMRecord',
                     'nSEC3Record',
                     'nSECRecord',
                     'nSRecord',
                     'nXTRecord',
                     'pTRRecord',
                     'rPRecord',
                     'rRSIGRecord',
                     'sIGRecord',
                     #'sOARecord', # special case
                     'sPFRecord',
                     'sRVRecord',
                     'sSHFPRecord',
                     'tARecord',
                     'tKEYRecord',
                     'tSIGRecord',
                     'tXTRecord']
SOA_ATTRIBUTES = {'sOANameServer': 'ns',
                  'sOAEmail':      'email',
                  'sOASerial':     'serial',
                  'sOARefresh':    'refresh',
                  'sOARetry':      'retry',
                  'sOAExpire':     'expire',
                  'sOANegCache':   'negcache',
                  'defaultTTL':    'dttl'} # doesn't actually belong here
SOA_DEFAULTS = {'refresh':  1200, # RFC1912
                'retry':    180,
                'expire':   1209600, # RFC1912
                'negcache': 60}

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
    print RECORD % values

def mtime2epoch(mtimestr):
    '''Convert LDAP modifyTimestamp attribute value to unix epoch timestamp.'''
    return int(time.mktime(time.strptime(mtimestr, "%Y%m%d%H%M%SZ")))

def attribute2type(attribute):
    '''Convert LDAP attribute name to DNS record type.'''
    return attribute.split('Record')[0].upper()

def output_soa(zone_entry, computed_serial):
    '''Output SOA record based on existing values in zone entry or guesses.'''
    if 'sOARecord' in zone_entry:
        output_record({'name': zone_entry['relativeDomainName'][1][0],
                       'type': attribute2type('sOARecord'),
                       'data': zone_entry['sOARecord'][1][0]})
    else:
        soa_values = SOA_DEFAULTS.copy()
        soa_values['serial'] = computed_serial
        for attr in SOA_ATTRIBUTES.keys():
            if attr in zone_entry:
                soa_values[SOA_ATTRIBUTES[attr]] = zone_entry[attr][1][0]

        output_record({'name': '@',
                       'ttl':  '',
                       'type': 'SOA',
                       'data': ('%(ns)s %(email)s (%(serial)s %(refresh)s '
                                '%(retry)s %(expire)s %(negcache)s)' %
                                soa_values)})

def generate_zonefile(ds, base, zone, views):
    '''Generates the zonefile from ldap. Does the actual work.'''
    # pylint: disable-msg=C0103,R0912,R0914
    unified_entries = {}

    computed_serial = 0

    if views == []:
        views = ['']

    query_attrs = ['relativeDomainName', 'modifyTimestamp', 'dNSView', 'dNSTTL',
                   'defaultTTL'] + RECORD_ATTRIBUTES + SOA_ATTRIBUTES.keys()
    for view in views:
        if view != '':
            filterstr = ('(&(objectClass=dNSRecord)(zoneName=%(zone)s)'
                         '(dNSView=%(view)s))' % {'zone': zone, 'view': view})
        else:
            filterstr = '(&(objectClass=dNSRecord)(zoneName=%s))' % zone
        entries = ds.search_s(base, ldap.SCOPE_SUBTREE, filterstr, query_attrs)

        epochs = [mtime2epoch(e[1]['modifyTimestamp'][0]) for e in entries]
        epochs.append(computed_serial)
        computed_serial = max(epochs)

        for entry in entries:
            attrs = entry[1]
            for name in attrs['relativeDomainName']:
                if name in unified_entries and unified_entries[name][0] != view:
                    del unified_entries[name]
                if not name in unified_entries:
                    unified_entries[name] = (view, {})
                unified_attrs = unified_entries[name][1]
                for attr in RECORD_ATTRIBUTES + SOA_ATTRIBUTES.keys():
                    ttl = None
                    if 'dNSTTL' in attrs:
                        ttl = attrs['dNSTTL'][0]
                    if attr in attrs:
                        unified_attrs[attr] = (ttl, attrs[attr])

    zone_entry = unified_entries['@'][1]

    default_ttl = 60
    if 'defaultTTL' in zone_entry:
        default_ttl = zone_entry['defaultTTL'][1][0]

    output_header(zone, default_ttl)

    output_soa(zone_entry, computed_serial)

    for name in unified_entries:
        attrs = unified_entries[name][1]
        ttl = ''

        if 'dNSTTL' in attrs and attrs['dNSTTL'][0] != default_ttl:
            ttl = attrs['dNSTTL'][0]
        for attr in RECORD_ATTRIBUTES:
            if attr in attrs:
                if attrs[attr][0] is not None and attrs[attr][0] != default_ttl:
                    ttl = attrs[attr][0]
                for value in attrs[attr][1]:
                    output_record({'name': name,
                                   'ttl':  ttl,
                                   'type': attribute2type(attr),
                                   'data': value})

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
    parser.add_option('-v',
                      '--view',
                      action='append',
                      dest='views',
                      default=[],
                      help='View(s) to include')

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

    if opts.zone:
        zone = opts.zone

    ds = ldap.initialize(uri)

    if opts.binddn:
        ds.simple_bind_s(opts.binddn, opts.bindpw)

    generate_zonefile(ds, base, zone, opts.views)

if __name__ == '__main__':
    run()
