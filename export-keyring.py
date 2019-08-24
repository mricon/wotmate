#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Copyright (C) 2015 by The Linux Foundation and contributors
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

from __future__ import (absolute_import,
                        division,
                        print_function,
                        unicode_literals)

__author__ = 'Konstantin Ryabitsev <konstantin@linuxfoundation.org>'

import sys
import os
import sqlite3

import wotmate
import pydotplus.graphviz as pd


if __name__ == '__main__':
    import argparse
    ap = argparse.ArgumentParser(
        description='Export a keyring as individual .asc files with graphs',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )

    ap.add_argument('--quiet', action='store_true',
                    default=False,
                    help='Be quiet and only output errors')
    ap.add_argument('--fromkey',
                    help='Top key ID (if omitted, will use the key with ultimate trust)')
    ap.add_argument('--maxdepth', default=4, type=int,
                    help='Try up to this maximum depth')
    ap.add_argument('--maxpaths', default=4, type=int,
                    help='Stop after finding this many paths')
    ap.add_argument('--font', default='droid sans,dejavu sans,helvetica',
                    help='Font to use in the graph')
    ap.add_argument('--fontsize', default='11',
                    help='Font size to use in the graph')
    ap.add_argument('--dbfile', default='siginfo.db',
                    help='Sig database to use')
    ap.add_argument('--gpgbin',
                    default='/usr/bin/gpg2',
                    help='Location of the gpg binary to use')
    ap.add_argument('--gnupghome',
                    help='Set this as gnupghome instead of using the default')
    ap.add_argument('--outdir', default='export',
                    help='Export keyring data into this dir as keys/ and graphs/ subdirs')
    ap.add_argument('--show-trust', action='store_true', dest='show_trust',
                    default=False,
                    help='Display validity and trust values')
    ap.add_argument('--graph-out-format', dest='graph_out_format', default='svg',
                    help='Export graphs in this format')
    ap.add_argument('--key-export-options', dest='key_export_options',
                    default='export-attributes',
                    help='The value to pass to gpg --export-options')

    cmdargs = ap.parse_args()

    if cmdargs.gnupghome:
        wotmate.GNUPGHOME = cmdargs.gnupghome
    if cmdargs.gpgbin:
        wotmate.GPGBIN = cmdargs.gpgbin

    logger = wotmate.get_logger(cmdargs.quiet)

    dbconn = sqlite3.connect(cmdargs.dbfile)
    c = dbconn.cursor()

    if not cmdargs.fromkey:
        from_rowid = wotmate.get_u_key(c)
        if from_rowid is None:
            logger.critical('Could not find ultimate-trust key, try specifying --fromkey')
            sys.exit(1)
    else:
        from_rowid = wotmate.get_pubrow_id(c, cmdargs.fromkey)
        if from_rowid is None:
            sys.exit(1)

    # Iterate through all keys
    c.execute('''SELECT pub.rowid,
                        pub.keyid, 
                        uid.uiddata
                   FROM uid JOIN pub 
                     ON uid.pubrowid = pub.rowid 
                  WHERE uid.is_primary = 1''')

    if not os.path.isdir(cmdargs.outdir):
        os.mkdir(cmdargs.outdir)
    keydir = os.path.join(cmdargs.outdir, 'keys')
    if not os.path.isdir(keydir):
        os.mkdir(keydir)
    graphdir = os.path.join(cmdargs.outdir, 'graphs')
    if not os.path.isdir(graphdir):
        os.mkdir(graphdir)

    kcount = wcount = 0
    for (to_rowid, kid, uiddata) in c.fetchall():
        kcount += 1
        # First, export the key
        args = ['-a', '--export', '--export-options', cmdargs.key_export_options, kid]
        keydata = wotmate.gpg_run_command(args, with_colons=False)
        keyout = os.path.join(keydir, '%s.asc' % kid)
        # Do we already have a file in place?
        if os.path.exists(keyout):
            # Load it up and see if it's different
            with open(keyout, 'r') as fin:
                old_keyexport = fin.read().encode('utf-8')
                if old_keyexport.find(keydata) > 0:
                    logger.debug('No changes for %s', kid)
                    continue

        # Now, export the header
        args = ['--list-options', 'show-notations', '--list-options',
                'no-show-uid-validity', '--with-subkey-fingerprints', '--list-key', kid]
        header = wotmate.gpg_run_command(args, with_colons=False)
        keyexport = header + b'\n\n' + keydata

        key_paths = wotmate.get_key_paths(c, from_rowid, to_rowid, cmdargs.maxdepth, cmdargs.maxpaths)
        if not len(key_paths):
            logger.debug('Skipping %s due to invalid WoT', kid)
            continue

        with open(keyout, 'w') as fout:
            fout.write(keyexport.decode('utf-8', 'ignore'))
            logger.info('Wrote %s', keyout)

        graph = pd.Dot(
            graph_type='digraph',
        )
        graph.set_node_defaults(
            fontname=cmdargs.font,
            fontsize=cmdargs.fontsize,
        )

        wotmate.draw_key_paths(c, key_paths, graph, cmdargs.show_trust)
        graphout = os.path.join(graphdir, '%s.%s' % (kid, cmdargs.graph_out_format))
        graph.write(graphout, format=cmdargs.graph_out_format)
        logger.info('Wrote %s', graphout)
        wcount += 1

    logger.info('Processed %s keys, made %s changes', kcount, wcount)

