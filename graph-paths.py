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
import sqlite3

import wotmate
import pydotplus.graphviz as pd


def get_u_key(c):
    c.execute('''SELECT rowid 
                   FROM pub
                  WHERE ownertrust = 'u' 
                  LIMIT 1
    ''')
    try:
        (p_rowid,) = c.fetchone()
        return p_rowid
    except ValueError:
        return None


def get_key_paths(c, t_p_rowid, b_p_rowid, maxdepth=5, maxpaths=5):
    # Next, get rowids of all keys signed by top key
    sigs = wotmate.get_all_signed_by(c, t_p_rowid)
    if not sigs:
        logger.critical('Top key did not sign any keys')
        sys.exit(1)

    ignorekeys = [item for sublist in sigs for item in sublist] + [t_p_rowid]

    if b_p_rowid in ignorekeys:
        logger.info('Bottom key is signed directly by the top key')
        return [[t_p_rowid, b_p_rowid]]

    logger.info('Found %s keys signed by top key' % len(sigs))
    lookedat = 0

    paths = []

    for (s_p_rowid,) in sigs:
        lookedat += 1
        logger.info('Trying "%s" (%s/%s)' %
                    (wotmate.get_uiddata_by_pubrow(c, s_p_rowid), lookedat, len(sigs)))
        path = wotmate.get_shortest_path(c, s_p_rowid, b_p_rowid, 0, maxdepth-1, ignorekeys)
        if path:
            logger.info('`- found a path with %s members' % len(path))
            paths.append([t_p_rowid] + path)
            ignorekeys.append(path[1])

    if not paths:
        logger.critical('No paths found.')
        sys.exit(1)

    culled = wotmate.cull_redundant_paths(paths, maxpaths)
    logger.info('%s paths left after culling' % len(culled))

    return culled


if __name__ == '__main__':
    import argparse
    ap = argparse.ArgumentParser(
        description='Make a graph of paths from any key to any key',
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
    ap.add_argument('--out', default='graph.png',
                    help='Write graph into this file, guessing the output format by extension')
    ap.add_argument('--show-trust', action='store_true', dest='show_trust',
                    default=False,
                    help='Display validity and trust values')
    ap.add_argument('key_id', nargs=1, default=False,
                    help='Bottom key ID for path tracing')

    cmdargs = ap.parse_args()

    global logger
    logger = wotmate.get_logger(cmdargs.quiet)

    if len(cmdargs.key_id) != 1:
        logger.critical('Please provide a single key id for path tracing')
        sys.exit(1)

    dbconn = sqlite3.connect(cmdargs.dbfile)
    cursor = dbconn.cursor()

    if not cmdargs.fromkey:
        from_rowid = get_u_key(cursor)
        if from_rowid is None:
            logger.critical('Could not find ultimate-trust key, try specifying --fromkey')
            sys.exit(1)
    else:
        from_rowid = wotmate.get_pubrow_id(cursor, cmdargs.fromkey)
        if from_rowid is None:
            sys.exit(1)

    to_rowid = wotmate.get_pubrow_id(cursor, cmdargs.key_id[0])
    if to_rowid is None:
        sys.exit(1)

    key_paths = get_key_paths(cursor, from_rowid, to_rowid, cmdargs.maxdepth, cmdargs.maxpaths)

    graph = pd.Dot(
        graph_type='digraph',
    )
    graph.set_node_defaults(
        fontname=cmdargs.font,
        fontsize=cmdargs.fontsize,
    )

    wotmate.draw_key_paths(cursor, key_paths, graph, cmdargs.show_trust)

    chunks = cmdargs.out.split('.')
    outformat = chunks[-1]
    graph.write(cmdargs.out, format=outformat)
    logger.info('Wrote %s' % cmdargs.out)
