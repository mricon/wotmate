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


def get_u_keyid(c):
    c.execute('''SELECT keyid 
                   FROM pub
                  WHERE ownertrust = 'u' 
                  LIMIT 1
    ''')
    try:
        (keyid,) = c.fetchone()
        return keyid
    except ValueError:
        return None


def get_key_paths(c, t_keyid, b_keyid, maxdepth=5, maxpaths=5):
    # First, get rowid of the top and bottom key
    try:
        c.execute('''SELECT rowid FROM pub WHERE keyid = ?''', (t_keyid,))
        (t_p_rowid,) = c.fetchone()
    except TypeError:
        logger.critical('Top key %s is not in the db' % t_keyid)
        sys.exit(1)

    try:
        c.execute('''SELECT rowid FROM pub WHERE keyid = ?''', (b_keyid,))
        (b_p_rowid,) = c.fetchone()
    except TypeError:
        logger.critical('Bottom key %s is not in the db' % b_keyid)
        sys.exit(1)

    # Next, get rowids of all keys signed by top key
    sigs = wotmate.get_all_signed_by(c, t_p_rowid)
    if not sigs:
        logger.critical('Top key %s did not sign any keys' % t_keyid)
        sys.exit(1)

    logger.info('Found %s keys signed by %s' % (len(sigs), t_keyid))

    paths = []
    ignorekeys = [item for sublist in sigs for item in sublist]
    for (s_p_rowid,) in sigs:
        path = wotmate.get_shortest_path(c, s_p_rowid, b_p_rowid, 0, maxdepth-1, [], ignorekeys)
        if path:
            logger.info('Found a path with %s members' % len(path))
            paths.append([t_p_rowid] + path)
            ignorekeys += path

    if not paths:
        logger.critical('No paths found from %s to %s' % (t_keyid, b_keyid))
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
    ap.add_argument('--tokey', required=True,
                    help='Bottom key ID')
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

    cmdargs = ap.parse_args()

    global logger
    logger = wotmate.get_logger(cmdargs.quiet)

    dbconn = sqlite3.connect(cmdargs.dbfile)
    cursor = dbconn.cursor()

    if not cmdargs.fromkey:
        t_keyid = get_u_keyid(cursor)
        if t_keyid is None:
            logger.critical('Could not find ultimate-trust key, try specifying --fromkey')
            sys.exit(1)
    else:
        t_keyid = cmdargs.fromkey[-16:].upper()

    b_keyid = cmdargs.tokey[-16:].upper()

    paths = get_key_paths(cursor, t_keyid, b_keyid, cmdargs.maxdepth, cmdargs.maxpaths)

    graph = pd.Dot(
        graph_type='digraph',
    )
    graph.set_node_defaults(
        fontname=cmdargs.font,
        fontsize=cmdargs.fontsize,
    )

    wotmate.draw_key_paths(cursor, paths, graph, cmdargs.show_trust)

    chunks = cmdargs.out.split('.')
    outformat = chunks[-1]
    graph.write(cmdargs.out, format=outformat)

