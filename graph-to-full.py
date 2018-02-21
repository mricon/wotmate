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


def get_key_paths(c, b_keyid, maxdepth=5):
    # First, get rowid of the bottom key
    try:
        c.execute('''SELECT rowid FROM pub WHERE keyid = ?''', (b_keyid,))
        (b_p_rowid,) = c.fetchone()
    except TypeError:
        logger.critical('Bottom key %s is not in the db' % b_keyid)
        sys.exit(1)

    # Next, get rowids of all keys with full trust
    f_p_rowids = wotmate.get_all_full_trust(c)

    if not f_p_rowids:
        logger.critical('No fully trusted keys found in the db')
        sys.exit(1)

    paths = []
    ignorekeys = [item for sublist in f_p_rowids for item in sublist]

    logger.info('Found %s fully trusted keys in the db' % len(f_p_rowids))
    for (f_p_rowid,) in f_p_rowids:
        path = wotmate.get_shortest_path(c, f_p_rowid, b_p_rowid, 0, maxdepth-1, [], ignorekeys)

        if path:
            logger.info('Found a path with %s members' % len(path))
            paths.append(path)
            ignorekeys += path

    if not paths:
        logger.critical('No paths found to any fully trusted keys')
        sys.exit(1)

    culled = wotmate.cull_redundant_paths(paths)
    logger.info('%s paths left after culling' % len(culled))

    return culled


if __name__ == '__main__':
    import argparse
    ap = argparse.ArgumentParser(
        description='Make a graph from any key to fully trusted keys',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )

    ap.add_argument('--quiet', action='store_true',
                    default=False,
                    help='Be quiet and only output errors')
    ap.add_argument('--tokey', required=True,
                    help='Bottom key ID')
    ap.add_argument('--maxdepth', default=4, type=int,
                    help='Try up to this maximum depth')
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

    tokey = cmdargs.tokey[-16:].upper()

    key_paths = get_key_paths(cursor, tokey, cmdargs.maxdepth)

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
