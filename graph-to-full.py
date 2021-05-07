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
__author__ = 'Konstantin Ryabitsev <konstantin@linuxfoundation.org>'

import sys
import sqlite3

import wotmate
import pydotplus.graphviz as pd


def get_key_paths(c, b_p_rowid, maxdepth=5):
    # Next, get rowids of all keys with full trust
    f_p_rowids = wotmate.get_all_full_trust(c)

    if not f_p_rowids:
        logger.critical('No fully trusted keys found in the db')
        sys.exit(1)

    paths = []
    ignorekeys = [item for sublist in f_p_rowids for item in sublist]
    lookedat = 0

    logger.info('Found %s fully trusted keys in the db' % len(f_p_rowids))
    for (f_p_rowid,) in f_p_rowids:
        lookedat += 1
        logger.info('Trying "%s" (%s/%s)' %
                    (wotmate.get_uiddata_by_pubrow(c, f_p_rowid), lookedat, len(f_p_rowids)))

        path = wotmate.get_shortest_path(c, f_p_rowid, b_p_rowid, 0, maxdepth-1, ignorekeys)

        if path:
            logger.info('`- found a path with %s members' % len(path))
            paths.append(path)
            # we want to find maximum paths, so we unset _seenkeys
            wotmate._seenkeys = []
            if len(path) > 2:
                ignorekeys += path[1:-1]

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
    ap.add_argument('key_id', nargs=1, default=False,
                    help='Bottom key ID for path tracing')

    cmdargs = ap.parse_args()

    logger = wotmate.get_logger(cmdargs.quiet)

    dbconn = sqlite3.connect(cmdargs.dbfile)
    cursor = dbconn.cursor()

    if len(cmdargs.key_id) != 1:
        logger.critical('Please provide a single key id for path tracing')
        sys.exit(1)

    to_rowid = wotmate.get_pubrow_id(cursor, cmdargs.key_id[0])
    if to_rowid is None:
        sys.exit(1)

    key_paths = get_key_paths(cursor, to_rowid, cmdargs.maxdepth)

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
