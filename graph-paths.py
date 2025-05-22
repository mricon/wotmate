#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright © 2018-2024 by The Linux Foundation and contributors
__author__ = 'Konstantin Ryabitsev <konstantin@linuxfoundation.org>'

import sys
import sqlite3

import wotmate
import pydotplus.graphviz as pd  # type: ignore[import]


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

    logger = wotmate.get_logger(cmdargs.quiet)

    if len(cmdargs.key_id) != 1:
        logger.critical('Please provide a single key id for path tracing')
        sys.exit(1)

    dbconn = sqlite3.connect(cmdargs.dbfile)
    cursor = dbconn.cursor()

    if not cmdargs.fromkey:
        from_rowid = wotmate.get_u_key(cursor)
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

    key_paths = wotmate.get_key_paths(cursor, from_rowid, to_rowid, cmdargs.maxdepth, cmdargs.maxpaths)

    graph = pd.Dot(
        graph_type='digraph',
    )
    graph.set_node_defaults(  # type: ignore[no-untyped-call]
        fontname=cmdargs.font,
        fontsize=cmdargs.fontsize,
    )

    wotmate.draw_key_paths(cursor, key_paths, graph, cmdargs.show_trust)

    chunks = cmdargs.out.split('.')
    outformat = chunks[-1]
    graph.write(cmdargs.out, format=outformat)  # type: ignore[no-untyped-call]
    logger.info('Wrote %s' % cmdargs.out)
