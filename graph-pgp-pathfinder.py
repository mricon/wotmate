#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Copyright (C) 2018 by The Linux Foundation and contributors
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

import anyjson
import requests

import wotmate
import pydotplus.graphviz as pd

PATHFINDER_URL = 'http://pgp.cs.uu.nl/paths/%s/to/%s.json'


def make_graph_node(actor, position='middle'):
    kid = actor['kid']
    uiddata = actor['uid']

    nodename = 'a_%s' % kid
    anode = pd.Node(nodename)
    anode.set('shape', 'record')
    anode.set('style', 'rounded')
    if position == 'top':
        anode.set('color', 'purple')
    elif position == 'middle':
        anode.set('color', 'blue')
    elif position == 'bottom':
        anode.set('color', 'orange')
    else:
        anode.set('color', 'gray')

    uiddata = uiddata.replace('"', '')
    name = uiddata.split('<')[0].replace('"', '').strip()
    name = name.split('(')[0].strip()

    try:
        email = uiddata.split('<')[1].replace('>', '').strip()
        try:
            domain = email.split('@')[1]
            show = domain
        except IndexError:
            show = email
    except IndexError:
        show = ''

    keyline = '{%s}' % kid.upper()

    anode.set('label', '{%s\n%s|%s}' % (name, show, keyline))

    return anode


def draw_key_paths(paths, graph, maxdepth):
    seenactors = {}
    # make a subgraph for toplevel node
    tl_subgraph = pd.Subgraph('cluster_toplevel')
    tl_subgraph.set('color', 'white')
    # make a top and bottom nodes, which get special colours
    t_node = make_graph_node(paths[0][0], position='top')
    tl_subgraph.add_node(t_node)
    seenactors[paths[0][0]['kid']] = t_node

    b_node = make_graph_node(paths[0][-1], position='bottom')
    graph.add_node(b_node)
    seenactors[paths[0][-1]['kid']] = b_node

    for path in paths:
        if len(path) - 1 > maxdepth:
            continue
        signer = None
        for actor in path:
            kid = actor['kid']
            if kid not in seenactors.keys():
                anode = make_graph_node(actor)
                seenactors[kid] = anode
                if signer is None:
                    tl_subgraph.add_node(anode)
                else:
                    graph.add_node(anode)
            else:
                anode = seenactors[kid]

            if signer is not None:
                graph.add_edge(pd.Edge(signer, anode))

            signer = anode

    graph.add_subgraph(tl_subgraph)


def get_pathfinder_paths(top_key, bottom_key):
    # Get json between two keys
    logger.info('Querying pathfinder...')
    url = PATHFINDER_URL % (top_key, bottom_key)
    r = requests.get(url)
    if r.status_code != 200:
        logger.critical('Could not grab %s', url)
        sys.exit(1)

    pfresult = anyjson.deserialize(r.content.decode('utf-8'))

    if 'error' in pfresult and len(pfresult['error']):
        logger.critical('Could not get results from server: %s', pfresult['error'])
        sys.exit(1)

    logger.info('Got a result with %s paths', len(pfresult['xpaths']))

    return pfresult['xpaths']


if __name__ == '__main__':
    import argparse
    ap = argparse.ArgumentParser(
        description='Make a graph using the results of PGP Pathfinder lookup',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )

    ap.add_argument('--quiet', action='store_true',
                    default=False,
                    help='Be quiet and only output errors')
    ap.add_argument('--font', default='droid sans,dejavu sans,helvetica',
                    help='Font to use in the graph')
    ap.add_argument('--fontsize', default='11',
                    help='Font size to use in the graph')
    ap.add_argument('--maxdepth', default=4, type=int,
                    help='Try up to this maximum depth')
    ap.add_argument('--out', default='graph.png',
                    help='Write graph into this file, guessing the output format by extension')
    ap.add_argument('top_key', nargs=1, default=False,
                    help='16-character top key ID')
    ap.add_argument('bottom_key', nargs=1, default=False,
                    help='16-character bottom key ID')

    cmdargs = ap.parse_args()

    logger = wotmate.get_logger(cmdargs.quiet)

    key_paths = get_pathfinder_paths(cmdargs.top_key[0], cmdargs.bottom_key[0])

    graph = pd.Dot(
        graph_type='digraph',
    )
    graph.set_node_defaults(
        fontname=cmdargs.font,
        fontsize=cmdargs.fontsize,
    )

    draw_key_paths(key_paths, graph, cmdargs.maxdepth)

    chunks = cmdargs.out.split('.')
    outformat = chunks[-1]
    graph.write(cmdargs.out, format=outformat)
    logger.info('Wrote %s' % cmdargs.out)
