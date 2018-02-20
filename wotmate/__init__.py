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
import subprocess
import logging

from datetime import datetime
import pydotplus.graphviz as pd


ALGOS = {
    1: 'RSA',
    17: 'DSA',
    18: 'ECDH',
    19: 'ECDSA',
    22: 'EdDSA',
}

DB_VERSION = 1
GPGBIN = '/usr/bin/gpg2'
GNUPGHOME = None

logger = logging.getLogger(__name__)

# convenience caching so we avoid redundant lookups
_all_signed_by_cache = {}
_all_sigs_cache = {}


def get_logger(quiet=False):
    logger.setLevel(logging.DEBUG)
    ch = logging.StreamHandler()
    formatter = logging.Formatter('%(message)s')
    ch.setFormatter(formatter)
    if quiet:
        ch.setLevel(logging.CRITICAL)
    else:
        ch.setLevel(logging.DEBUG)

    logger.addHandler(ch)
    return logger


def gpg_run_command(args, matchonly=()):
    args = [GPGBIN, '--with-colons'] + args

    env = {}

    if GNUPGHOME is not None:
        env['GNUPGHOME'] = GNUPGHOME

    logger.info('Running %s...' % ' '.join(args))

    (output, error) = subprocess.Popen(args, stdout=subprocess.PIPE,
                                       stderr=subprocess.PIPE,
                                       env=env).communicate()
    output = output.strip()

    if len(error.strip()):
        sys.stderr.write(error.decode('utf-8'))

    lines = []
    for line in output.split(b'\n'):
        if line == b'' or line[0] == b'#':
            continue
        if len(matchonly):
            for umatch in matchonly:
                match = umatch.encode('utf-8')
                if line.startswith(match):
                    lines.append(line)
                    continue
        else:
            lines.append(line)

    return lines


def gpg_get_fields(bline):
    # gpg uses \x3a to indicate an encoded colon, so we explode and de-encode
    line = bline.decode('utf-8')
    fields = [rawchunk.replace('\\x3a', ':') for rawchunk in line.split(':')]
    # fields 5 and 6 are timestamps, so make them python datetime
    if len(fields[5]):
        fields[5] = datetime.fromtimestamp(int(fields[5]))
    if len(fields[6]):
        fields[6] = datetime.fromtimestamp(int(fields[6]))

    return fields


def init_sqlite_db(c):
    # Create primary keys table
    logger.info('Initializing new sqlite3 db with metadata version %s' % DB_VERSION)
    c.execute('''CREATE TABLE metadata (
                  version INTEGER
                 )''')
    c.execute('''INSERT INTO metadata VALUES(?)''', (DB_VERSION,))
    c.execute('''CREATE TABLE pub (
                  keyid TEXT UNIQUE,
                  validity TEXT,
                  size INTEGER,
                  algo INTEGER,
                  created TEXT,
                  expires TEXT,
                  ownertrust TEXT
                 )''')
    c.execute('''CREATE TABLE uid (
                  pubrowid INTEGER,
                  validity TEXT,
                  created TEXT,
                  expires TEXT,
                  uiddata TEXT,
                  is_primary INTEGER,
                  FOREIGN KEY(pubrowid) REFERENCES pub(rowid)
                 )''')
    c.execute('''CREATE TABLE sig (
                  uidrowid INTEGER,
                  pubrowid INTEGER,
                  created TEXT,
                  expires TEXT,
                  sigtype INTEGER,
                  FOREIGN KEY(uidrowid) REFERENCES pub(rowid),
                  FOREIGN KEY(pubrowid) REFERENCES uid(rowid),
                  PRIMARY KEY (uidrowid, pubrowid)
                 ) WITHOUT ROWID''')


def get_all_signed_by(c, p_rowid):
    if p_rowid not in _all_signed_by_cache:
        c.execute('''SELECT DISTINCT uid.pubrowid
                                FROM uid JOIN sig ON sig.uidrowid = uid.rowid 
                               WHERE sig.pubrowid=?''', (p_rowid,))
        _all_signed_by_cache[p_rowid] = c.fetchall()

    return _all_signed_by_cache[p_rowid]


def get_all_signed(c, p_rowid):
    if p_rowid not in _all_sigs_cache:
        c.execute('''SELECT DISTINCT sig.pubrowid 
                       FROM sig JOIN uid ON sig.uidrowid = uid.rowid 
                      WHERE uid.pubrowid = ?''', (p_rowid,))
        _all_sigs_cache[p_rowid] = c.fetchall()

    return _all_sigs_cache[p_rowid]


def get_all_full_trust(c):
    c.execute('''SELECT DISTINCT pub.rowid
                   FROM pub
                  WHERE ownertrust IN ('u', 'f')''')
    return c.fetchall()


def make_graph_node(c, p_rowid, show_trust=False):
    c.execute('''SELECT pub.*, 
                        uid.uiddata
                   FROM uid JOIN pub 
                     ON uid.pubrowid = pub.rowid 
                  WHERE pub.rowid=? AND uid.is_primary = 1''', (p_rowid,))
    (kid, val, size, algo, cre, exp, trust, uiddata) = c.fetchone()

    nodename = 'a_%s' % p_rowid
    anode = pd.Node(nodename)
    anode.set('shape', 'record')
    anode.set('style', 'rounded')
    if trust == 'u':
        anode.set('color', 'purple')
    elif trust == 'f':
        anode.set('color', 'red')
    elif trust == 'm':
        anode.set('color', 'blue')
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


    if algo in ALGOS.keys():
        algosize = '%s %s' % (ALGOS[algo], size)
    else:
        algosize = 'ALGO? %s' % size

    if show_trust:
        anode.set('label', '{{%s\n%s|{val: %s|tru: %s}}|{%s|%s}}' % (name, show, val, trust, algosize, kid))
    else:
        anode.set('label', '{%s\n%s|{%s|%s}}' % (name, show, algosize, kid))
    return anode


def cull_redundant_paths(paths, maxpaths=None):
    paths.sort(key=len)

    culled = []
    chunks = []
    for path in paths:
        redundant = False
        pos = -2
        while pos > -len(path):
            if path[pos:] in chunks:
                redundant = True
                break
            chunks.append(path[pos:])
            pos -= 1

        if not redundant:
            culled.append(path)
            if maxpaths and len(culled) >= maxpaths:
                break

    return culled


def get_shortest_path(c, t_p_rowid, b_p_rowid, depth, maxdepth, seenkeys, ignorekeys):
    depth += 1
    sigs = get_all_signed_by(c, t_p_rowid)

    if (b_p_rowid,) in sigs:
        return [t_p_rowid, b_p_rowid]

    shortest = None

    if depth >= maxdepth:
        return None

    for (s_p_rowid,) in sigs:
        if (depth, s_p_rowid) in seenkeys:
            continue
        if s_p_rowid in ignorekeys:
            continue

        subchain = get_shortest_path(c, s_p_rowid, b_p_rowid, depth, maxdepth, seenkeys, ignorekeys)
        if subchain:
            if shortest is None or len(shortest) > len(subchain):
                shortest = subchain
                seenkeys.append((depth, s_p_rowid))
                # no need to go any deeper than current shortest
                maxdepth = depth - 1 + len(shortest)
        else:
            # if we returned with None, then this key is a dead-end at this depth
            seenkeys.append((depth, s_p_rowid))

    if shortest is not None:
        return [t_p_rowid] + shortest

    return None


def draw_key_paths(c, paths, graph, show_trust):
    seenactors = {}
    # make a subgraph for toplevel nodes
    tl_subgraph = pd.Subgraph('cluster_toplevel')
    tl_subgraph.set('color', 'white')
    for path in paths:
        signer = None
        for actor in path:
            if actor not in seenactors.keys():
                anode = make_graph_node(c, actor, show_trust)
                seenactors[actor] = anode
                if signer is None:
                    tl_subgraph.add_node(anode)
                else:
                    graph.add_node(anode)
            else:
                anode = seenactors[actor]

            if signer is not None:
                graph.add_edge(pd.Edge(signer, anode))

            signer = anode

    graph.add_subgraph(tl_subgraph)
