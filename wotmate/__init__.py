#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright © 2018-2024 by The Linux Foundation and contributors
__author__ = 'Konstantin Ryabitsev <konstantin@linuxfoundation.org>'

import sys
import subprocess
import logging

from typing import Optional

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
GPGBIN = '/usr/bin/gpg'
GNUPGHOME = None

logger = logging.getLogger(__name__)

# convenience caching to avoid redundant look-ups
_all_signed_by_cache = dict()
_all_sigs_cache = dict()
_all_pub_uiddata_cache = dict()
_seenkeys = set()


def get_pub_uid_by_pubrow(c, p_rowid):
    if p_rowid not in _all_pub_uiddata_cache:
        c.execute('SELECT pub.keyid, uid.uiddata FROM uid JOIN pub ON uid.pubrowid = pub.rowid WHERE pubrowid=?', (p_rowid,))
        _all_pub_uiddata_cache[p_rowid] = c.fetchone()
    return _all_pub_uiddata_cache[p_rowid]


def get_uiddata_by_pubrow(c, p_rowid):
    return get_pub_uid_by_pubrow(c, p_rowid)[1]


def get_logger(quiet=False):
    logger.setLevel(logging.DEBUG)
    ch = logging.StreamHandler()
    formatter = logging.Formatter('%(message)s')
    ch.setFormatter(formatter)
    if quiet:
        ch.setLevel(logging.CRITICAL)
    else:
        ch.setLevel(logging.INFO)

    logger.addHandler(ch)
    return logger


def gpg_run_command(args: list, with_colons: bool = True, stdin: Optional[bytes] = None) -> bytes:
    cmdargs = [GPGBIN, '--batch']
    if with_colons:
        cmdargs += ['--with-colons']

    cmdargs += args
    env = None
    if GNUPGHOME is not None:
        env = {'GNUPGHOME': GNUPGHOME}

    logger.debug('Running %s...' % ' '.join(cmdargs))

    sp = subprocess.Popen(cmdargs, stdout=subprocess.PIPE, stdin=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
    (output, error) = sp.communicate(input=stdin)
    output = output.strip()

    if len(error.strip()):
        sys.stderr.buffer.write(error)

    return output


def lint(keydata: bytes) -> bool:
    sp = subprocess.Popen('sq cert -q lint'.split(), stdout=subprocess.PIPE, stdin=subprocess.PIPE, stderr=subprocess.PIPE, env=None)
    sp.communicate(input=keydata)

    return sp.returncode == 0


def gpg_get_lines(args, matchonly=()):
    output = gpg_run_command(args)
    lines = []
    logger.debug('Processing the output...')
    for line in output.split(b'\n'):
        if line == b'' or line[0] == b'#':
            continue
        if len(matchonly):
            for match in matchonly:
                if line.startswith(match):
                    lines.append(line)
                    continue
        else:
            lines.append(line)

    return lines


def gpg_get_fields(bline):
    line = bline.decode('utf8', 'ignore')
    # gpg uses \x3a to indicate an encoded colon, so explode and de-encode
    fields = [rawchunk.replace('\\x3a', ':') for rawchunk in line.split(':')]
    # fields 5 and 6 are timestamps, so convert them to isoformat for sqlite3 needs
    if len(fields[5]):
        fields[5] = datetime.fromtimestamp(int(fields[5])).isoformat()
    if len(fields[6]):
        fields[6] = datetime.fromtimestamp(int(fields[6])).isoformat()

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
                  FOREIGN KEY(uidrowid) REFERENCES uid(rowid),
                  FOREIGN KEY(pubrowid) REFERENCES pub(rowid),
                  PRIMARY KEY (uidrowid, pubrowid)
                 ) WITHOUT ROWID''')


def get_all_signed_by(c, p_rowid):
    if p_rowid not in _all_signed_by_cache:
        c.execute('''SELECT DISTINCT uid.pubrowid
                                FROM uid JOIN sig ON sig.uidrowid = uid.rowid 
                               WHERE sig.pubrowid=?''', (p_rowid,))
        _all_signed_by_cache[p_rowid] = [pubrowid for (pubrowid,) in c.fetchall()]

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
        keyline = '{%s %s|%s}' % (ALGOS[algo], size, kid)
    else:
        keyline = '{%s}' % kid

    if show_trust:
        anode.set('label', '{{%s\n%s|{val: %s|tru: %s}}|%s}' % (name, show, val, trust, keyline))
    else:
        anode.set('label', '{%s\n%s|%s}' % (name, show, keyline))
    anode.set('URL', '%s.svg' % kid)
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


def get_shortest_path(c, t_p_rowid, b_p_rowid, depth, maxdepth, ignorekeys):
    global _seenkeys
    # Zero out seenkeys at 0-depth
    if depth == 0:
        _seenkeys = set()
    depth += 1
    sigs = get_all_signed_by(c, t_p_rowid)

    if b_p_rowid in sigs:
        return [t_p_rowid, b_p_rowid]

    shortest = None

    if depth >= maxdepth:
        return None

    for s_p_rowid in sigs:
        if s_p_rowid in ignorekeys or (depth, s_p_rowid) in _seenkeys:
            continue

        subchain = get_shortest_path(c, s_p_rowid, b_p_rowid, depth, maxdepth, ignorekeys)
        if subchain:
            if shortest is None or len(shortest) > len(subchain):
                shortest = subchain
                _seenkeys.add((depth, s_p_rowid))
                # no need to go any deeper than current shortest
                maxdepth = depth - 1 + len(shortest)
        else:
            # if it returns with None, then this key is a dead-end at this and lower depths
            for _d in range(depth, maxdepth):
                _seenkeys.add((_d, s_p_rowid))

    if shortest is not None:
        _seenkeys.add((depth, t_p_rowid))
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


def get_pubrow_id(c, whatnot):
    # first, attempt to treat it as key id
    try:
        int(whatnot, 16)
        as_keyid = '%%%s' % whatnot[-16:].upper()
        c.execute('''SELECT DISTINCT rowid FROM pub WHERE keyid LIKE ?''', (as_keyid,))
        rows = c.fetchall()
        if len(rows) == 1:
            return rows[0][0]
        elif len(rows) > 1:
            logger.critical('More than one key matched %s, use 16-character keyid' % whatnot)
        else:
            logger.critical('No keyids in the database matching %s' % whatnot)
        return None
    except ValueError:
        # not hexadecimal, so not keyid
        pass

    # attempt to look up in uiddata
    c.execute('''SELECT DISTINCT pubrowid FROM uid WHERE uiddata LIKE ? COLLATE NOCASE''', ('%%%s%%' % whatnot,))
    rows = c.fetchall()
    if len(rows) == 1:
        return rows[0][0]
    elif len(rows) > 1:
        logger.critical('More than one result matching "%s", be more specific' % whatnot)
    else:
        logger.critical('Nothing found matching "%s"' % whatnot)

    return None


def get_key_paths(c, t_p_rowid, b_p_rowid, maxdepth=5, maxpaths=5):
    # Next, get rowids of all keys signed by top key
    sigs = get_all_signed_by(c, t_p_rowid)
    if not sigs:
        logger.critical('Top key did not sign any keys')
        sys.exit(1)

    ignorekeys = sigs + [t_p_rowid]

    if b_p_rowid in ignorekeys:
        logger.debug('Bottom key is signed directly by the top key')
        return [[t_p_rowid, b_p_rowid]]

    logger.debug('Found %s keys signed by top key' % len(sigs))
    lookedat = 0

    paths = []

    for s_p_rowid in sigs:
        lookedat += 1
        # logger.debug('Trying "%s" (%s/%s)', get_uiddata_by_pubrow(c, s_p_rowid), lookedat, len(sigs))
        path = get_shortest_path(c, s_p_rowid, b_p_rowid, 0, maxdepth-1, ignorekeys)
        if path:
            logger.debug('`- found a path with %s members' % len(path))
            paths.append([t_p_rowid] + path)
            if len(path) > 2:
                ignorekeys += path[1:-2]

    if not paths:
        logger.info('No valid paths between %s and %s',
                    get_uiddata_by_pubrow(c, t_p_rowid), get_uiddata_by_pubrow(c, b_p_rowid))
        return []

    culled = cull_redundant_paths(paths, maxpaths)
    logger.debug('%s paths left after culling' % len(culled))

    return culled


def get_u_key(c):
    c.execute('''SELECT rowid 
                   FROM pub
                  WHERE ownertrust = 'u' 
                  LIMIT 1
    ''')
    try:
        (p_rowid,) = c.fetchone()
        return p_rowid
    except (ValueError, TypeError):
        return None
