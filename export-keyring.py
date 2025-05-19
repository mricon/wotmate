#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright © 2018-2024 by The Linux Foundation and contributors
__author__ = 'Konstantin Ryabitsev <konstantin@linuxfoundation.org>'

import sys
import os
import sqlite3
import pathlib

from email.utils import parseaddr
from urllib.parse import quote_plus

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
                    default='/usr/bin/gpg',
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
    ap.add_argument('--gen-b4-keyring', action='store_true', dest='gen_b4_keyring',
                    default=False,
                    help='Generate a b4-style symlinked keyring as well')

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
    my_symlinks = set()
    for (to_rowid, kid, uiddata) in c.fetchall():
        kcount += 1
        # First, export the key
        args = ['-a', '--export', '--export-options', cmdargs.key_export_options, kid]
        keydata = wotmate.gpg_run_command(args, with_colons=False)
        keyout = os.path.join(keydir, '%s.asc' % kid)

        # Is there already a key file in place?
        key_changed = False
        if os.path.exists(keyout):
            key_already_exists = True
            # Load it up and see if it's different
            with open(keyout, 'rb') as fin:
                old_keyexport = fin.read()
                if keydata not in old_keyexport:
                    key_changed = True
                    logger.debug('Key changes detected for %s', kid)
        else:
            key_already_exists = False
            key_changed = True

        key_paths = wotmate.get_key_paths(c, from_rowid, to_rowid, cmdargs.maxdepth, cmdargs.maxpaths)
        if not len(key_paths):
            if key_already_exists:
                logger.debug('%s has an to invalid WoT, but already exists, so still update it', kid)
            else:
                logger.debug('Skipping %s due to invalid WoT', kid)
                continue

        kpblock = ''
        for kp in key_paths:
            for lvl, rowid in enumerate(kp):
                kid, kpuid = wotmate.get_pub_uid_by_pubrow(c, rowid)
                kpblock += f'   {lvl}' if lvl > 0 else f'from'
                kpblock += f'  {kid}  {kpuid}\n'
            kpblock += '\n'
        key_paths_repr = kpblock.encode()

        txtgraphout = os.path.join(graphdir, "%s.txt" % kid)
        trust_changed = key_changed
        if not os.path.exists(txtgraphout):
            logger.debug('Forcing generation of the text graph for %s', kid)
            trust_changed = True
        elif not key_changed:
            # Load it up and see if trust relationships changed
            with open(txtgraphout, 'rb') as fin:
                old_key_paths_repr = fin.read()
                if key_paths_repr != old_key_paths_repr:
                    trust_changed = True
                    logger.debug('Trust changes detected for %s', kid)

        if not (key_changed or trust_changed):
            logger.debug('No changes detected for %s', kid)
            continue

        if key_changed:
            # Now, export the header
            args = ['--list-options', 'show-notations', '--list-options',
                    'no-show-uid-validity', '--with-subkey-fingerprints', '--list-key', kid]
            header = wotmate.gpg_run_command(args, with_colons=False)
            keyexport = header + b"\n\n" + keydata + b"\n"

            if not wotmate.lint(keydata):
                logger.debug('Skipping %s due to bad linter results', kid)
                continue

            with open(keyout, 'wb') as fout:
                fout.write(keyexport)
                logger.info('Wrote %s', keyout)

            if cmdargs.gen_b4_keyring:
                # Grab all uid lines from the header
                for line in header.split(b'\n'):
                    if not line.startswith(b'uid'):
                        continue
                    line = line[3:].decode('utf-8', 'ignore').strip()
                    if line:
                        parts = parseaddr(line)
                        if not len(parts[1]) or parts[1].count('@') != 1:
                            continue
                        local, domain = parts[1].split('@', 1)
                        kpath = os.path.join(cmdargs.outdir, '.keyring', 'openpgp', quote_plus(domain),
                                             quote_plus(local))
                        pathlib.Path(kpath).mkdir(parents=True, exist_ok=True)
                        spath = os.path.join(kpath, 'default')
                        tpath = os.path.relpath(keyout, kpath)
                        if os.path.islink(spath):
                            if os.readlink(spath) == tpath:
                                continue
                            if spath in my_symlinks:
                                # There's multiple keys with the same identity. First one wins, for the lack of a
                                # better solution that is also sane.
                                logger.info('Notice: multiple keys with the same UID %s', parts[1])
                                continue
                            os.unlink(spath)
                            logger.info('Notice: fixing symlink for %s', parts[1])
                        os.symlink(tpath, spath)
                        my_symlinks.add(spath)
                        logger.info('Symlinked %s to %s', kid, spath)

        if trust_changed:
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

            logger.debug('Writing out the text graph')
            with open(txtgraphout, 'wb') as fout:
                fout.write(key_paths_repr)
                logger.info('Wrote %s', txtgraphout)

        wcount += 1

    logger.info('Processed %s keys, made %s changes', kcount, wcount)
