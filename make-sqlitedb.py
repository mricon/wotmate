#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright © 2018-2024 by The Linux Foundation and contributors
__author__ = 'Konstantin Ryabitsev <konstantin@linuxfoundation.org>'

import os
import sqlite3
import wotmate

from typing import Tuple, Dict, Any, Set


def keyring_load_pub_uid(c: sqlite3.Cursor, 
                         use_weak: bool) -> Tuple[Dict[str, Tuple[int, int]], Dict[Tuple[str, str], int]]:
    logger.info('Loading all valid pubkeys')
    uid_hash_rowid_map: Dict[Tuple[str, str], int] = dict()
    pub_keyid_rowid_map: Dict[str, Tuple[int, int]] = dict()
    current_pubkey = None
    current_pubrowid = None
    is_primary = 1
    ignored_keys = 0
    ignored_uids = 0
    for line in wotmate.gpg_get_lines(['--list-public-keys'], [b'pub:', b'uid']):
        fields = wotmate.gpg_get_fields(line)
        if fields[0] == 'pub':
            # is this key expired/revoked or is otherwise invalid?
            if fields[1] in ('e', 'r', 'i'):
                ignored_keys += 1
                continue
            # is this key too weak to bother considering it?
            if not use_weak and (fields[3] in ('1', '17') and int(fields[2]) < 2048):
                # logger.info('Ignoring weak key: %s' % fields[4])
                ignored_keys += 1
                continue

            data = (
                    fields[4], # KeyID
                    fields[1], # Validity
                    fields[2], # Key length
                    fields[3], # Public key algorithm
                    fields[5], # Creation date
                    fields[6], # Expiration date
                    fields[8], # Ownertrust
                   )
            c.execute('INSERT INTO pub VALUES (?,?,?,?,?,?,?)', data)
            current_pubkey = fields[4]
            current_pubrowid = c.lastrowid
            is_primary = 1

        elif fields[0] == 'uid':
            if fields[1] in ('e', 'r', 'i'):
                ignored_uids += 1
                continue

            if current_pubrowid is not None:
                if current_pubkey is None:
                    logger.error('No pubkey for uid %s' % fields[7])
                    continue
                data = (
                    current_pubrowid,
                    fields[1], # Validity
                    fields[5], # Creation date
                    fields[6], # Expiration date
                    fields[9], # User-ID
                    is_primary,
                )
                c.execute('INSERT INTO uid VALUES (?,?,?,?,?,?)', data)
                if c.lastrowid is None:
                    logger.error('Failed to insert uid %s' % fields[9])
                    continue
                uid_hash_rowid_map[(current_pubkey, fields[7])] = c.lastrowid

                if is_primary:
                    pub_keyid_rowid_map[current_pubkey] = (current_pubrowid, c.lastrowid)

                is_primary = 0
            else:
                ignored_uids += 1
        else:
            pass

    logger.info('Loaded %s pubkeys (%s ignored)' % (len(pub_keyid_rowid_map), ignored_keys))
    logger.info('Loaded %s uids (%s ignored)' % (len(uid_hash_rowid_map), ignored_uids))
    return pub_keyid_rowid_map, uid_hash_rowid_map


def keyring_load_sig_data(c: sqlite3.Cursor, 
                          pub_keyid_rowid_map: Dict[str, Tuple[int, int]],
                          uid_hash_rowid_map: Dict[Tuple[str, str], int],
                          use_weak: bool = False) -> None:
    logger.info('Loading signature data')
    sigquery = 'INSERT INTO sig VALUES (?,?,?,?,?)'
    # used to track the current pubkey/uid
    pubkeyid = None
    uidrowid = None
    uidsigs: Dict[str, Any] = dict()
    revsigs: Set[str] = set()
    is_revuid = False
    sigcount = 0
    ignored_sigs = 0

    for line in wotmate.gpg_get_lines(['--list-sigs', '--fast-list-mode'],
                                      [b'pub:', b'uid', b'sig:', b'rev:']):

        fields = wotmate.gpg_get_fields(line)

        if uidsigs and fields[0] in ('pub', 'uid'):
            c.executemany(sigquery, uidsigs.values())
            sigcount += len(uidsigs)
            uidsigs = dict()
            revsigs = set()

        if fields[0] == 'pub':
            uidrowid = None
            pubkeyid = None
            is_revuid = False
            if fields[4] in pub_keyid_rowid_map.keys():
                pubkeyid = fields[4]

        elif fields[0] == 'uid':
            if not pubkeyid:
                continue
            # is this uid expired/revoked or is otherwise invalid?
            if fields[1] in ('e', 'r', 'i'):
                is_revuid = True
                continue
            try:
                uidrowid = uid_hash_rowid_map[(pubkeyid, fields[7])]
            except IndexError:
                # unknown uid somehow, ignore it
                continue

        elif fields[0] in ('sig', 'rev'):
            if not pubkeyid or is_revuid:
                ignored_sigs += 1
                continue
            # some gpg versions, when using --fast-list-mode, don't show UID
            # entries, so for those cases use the primary UID of the pubkey
            if uidrowid is None:
                uidrowid = pub_keyid_rowid_map[pubkeyid][1]

            sigkeyid = fields[4]

            # ignore self-sigs
            if sigkeyid == pubkeyid:
                ignored_sigs += 1
                continue

            # We use this map to eject revoked sigs before we store them
            # We only want sig types 0x10-13
            if len(fields[10]) >= 2:
                sigtype = int(fields[10][:2], base=16)
                if sigtype == 0x30:
                    # this is a revsig!
                    if sigkeyid in uidsigs.keys():
                        # remove this signature from our sigs to store
                        del(uidsigs[sigkeyid])
                        ignored_sigs += 1
                    # add to revsigs, so we ignore this sig if we see it
                    revsigs.add(sigkeyid)
                    continue

                elif sigtype < 0x10 or sigtype > 0x13:
                    ignored_sigs += 1
                    continue

            else:
                # don't want this sig, as it's not anything we recognize
                # for our purposes
                continue

            # has this sig been revoked?
            if sigkeyid in revsigs:
                ignored_sigs += 1
                continue

            if not use_weak and fields[15] in {'1', '2'}:
                logger.debug('Ignoring weak sig with algo=%s' % fields[15])
                ignored_sigs += 1
                continue

            # do we have the key that signed it?
            if sigkeyid in pub_keyid_rowid_map.keys():
                uidsigs[sigkeyid] = (
                    uidrowid,
                    pub_keyid_rowid_map[sigkeyid][0],
                    fields[5],
                    fields[6],
                    sigtype
                )
    if uidsigs:
        # store all sigs seen for previous key+uid
        c.executemany(sigquery, uidsigs.values())
        sigcount += len(uidsigs)

    logger.info('Loaded %s valid sigs (%s ignored)' % (sigcount, ignored_sigs))


if __name__ == '__main__':
    import argparse

    ap = argparse.ArgumentParser(
        description='Create a sqlite database of key and signature data',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )

    ap.add_argument('--quiet', action='store_true',
                    default=False,
                    help='Be quiet and only output errors')
    ap.add_argument('--dbfile', dest='dbfile',
                    default='siginfo.db',
                    help='Create database in this file')
    ap.add_argument('--use-weak-keys', dest='use_weak_keys',
                    action='store_true', default=False,
                    help='Do not discard keys considered too weak')
    ap.add_argument('--use-weak-algos', dest='use_weak_algos',
                    action='store_true', default=False,
                    help='Do not discard cross-signatures that use weak algorithms')
    ap.add_argument('--gpgbin',
                    default='/usr/bin/gpg',
                    help='Location of the gpg binary to use')
    ap.add_argument('--gnupghome',
                    help='Set this as gnupghome instead of using the default')

    cmdargs = ap.parse_args()

    logger = wotmate.get_logger(cmdargs.quiet)

    if cmdargs.gnupghome:
        wotmate.GNUPGHOME = cmdargs.gnupghome
    if cmdargs.gpgbin:
        wotmate.GPGBIN = cmdargs.gpgbin

    try:
        os.unlink(cmdargs.dbfile)
        logger.debug('Removed old %s', cmdargs.dbfile)
    except OSError as ex:
        pass

    dbconn = sqlite3.connect(cmdargs.dbfile)
    cursor = dbconn.cursor()
    wotmate.init_sqlite_db(cursor)

    (pub_map, uid_map) = keyring_load_pub_uid(cursor, cmdargs.use_weak_keys)
    keyring_load_sig_data(cursor, pub_map, uid_map, use_weak=cmdargs.use_weak_algos)

    dbconn.commit()
    dbconn.close()
    logger.info('Wrote %s' % cmdargs.dbfile)
