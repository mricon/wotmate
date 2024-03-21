#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright © 2018-2024 by The Linux Foundation and contributors
__author__ = 'Konstantin Ryabitsev <konstantin@linuxfoundation.org>'

import os
import sqlite3
import wotmate


def keyring_load_pub_uid(c, use_weak):
    logger.info('Loading all valid pubkeys')
    uid_hash_rowid_map = {}
    pub_keyid_rowid_map = {}
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
                    fields[4],
                    fields[1],
                    fields[2],
                    fields[3],
                    fields[5],
                    fields[6],
                    fields[8],
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
                data = (
                    current_pubrowid,
                    fields[1],
                    fields[5],
                    fields[6],
                    fields[9],
                    is_primary,
                )
                c.execute('INSERT INTO uid VALUES (?,?,?,?,?,?)', data)
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


def keyring_load_sig_data(c, pub_keyid_rowid_map, uid_hash_rowid_map):
    logger.info('Loading signature data')
    sigquery = 'INSERT INTO sig VALUES (?,?,?,?,?)'
    # used to track the current pubkey/uid
    pubkeyid = None
    uidrowid = None
    uidsigs = {}
    revsigs = []
    is_revuid = False
    sigcount = 0
    ignored_sigs = 0

    for line in wotmate.gpg_get_lines(['--list-sigs', '--fast-list-mode'],
                                      [b'pub:', b'uid', b'sig:', b'rev:']):

        fields = wotmate.gpg_get_fields(line)

        if uidsigs and fields[0] in ('pub', 'uid'):
            c.executemany(sigquery, uidsigs.values())
            sigcount += len(uidsigs)
            uidsigs = {}
            revsigs = []

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
                    revsigs.append(sigkeyid)
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
    ap.add_argument('--use-weak-keys', dest='use_weak',
                    action='store_true', default=False,
                    help='Do not discard keys considered too weak')
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

    (pub_map, uid_map) = keyring_load_pub_uid(cursor, cmdargs.use_weak)
    keyring_load_sig_data(cursor, pub_map, uid_map)

    dbconn.commit()
    dbconn.close()
    logger.info('Wrote %s' % cmdargs.dbfile)
