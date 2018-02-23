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

import os
import sys
import sqlite3
import wotmate


def keyring_populate_all_pubkeys(c, use_weak):
    logger.info('Loading all valid pubkeys')
    keyid_rowid_map = {}
    for line in wotmate.gpg_run_command(['--list-public-keys'], [b'pub:']):
        fields = wotmate.gpg_get_fields(line)
        # is this key expired/revoked or is otherwise invalid?
        if fields[1] in ('e', 'r', 'i'):
            continue
        # is this key too weak to bother considering it?
        if not use_weak and (fields[3] in ('1', '17') and int(fields[2]) < 2048):
            logger.info('Ignoring weak key: %s' % fields[4])
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
        keyid_rowid_map[fields[4]] = c.lastrowid

    logger.info('Loaded %s pubkeys' % len(keyid_rowid_map))
    return keyid_rowid_map


def store_uid(c, pubrowid, fields, is_primary):
    data = (
            pubrowid,
            fields[1],
            fields[5],
            fields[6],
            fields[9],
            is_primary,
            )
    c.execute('INSERT INTO uid VALUES (?,?,?,?,?,?)', data)
    return c.lastrowid


def keyring_populate_uid_sig_data(c, keyid_rowid_map):
    logger.info('Loading uid and signature data')
    sigquery = 'INSERT INTO sig VALUES (?,?,?,?,?)'
    # we use these to track which is the current pubkey/uid we're looking at
    pubkeyid = None
    pubrowid = None
    is_primary = 1
    uidrowid = None
    uidsigs = {}
    revsigs = []
    uidcount = 0
    sigcount = 0
    seen_pubkeys = 0

    for line in wotmate.gpg_run_command(['--list-sigs'], [b'pub:', b'uid:', b'sig:', b'rev:']):
        if line.startswith(b'pub:'):
            fields = wotmate.gpg_get_fields(line)
            pubkeyid = fields[4]
            if pubkeyid not in keyid_rowid_map.keys():
                continue

            pubrowid = keyid_rowid_map[pubkeyid]
            is_primary = 1
            seen_pubkeys += 1
            uidrowid = None

        elif line.startswith(b'uid:'):
            if uidsigs:
                # store all sigs seen for previous uid
                c.executemany(sigquery, uidsigs.values())
                sigcount += len(uidsigs)
                uidsigs = {}
                revsigs = []

            try:
                fields = wotmate.gpg_get_fields(line)
            except UnicodeDecodeError:
                # Broken uid, ignore it
                uidrowid = None
                continue

            # is this uid expired/revoked or is otherwise invalid?
            if pubrowid is None or fields[1] in ('e', 'r', 'i'):
                uidrowid = None
                continue

            uidrowid = store_uid(c, pubrowid, fields, is_primary)
            uidcount += 1
            is_primary = 0
            revsigs = []

        elif line.startswith(b'sig:') or line.startswith(b'rev:'):
            # if we don't have a valid uidrowid, skip this until we do
            if uidrowid is None:
                continue

            fields = wotmate.gpg_get_fields(line)
            sigkeyid = fields[4]

            # ignore self-sigs
            if sigkeyid == pubkeyid:
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
                    # add to revsigs, so we ignore this sig if we see it
                    revsigs.append(sigkeyid)
                    continue

                elif sigtype < 0x10 or sigtype > 0x13:
                    continue

            else:
                # don't want this sig, as it's not anything we recognize
                # for our purposes
                continue

            # has this sig been revoked?
            if sigkeyid in revsigs:
                continue

            # do we have the key that signed it?
            if sigkeyid in keyid_rowid_map.keys():
                uidsigs[sigkeyid] = (
                    uidrowid,
                    keyid_rowid_map[sigkeyid],
                    fields[5],
                    fields[6],
                    sigtype
                )
    if uidsigs:
        # store all sigs seen for previous key+uid
        c.executemany(sigquery, uidsigs.values())
        sigcount += len(uidsigs)

    logger.info('Loaded %s valid uids and %s valid sigs' % (uidcount, sigcount))


def wotsap_populate_keys(c, fh, size):
    logger.info('Converting keys...')
    readbytes = 0
    keycount = 0
    while readbytes < size:
        key = fh.read(8)
        readbytes += 8
        # wotsap doesn't give us useful info about the key, just the ID
        c.execute('''INSERT INTO pub (keyid) VALUES (?)''', (key.hex().upper(),))
        keycount += 1
    logger.info('Imported %s keys' % keycount)


def wotsap_populate_names(c, fh, size):
    logger.info('Converting names...')
    readbytes = 0
    p_rowid = 1
    namecount = 0
    while readbytes < size:
        blob = b''
        while True:
            char = fh.read(1)
            readbytes += 1
            if char == b'\n':
                break
            blob += char
            if readbytes >= size:
                break
        uiddata = blob.decode('utf8', 'ignore')
        c.execute('''INSERT INTO uid (pubrowid, uiddata, is_primary) VALUES (?, ?, 1)''',
                  (p_rowid, uiddata))
        p_rowid += 1
        namecount += 1

    logger.info('Imported %s names' % namecount)


def wotsap_populate_sigs(c, fh, size):
    logger.info('Converting sigs...')
    import struct
    readbytes = 0
    p_rowid = 1
    totalsigs = 0
    while readbytes < size:
        sigcount = struct.unpack('!i', fh.read(4))[0]
        readbytes += 4
        cursig = 0
        while cursig < sigcount:
            # ignore the leading 4 bits for now, as we don't do
            # anything with sig types for our purposes
            _sig = 0x0FFFFFFF & struct.unpack('!i', fh.read(4))[0]

            readbytes += 4
            # in wotsap uidrow ends up being the same as pubrow
            c.execute('''INSERT INTO sig (uidrowid, pubrowid) VALUES (?, ?)''',
                      (p_rowid, _sig+1))

            cursig += 1
            totalsigs += 1

        p_rowid += 1

    logger.info('Imported %s signature relationships' % totalsigs)


def convert_wotsap(c, wotsap):
    import bz2
    fh = bz2.open(wotsap)
    magic = fh.read(8)
    if magic != b'!<arch>\n':
        logger.critical('%s does not appear to be in ar archive' % wotsap)
        sys.exit(1)
    while True:
        fileident = fh.read(16).strip()
        if not fileident:
            break
        fh.read(32)
        size = int(fh.read(10).strip())
        fh.read(2)
        if fileident[:4] == b'keys':
            wotsap_populate_keys(c, fh, size)
        elif fileident[:4] == b'name':
            wotsap_populate_names(c, fh, size)
        elif fileident[:4] == b'sign':
            wotsap_populate_sigs(c, fh, size)
        else:
            fh.read(size)


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
                    default='/usr/bin/gpg2',
                    help='Location of the gpg binary to use')
    ap.add_argument('--wotsap', default=None,
                    help='Convert a wotsap archive instead of using keyring')
    ap.add_argument('--gnupghome',
                    help='Set this as gnupghome instead of using the default')

    cmdargs = ap.parse_args()

    global logger
    logger = wotmate.get_logger(cmdargs.quiet)

    if cmdargs.gnupghome:
        wotmate.GNUPGHOME = cmdargs.gnupghome
    if cmdargs.gpgbin:
        wotmate.GPGBIN = cmdargs.gpgbin

    try:
        os.unlink(cmdargs.dbfile)
    except OSError as ex:
        pass

    dbconn = sqlite3.connect(cmdargs.dbfile)
    cursor = dbconn.cursor()
    wotmate.init_sqlite_db(cursor)

    if not cmdargs.wotsap:
        kr_map = keyring_populate_all_pubkeys(cursor, cmdargs.use_weak)
        keyring_populate_uid_sig_data(cursor, kr_map)
    else:
        convert_wotsap(cursor, cmdargs.wotsap)

    dbconn.commit()
    dbconn.close()
    logger.info('Wrote %s' % cmdargs.dbfile)
