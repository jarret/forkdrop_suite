#!/usr/bin/env python3
# Copyright (c) 2018 PrimeVR
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php

import argparse
import sys
import json
import binascii

from lib.tails import check_tails
from lib.options import not_tails_arg

from lib.web_data import WebData
from lib.utl.dir_manager import DirectoryManager
from lib.utl.file_manager import FileManager

from lib.electrum_query import ElectrumQuery

from lib.stransaction import STransaction

ELECTRUM = """electrum server url and port to connect to"""

###############################################################################

def electrum_arg(parser):
    parser.add_argument('-e', '--electrum', type=str, help=ELECTRUM)

def parse_electrum_arg(electrum):
    if not electrum:
        return
    split = electrum.split(':')
    if len(split) != 2:
        sys.exit("invalid electrum server: %s" % electrum)

    s = electrum.split(':')[0]
    p = int(electrum.split(':')[1])
    return s, p

###############################################################################

if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description="Pull down the current fork metadata from forkdrop.io")
    not_tails_arg(parser)
    electrum_arg(parser)

    settings = parser.parse_args()

    tails = not settings.not_tails
    check_tails(tails)

    s, p = parse_electrum_arg(settings.electrum)

    eq = ElectrumQuery(s, p, ssl=True, tails=tails, cache=True)

    q = eq.query("blockchain.address.listunspent",
                 "1MrpoVBweTnwPTase83S13LSZZ2Ga4Amk7")

    print(json.dumps(q, sort_keys=True, indent=1))

    q = eq.query("blockchain.address.get_history",
                 "1MrpoVBweTnwPTase83S13LSZZ2Ga4Amk7")
    print(json.dumps(q, sort_keys=True, indent=1))

    for r in q['result']:
        #print(r['tx_hash'])
        t = eq.query("blockchain.transaction.get",
                     r['tx_hash'])
        st = STransaction(t['result'])
        for h, n in st.iter_ins():
            print("prevout: %s %d" % (h, n))
        for a, v, n in st.iter_outs():
            print("newout: %s %d %d" % (a, v, n))
        #print(st.to_json())
