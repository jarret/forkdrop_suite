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


from lib.args import add_args, validate_args
###############################################################################


###############################################################################

class ElectrumAddressInfo(object):
    def __init__(self, settings, addr):
        self.server = server
        self.port = port
        self.ssl = ssl
        self.addr = addr
        # TODO sanitize addres
        CBase58Data(self.addr)

        #eq = ElectrumQuery(self.server, self.port, ssl

    def _get_tx_block_map(self):
        pass

###############################################################################

ARGS = ['electrum_server', 'electrum_port', 'electrum_no_ssl',
        'cache_requests', 'address_list', "not_tails"]

if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description="Pull down the current fork metadata from forkdrop.io")

    add_args(parser, ARGS)
    settings = parser.parse_args()
    validate_args(settings, ARGS)

    eq = ElectrumQuery(settings.electrum_server, settings.electrum_port,
                       ssl=(not settings.electrum_no_ssl),
                       tails=(not settings.not_tails),
                       cache=settings.cache_requests)

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
