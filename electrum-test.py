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

class ElectrumAddressInfo(dict):
    """
    info queried for a single address
    """
    def __init__(self, settings, addr):
        super().__init__()
        self.server = settings.electrum_server
        self.port = settings.electrum_port
        self.ssl = not settings.electrum_no_ssl
        self.tails = not settings.not_tails
        self.cache = settings.cache_requests
        self.addr = addr
        self.eq = ElectrumQuery(self.server, self.port, ssl=self.ssl,
                                tails=self.tails, cache=self.cache)

        tx_block_map = self._get_tx_block_map()

        unspent = self._get_unspent_outputs()
        sts = list(self._get_stransactions(tx_block_map.keys()))
        funding = list(self._get_funding(sts))
        defunding = list(self._get_defunding(sts, funding))

        print("tx_block_map: %s" % tx_block_map)
        print("unspent: %s" % unspent)
        print("funding: %s" % funding)
        print("defunding: %s" % defunding)

        self['addr'] = self.addr
        self['spans'] = []
        self['p2sh_p2wpkh'] = self.addr[:1] == "3"
        #TODO bech32 isn't really supported yet
        self['bech32'] = self.addr[:3] == "bc1"

    def _get_tx_block_map(self):
        q = self.eq.query("blockchain.address.get_history", self.addr)
        return {r['tx_hash']: r['height'] for r in q['result']}

    def _funding_id(self, tx_hash, n):
        return "%s %s" % (tx_hash, n)

    def _get_unspent_outputs(self):
        q = self.eq.query("blockchain.address.listunspent", self.addr)
        return q['result']

    def _get_stransactions(self, txids):
        for txid in txids:
            t = self.eq.query("blockchain.transaction.get", txid)
            yield STransaction(txid, t['result'])

    def _get_funding(self, sts):
        for st in sts:
            for addr, satoshis, n in st.iter_outs():
                if addr != self.addr:
                    continue
                yield {'satoshis': satoshis,
                       'n':        n,
                       'txid':     st.txid}

    def _get_defunding(self, sts, funding):
        funding_txids = {f['txid']: f for f in funding}
        for st in sts:
            for txid, n in st.iter_ins():
                if txid not in funding_txids.keys():
                    continue
                yield {'satoshis': funding_txids[txid]['satoshis'],
                       'n':        n,
                       'txid':     st.txid}

###############################################################################

ARGS = ['electrum_server', 'electrum_port', 'electrum_no_ssl',
        'cache_requests', 'address_list', "not_tails"]

if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description="Pull down the current fork metadata from forkdrop.io")

    add_args(parser, ARGS)
    settings = parser.parse_args()
    validate_args(settings, ARGS)


    for a in settings.addresses:
        eai = ElectrumAddressInfo(settings, a)


#    eq = ElectrumQuery(settings.electrum_server, settings.electrum_port,
#                       ssl=(not settings.electrum_no_ssl),
#                       tails=(not settings.not_tails),
#                       cache=settings.cache_requests)
#
#    q = eq.query("blockchain.address.listunspent",
#                 "1MrpoVBweTnwPTase83S13LSZZ2Ga4Amk7")
#
#    print(json.dumps(q, sort_keys=True, indent=1))
#
#    q = eq.query("blockchain.address.get_history",
#                 "1MrpoVBweTnwPTase83S13LSZZ2Ga4Amk7")
#    print(json.dumps(q, sort_keys=True, indent=1))
#
#
#    for r in q['result']:
#        #print(r['tx_hash'])
#        t = eq.query("blockchain.transaction.get",
#                     r['tx_hash'])
#        st = STransaction(r['tx_hash'], t['result'])
#        for h, n in st.iter_ins():
#            print("prevout: %s %d" % (h, n))
#        for a, v, n in st.iter_outs():
#            print("newout: %s %d %d" % (a, v, n))
#        #print(st.to_json())
#    print(settings)
