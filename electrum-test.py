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

from bitcoin.core import CTransaction, VectorSerializer
from bitcoin.core.script import CScriptOp

from bitcoin.base58 import CBase58Data

ELECTRUM = """electrum server url and port to connect to"""

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

def b2x(b):
    """Convert bytes to a hex string"""
    return binascii.hexlify(b).decode('utf8')

def b2lx(b):
    """Convert bytes to a little-endian hex string

    Lets you show uint256's and uint160's the way the Satoshi codebase shows
    them.
    """
    return binascii.hexlify(b[::-1]).decode('utf8')

def lx(h):
    """Convert a little-endian hex string to bytes

    Lets you write uint256's and uint160's the way the Satoshi codebase shows
    them.
    """
    return binascii.unhexlify(h.encode('utf8'))[::-1]

###############################################################################

# ins

def coutpoint2dict(coutpoint):
    d = {}
    d['hash'] = b2lx(coutpoint.hash)
    d['n'] = coutpoint.n
    return d

def scriptstuff2dict(opcode, data, idx):
    return {'opcode':  str(CScriptOp(opcode)),
            'data':    b2lx(data) if data else None,
            'sop_idx': idx}

def cscript2dict(cscript):
    return {'script': [scriptstuff2dict(o, d, i) for o, d, i in
                       cscript.raw_iter()]}

def ctxin2dict(ctxin):
    d = {}
    d['nSequence'] = ctxin.nSequence
    d['prevout'] = coutpoint2dict(ctxin.prevout)
    d['scriptSig'] = cscript2dict(ctxin.scriptSig)
    return d

# outs

def scriptpubkey2dict(scriptPubKey):
    s = cscript2dict(scriptPubKey)['script']
    if s[0]['opcode'] == "OP_HASH160":
        assert len(s) == 3, "unexpected script length"
        assert s[2]['opcode'] == 'OP_EQUAL', "unexpected scriptPubKey"
        return {'type':    "P2SH_OR_PTPKWH",
                'address': str(CBase58Data.from_bytes(lx(s[1]['data']), 5))}
    elif s[0]['opcode'] == 'OP_DUP':
        assert s[1]['opcode'] == 'OP_HASH160', "unexpected scriptPubKey"
        assert s[3]['opcode'] == 'OP_EQUALVERIFY', "unexpected scriptPubKey"
        assert s[4]['opcode'] == 'OP_CHECKSIG', "unexpected scriptPubKey"
        return {'type':    "P2PKH",
                'address': str(CBase58Data.from_bytes(lx(s[2]['data']), 0))}
    else:
        assert False, "unexpected scriptPubKey"


def ctxout2dict(ctxout):
    d = {}
    d['nValue'] = ctxout.nValue
    d['scriptPubKey'] = scriptpubkey2dict(ctxout.scriptPubKey)
    return d

# witness

def cscriptwitness2dict(cscriptwitness):
    return {'stack': [str(s) for s in cscriptwitness.stack]}

def ctxinwitness2dict(ctxinwitness):
    return {'scriptWitness': cscriptwitness2dict(ctxinwitness.scriptWitness)}

def ctxwitness2dict(ctxwitness):
    d = {}
    d['vtxinwit'] = [ctxinwitness2dict(w) for w in ctxwitness.vtxinwit]
    return d

# transactions

def ct2dict(ct):
    d = {}
    d['nVersion'] = ct.nVersion
    d['nLockTime'] = ct.nLockTime
    d['vin'] = [ctxin2dict(i) for i in ct.vin]
    d['vout'] = [ctxout2dict(o) for o in ct.vout]
    d['wit'] = ctxwitness2dict(ct.wit)
    return d

###############################################################################


def print_indent(indent, s):
    print("%s%s" % ("\t" * indent, s))

def print_slots(obj, indent=0, slot_name=None):
    if not hasattr(obj, '__slots__'):
        if type(obj) == bytes:
            print_indent(indent, "slot_name: %s bytes" % (slot_name))
            print_indent(indent, b2lx(obj))
        elif hasattr(obj, '__iter__'):
            print_indent(indent, "slot_name: %s, iterable: %s" % (slot_name,
                                                                  type(obj)))
            idx = 0
            for e in iter(obj):
                print_indent(indent, "slot_name: %s, iteration %d" % (slot_name,
                                                                      idx))
                print_slots(e, indent=(indent+1), slot_name=slot_name)
                idx = idx + 1
        else:
            print_indent(indent, "slot_name %s, primitive: %s" % (slot_name,
                                                                  type(obj)))
            print_indent(indent, obj)
        return

    for s in obj.__slots__:
        print_indent(indent, "slots obj - name: %s, of parent: %s" % (s,
                                                                      type(obj)))
        print_slots(getattr(obj, s), indent=(indent + 1), slot_name=s)


#    print("to_dict %s" % type(obj))
#    if not hasattr(obj, '__slots__'):
#        print("type: %s str: %s" % (type(obj), str(obj)))
#        return obj
#    return {s: to_dict(getattr(obj, s, None)) for s in obj.__slots__}

def print_ct2(ct):
    #d = to_dict(ct)
    #print(json.dumps(d, indent=1, sort_keys=True))
    #print_slots(ct)
    print(ct2dict(ct))
    print(json.dumps(ct2dict(ct), indent=1, sort_keys=True))


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
        print(r['tx_hash'])
        t = eq.query("blockchain.transaction.get",
                     r['tx_hash'])
        print(t['result'])
        b = binascii.unhexlify(t['result'].encode('utf8'))
        ct = CTransaction.deserialize(b)
        print(ct)

        print_ct2(ct)

        #vs = VectorSerializer()
        #print(ct.serialize())
        #print(json.dumps(ct, sort_keys=True, indent=1))


    #wd = WebData(tails=tails)
    #coin_data = wd.fetch_forkdrop_info()
    #dm = DirectoryManager()
    #p = dm.get_forkdrop_file()
    #FileManager.write_json_info(p, coin_data)
    print(settings)
