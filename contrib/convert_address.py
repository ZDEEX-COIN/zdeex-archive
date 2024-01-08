#!/usr/bin/env python3
# Copyright (c) 2019 Hush developers
# Released under the GPLv3

import sys
import base58
from binascii import unhexlify
from base58 import b58encode, b58decode_check
from hashlib import sha256

# based on https://github.com/KMDLabs/pos64staker/blob/master/stakerlib.py#L89
def addr_convert(prefix, address, prefix_bytes):
    rmd160_dict  = {}
    # ZEC/HUSH/etc have 2 prefix bytes, BTC/KMD only have 1
    # NOTE: any changes to this code should be verified against https://dexstats.info/addressconverter.php
    ripemd       = b58decode_check(address).hex()[2*prefix_bytes:]
    net_byte     = prefix + ripemd
    bina         = unhexlify(net_byte)
    sha256a      = sha256(bina).hexdigest()
    binb         = unhexlify(sha256a)
    sha256b      = sha256(binb).hexdigest()
    final        = b58encode(unhexlify(net_byte + sha256b[:8]))
    return(final.decode())

if len(sys.argv) < 2:
    sys.exit('Usage: %s hushv2address' % sys.argv[0])

address = sys.argv[1]
# convert given address to a KMD address
print(addr_convert('3c', address,2))
