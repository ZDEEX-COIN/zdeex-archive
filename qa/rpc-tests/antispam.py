#!/usr/bin/env python2
# Copyright (c) 2016-2023 The Hush developers
# Distributed under the GPLv3 software license, see the accompanying
# file COPYING or https://www.gnu.org/licenses/gpl-3.0.en.html

from test_framework.test_framework import BitcoinTestFramework
from test_framework.authproxy import JSONRPCException
from test_framework.util import (
    assert_equal,
    start_nodes,
    wait_and_assert_operationid_status,
)

from decimal import Decimal

class AntispamTest(BitcoinTestFramework):

    def setup_nodes(self):
        return start_nodes(2, self.options.tmpdir, [[ ]] * 2)

    def run_test(self):
        # Sanity-check the test harness
        assert_equal(self.nodes[0].getblockcount(), 200)

        # make sure we can mine a block
        self.nodes[1].generate(1)
        self.sync_all()

        # make a new zaddr on each node
        saplingAddr0 = self.nodes[0].z_getnewaddress()
        saplingAddr1 = self.nodes[1].z_getnewaddress()

        # Verify addresses
        assert(saplingAddr0 in self.nodes[0].z_listaddresses())
        assert(saplingAddr1 in self.nodes[1].z_listaddresses())
        assert_equal(self.nodes[0].z_validateaddress(saplingAddr0)['type'], 'sapling')
        assert_equal(self.nodes[0].z_validateaddress(saplingAddr1)['type'], 'sapling')

        # Verify balance
        assert_equal(self.nodes[0].z_getbalance(saplingAddr0), Decimal('0'))
        assert_equal(self.nodes[1].z_getbalance(saplingAddr1), Decimal('0'))

if __name__ == '__main__':
    AntispamTest().main()
