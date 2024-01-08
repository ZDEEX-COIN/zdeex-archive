#!/usr/bin/env python
# Copyright (c) 2016-2023 The Hush developers
# Copyright 2014 BitPay, Inc.
# Distributed under the GPLv3 software license, see the accompanying
# file COPYING or https://www.gnu.org/licenses/gpl-3.0.en.html

import os
import bctest
import buildenv

if __name__ == '__main__':
	bctest.bctester(os.environ["srcdir"] + "/test/data",
			"bitcoin-util-test.json",buildenv)
