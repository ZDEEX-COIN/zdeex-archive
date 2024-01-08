#!/usr/usr/bin/env bash
# Copyright (c) 2016-2023 The Hush developers
# Distributed under the GPLv3 software license, see the accompanying
# file COPYING or https://www.gnu.org/licenses/gpl-3.0.en.html
# This script makes the neccesary transactions to migrate
# coin between 2 assetchains on the same -ac_cc id
set -e
source=DERPZ
target=DERPZ000
address="Rxxx"
amount=1

# Alias for running cli on source chain
cli_source="hush-cli -ac_name=$source"

# Raw tx that we will work with
txraw=`$cli_source createrawtransaction "[]" "{\"$address\":$amount}"`

# Convert to an export tx
exportData=`$cli_source migrate_converttoexport $txraw $target $amount`
exportRaw=`echo $exportData | jq -r .exportTx`
exportPayouts=`echo $exportData | jq -r .payouts`

# Fund
exportFundedData=`$cli_source fundrawtransaction $exportRaw`
exportFundedTx=`echo $exportFundedData | jq -r .hex`

# Sign
exportSignedData=`$cli_source signrawtransaction $exportFundedTx`
exportSignedTx=`echo $exportSignedData | jq -r .hex`

# Send
echo "Sending export tx"
$cli_source sendrawtransaction $exportSignedTx

read -p "Wait for a notarization to HUSH, and then two more notarizations from the target chain, and then press enter to continue"

# Create import
importTx=`$cli_source migrate_createimporttransaction $exportSignedTx $payouts`
importTx=`hush-cli migrate_completeimporttransaction $importTx`

# Send import
hush-cli -ac_name=$target sendrawtransaction $importTx
