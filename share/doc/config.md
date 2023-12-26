# HUSH3.conf config options

This document explains all options that can be used in HUSH3.conf

# Basics

Options can either be put in HUSH3.conf or given on the `hushd` commandline when starting. If you think you will want to continually use a feature, it's better to put it in HUSH3.conf. If you don't, and start `hushd` without an option on accident, it can cause downtime from a long rescan, that you didn't want to do anyway.


## Common Options

## addnode=1.2.3.4

Tells your node to connect to another node, by IP address or hostname.

## consolidation=1

Defaults to 0 in CLI hushd, defaults to 1 in SilentDragon. This option consolidates many unspent shielded UTXOs (zutxos) into one zutxo, which makes spending them in the future faster and potentially cost less in fees. It also helps prevent
certain kinds of metadata leakages and spam attacks. It is not recommended for very large wallets (wallet.dat files with thousands of transactions) for performance reasons. This is why it defaults to OFF for CLI full nodes but ON for GUI wallets that use an embedded hushd.

## rescan=1

Defaults to 0. Performs a full rescan of all of chain history. Can take a very long time. Speed this up with `rescanheight=123` to only rescan from a certain block height. Also speed this up with `keepnotewitnesscache=1` to not rebuild the zaddr witness cache.

## rpcuser=hushpuppy

No default. This option sets the RPC username and should only be used in HUSH3.conf, because setting it from the command-line makes it show up in `ps` output.

## rpcpassword=TOOMANYSECRETS

No default. This option sets the RPC password and should only be used in HUSH3.conf, because setting it from the command-line makes it show up in `ps` output.

## txindex=1

Defaults to 1. This is a default option that should not be changed or things will not work correctly.

## zindex=1

Defaults to 0. This option enables the "shielded index" which also calculates the "anonset" (anonymity set) also known as the "shielded pool". This data is avaailable in the getchaintxstats RPC, if zindex is enabled. Enabling this feature requires a full rescan or full sync from scratch, which is not done by default. If you don't do one of those things, your zindex stats will be incorrect.

# Mining and Stratum server options

These options are only of interest to solo miners and mining pool operators....

## stratum

Defaults to off. This option enables a Stratum server.

## stratumaddress=<address>

Defaults to none. This option sets a Stratum Mining address to use when special address of 'x' is sent by miner.

## stratumbind=<ipaddr>

Defaults to: bind to all interfaces. This option Binds to given address to listen for Stratum work requests. Use [host]:port notation for IPv6. This option can be specified multiple times.

## stratumport=<port>

Defaults to 19031 or 19031 for testnet. This option sets the <port> to listen for Stratum work requests on.

## stratumallowip=<ip>

No default. This option allows Stratum work requests from specified source. Valid for <ip> are a single IP (e.g. 1.2.3.4), a network/netmask (e.g. 1.2.3.4/255.255.255.0) or a network/CIDR (e.g. 1.2.3.4/24). This option can be specified multiple times.

# Other options

These options are not commonly used and likely on for advanced users and/or developers...

## addressindex=1

Defaults to 0 in hushd, defaults to 1 in some GUI wallets. Maintain a full address index, used to query for the balance, txids and unspent outputs for addresses

## timestampindex=1

Defaults to 0 in hushd, defaults to 1 in some GUI wallets. Maintain a timestamp index for block hashes, used to query blocks hashes by a range of timestamps 

## spentindex=1

Defaults to 0 in hushd, defaults to 1 in some GUI wallets. Maintain a full spent index, used to query the spending txid and input index for an outpoint 
