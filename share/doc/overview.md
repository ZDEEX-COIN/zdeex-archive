# Hush Overview

## Mining Algorithm

Equihash (200,9) (ASIC)

## Block time

75 seconds

## Block size

4MB

## P2P

TLS1.3 via WolfSSL is enforced for all network connections as of v3.6.1

## RPC

Inherited many RPC's from Bitcoin and Zcash with many new ones

## Consensus

Hush is a mandatory privacy blockchain as of Block 340000 (Nov 2020),
which means you can only send to a shielded address, never to a transparent
address. This is enforced via consensus rules and sometimes called "z2z".
