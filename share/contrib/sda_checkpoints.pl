#!/usr/bin/perl
# Copyright (c) 2016-2022 The Hush developers
# Distributed under the GPLv3 software license, see the accompanying
# file COPYING or https://www.gnu.org/licenses/gpl-3.0.en.html

# This script is used to generate the checkpoint data used by the SilentDragon Android SDK
# https://git.hush.is/fekt/hush-android-wallet-sdk/src/branch/main/sdk-lib/src/main/assets/co.electriccoin.zcash/checkpoint/mainnet

use warnings;
use strict;
my $hush    = "./src/hush-cli";
my $getblock= "$hush getblock";
my $gethash = "$hush getblockhash";
my $gettree = "$hush getblockmerkletree";
my $start   = shift || 1390000;
my $end     = shift || 1422000;
my $stride  = shift || 10000;

my $blocks  = qx{$hush getblockcount};
if($?) {
    print "ERROR, is hushd running? exiting...\n";
    exit 1;
}

if ($end > $blocks) {
    print "The block $end is beyond how many blocks this node knows about, exiting...\n";
    exit 1;
}

if ($start < 1) {
    print "Invalid start block $start, exiting...\n";
    exit 1;
}

my $block = $start;
while (1) {
    last if $block > $end;
	my $blockhash = qx{$gethash $block};
	my $blocktime = qx{$getblock $block | grep time};
	my $merkle    = qx{$gettree $block};
    chomp $merkle;
    chomp $blockhash;
    chomp $blocktime;
    $blocktime =~ s/^\s+|\s+$//g;
    my $checkpoint = qq{{\n\t"network": "main",\n\t"height": "$block",\n\t"hash": "$blockhash",\n\t$blocktime\n\t"saplingTree": "$merkle"\n}\n};
    my $filename = "$block.json";
    open(FH, '>', $filename) or die $!;
    print FH $checkpoint;
    close(FH);

    $block += $stride;
}
