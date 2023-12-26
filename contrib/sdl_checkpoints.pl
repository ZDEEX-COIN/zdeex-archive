#!/usr/bin/perl
# Copyright (c) 2016-2023 The Hush developers
# Distributed under the GPLv3 software license, see the accompanying
# file COPYING or https://www.gnu.org/licenses/gpl-3.0.en.html

# This script is used to generate the data used by the silentdragonlite-cli checkpoints.rs file
# https://git.hush.is/hush/silentdragonlite-cli/src/branch/master/lib/src/lightclient/checkpoints.rs#L24

use warnings;
use strict;
my $hush    = "./src/hush-cli";
my $gethash = "$hush getblockhash";
my $gettree = "$hush getblockmerkletree";
my $start   = shift || 300000;
my $end     = shift || 840000;
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
	my $merkle    = qx{$gettree $block};
    chomp $merkle;
    chomp $blockhash;
    print qq{($block,"$blockhash",\n\t"$merkle"\n),\n};

    $block += $stride;
}
