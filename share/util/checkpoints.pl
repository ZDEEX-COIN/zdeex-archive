#!/usr/bin/perl
# Copyright (c) 2016-2023 The Hush developers
# Distributed under the GPLv3 software license, see the accompanying
# file COPYING or https://www.gnu.org/licenses/gpl-3.0.en.html
use warnings;
use strict;

# Generate checkpoint data for use in src/chainparams.cpp
my $perday  = 1152;
my $cli     = "./src/hush-cli";
my $stride  = shift || 1000;
if ($stride =~ m/help/) {
    print "To generate checkpoint data every 1000 blocks: $0 &> checkpoints.txt\n";
    print "To generate checkpoint data every X blocks: $0 X &> checkpoints.txt\n";
    print "To generate checkpoint data every X blocks starting at height Y: $0 X Y &> checkpoints.txt\n";
    print "To generate checkpoint data every X blocks starting at height Y for -ac_name CHAIN: $0 X Y CHAIN &> checkpoints.txt\n";
    exit 0;
}
unless ($stride == int($stride) and $stride >= 0) {
    print "Invalid stride! Must be an integer > 0\n";
    exit 1;
}
my $start_height = shift || 0;

unless ($start_height == int($start_height) and $start_height >= 0) {
    print "Invalid start_height! Must be an integer > 0\n";
    exit 1;
}

my $acname = shift;
if ($acname) {
    # TODO: is acname valid?
    $cli .= " -ac_name=$acname";
    # HSC's by default have a blocktime of 60s
    $perday = 1440;
    # Dragonx has a blocktime of 36s
    $perday = 2400 if ($acname eq 'DRAGONX');
} else {
    $acname = 'HUSH3';
}

my $gethash = "$cli getblockhash";
my $count   = 0;
my $blocks  = qx{$cli getblockcount};
if($?) {
    print "ERROR, exiting...\n";
    exit 1;
}
my $prev    = $blocks - $perday;
my $last    = 0;
my $now     = time();
chomp($blocks);

print "// Generated at $now via hush3 util/checkpoints.pl by Duke Leto\n";

while (1) {
	$count++;
	my $block = $start_height + $stride*$count;
	if ($block > $blocks) {
		$last = $start_height + $stride*($count-1);
        #print "last checkpointed block=$last\n";
        last;
    }
	my $blockhash = qx{$gethash $block};
	chomp $blockhash;
	print qq{($block,     uint256S("0x$blockhash"))\n};
}
my $time    = qx{$cli getblock $last |grep time|cut -d: -f2| sed 's/,//g'};
chomp($time);
# TODO: This is Linux-only and assumes new (not legacy) dir
my $line1       = qx{grep --text height=$prev   ~/.hush/$acname/debug.log};
my $line2       = qx{grep --text height=$blocks ~/.hush/$acname/debug.log};
my $txs_per_day = 2 * $perday; # default estimate is 2 txs per block, on average
my $total_txs   = 0;
#print "line1: $line1\n";
#print "line2: $line2\n";

# This will calculate the number of txs in the previous day to the last checkpointed block
if ($line1 =~ m/tx=(\d+)/) {
    my $tx1 = $1; # number of txs in the block 1 day ago
    #print "prevblock has $tx1 txs\n";
    if ($line2 =~ m/tx=(\d+)/) {
        $total_txs = $1;
        # TODO: average of last N days might be better
        $txs_per_day  = $total_txs - $tx1;
    }
}
print ",(int64_t) $time, // time of last checkpointed block\n";
print "(int64_t) $total_txs,      // total txs\n";
print "(double)  $txs_per_day        // txs in the last day before block $blocks\n";
