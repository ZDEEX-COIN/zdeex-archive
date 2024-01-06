#!/usr/bin/env perl
# Copyright (c) 2016-2023 The Hush developers
# Distributed under the GPLv3 software license, see the accompanying
# file COPYING or https://www.gnu.org/licenses/gpl-3.0.en.html
use warnings;
use strict;

# Given a block time, estimate when it will happen
my $block      = shift || die "Usage: $0 123";
my $coin       = shift || '';
my $hush       = "./src/hush-cli";
unless (-e $hush) {
    die "$hush does not exist, aborting";
}
if ($coin) {
    $hush .= " -ac_name=$coin";
}
my $blockcount = qx{$hush getblockcount};

unless ($blockcount = int($blockcount)) {
    print "Invalid response from $hush\n";
    exit 1;
}

if ($block <= $blockcount) {
	die "That block has already happened!";
} else {
	my $diff    = $block - $blockcount;
    my $minpb   = 1.25; # 75s in minutes for HUSH3
    if ($coin eq 'DRAGONX') {
        $minpb = 0.6; # minutes per block
    } elsif ($coin) {
        # TODO: support custom bloctimes
        $minpb = 1; # assumes default blocktime of 60s
    }
	my $minutes = $diff*$minpb;
	my $seconds = $minutes*60;
	my $now     = time;
	my $then    = $now + $seconds;
	my $ldate   = localtime($then);
	my $gmdate  = gmtime($then);
    if ($coin) {
	    print "$coin Block $block will happen at roughly:\n";
    } else {
	    print "Hush Block $block will happen at roughly:\n";
    }
	print "$ldate Eastern # $then\n";
	print "$gmdate GMT     # $then\n";
}
