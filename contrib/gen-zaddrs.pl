#!/usr/bin/env perl
# Copyright 2019-2023 The Hush developers
# Released under the GPLv3
use warnings;
use strict;

my $hush    = "./src/hush-cli";
my $znew    = "$hush z_getnewaddress";
my $count   = 1;
my $howmany = shift || 50;

while ($count < $howmany) {
    my $zaddr   = qx{$znew};
    chomp($zaddr);
    print qq{$zaddr\n};
    $count++;
}
