#!/usr/bin/perl
# Copyright (c) 2016-2023 The Hush developers
# Distributed under the GPLv3 software license, see the accompanying
# file COPYING or https://www.gnu.org/licenses/gpl-3.0.en.html
use warnings;
use strict;
use JSON;

# Generates taddrs/scriptpubs for testing the decentralized devtax
# where all generated taddrs/scriptpubs will be part of existing wallet.dat
# OR generates scriptpubs for addresses if given a file argument
# addresses must be one-per-line in the file

my $file     = shift;
my $N        = 20; # hushd is currently hardcoded to use 20 addresses
my $hush     = "./src/hush-cli";
my $getnew   = "$hush getnewaddress";
my $validate = "$hush validateaddress";
my $fh;

if($file) {
    open($fh, '<', $file) or die $!;
}

print "std::string DEVTAX_DATA[DEVTAX_NUM][2] = {\n";

for my $i (1 .. $N) {
    my $taddr;
    if ($file) {
        $taddr = <$fh>;
        unless($taddr) {
            print "Error: Less than $N addresses in $file !\n";
            exit(1);
        }
    } else {
        $taddr = qx{$getnew};
    }
    chomp $taddr;
    my $j = qx{$validate $taddr};
    my $json = decode_json($j);
    my $scriptpub = $json->{scriptPubKey};
    printf qq!{"%s", "%s"},\n!, $taddr, $scriptpub;
}

print "};\n";
close($fh) if $file;
