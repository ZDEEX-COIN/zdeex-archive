# Hush utilities

Scripts in this directory are used by Hush developers in the process of development
or in releasing a new version of Hush.

Utilities in this directory:

## build.sh

Compile Hush full node code.

## build-arm.sh

Compile Hush full node code for ARM architecture.
**has not worked for some time**

## build-arm-xcompile.sh

Cross-Compile Hush full node code for ARM architecture on an x86 build server.

## build-debian-package.sh

Builds an x86 Debain package for Hush.

## build-debian-package-ARM.sh

Builds an ARM Debain package for Hush.

## build-mac.sh

Compile Hush full node code for mac. NOTE: This is likely broken.

## build-win.sh

Compile Hush full node code for windows

## checkpoints.pl

Generate checkpoint data for chainparams.cpp . This automates the creation of
block heights and block hashes by asking hushd for the data and then generating
the C++ code needed to embed them in the Hush source code.

## docker-entrypoint.sh

Script to use Hush with Docker.

## docker-hush-cli.sh

Convenience script to run hush-cli in a running Docker container.

## replace.pl

Replace a string in a set of files by another string. Very useful for updating
a variable name or value across many files, or updating copyrights.

## security-check.py

Perform basic ELF security checks on a series of executables.

## symbol-check.py

A script to check that the (Linux) executables produced by gitian only contain
allowed gcc, glibc and libstdc++ version symbols.  This makes sure they are
still compatible with the minimum supported Linux distribution versions.

Example usage after a gitian build:

    find ../gitian-builder/build -type f -executable | xargs python util/symbol-check.py 

If only supported symbols are used the return value will be 0 and the output will be empty.

If there are 'unsupported' symbols, the return value will be 1 a list like this will be printed:

    .../64/test_bitcoin: symbol memcpy from unsupported version GLIBC_2.14
    .../64/test_bitcoin: symbol __fdelt_chk from unsupported version GLIBC_2.15
    .../64/test_bitcoin: symbol std::out_of_range::~out_of_range() from unsupported version GLIBCXX_3.4.15
    .../64/test_bitcoin: symbol _ZNSt8__detail15_List_nod from unsupported version GLIBCXX_3.4.15

## gen-manpages.sh

A small script to automatically create manpages in ../../doc/man by running the release binaries with the -help option.
This requires help2man which can be found at: https://www.gnu.org/software/help2man/

When you type "make manpages" it runs this script.

## gen-linux-binary-release.sh

Generate linux release binary.
