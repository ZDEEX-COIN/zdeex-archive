#!/bin/sh
# Copyright (c) 2016-2023 The Hush developers
# Released under the GPLv3

TOPDIR=${TOPDIR:-$(git rev-parse --show-toplevel)}
SRCDIR=${SRCDIR:-$TOPDIR/src}
MANDIR=${MANDIR:-$TOPDIR/doc/man}

HUSHD=${HUSHD:-$SRCDIR/hushd}
HUSHCLI=${HUSHCLI:-$SRCDIR/hush-cli}
HUSHTX=${HUSHTX:-$SRCDIR/hush-tx}

[ ! -x $HUSHD ] && echo "$HUSHD not found or not executable." && exit 1
# Check if help2man is installed & if not then display error to user and exit
[ ! -x "$(command -v help2man)" ] && echo "help2man could not be found" && echo "Please install from your Linux package manager and try again" && echo "On Debian-based systems you can do: apt-get install help2man" && exit 1

# use this if hushd is not running
#HUSHVER="v3.6.2"
HUSHVER=$(./src/hushd --version|head -n1|cut -d' ' -f4|cut -d- -f1)

# Create a footer file with copyright content.
# This gets autodetected fine for hushd if --version-string is not set,
# but has different outcomes for hush-cli.
echo "[COPYRIGHT]" > footer.h2m
$HUSHD --version | sed -n '1!p' >> footer.h2m

echo "Generating man pages for Hush $HUSHVER"
for cmd in $HUSHD $HUSHCLI $HUSHTX; do
  cmdname="${cmd##*/}"
  help2man -N --version-string=${HUSHVER} --include=footer.h2m -o ${MANDIR}/${cmdname}.1 ${cmd}
  #sed -i "s/\\\-${HUSHVER[1]}//g" ${MANDIR}/${cmdname}.1
done

rm -f footer.h2m
