# Copyright (c) 2016-2023 The Hush Developers
# Distributed under the GPLv3 software license, see the accompanying
# file COPYING or https://www.gnu.org/licenses/gpl-3.0.en.html
# Just type make to compile all dat dapp code, fellow cypherpunkz

# we no longer build zmigrate by default, nobody uses that fucking code
all: hushdex

hushdex:
	$(CC) hushdex.c -o hushdex -lm

# Just for historical knowledge, to study how fucking stupid
# ZEC+KMD were to still support sprout, to this day!!!!!!!!
# Hush leads the entire world into the future, sans Sprout turdz
zmigrate:
	$(CC) zmigrate.c -o zmigrate -lm

clean:
	rm zmigrate

