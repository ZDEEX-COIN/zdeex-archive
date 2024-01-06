# Hush

## What is Hush?

![Logo](doc/hush/hush.png "Logo")

Hush implements Extreme Privacy via blockchain tech. We have our own
genesis block. We are not a chain fork (copy) of another coin. We are based on
Bitcoin code, with sophisticated zero-knowledge mathematics added for privacy.
This keeps your transaction metadata private!

### This repository

This software is the Hush node and command-line client. It downloads and stores
the entire history of Hush transactions; depending on the speed of your
computer and network connection, it will likely take a few hours at least, but
some people report full nodes syncing in less than 1.5 hours. A competing privacy
coin takes over 24 hours to sync their full nodes because of Sprout Transactions, lulz.

### BANNED BY GITHUB

In working on this release, Duke Leto was suspended from Github, which gave Hush developers
the impetus to completely leave that racist and censorship-loving platform.

Hush now has it's own [git.hush.is](https://git.hush.is/hush) Gitea instance,
because we will not be silenced by Microsoft.

All Hush software will be released from git.hush.is and hush.is, downloads from any other
domains should be assumed to be backdoored.

**Hush is unfinished and highly experimental.** Use at your own risk! Just like Bitcoin.

## Installing

You can either compile it yourself or you can install a binary which was compiled by us.
Please refer to the instructions which apply to you below:

* See [INSTALL.md](INSTALL.md) to compile from source on Linux and to cross-compile for Windows
* See [INSTALL-BIN.md](INSTALL-BIN.md) to install pre-compiled binary on Linux

### Claiming Funds From Old Hush Wallets

If you have an older wallet, then refer to [OLD_WALLETS.md](OLD_WALLETS.md).

### Official Explorers

The links for the Official Hush explorers:
  * [explorer.hush.is](https://explorer.hush.is)
  * [explorer.hush.land](https://explorer.hush.land)

We are looking for alternate explorers to be run on Tor, i2P and other TLDs, if you are interested
please join Telegram and ask questions.

### For system admins

There is a new systemd user service script so you can easily start/stop/restart your hushd service on your server.
[Try it out today](doc/hushd-systemd.md) and the systemd script is located in the doc directory of the source tree.

## Support and Socials

Please feel free to join us on Telegram for official support:
* Main group: https://hush.is/tg
* Support group: https://hush.is/telegram_support
* Mining group: https://hush.is/telegram_mining

Other socials:
* Twitter: <a href="https://hush.is/twitter">@hushisprivacy</a>
* Matrix: <a href="https://hush.is/matrix">@hush_main:meowchat.xyz</a>
* PeerTube <a href="https://hush.is/peertube">videos.hush.is</a>
* Reddit <a href="https://hush.is/reddit">@Myhush</a>
* Mastodon <a href="https://hush.is/mastodon">@myhushteam@fosstodon.org</a>

## License

For license information see the file [COPYING](COPYING).
