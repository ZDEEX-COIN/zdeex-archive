# Copyright (c) 2016-2023 The Hush developers
# Distributed under the GPLv3 software license, see the accompanying
# file COPYING or https://www.gnu.org/licenses/gpl-3.0.en.html
FROM ubuntu:16.04
MAINTAINER Duke Leto <duke@leto.net>

RUN apt-get -y update && \
    apt-get -y upgrade && \
    apt-get -y install build-essential pkg-config libc6-dev m4 g++-multilib autoconf libtool ncurses-dev \
    unzip python zlib1g-dev wget bsdmainutils automake libssl-dev libprotobuf-dev \
    protobuf-compiler libqrencode-dev libdb++-dev software-properties-common libcurl4-openssl-dev curl && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

ADD ./ /hush
ENV HOME /hush
WORKDIR /hush

# configure || true or it WILL halt
RUN cd /hush && \
    ./autogen.sh && \
    ./configure --with-incompatible-bdb --with-gui || true && \
    ./build.sh -j$(nproc)

RUN ln -sf /hush/src/hushd /usr/bin/hushd && \
    ln -sf /hush/src/hush-tx /usr/bin/hush-tx && \
    ln -sf /hush/src/wallet-utility /usr/bin/hush-wallet-utility && \
    ln -sf /hush/src/hush-smart-chain /usr/bin/hush-smart-chain && \
    ln -sf /hush/util/docker-entrypoint.sh /usr/bin/entrypoint && \
    ln -sf /hush/util/docker-hush-cli.sh /usr/bin/hush-cli

CMD ["entrypoint"]
