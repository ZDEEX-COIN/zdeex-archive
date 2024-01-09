# Installing ZDEEX


## Build ZDEEX dependencies

The following build process generally applies to Ubuntu (and similar) Linux
distributions. For best results it is recommended to use Ubuntu Linux 16.04
or later.

## Swap Space (Optional)
You will need at least 4GB of RAM to build hush from git source, OR you can
enable a swap file. To enable a 4GB swap file on modern Linux distributions:

```sh
sudo fallocate -l 4G /swapfile
sudo chmod 600 /swapfile
sudo mkswap /swapfile
sudo swapon /swapfile
```

## Build on Ubuntu 20.04:

```sh
          sudo apt-get update  # prevents repo404 errors on apt-remove below
          sudo apt-get remove php* msodbcsql17 mysql* powershell dotn*
          sudo apt-get update
          sudo ACCEPT_EULA=Y apt-get upgrade -y
          sudo apt-get install -q curl python3 python3-dev python3-setuptools python3-pip libcurl4-openssl-dev libssl-dev -y
          python3 -m pip install setuptools wheel
          python3 -m pip install pytest wget jsonschema
          python3 -m pip install -Iv https://github.com/KomodoPlatform/slick-bitcoinrpc/archive/refs/tags/0.1.4.tar.gz
          sudo add-apt-repository ppa:ubuntu-toolchain-r/test
          sudo apt update
          sudo apt install gcc-9
          sudo apt upgrade libstdc++6
          ./util/build.sh -j$(nproc)
          tar -czvf zdeex-linux.tar.gz src/hushd src/hush-cli src/asmap.dat src/sapling-output.params src/sapling-spend.params src/zdeexd src/zdeex-cli
```

## Run a ZDEEX Node Ubuntu 20.04

After you have compiled Hush, then you can run it with the following command:

```sh
./src/zdeexd
```

## Windows (cross-compiled on Linux)
Get dependencies:
```
        sudo apt-get update  # prevents repo404 errors on apt-remove below
        sudo apt-get remove php* msodbcsql17 mysql* powershell containernetworking-* containers* dotn*
        sudo ACCEPT_EULA=Y apt-get upgrade -y
        sudo apt-get update
        sudo apt-get install build-essential pkg-config libc6-dev m4 g++-multilib autoconf libtool libncurses-dev unzip git python3 zlib1g-dev wget bsdmainutils automake libboost-all-dev libssl-dev libprotobuf-dev protobuf-compiler libqrencode-dev libdb++-dev ntp ntpdate nano software-properties-common curl libevent-dev libcurl4-gnutls-dev cmake clang libsodium-dev python3-zmq mingw-w64 -y
        curl https://sh.rustup.rs -sSf | sh -s -- -y
        source $HOME/.cargo/env
        rustup target add x86_64-pc-windows-gnu
        sudo update-alternatives --set x86_64-w64-mingw32-gcc /usr/bin/x86_64-w64-mingw32-gcc-posix
        sudo update-alternatives --set x86_64-w64-mingw32-g++ /usr/bin/x86_64-w64-mingw32-g++-posix
        ./util/build-win.sh -j$(nproc)
        zip --junk-paths zdeex-win src/hushd.exe src/hush-cli.exe src/asmap.dat src/sapling-output.params src/sapling-spend.params src/zdeexd.bat src/zdeex-cli.bat

```
## Run a ZDEEX Node Windows

After you have compiled Hush, then you can run it with the following command:

```sh
./src/zdeexd.exe
```
