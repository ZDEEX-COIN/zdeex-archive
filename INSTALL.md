# Installing ZdeeX

Instructions to compile ZdeeX yourself.

## Build ZdeeX dependencies

The following build process generally applies to Ubuntu (and similar) Linux
distributions. For best results it is recommended to use Ubuntu Linux 20.04
or later.

## Swap Space (Optional)
You will need at least 4GB of RAM to build ZdeeX from git source, OR you can
enable a swap file. To enable a 4GB swap file on modern Linux distributions:

```sh
sudo fallocate -l 4G /swapfile
sudo chmod 600 /swapfile
sudo mkswap /swapfile
sudo swapon /swapfile
```

## Build on Linux:

```sh
# install build dependencies
sudo apt-get install build-essential pkg-config libc6-dev m4 g++-multilib \
      autoconf libtool ncurses-dev unzip git zlib1g-dev wget \
      bsdmainutils automake curl unzip nano libsodium-dev cmake
# clone git repo
git clone https://github.com/ZDEEX-COIN/zdeex
cd ZdeeX3
# Build
# This uses 3 build processes, you need 2GB of RAM for each. 
./build.sh -j3
# Run a ZdeeX node
./src/zdeexd
```

### Building On Ubuntu 20.04 and older systems

Some older compilers may not be able to compile modern code, such as gcc 5.4 which comes with Ubuntu 20.04 by default. Here is how to install gcc 7 on Ubuntu 20.04. Run these commands as root:

```
add-apt-repository ppa:ubuntu-toolchain-r/test && \
apt update && \
apt-get install -y gcc-7 g++-7 && \
  update-alternatives --install /usr/bin/g++ g++ /usr/bin/g++-7 60 && \
  update-alternatives --install /usr/bin/gcc gcc /usr/bin/gcc-7 60
```

### Build on mac

These instructions are a work in progress.

```
sudo port update
sudo port upgrade outdated
sudo port install qt5

# clone git repo
git clone https://github.com/ZDEEX-COIN/zdeex
cd ZdeeX3
# Build
# This uses 3 build processes, you need 2GB of RAM for each. 
./build.sh -j3
# Run a ZdeeX node
./src/zdeexd
```

## Run a ZdeeX Node

After you have compiled ZdeeX, then you can run it with the following command:

```sh
# Run a ZdeeX node
./src/zdeexd
```

## Windows (cross-compiled on Linux)
Get dependencies:
```ssh
sudo apt-get install \
      build-essential pkg-config libc6-dev m4 g++-multilib \
      autoconf libtool ncurses-dev unzip git python \
      zlib1g-dev wget bsdmainutils automake mingw-w64 cmake libsodium-dev
```

Downloading Git source repo, building and running ZdeeX:

```sh
# pull
git clone https://github.com/ZDEEX-COIN/zdeex
cd ZdeeX
# Build
./build-win.sh -j$(nproc)
# Run a ZdeeX node
./src/zdeexd
```

## ARM Architecture

Currently, any ARMv7 machine will not be able to build this repo, because the
underlying tech (zcash and the zksnark library) do not support that instruction
set.

This also means that old RaspberryPi devices will not work, unless they have a
newer ARMv8-based Raspberry Pi. Raspberry Pi 4 and newer are known to work.
