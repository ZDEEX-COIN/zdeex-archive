# ZdeeX

## What is ZdeeX?

![Logo](https://explorer.zdeex.org/assets/images/logo/logo.png "Logo")

## Installing

You can either compile it yourself or you can install a binary which was compiled by us.
Please refer to the instructions which apply to you below:

* See [INSTALL.md](INSTALL.md) to compile from source on Linux and to cross-compile for Windows
* See [INSTALL-BIN.md](INSTALL-BIN.md) to install pre-compiled binary on Linux

# Start zdeex Ubuntu 20.04
###### *`This doesn't work` ./hushd: /lib/x86_64-linux-gnu/libstdc++.so.6: version `GLIBCXX_3.4.30' not found (required by ./hushd) do the following command:*
```
sudo add-apt-repository ppa:ubuntu-toolchain-r/test
sudo apt update
sudo apt install gcc-9
sudo apt upgrade libstdc++6
```

# Install zdeex
Look at [this guide](https://git.zdeex.is/zdeex/zdeex3/src/branch/master/INSTALL.md) if you <u>have not</u> already installed zdeex on the machine you intend to mine on.
###### *`Note:` If running <u>Windows</u> head over to the [releases page](https://git.zdeex.is/zdeex/zdeex3/releases) and download the latest Windows version. I would recommend installing [Windows Terminal](https://github.com/microsoft/terminal) to make it easier to access and execute commands with windows powershell*
###### *`Note:` If running on a Virtual Machine make sure the VM network settings are set to `Bridged Connection`.*

# Linux - zdeex Smart Chain (HSC) Setup
After installing zdeex open a terminal in `~/zdeex/src`
###### *`Note:` installation path may be different depending on if installed as `root` or `normal` user, look for the `zdeex` directory in either the `root` or `home` directory.*

###### *`Note:` you can specify number of threads to mine with by changing `nproc` to the number of threads you  want*
###### EX: `./zdeex-cli setgenerate true 2 &`

### Start ZdeeX
To make sure you are actually connected to the network and mining input the following command:
```
cd ~/zdeex/src
./zdeexd
```

### Verify Mining
To make sure you are actually connected to the network and mining input the following command:
```
./zdeex-cli getinfo | grep connections
```
- If it returns `"connection": 1` you are connected and mining.

<br>
<br>
<br>

# Install zdeex
Look at [this guide](https://github.com/ZDEEX-COIN/zdeex/INSTALL.md) if you <u>have not</u> already installed zdeex on the machine you intend to mine on.
###### *`Note:` If running <u>Windows</u> head over to the [releases page](https://github.com/ZDEEX-COIN/zdeex/releases) and download the latest Windows version. I would recommend installing [Windows Terminal](https://github.com/microsoft/terminal) to make it easier to access and execute commands with windows powershell*
###### *`Note:` If running on a Virtual Machine make sure the VM network settings are set to `Bridged Connection`.*


# Windows - zdeex Smart Chain (HSC) Setup
After downloading the latest build of zdeex, unzip then navigate to the zdeex folder (ex: zdeex-3.9.4-win). Right click, `Open in Terminal` or type `powershell` in the address bar of windows explorer if windows terminal is not installed.

###### *`Note:` Make sure to input any parts with "-ac" in this command <u>exactly</u>, otherwise your node may not be able to connect!*

### Enable Mining

once the HSC is running all that is left to do is enable mining with this command, open another instance of terminal or powershell:

```
./zdeex-cli setgenerate true $(1)
```

###### *`Note:` you can specify number of threads to mine with by changing `$(1)` to the number of threads you want*

### Verify Mining
To make sure you are actually connected to the network and mining input the following command:
```
./zdeex-cli getinfo
```
- If it returns `"connection": 1` you are connected and mining.

<br>
<br>
<br>

# Shield and send newly mined DRGX

Check if you have balance to spend:

```
./zdeex-cli getbalance
```

Create a new zaddr:

```
./zdeex-cli z_getnewaddress
```

<b>SAVE YOUR PRIVATE KEY!!!</b>

```
/zdeex-cli z_exportkey "zs1..."
```

Transfer all mined coins to a private zaddr address we just created:
- With a second command it is possible to increase the number of utxos to shield to 180 (50 is default).
- The third call will attempt to shield the maximum number of coins for a given zaddr per transaction.

```
./zdeex-cli z_shieldcoinbase "*" "zs1..."
``` 

```
./zdeex-cli z_shieldcoinbase "*" "zs1..." 0.0001 180
./zdeex-cli z_shieldcoinbase "*" "zs1..." 0.0001 0
``` 

To send coins use the following call: (FROM address TO address)

```
./zdeex-cli z_sendmany "zs1..." '[{"address": "zs1...", "amount": 69.69}]'
```

On Windows use:

```
./zdeex-cli z_sendmany "zs1..." '[{\"address\": \"zs1...\", \"amount\": 69.69}]'
```

# Useful RPC commands 

## License

For license information see the file [COPYING](COPYING).


