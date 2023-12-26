# RandomX

Hush Smart Chains support using RandomX as a Proof-Of-Work algorithm as of release 3.9.2 .
This means you can now launch a privacy coin with Hush tech that can be mined with a CPU
instead of requiring an ASIC or GPU. RandomX is the same algorithm that Monero (XMR) and
various other cryptocoins use. As far as we know, Hush Smart Chains are the first coins
based on Zcash Protocol that can use the RandomX PoW algorithm. Many thanks to all the
people who helped make this possible.

# Example

The following command can be used to launch an HSC on a single computer. Each option will be explained.
HSC CLI arguments that start with `-ac_` means they *Affect Consensus*.

```
./src/hush-smart-chain -ac_halving=100 -ac_algo=randomx -ac_name=RANDOMX -ac_private=1 -ac_blocktime=15 -ac_reward=500000000 -ac_supply=55555 -gen=1 -genproclimit=1 -testnode=1
```

  * `hush-smart-chain` is the script used to launch or connect to HSCs
    * It lives in the `./src` directory, next to `hushd` and `hush-cli`
    * It is called `hush-smart-chain.bat` on Windows
  * `-ac_halving=100` means "the block reward halves every 100 blocks"
  * `-ac_algo=randomx` means "use RandomX for Proof-Of-Work
    * The default is Equihash (200,9)
  * `-ac_name=RANDOMX` sets the name of the HSC to RANDOMX
  * `-ac_private=1` means only z2z transactions will be allowed, like HUSH mainnet
  * `-ac_blocktime=15` means blocks will be 15 seconds on average
    * The default is 60 seconds
  * `-ac_reward=500000000` means the block reward will start at 5 RANDOMX coins per block
    * This argument is given in satoshis
  * `-ac_supply=55555` means an existing supply of 55555 will exist at block 1
    * This argument is given in coins, not satoshis
    * This is sometimes called a "pre-mine" and is useful when migrating an existing coin
    * Block 0 of HSC's is always the BTC mainnet genesis block.
    * So the genesis block of HSC's is actually block 1, not block 0
  * `-gen=1` means this node is a mining node
  * `-genproclimit=1` means use 1 CPU thread will be used for mining
  * `-testnode=1` means only 1 node can be used to mine a genesis block
    * testnode is primarily for testing, when launching a real genesis block, this option should not be used
    * By default, at least two nodes are required to mine a genesis block
    * One node would use
```
# first node
./src/hush-smart-chain -ac_halving=100 -ac_algo=randomx -ac_name=RANDOMX -ac_private=1 -ac_blocktime=15 -ac_reward=500000000 -ac_supply=55555
```
    * And the second node would use:
```
# mining node. NOTE: This node will mine the genesis block and pre-mine, if any
./src/hush-smart-chain -ac_halving=100 -ac_algo=randomx -ac_name=RANDOMX -ac_private=1 -ac_blocktime=15 -ac_reward=500000000 -ac_supply=55555 -gen=1 -genproclimit=1
```

# Advanced Options

HUSH RandomX currently has two advanced options that some may want to use:

  * `ac_randomx_interval` controls how often the RandomX key block will change
    * The default is 1024 blocks and is good for most use cases.
    * This corresponds to ~17 hours for HSCs with the default block time of 60s
  * `ac_randomx_lag` sets the number of blocks to wait before updating the key block
    * The default is 64 blocks
    * This corresponds to 64 mins for HSCs with the default block time of 60s
  * `ac_randomx_interval` should always be larger than 2 times `ac_randomx_lag`
  * Setting these to arbitrary values could affect the chain security of your coin
    * It is not recommended to change these values unless you are really sure why you are doing it

# RandomX Internals

This section is not required reading if you just want to use it as a PoW algorithm for an HSC. Here we will explain how the internals of RandomX works inside of the Hush codebase.

We use the official RandomX implementation from https://github.com/tevador/RandomX with custom configuration options. If some type of hardware is created to mine the XMR RandomX algorithm, it will not be compatible with the Hush RandomX algorithm. This is by design. All Hush Smart Chains use the same RandomX config options, so if a hardware device is created to mine one HSC that uses RandomX, it can be used to mine any HSC using RandomX. Every HSC with unique consensus parameters will start off with it's own unique key block with at least 9 bytes of entropy.

The source code of RandomX is embedded in the Hush source code at `./src/RandomX` and the configuration options used are at `./src/RandomX/src/configuration.h` .

The changes from default RandomX configuration options are listed below.

```
 //Argon2d salt
-#define RANDOMX_ARGON_SALT         "RandomX\x03"
+#define RANDOMX_ARGON_SALT         "RandomXHUSH\x03"

 //Number of Argon2d iterations for Cache initialization.
-#define RANDOMX_ARGON_ITERATIONS   3
+#define RANDOMX_ARGON_ITERATIONS   5
 
 //Number of parallel lanes for Cache initialization.
 #define RANDOMX_ARGON_LANES        1
@@ -53,13 +53,13 @@ OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 #define RANDOMX_DATASET_EXTRA_SIZE 33554368
 
 //Number of instructions in a RandomX program. Must be divisible by 8.
-#define RANDOMX_PROGRAM_SIZE       256
+#define RANDOMX_PROGRAM_SIZE       512
 
 //Number of iterations during VM execution.
-#define RANDOMX_PROGRAM_ITERATIONS 2048
+#define RANDOMX_PROGRAM_ITERATIONS 4096
 
 //Number of chained VM executions per hash.
-#define RANDOMX_PROGRAM_COUNT      8
+#define RANDOMX_PROGRAM_COUNT      16
 
```
RandomX opcode frequencies were not modfiied, the defaults are used.

