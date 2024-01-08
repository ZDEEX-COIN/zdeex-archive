## Claiming Funds From Old Hush Wallets

Hush migrated to a new mainnet after Block 500,000 on the old Hush blockchain.
Funds in addresses as of Block 500,000 were transported to our new chain. About
31,000 addresses with at least 0.00000001 HUSH were transported to the new Hush
mainnet.

To claim funds on the new chain, there are few options.

### Funds on exchanges

Firstly, no bueno! Not your keys, not your coins. It's best not to store coins
on exchanges. But in this case, you lucked out! There is nothing to do to claim
new coins if you have coins on an exchange that supports the new Hush chain.
The exchange will follow the instructions from the next section and you will
magically have funds on the new chain. Note that old Hush addresses started
with `t1` and now they begin with `R`.

To see what an old HUSH v2 address looks like on the new chain, this online tool
can be used: https://dexstats.info/addressconverter.php

or this command line tool: https://git.hush.is/hush/hush3/src/master/contrib/convert_address.py


### Using an old wallet.dat

Backup your old HUSH wallet.dat, and backup any current wallet.dat that is in

        ~/.komodo/HUSH3/

OR
        ~/.hush/HUSH3/

There is no way to lose funds, as long as you have backups!!! Make sure
to make backups. Do not skip this step.

Make sure any/all GUI wallets are stopped! Also make sure your old Hush node
and new Hush3 node are stopped:

        cd hush3
        ./src/hush-cli stop

Do not copy wallets or move wallets while your full node is running! This could
corrupt your wallet!

Now copy your old Hush wallet.dat to

        ~/.hush/HUSH3/

with a command like

        # DO NOT RUN THIS WITHOUT MAKING BACKUPS!
        cp ~/.hush/wallet.dat ~/.hush/HUSH3/

The reason this works is that both old HUSH and new HUSH are still Bitcoin Protocol
coins, which both use secp256k1 public keys. Now start your HUSH3 node again,
with this special CLI argument that will clear out transactions from your wallet:

        cd hush3
        ./src/hushd -zapwallettxes

This will cause a full history rescan, which will take some time. Once it's complete,
you can see your funds with this command:

        ./src/hush-cli getwalletinfo

NOTE: Do not use this wallet except to send funds to a new wallet!

### Private Keys

You can also transport funds one address at a time via private keys.
