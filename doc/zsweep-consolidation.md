# zsweep and consolidation

This is to document zsweep and consolidation for advanced HUSH users.

**Warning: If you don't know what Zsweep or Consolidation are, there is a good chance that you will not be using these advanced options. User beware!**

# Table of Contents
1. [Using Zsweep](#zsweep)
1. [Using Consolidation](#consolidation)
1. [Using Zsweep & Consolidation Together](#zsweep-&-consolidation-together)

# Pre-Step & Further Details

A user can use these options at the command line, but it is **recommended to configure these options within the HUSH3.conf file**.

Consolidation takes many unspent shielded UTXOs (zutxos) into one zutxo, which makes spending them in the future faster and potentially cost less in fees. It also helps prevent certain kinds of metadata leakages and spam attacks. It is not recommended for very large wallets (wallet.dat files with thousands of transactions) for performance reasons. This is why it defaults to OFF for CLI full nodes but ON for GUI wallets that use an embedded hushd.

Zsweep is when you sweep numerous zutxos into one z-address that you configure. This z-address can be local to that system or it can be configured to sweep to a remote wallet on a different system with the zsweepexternal=1 option, which is explained below in the Zsweep section.

## Zsweep

1. We add the following to our conf file as per the Pre-Step.
	```
	zsweep=1
	zsweepaddress=zs1...
	```

1. The above zsweepaddress will be the z-address you want to sweep into (zs1... is a placeholder for this documentation) and it must exist within the same local wallet you are configuring this for. If you want to zsweep to an address on another computer, then set zsweepexternal=1 as explained in the options below.

1. The following are optional zsweep settings with their details:

	| Zsweep Option Name| Details of what it does |
	|-------------------|-------------------------|
	| zsweepexternal=1	| Will enable the option to zsweep to an "external" z-address which exists in a wallet on a different system. |
	| zsweepinterval=5	| By default zsweep runs every 5 blocks, so set and modify this value to change that. |
	| zsweepmaxinputs=50 | By default zsweep makes sure to not reduce the anonset in any tx by having a maximum number of inputs of 8. This should be fine for new wallets, but if you have an existing wallet with many zutxos it can be changed with this option. Keep in mind that large values will make sweeping faster at the expense of reducing the AnonSet. |
	| zsweepfee=0 | The default zsweep fee is 10000 puposhis or 0.0001 HUSH, the default for all transactions. To use fee=0 for zsweep transactions, set this option. |
    | zsweepexclude=zs1... | Exclude a certain address from being swept. Can be used multiple times to exclude multiple addressses |

1. The following HUSH RPC will let you view your zsweep configuration options and run-time stats at the command line: `hush-cli z_sweepstatus`

## Consolidation

1. We add the following to our conf file as per the Pre-Step.
	```
	consolidation=1
	```

1. The following are optional consolidation settings with their details:

	| Consolidation Option Name| Details of what it does |
	|--------------------------|-------------------------|
	| consolidationtxfee=0     | The default consolidation fee is 10000 puposhis or 0.0001 HUSH, the default for all transactions. To use fee=0 for consolidation transactions, set this option. |
	| consolidatesaplingaddress=zs1... | Default of consolidation is set to all, but you can set this option if you have one specific z-address (zs1... is a placeholder for this documentation) that you want to only consolidate to. |

1. The following HUSH RPC will let you view your consolidation configuration options and run-time stats at the command line: `hush-cli z_sweepstatus`

## Zsweep & Consolidation Together

1. We add the following to our conf file as per the Pre-Step.
	```
	zsweep=1
	zsweepaddress=zs1...
	consolidation=1
	```

1. Then follow along with the zsweep section above if you want to set specific options for the zsweep behavior.

### Copyright

jahway603 and The Hush Developers

### License

GPLv3

