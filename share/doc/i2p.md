# I2P support in Hush

It is possible to run a Hush or HSC full node as an
[I2P (Invisible Internet Project)](https://en.wikipedia.org/wiki/I2P)
service and connect to such services.

This [glossary](https://geti2p.net/en/about/glossary) may be useful to get
started with I2P terminology.

## Run with an I2P router (proxy)

A running I2P router (proxy) with [SAM](https://geti2p.net/en/docs/api/samv3)
enabled is required. Options include:

- [i2prouter (I2P Router)](https://geti2p.net), the official implementation in
  Java
- [i2pd (I2P Daemon)](https://github.com/PurpleI2P/i2pd)
  ([documentation](https://i2pd.readthedocs.io/en/latest)), a lighter
  alternative in C++ (successfully tested with version 2.23 and up; version 2.36
  or later recommended)
- [i2p-zero](https://github.com/i2p-zero/i2p-zero)
- [other alternatives](https://en.wikipedia.org/wiki/I2P#Routers)

Note the IP address and port the SAM proxy is listening to; usually, it is
`127.0.0.1:7656`.

Once an I2P router with SAM enabled is up and running, use the following
configuration options:

```
-i2psam=<ip:port>
     I2P SAM proxy to reach I2P peers and accept I2P connections (default:
     none)

-i2pacceptincoming
     Whether to accept inbound I2P connections (default: 1). Ignored if
     -i2psam is not set. Listening for inbound I2P connections is
     done through the SAM proxy, not by binding to a local address and
     port.
```

In a typical situation, this suffices:

```
hushd -i2psam=127.0.0.1:7656
```

The first time hushd connects to the I2P router, if
`-i2pacceptincoming=1`, then it will automatically generate a persistent I2P
address and its corresponding private key. The private key will be saved in a
file named `i2p_private_key` in the Hush data directory. The persistent
I2P address is used for accepting incoming connections and for making outgoing
connections if `-i2pacceptincoming=1`. If `-i2pacceptincoming=0` then only
outbound I2P connections are made and a different transient I2P address is used
for each connection to improve privacy.

## Additional configuration options related to I2P

```
-debug=i2p
```

Set the `debug=i2p` config logging option to see additional information in the
debug log about your I2P configuration and connections.

```
-onlynet=i2p
```

Make automatic outbound connections only to I2P addresses. Inbound and manual
connections are not affected by this option. It can be specified multiple times
to allow multiple networks, e.g. onlynet=onion, onlynet=i2p.

I2P support was added to Hush in version 3.9.3 and there may be fewer I2P
peers than Tor or IP ones. Therefore, using I2P alone without other networks may
make a node more susceptible to [Sybil
attacks](https://en.bitcoin.it/wiki/Weaknesses#Sybil_attack). 

Another consideration with `onlynet=i2p` is that the initial blocks download
phase when syncing up a new node can be very slow. This phase can be sped up by
using other networks, for instance `onlynet=onion`, at the same time.

In general, a node can be run with both onion and I2P hidden services (or
any/all of IPv4/IPv6/onion/I2P/CJDNS), which can provide a potential fallback if
one of the networks has issues.

## Persistent vs transient I2P addresses

In I2P connections, the connection receiver sees the I2P address of the
connection initiator. This is unlike the Tor network where the recipient does
not know who is connecting to them and can't tell if two connections are from
the same peer or not.

If an I2P node is not accepting incoming connections, then Hush uses
random, one-time, transient I2P addresses for itself for outbound connections
to make it harder to discriminate, fingerprint or analyze it based on its I2P
address.

## Additional configuration options related to I2P

```
-debug=i2p
```

Set the `debug=i2p` config logging option to see additional information in the
debug log about your I2P configuration and connections. Run `hush-cli help
logging` for more information.

```
-onlynet=i2p
```

Make automatic outbound connections only to I2P addresses. Inbound and manual
connections are not affected by this option. It can be specified multiple times
to allow multiple networks, e.g. onlynet=onion, onlynet=i2p.

I2P support was added to Hush in version 3.9.3 and there may be fewer I2P
peers than Tor or IP ones. Therefore, using I2P alone without other networks may
make a node more susceptible to [Sybil
attacks](https://en.bitcoin.it/wiki/Weaknesses#Sybil_attack). You can use
`hush-cli -addrinfo` to see the number of I2P addresses known to your node.

Another consideration with `onlynet=i2p` is that the initial blocks download
phase when syncing up a new node can be very slow. This phase can be sped up by
using other networks, for instance `onlynet=onion`, at the same time.

In general, a node can be run with both onion and I2P hidden services (or
any/all of IPv4/IPv6/onion/I2P/CJDNS), which can provide a potential fallback if
one of the networks has issues.

## I2P-related information

There are several ways to see your I2P address if accepting
incoming I2P connections (`-i2pacceptincoming`):
- in the "Local addresses" output of CLI `-netinfo`
- in the "localaddresses" output of RPC `getnetworkinfo`
- in the debug log (grep for `AddLocal`; the I2P address ends in `.b32.i2p`)

To see which I2P peers your node is connected to, use `hush-cli -netinfo 4`
or the `getpeerinfo` RPC (e.g. `hush-cli getpeerinfo`).

To see which I2P addresses your node knows, use the `getnodeaddresses 0 i2p`
RPC.

## Compatibility

Hush uses the [SAM v3.1](https://geti2p.net/en/docs/api/samv3) protocol
to connect to the I2P network. Any I2P router that supports it can be used.

## Ports in I2P and Hush

Hush uses the [SAM v3.1](https://geti2p.net/en/docs/api/samv3)
protocol. One particularity of SAM v3.1 is that it does not support ports,
unlike newer versions of SAM (v3.2 and up) that do support them and default the
port numbers to 0. From the point of view of peers that use newer versions of
SAM or other protocols that support ports, a SAM v3.1 peer is connecting to them
on port 0, from source port 0.

To allow future upgrades to newer versions of SAM, Hush sets its
listening port to 0 when listening for incoming I2P connections and advertises
its own I2P address with port 0. Furthermore, it will not attempt to connect to
I2P addresses with a non-zero port number because with SAM v3.1 the destination
port (`TO_PORT`) is always set to 0 and is not in the control of Hush.

## Bandwidth

By default, your node shares bandwidth and transit tunnels with the I2P network
in order to increase your anonymity with cover traffic, help the I2P router used
by your node integrate optimally with the network, and give back to the network.
It's important that the nodes of a popular application like Hush contribute
as much to the I2P network as they consume.

It is possible, though strongly discouraged, to change your I2P router
configuration to limit the amount of I2P traffic relayed by your node.

With `i2pd`, this can be done by adjusting the `bandwidth`, `share` and
`transittunnels` options in your `i2pd.conf` file. For example, to limit total
I2P traffic to 256KB/s and share 50% of this limit for a maximum of 20 transit
tunnels:

```
bandwidth = 256
share = 50

[limits]
transittunnels = 20
```

Similar bandwidth configuration options for the Java I2P router can be found in
`http://127.0.0.1:7657/config` under the "Bandwidth" tab.

Before doing this, please see the "Participating Traffic Considerations" section
in [Embedding I2P in your Application](https://geti2p.net/en/docs/applications/embedding).

In most cases, the default router settings should work fine.

## Bundling I2P in a Hush application

Please see the "General Guidance for Developers" section in https://geti2p.net/en/docs/api/samv3
if you are developing a downstream application that may be bundling I2P with Hush.