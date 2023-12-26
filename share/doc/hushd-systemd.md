# Systemd script for the Hush daemon

## Set it up

First set it up as follows:
* Copy hushd.service to the systemd user directory, which is /usr/lib/systemd/user directory

## Basic Usage

How to start the script:
`systemctl start --user hushd.service`

How to stop the script:
`systemctl stop --user hushd.service`

How to restart the script:
`systemctl restart --user hushd.service`

## How to watch it as it starts

Use the following on most Linux distros:
`watch systemctl status --user hushd.service`

If you're using Ubuntu 20.04, then try this instead as the above did not work for me on Ubuntu 20.04 server:
`tail -f ~/.hush/HUSH3/debug.log`

## Troubleshooting

* Don't run it with sudo or root, or it won't work with the wallet.

### To-do

* Determine why Ubuntu 20.04 didn't produce the expected outcome with watch and systemctl
* Create the hushd rc.d script
* Create the hushd runit script
