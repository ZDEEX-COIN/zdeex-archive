# Hush Release Process

## High-Level Philosophy

Beware of making high-risk changes (such as consensus changes, p2p layer changes and wallet/transaction changes) too close to a new release, because they will not get as much testing as they should. Don't merge large branches which haven't undergone lots of testing just before a release.

It is best to keep doc/relnotes/README.md up to date as changes and bug fixes are made. It's more work to summarize all changes and bugfixes just before the release.

## Check for changes on master that should be on dev

Often there are trivial changes made directly on master, such as documentation changes. In theory, no code changes should happen on master without being on dev first, but it's better to be safe than sorry. We want the dev branch which undergoes testing to be as close as possible to what the master branch will become, so we don't want to merge dev into master and just assume everything works. So it's best to merge the master branch into dev just before merging the dev branch into master.

To check if the master branch has any changes that the dev branch does not:

```
# this assumes you are working with https://git.hush.is/hush/hush3 as your remote
git checkout dev  
git pull               # make sure dev is up to date
git checkout master
git pull               # make sure master is up to date
git diff dev...master  # look at the set of changes which exist in master but not dev
```

If the last command has no output, congrats, there is nothing to do. If the last command has output, then you should merge master into dev:

```
git checkout master
git merge --no-ff dev # using the default commit message is fine
git tag vX.Y.Z # this creates a tag vX.Y.Z on current master, or you can let gitea do it later
git push --tags origin master
git checkout dev
git merge master
git push origin dev
```

The `--no-ff` flag above makes sure to make a merge commit, no matter what, even if a "fast forward" could be done. For those in the future looking back, it's much better to see evidence of when branches were merged.


### Git Issues

Look for Git issues that should be fixed in the next release. Especially low-risk and simple things, like documentation changes, improvements to error messages and RPC help output. 

### Pre-release checklist:
  * Is this release changing consensus rules? Definitely update protocol version.

### Protocol Safety Checks:

  * Does `PROTOCOL_VERSION` in src/version.h need to be increased?
    * All releases with a consensus change should increase the value by 1
    * All releases with a large change to the networking (P2P) layer should increase the value by 1
    * This identifies a nodes protocol version to all other peers it connects to.
  * Does `MIN_PEER_PROTO_VERSION` in src/version.h need to change?
    * If it does, new nodes will not be able to talk to nodes with a version less than `MIN_PROTO_VERSION`
  * The main use of these is for newer nodes that know they do not want to talk to older nodes to prevent connecting to older nodes efficiently
  * For instance, when a new release has different consensus rules than older nodes, `MIN_PROTO_VERSION` prevents wasting lots of network bandwidth talking to incompatible nodes which will eventually be banned for disagreeing on consensus rules

## Release dependencies

Install deps on Linux:

	apt-get install help2man debchange

## Release process
 - If new seeds are being added or seeds are changing:
   - Edit contrib/seeds/nodes_main.txt
   - Run "make seeds"
   - Commit the result
 - Update version in configure.ac and src/clientversion.h to update the hushd version
   - In src/clientversion.h you update `CLIENT_VERSION_*` variables. Usually you will just update `CLIENT_VERSION_REVISION`
   - If there is a consensus change, it may be a good idea to update `CLIENT_VERSION_MINOR` or `CLIENT_VERSION_MAJOR`
   - To make a pre-release "beta" you can modify `CLIENT_VERSION_BUILD` but that is rarely done in Hush world.
   - A `CLIENT_VERSION_BUILD` of 50 means "actual non-beta release"
   - Make sure to keep the values in configure.ac and src/clientversion.h the same. The variables are prefixed wth an underscore in configure.ac
 - Run `make manpages`, commit + push results
   - hushd must be running so the script can automatically get the correct version number
     - There is a hack in the script where you can hardcode a version number if hushd isn't running.
     - Comment out the HUSHVER line and uncomment the line above it with a hardcoded version number
   - PROTIP: Man page creation must be done after updating the version number and recompiling and before Debian package creation
 - Update checkpoints in src/chainparams.cpp via util/checkpoints.pl
   - Run "./util/checkpoints.pl help" to get example usage
   - hushd must be running to run this script, since it uses hush-cli to get the data
   - Look for line which says "END HUSH mainnet checkpoint data" near line 560 in chainparams.cpp , that is where checkpoint data ends
   - Find the highest block height of checkpoint data, let's call it HEIGHT
   - Run `./util/checkpoints.pl 1000 HEIGHT &> checkpoints.txt` to generate the latest checkpoint data
   - To copy the new data from checkpoints.txt into the file, one way in Vim is to type ":r checkpoints.txt" which will read in a file and paste it as the current cursor
   - You will see 3 lines of "stats" at the end of the output, you just pasted in the newest stats. Delete the old stats that should be the 3 lines under the current stats
   - Make sure the new code compiles, commit and push
   - Run `./util/checkpoints.pl help` to see some basic help
     - By default it will generate checkpoints for every 1000 blocks, the "stride"
     - You can get a different "stride" by passing it in as the first arg to the script
     - To get checkpoint data for every 5000 blocks: `./util/checkpoints.pl 5000 &> checkpoints.txt`
     - Currently checkpoints from before block 340k are given for every 5k blocks to keep the data smaller
   - checkpoints.pl will just generate the data you need, it must be manually copied into the correct place
   - Checkpoints are a list of block heights and block hashes that tell a full node the correct block history of the blockchain
   - Checkpoints make block verification a bit faster, because nodes can say "is this block a descendant of a checkpoint block?" instead of doing full consensus checks, which take more time
   - Checkpoints also provide a bit of security against some attacks that would create malicious chainforks
     - They only provide limited security, because they talk about the past, not future block heights.
   - Try to generate checkpoints as close to the release as possible, so you can have a recent block height be protected.
     - For instance, don't update checkpoints and then do a release a month later. You can always update checkpoint data again or multiple times
   - DRAGONX now has checkpoints, you can generate them with: `./util/checkpoints.pl 1000 1 DRAGONX`
 - Update copyright years if applicable. Example: `./util/update-copyrights.h 2022 2023`
 - Update doc/relnotes/README.md
   - To get the stats of file changes: `git diff --stat master...dev`
 - Do a fresh clone and fresh sync with new checkpoints
 - Stop node, wait 20 minutes, and then do a partial sync with new checkpoints
 - Merge dev into master: `git checkout dev && git pull && git checkout master && git pull && git merge --no-ff dev && git push`
   - The above command makes sure that your local dev branch is up to date before doing anything
   - The above command will not merge if "git pull" creates a merge conflict
   - The above command will not push if there is a problem with merging dev
 - Make Gitea release with git tag from master branch (make sure to merge dev in first)
   - Make sure git tag starts with a `v` such as `v3.9.2`
 - Use util/gen-linux-binary-release.sh to make a Linux release binary
 - Upload Linux binary to Gitea release and add SHA256 sum
 - Use util/build-debian-package.sh to make an x86 Debian package for the release
   - Debian packages should be done after you make manpages, because those are included in Debian packages
   - `lintian` is an optional dependency, it's not needed to build the .deb
   - Upload .deb to Gitea release
   - Add SHA256 checksum of .deb to release
 - Use util/build-debian-package-ARM.sh (does this still work?) to make an ARM Debian package for the release
 - Upload the debian packages to the Gitea release page, with SHA256 sums
 - Figure out how to update https://faq.hush.is/rpc/ for new release

## Platform-specific notes

Use `./util/build-mac.sh` to compile on Apple/Mac systems, use `./util/build-win.sh` to build on Windows and `./util/build-arm.sh` to build on ARMv8 systems.

Use `./util/build-debian-package.sh aarch64` to build a Debian package for aarch64 .

## Optional things

### Updating RandomX

If you need to update the source code of our in tree copy of RandomX, see issue https://git.hush.is/hush/hush3/issues/337#issuecomment-5114 for details. Currently we use RandomX v1.2.1 from the official repo at https://github.com/tevador/RandomX/releases/tag/v1.2.1
