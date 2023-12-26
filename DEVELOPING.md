# Being a Hush Developer

## Compiling Hush

Normal compiling is as simple as:

	./build.sh

To make it use as many CPU threads as you have:

	./build.sh -j$(nproc)  # assumes linux
	./build.sh -j8 		  # use a fixed 8 threads, more portable

This is dangerous! You need about 2GB of RAM per thread, plus all the
other programs and Operating System overhead. A good rule of thumb is:

Divide how many GBs of RAM you have by 2, subtract one. Use that many jobs.


## Dealing with dependency changes

Let's say you change a dependency and want the compile to notice. If your
change is outside of the main Hush source code, in ./src, simply running
`make` will not notice, and sometimes not even `build.sh`. You can always
do a fresh clone or `make clean`, but that will take a lot of time. Those
methods are actually best for Continuous Integration systems, but to help
reduce the time a developer has to wait, here are some PROTIPs.


If you are changing how a dependency is built, you should remove the entire directory like this:

    rm -rf depends/work/build/x86_64-unknown-linux-gnu/wolfssl/

The above will delete the entire source code of wolfssl dependency on `x86_64`
but it will keep the tar.gz and you will not need to download it again. If
you are testing a change in URL or SHA256, you will want to force it to download
again:

    rm -rf depends/sources/wolfssl*.tar.gz

Now when you run `build.sh` again, you will be able to test your changes.


## Good Hygiene

To avoid weird build system issues, it's often good to run:

	make clean

*before* you switch Git branches. Otherwise, the new branches Makefiles
often are incompatible and `make clean` will be impossible, which can
sometimes introduce weird bugs or make compiling really annoying.
If `make clean` produces a compilation error, you just experienced it.

## Switching branches

Switching branches and doing partial compiles in Hush source code
can introduce weird bugs, which are fixed by running `build.sh` again.
Additionally, it's a good idea to run `make clean` before you switch
between branches.

## Partial compiles

At any point, you can modify hush source code and then use `make` or `build.sh`
to do a partial compile. The first is faster but the latter is more likely to
work correctly in all circustances. Sometimes partial compiles break weird
build system dependencies, and you must do a `make clean` first, or even
`git clean -fdx` (look up what it means first!) to clean things. The nuclear
option is to re-clone the repo, which sometimes is the least work to fix
the problem.

Running `make` doesn't understand about dependency changes, such as Rust crates.
A simple C/C++ change can be tested with just `make` but if you change the version
of a dependency or something inside of Rust, you will need `build.sh` .

## Generating new unix man pages

Make sure that you have updated all version numbers in hushd and compiled, then
to generate new unix man pages for that version :

	./util/gen-manpages.sh

## Generating new debian packages

After successfully compiling Hush, you can generate a debian package of these binaries with:

	./util/build-debian-package.sh

This command will not work on Mac OS X. Currently you cannot generate a Debian package
from operating systems other than Linux. Oh well.

## Updates to this document

If you think something else should be in this guide, please send your suggestions!

Gitea: https://git.hush.is/hush/hush3
