This directory contains integration tests that test bitcoind and its
utilities in their entirety. It does not contain unit tests, which
can be found in [/src/test](/src/test), [/src/wallet/test](/src/wallet/test),
etc.

Every pull request to the dogecoin repository is built and run through
the regression test suite. You can also run all or only individual
tests locally.

- [functional](/test/functional) which test the functionality of 
bitcoind and bitcoin-qt by interacting with them through the RPC and P2P
interfaces.
- [util](test/util) which tests the bitcoin utilities, currently only
bitcoin-tx.

Unix
----
`python3-zmq` and `ltc_scrypt` are required. On Ubuntu or Debian they can be installed via:
```
sudo apt-get update
sudo apt-get install -y curl gcc python3-pip python3-setuptools python3-zmq
./test/functional/install-deps.sh
```

OS X
------
```
brew install curl
pip3 install pyzmq
./test/functional/install-deps.sh
```

- on Unix, run `sudo apt-get install python3-zmq`
- on mac OS, run `pip3 install pyzmq`

Running tests locally
=====================

Functional tests
----------------

You can run any single test by calling

    test/functional/test_runner.py <testname>

Or you can run any combination of tests by calling

    test/functional/test_runner.py <testname1> <testname2> <testname3> ...

Run the regression test suite with

    test/functional/test_runner.py

Run all possible tests with

    test/functional/test_runner.py -extended

By default, tests will be run in parallel. To specify how many jobs to run,
append `-parallel=n` (default n=4).

If you want to create a basic coverage report for the rpc test suite, append `--coverage`.

Possible options, which apply to each individual test run:

```
  -h, --help            show this help message and exit
  --nocleanup           Leave dogecoinds and test.* datadir on exit or error
  --noshutdown          Don't stop dogecoinds after the test execution
  --srcdir=SRCDIR       Source directory containing dogecoind/dogecoin-cli
                        (default: ../../src)
  --tmpdir=TMPDIR       Root directory for datadirs
  --tracerpc            Print out all RPC calls as they are made
  --coveragedir=COVERAGEDIR
                        Write tested RPC commands into this directory
```

If you set the environment variable `PYTHON_DEBUG=1` you will get some debug
output (example: `PYTHON_DEBUG=1 test/functional/test_runner.py wallet`).

A 200-block -regtest blockchain and wallets for four nodes
is created the first time a regression test is run and
is stored in the cache/ directory. Each node has 25 mature
blocks (25*50=1250 BTC) in its wallet.

After the first run, the cache/ blockchain and wallets are
copied into a temporary directory and used as the initial
test state.

If you get into a bad state, you should be able
to recover with:

```bash
rm -rf cache
killall dogecoind
```

Writing tests
======tests is found in [test/functional](/test/functional).
