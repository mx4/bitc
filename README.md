[![CI](https://github.com/mx4/bitc/actions/workflows/ci.yml/badge.svg)](https://github.com/mx4/bitc/actions/workflows/ci.yml)

### BITC

bitc is a *thin* SPV bitcoin client.
* 100% C11,
* support for Linux, macOS,
* ncurses-based TUI,
* home-grown async network I/O (single-threaded poll(2) loop),
* home-grown Bitcoin P2P engine,
* BIP157/158 compact block filters (not BIP37),
* encrypted wallet (AES-256-CBC via OpenSSL EVP),
* Tor/SOCKS5 support,
* CPU offload pool for signature verification,
* clean under ASan and UBSan.

**WARNING:** this app is experimental and should not be used as a secure wallet.
See [TODO.md](TODO.md) for the modernization roadmap.

---

#### Screenshots

![dashboard](https://i.imgur.com/IJJU14s.png)

---

#### Dependencies

These are discovered at build time via `pkg-config`, so install them with your
package manager (e.g. `brew install openssl leveldb snappy curl cjson pkg-config`
on macOS, or the matching `-dev` packages on Debian/Ubuntu:
`libssl-dev libleveldb-dev libsnappy-dev libcurl4-openssl-dev libncurses-dev
libcjson-dev pkg-config`).

 - OpenSSL: crypto library (EC keys, ECDSA, AES), used via the OpenSSL 3 EVP
   API. https://www.openssl.org/
 - LevelDB: Google's key/value store for the transaction db, BSD 3-Clause.
   https://github.com/google/leveldb (with Snappy for compression).
 - libcurl: HTTP client (fx rates, ip info), MIT/X derivative.
   https://curl.se/libcurl/
 - ncurses (with panel/form): the console UI.
 - cJSON: JSON parser, MIT. https://github.com/DaveGamble/cJSON

MurmurHash3 (public domain) is bundled under `ext/src/`.

---

#### Install

##### Linux (Debian / Ubuntu)

You first need to install the build tools and libraries this app uses:
```
   # sudo apt-get install git make clang pkg-config
   # sudo apt-get install libssl-dev libcurl4-openssl-dev libncurses-dev
   # sudo apt-get install libleveldb-dev libsnappy-dev libcjson-dev
```

then clone the git repository:
```
   # git clone https://github.com/mx4/bitc.git
```

finally build and launch:
```
   # cd bitc && make
   # ./bitc
```

##### macOS

Install the dependencies via `brew` (or `port`):
```
   # brew install pkg-config openssl leveldb snappy libcurl ncurses cjson
```
then build and launch:
```
   # cd bitc && make
   # ./bitc
```

#### Daemon Mode

bitc can run headless without the ncurses UI:

    ./bitc -d                          # daemon, no TUI
    ./bitc -d --connect <ip>           # pin a specific peer
    ./bitc -d --sync-and-exit          # sync headers then quit
    ./bitc -z                          # wipe blockstore, addrbook, txdb

The `-e` flag encrypts the wallet interactively. Self-tests: `./bitc -t 0`.

#### Build Targets

    make              # debug build (default)
    make BUILD=release
    make BUILD=asan   # AddressSanitizer
    make BUILD=ubsan  # UndefinedBehaviorSanitizer
    make check        # build + run fuzz-parse and test-gcs
    make tags         # ctags index

---

#### Usage

The first time you launch the app, a message will notify you
of the list of files & directory it uses.

bitc uses the folder `~/.bitc` to store various items:

|    what              |    where                | avg size |
|:---------------------|:------------------------|:--------:|
| block headers        | ~/.bitc/headers.dat     | ~ 75MB   |
| peer IP addresses    | ~/.bitc/peers.dat       |  ~ 1MB   |
| transaction database | ~/.bitc/txdb            |  < 1MB   |
| config file          | ~/.bitc/main.cfg        |  < 1KB   |
| wallet keys          | ~/.bitc/wallet.cfg      |  < 1KB   |
| tx-label file        | ~/.bitc/tx-labels.cfg   |  < 1KB   |
| contacts file        | ~/.bitc/contacts.cfg    |  < 1KB   |


A log file is generated in `/tmp/bitc-$USER.log`.

To navigate the UI:
 - `<left>` and `<right>` allow you to change panel,
 - `<CTRL>` + `t` to initiate a transaction,
 - type `q` or `back quote` to exit.

---

#### Encrypted wallet

bitc has support for encrypted wallets. The first time you launch the app, it will
automatically generate a new bitcoin address for you, and the wallet file will
have private key **unencrypted**.

To turn on encryption, or to change the encryption password:
```
  # ./bitc -e
```

The next time you launch the app, you may or may not specify `-p` on
the command line. If you do, you will be able to initiate transactions. If you
do not the dashboard will still be functional but you won't be able to
initiate transactions.

Note that bitc encrypts each private key separately.

**WARNING:** please remember to make back-ups.

---

#### TOR / SOCKS5 support

Bitc can route all outgoing TCP connections through a socks5 proxy. Since TOR
implements a SOCKS5 proxy, you just need to put the entry:
```
	network.useSocks5="true"
```
in your main config file to use bitc over Tor (for a local Tor client). If the
Tor proxy is not running locally, you need to modify the config options:
```
 	socks5.hostname="localhost"
	socks5.port=9050
```
.. in the file `~/.bitc/main.cfg`. The default `hostname:port` is
`localhost:9050` on linux, and `localhost:9150` on mac.

---

#### Watch-only Addresses

If you tag a key as
```
   key0.spendable = "FALSE"
```
in your `~/.bitc/wallet.cfg`, bitc won't attempt to spend the bitcoins held by
this address. This is not quite like a watch-only address, but we'll get there
eventually.

---

#### Problem?

There are still a variety of things that need to be fixed or implemented (cf [TODO
file](TODO.md)), and some of these may explain the behavior you're seeing.  If bitc
crashes, please collect the log file along with the core dump and open a ticket
on github:  

	https://github.com/mx4/bitc/issues

---

#### Feedback, comments?

Feel free to reach out to me if you have any feedback or if you're planning to
use this code in interesting ways.

   mailto:austruym@gmail.com
   PGP: 1C774FA3925A3076752B2741054E32DFBEE883DB
