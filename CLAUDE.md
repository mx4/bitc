# CLAUDE.md

Working notes for agents/developers. `README.md` covers the project overview and
dependencies; this file covers how to build, run, test, and reason about the code
efficiently.

`bitc` is a thin SPV bitcoin client, 100% C, with a home-grown async network stack,
poll loop, and bitcoin engine. Console UI via ncurses. leveldb for the tx db.

## Build

```
make          # binary is ./bitc
make clean
```

- Compiler: clang (gcc on armv6l). Flags in `Makefile`.
- **macOS/Apple Silicon**: OpenSSL/leveldb/etc. come from Homebrew under
  `/opt/homebrew`. The Makefile derives this via `brew --prefix` on Darwin, so a
  plain `make` works. If headers/libs aren't found, check `brew --prefix`.
- Build is warning-clean except one pre-existing `hashtable.c` `set but unused`
  warning. `-Werror` was removed, so warnings don't fail the build.

## Running & the fast dev loop

The default `./bitc` launches the **ncurses TUI**, which **panics without a real
TTY** (e.g. when backgrounded/piped). For any headless/agent work use daemon mode:

```
./bitc -d                          # daemon, no UI
./bitc -d --connect <ip[,ip...]>   # pin specific peer(s), skip DNS/addrbook
./bitc -d --sync-and-exit          # exit the moment headers reach the tip
time ./bitc -d --connect <ip> --sync-and-exit   # clean header-sync benchmark
```

- **Known-good peers** (real height, serve headers, reachable): `137.226.34.45`
  (RWTH), `116.202.223.108` (Hetzner), `85.26.102.232`.
- Full header sync (~957k headers) takes ~25–45s; it is **~75% network
  round-trip latency** (479 serial `getheaders` to one peer), not CPU/disk.
- `headers.dat` persists (~76 MB), so re-runs are incremental/instant. Force a
  fresh sync with `rm ~/.bitc/headers.dat` or a full `./bitc -z` (zaps
  blockstore + addrbook + txdb).

### Gotchas

- **leveldb lock**: a `kill -9` leaves the txdb locked, so the next run fails with
  `txdb/LOCK: Resource temporarily unavailable` and won't sync. Always:
  `pkill -9 bitc; rm -f ~/.bitc/txdb/LOCK` before re-running.
- **Logs**: `/tmp/bitc-$USER.log` (log level 1, µs timestamps, subsystem prefixes
  like `PEERG:`/`WALLET:`/`BLCK:`). **Rotated per run** (`.0`..`.9`), so the base
  filename is always the latest run. Panics + backtraces land here too.
- `./bitc -t 0` (self-test) has a **pre-existing, unrelated failure**: it spends
  from an empty wallet and the test ignores `wallet_craft_tx`'s error, so it
  asserts. Not a regression — ignore unless working on that test.

## Data directory

`~/.bitc/` : `headers.dat` (block headers), `peers.dat` (addrbook), `txdb/`
(leveldb), `wallet.cfg`, `main.cfg`, `contacts.cfg`, `tx-labels.cfg`.

## Architecture map

- `apps/bitc-cli/` — CLI entry (`main.c`), ncurses UI (`ncui.c`, `bitc_ui.c`).
- `core/` — the engine: `peer.c`/`peergroup.c` (p2p + peer management),
  `block-store.c` (header chain + checkpoints), `btc-message.c`/`serialize.c`
  (wire protocol), `key.c`/`crypt.c`/`hash.c` (crypto), `wallet.c`, `txdb.c`,
  `script.c`, `bloom.c`, `base58.c`, `rpc.c`.
- `lib/` — reusable infra: `poll/` (home-grown `poll(2)` event loop),
  `netasync/` (async sockets), `util/`, `file/`, `poolworker/`, `config/`, etc.
- `public/` — shared headers: `bitc.h` (the global `struct BITCApp *btc`),
  `bitc-defs.h` (protocol constants/messages).

**Threading model** (important, non-obvious): a **single-threaded `poll(2)` event
loop** (`lib/poll`, `select(2)` fallback) drives all socket I/O and message
handling — `peer_receive_cb` and everything it calls (block-store writes, peergroup
state) runs on that one thread, so that shared state needs no locking. The
"multi-threaded" claim is the separate **10-thread poolworker** (`lib/poolworker`)
used for CPU offload. During header sync CPU sits ~27%; the work is latency-bound.

**SPV mechanism**: currently BIP37 (bloom filter `filterload` + `merkleblock`),
which modern Core nodes disable by default. There is an unfinished BIP37
`peergroup_download_filtered_blocks` phase that runs after header sync and hits an
`ASSERT(0)` in `blockstore_get_hash_from_birth`. The modernization direction is
BIP157/158 compact block filters (not yet implemented).

**Header sync**: driven by a single `peergroup->downloadPeer` (parallel download
from multiple peers corrupts the shared counters). Sync loops `getheaders` until a
batch adds nothing new; it does **not** trust a peer's advertised `startingHeight`
(monitoring nodes report 0 and are rejected/evicted). Checkpoints in
`block-store.c` (`cpt_main`) only cover up to height ~275000.

## Modernization roadmap

Prioritized improvements:

1. Harden parsers and make little-endian serialization explicit.
2. Add comprehensive tests, sanitizers, fuzzing, and CI.
3. Validate header proof of work, difficulty, timestamps, and chainwork.
4. Make wallet accounting reorg-safe.
5. Version persistence formats and support recovery.
6. Replace BIP37 with BIP157/158 compact block filters.
7. Add SegWit, Bech32m, and Taproot support.
8. Migrate to versioned AEAD wallet encryption.
9. Add descriptors, BIP32, and PSBT support.
10. Improve peer diversity, addrv2, and eclipse resistance.
11. Make execution contexts and thread ownership explicit.
12. Enforce resource limits and replace unsafe assertions with robust error handling.

Until consensus validation and reorg correctness are addressed, the current client should be considered experimental and not a secure wallet.
