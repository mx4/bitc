#pragma once

#include "basic_defs.h"

/*
 * Tracks per-peer-address quality signals across runs (keyed by IP): observed
 * handshake latency, real (not self-advertised) services, and -- the signal
 * that actually matters for the BIP157 cfilter scan -- how often a peer has
 * proven it can actually serve compact filters vs. how often it has failed
 * (disconnected/stalled/sent a bad filter) while doing so.
 *
 * The ~10k-entry address book (core/addrbook.c) is a pool of addresses we've
 * merely heard about via DNS seeds or peer gossip; nothing there says which
 * ones are fast, responsive, or even still support compact filters. An
 * address only gets a peerstats entry once we've actually connected to it
 * and observed something, so this file stays small (tens to low hundreds of
 * entries) even though the address book itself is huge.
 */

struct peerstats;

struct peerstats_entry {
   uint8  ip[16];
   uint64 services;       /* last observed (real, from our own handshake) services */
   uint32 latencyUsec;    /* connect-to-verack handshake latency; 0 if unknown */
   uint32 cfilterOk;      /* # of cfilter scan chunks fully verified from this peer */
   uint32 cfilterFail;    /* # of chunks lost to this peer (disconnect/stall/bad data) */
   uint32 avgChunkUsec;   /* EMA of time from chunk-assigned to chunk-complete; 0 if
                            * never measured. This, not cfilterOk, is what "known-good"
                            * should really mean: a peer used 200 times at 13s/chunk is
                            * worse than one used 5 times at 1s/chunk. */
};

int  peerstats_init(const char *filename, struct peerstats **ps);
void peerstats_exit(struct peerstats *ps);

/* Write all entries to disk now (also done periodically and on exit). */
void peerstats_flush(struct peerstats *ps);

void peerstats_record_handshake(struct peerstats *ps, const uint8 ip[16],
                                uint32 latencyUsec, uint64 services);
/* chunkUsec: wall-clock time from when this chunk was assigned to this peer
 * to when it completed (see struct cf_segment.assignedTS in peergroup.h). */
void peerstats_record_cfilter_ok(struct peerstats *ps, const uint8 ip[16],
                                 uint32 chunkUsec);
void peerstats_record_cfilter_fail(struct peerstats *ps, const uint8 ip[16]);

bool peerstats_lookup(const struct peerstats *ps, const uint8 ip[16],
                      struct peerstats_entry *out);

/*
 * Higher is better. A peer with any recorded cfilter failure scores below
 * zero (deprioritized below a totally unknown peer, which scores exactly 0).
 * Among proven (never-failed) peers, score is dominated by speed
 * (avgChunkUsec) -- a reliably-fast peer beats a reliably-slow one even if
 * the slow one has far more accumulated successes; cfilterOk only breaks
 * near-ties between similarly-fast peers.
 */
int peerstats_score(const struct peerstats_entry *e);

/*
 * Collect up to maxOut of the highest-scoring known entries with a strictly
 * positive score (i.e. proven cfilter servers, never-failed) into out[].
 * Returns the number written.
 */
int peerstats_get_best(const struct peerstats *ps, int maxOut,
                       struct peerstats_entry *out);
