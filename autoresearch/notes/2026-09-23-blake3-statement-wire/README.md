# Full-width statement metadata on the shared codec

Implemented, pending runtime qualification. The existing guest statement metadata
codec now shares one typed encoder/decoder for legacy field roots and full-width
BLAKE3 roots. New entry points encodeBlake3Statement/decodeBlake3Statement preserve
all 32 bytes of each optional root. Active descriptor prefixes, public I/O limits,
canonical option tags, owned decoded slices and strict end-of-section checks are
shared. Legacy entry points retain their field-root format.

The real base proof fixture now round-trips full-width metadata, releases the
wire bytes, and derives its prepared verifier from the decoded statement. This
still requires a separately admitted commitment plan; it does not activate the
production CLI or permit metadata to choose a trusted verification key.

The preceding base check failed compilation at two stale State.finish(a) call
sites. Both now call finish() using owner allocation authority. New run:
/tmp/blake3-owned-base-run-proof-v2.log
Legacy compatibility target: test-riscv-statement-wire
Log: /tmp/blake3-statement-wire-legacy-compatibility.log

The base verifier reconstruction fixture now also transports its commitment plan
through a bounded B3CPLAN1 codec. Counts and exact payload size are checked before
allocation; the complete reconstructed plan identity must match the caller pin.
Three full roots are encoded once, and each typed schedule gets its required root
from those authorities. Plan semantics, order and namespace checks remain shared
with Plan.validate. Empty program schedules reject before allocation.

Tests added to the queued real-proof run: independently decoded plan+statement,
wrong expected plan ID, mutation of a root's final byte, truncated payload, count
limits and all decoder allocation failures. The original native witness is not a
verifier-metadata authority on this path. These new checks are not yet passed.

Next production step remains an outer manifest binding the statement, plan and
PCS policy to the caller's expected statement identity before deriving a verifier
key. The transport codecs alone do not provide that admission policy or CLI route.
