# Memory ownership qualification

User priority: lower memory at 16 transactions and beyond, preserving canonical
70 queries / 26 PoW bits and independently verified recursion.

## Measured bottleneck

The 16-transaction stage probe showed 16,435,928,547 worker bytes already live on
entry to the core proof, versus 17,196,556,091 peak. This is mainly retained
commitments, not an unbounded list of completed recursive nodes. Do not assume
that reducing composition scratch alone will remove most memory.

Native parent plans previously copied all fixed metadata into their persistent
arena while the current preparation also owned it. The replacement retains
23 BLAKE3 digests plus 23 row counts (920 bytes on this 64-bit host), in addition to
unchanged authenticated definitions/templates and fixed commitment. It does not
mean the entire plan is 920 bytes. Current source metadata is borrowed only during
synchronous lookup/interaction generation and freed at the last reader.

The digest is an internal content identity computed from the same rows whose
fixed commitment is independently admitted. Length, roster position, main shape,
and log-size checks remain mandatory. This introduces no new caller receipt,
proof format, transcript, or public-input encoding. All 16/32/64 outputs were
byte-identical to the previous implementation.

## Streaming ownership

A cached worker may hold a large fixed commitment. New key derivation constructs
another temporary commitment before replacement. The folder now checks current
row compatibility and evicts obsolete cache storage before key derivation; it
also checks the newly derived admission before reuse. No frontier node borrows
that plan. If replacement fails, verified children remain owned by the frontier
and can be retried; a new preparation may be required because rows are consumed.
The general `Worker.proveAdmitted` API still preserves its old fail-atomic cache
replacement contract for callers that require it.

## Remaining floor

BLAKE3 G AIR has 82 main and 80 base-field interaction columns per cohort, plus 16
fixed columns. These retained low-degree extensions remain large even after
source-row cleanup. The current changes eliminate redundant lifetime overlap;
they do not establish an absolute minimum or a sub-GiB recursive prover.
Further major reductions need changes to retained polynomial representation,
component geometry, or AIR width. Any such change needs a separate measured
experiment: reducing interaction columns can increase constraint degree and
composition work, and must not silently weaken security or change admitted keys.

## Evidence

- `memory-lifetimes-summary.json`: 16/32/64-transaction authentication.
- `test-composition-lifetime.log`: 1 test, including all allocation-failure points.
- `test-stream-memory-lifetimes.log`: real recursive proof plus changed/truncated
  metadata rejection, checked allocator, artifact verification after destruction.
- Full canonical 16-leaf stream qualification passed. The saved root was decoded,
  independently verified, and is byte-identical to the earlier root. See
  `stream-lifetimes-summary.json`: 18.06 GiB tracked / 14.40 GiB physical peak,
  678.91 seconds. This is the complete one-transaction authentication guest.
