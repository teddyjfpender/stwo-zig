# Ethereum mixed-service global-memory driver

`rv64-word16-ethereum` imports existing retained native packets into the full
Word16 CPU, optional Keccak/ADD/DOUBLE bridges, and independently sized truth
providers. Packet hashes, native execution and old RAM roots are advice only.
One chronological RAM ledger supplies one INIT and one TEARDOWN for the execution.
All physical fixed/MAIN commitments precede the shared-challenge manifest barrier.

Commands (independently pinned request JSON, producer job directory):

```
rv64-word16-ethereum plan CONFIG JOBS unused 0
rv64-word16-ethereum produce CONFIG JOBS NEW_OUTPUT 0
rv64-word16-ethereum verify CONFIG OUTPUT
rv64-word16-ethereum produce CONFIG JOBS NEW_PREFIX_OUTPUT 4
rv64-word16-ethereum verify-prefix CONFIG PREFIX_OUTPUT
```

Count zero requires reaching the trusted terminal PC. A positive count produces
an explicitly partial execution. Receivers consume no work packets or tape and
perform no native replay. Before constructing keys they check the configured
batch schedule, genesis, epoch/CPU adjacency, step budget and completed endpoint.
Geometry selects bounded physical shape; all keys derive from the pristine
pinned ELF/input authority. Setup caches depend on image, geometry and service
kind, while each statement, count, call span and transcript remains separate.

Completed acceptance verifies every CPU and truth STARK, actual committed roots,
all local debts and global RAM/KIO/Wire closure. It then requires the independently
pinned absorbing terminal PC, halt=1, length=43, and expected output read from the
authenticated terminal RAM list. A missing terminal word cannot fall back to a
native memory image. Prefix acceptance returns no completed-block/output claim.

Producer retention is bounded: 128 GiB of temporary unlinked file-backed native
MAIN coefficients, owned by their PCS trees and released on success or error.
Original CPU witnesses move into streaming commits; narrow sources retire once
their final proof and receiver obligations are encoded. The current packet
import retains tapes until the chronological ledger is built, then releases them
before key setup/proving; streaming import remains a memory optimization.

`cost.json` reports exact native column cells, active family counts, distinct
setup identities and a base lifted-leaf exposure. The latter is not a compression
count: the current BLAKE2 committer incrementally absorbs native-height groups.
With stage profiling enabled, `physical-NNNN.stages.json` is written after each
proof and separates source, MAIN, mapped retention, interactions, composition,
FRI and decommit. Process counters span all threads and overlapping intervals
are not additive. Peak RSS is a process-lifetime high-water mark at interval end.

The schema3 qualification receipt is
`vectors/reports/rv64-word16-execution-20261031/ethereum-global-driver-prefix-v1.json`.
Four real packets (16,777,212 instructions, 336 Keccak, 817 ADD, 680 DOUBLE)
produce four CPU and three truth proofs with a separate fresh receiver. Mapped
retention plus profiling preserves all seven proofs, manifest and RAM sidecar
byte for byte against resident storage. Complete-mode rejects an early prefix.
Safe/Fast receiver tests also prove programs with false halt, length or output;
these valid prefixes fail completed acceptance. All 25 packets of block24,628,607
have passed advice import and chronological collection, not yet whole-block
proving in this receipt. Concurrent observations establish no speedup or p50.
