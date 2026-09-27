# Shared BLAKE3 segment Span construction

Status: implemented; focused runtime qualification queued, not yet passed.

The base two-segment, base four-leaf tree, and Ethereum aggregation fixtures now
use the same exported constructor intended for production orchestration. It
validates leaf-local runner metadata and derives CPU states, continuation memory
roots, segment indices and global cycle offsets directly from each segment.
Temporary memory projections are released before return. It rejects a terminal
segment whose position disagrees with the complete job.

This is statement construction, not key admission. The existing parent admission
still binds the claim to verifier-owned execution geometry, public I/O and memory
custody. Production CLI routing and general execution orchestration remain open.
The already-running canonical aggregation binary predates this change.

Focused command:

```
python3 scripts/zig_serial_build.py --cwd . test-riscv-blake3-aggregation '-Driscv-test-filter=segment Span construction' -Doptimize=ReleaseSafe --summary all
```

Log: `/tmp/blake3-segment-span-construction.log`.
The focused fixture constructs and folds two actual runner segments, checks their
shared boundary and global coordinates, and rejects bad endpoint position and
zero global cycle metadata. Full proof fixtures were updated but have not yet
been rerun for this constructor.

The constructor now also derives the complete job from the actual first and last
segments: segment count, total global cycles, initial/final machine states and
public I/O identities. It compares all non-root endpoint public data against the
runner using the canonical BLAKE3 public-data transcript, and rejects different
program identities between endpoints. Commitment roots remain caller-admitted
inputs, bound by the existing proof/key admission rather than self-selected from
an artifact. The focused fixture includes mismatched endpoint registers and
program identities. The default aggregation target includes this focused case
and its test floor increases from three to four.

A one-second live sample of the earlier canonical aggregation run still showed
leaf proving/PCS work (including FRI commitments and cleanup), not a stopped
process. The sample is a diagnostic snapshot, not a latency breakdown.

The queued focused regression now also injects failure at every constructor
allocation. The constructors return scalar claims and retain no temporary public
I/O or snapshot projections. Leaf construction validates the complete job before
allocating projections. These additions are pending runtime qualification.

Result: Focused constructor and allocation-failure regression passed; wrapper 5 seconds, 539 MiB maximum RSS.
