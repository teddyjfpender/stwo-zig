# Full-width execution opening, query and terminal bindings

The real full-width execution capture now exercises the shared recursive STARK
opening machinery alongside its composition, DEEP and FRI graphs. Query and
terminal encoders accept the retained transcript plan directly; callers that
supply emitted transcript rows still receive fixed/live receipt consistency
checks. This avoids requiring a second transcript witness materialization to
prepare those bindings.

The execution-specific root adapter pins the preprocessing root to the admitted
execution key. Other trace/FRI roots are private full-width word producers shared
between transcript and opening consumers. The adapter binds the single PCS nonce
and its configured PoW difficulty without importing the legacy interaction nonce.
The shared path builder checks all computed roots against the verified capture.
Opening sources are checked against the exact DEEP/FRI input inventory; query
fanout incorporates Merkle direction and lifted-index projection reads.

The real-proof gate checks root and query substitutions, terminal coefficient
routing and idempotent path-read application. Canonical arithmetic circuit IDs
1500/1502/1504 are used throughout the execution routing test, matching the shared
opening builders. These remain diagnostic q8/PoW0 child-proof tests. Complete
parent row assembly, independent parent-key admission and end-to-end parent
proving remain unfinished, as do multilevel recursion, extensions and production
default promotion. This note makes no speedup or canonical recursion claim.

## Qualification evidence

`python3 scripts/zig_serial_build.py --cwd . test-riscv-blake3-execution-commitments -Doptimize=ReleaseSafe --summary all`

Passed in ReleaseSafe: 1 minute build/test time, 4 GiB peak RSS. The real capture
has 4 trace trees, 20 FRI layers and 8 queries. Its opening inventory contains
7,800 scalar sources; the shared path witness emits 324,352 G rows and 92,672 XOR
rows. Both root and query substitution checks reject, and repeated fanout
application is identical. The same gate retains the earlier composition,
DEEP/FRI and challenge/payload tamper checks. Zig formatting checks also pass.
No whole-repository suite or speed benchmark was run.
