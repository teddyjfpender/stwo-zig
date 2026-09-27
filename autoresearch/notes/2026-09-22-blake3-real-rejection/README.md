# Genuine native BLAKE3 rejection fixture

Absorb integer 418109725 into the initial experimental BLAKE3 channel. Its first
raw draw has word zero 0xffffffff, causing rejection of the entire eight-word
block. The second and third raw blocks accept. The fixture pins the initial
post-absorption digest and all three raw blocks. Normal tests only replay it.

The native eight-worker miner evaluated 417857536 candidates and found this seed
in 14 s (2 s compile), within its 2^31-candidate / 300-second-per-worker bounds.
Discovery order depends on thread scheduling; this does not claim the smallest
seed. The miner uses the current native Channel implementation, not a copied
hash or a substitute encoding. Search output and source are preserved here.

Draw tests now verify native byte-for-byte replay, genuine rejection, native bulk
secure extraction, two-attempt witness/fixed-column parity, rejection of a
premature one-attempt claim, and rejection of an attempt to skip the accepted
second block. The existing complete transcript proof begins with this genuine
rejection, then continues through another draw, absorption resets, root/field
absorption, raw queries and PoW. This tests the real retry path without changing
the protocol or adding expensive searches to test execution.

Validation exited 0: 8/8 build steps and 4/4 tests passed. The two draw tests
ran in 1 s / 4 MiB (4 s compile); the two transcript tests ran in 4 s / 394 MiB
(22 s compile). Command: `python3 scripts/zig_serial_build.py --cwd
src/integrations/riscv_cpu test-blake3-draw test-blake3-transcript-sequence
-Doptimize=ReleaseSafe --summary all`. Formatting and `git diff --check` pass.
These timings are fixture/test diagnostics, not prover speedup measurements.

Scheduler replacement is still incomplete. It must jointly constrain the first
accepted block, checked u64 counter advancement, and output selection under a
fixed-capacity schedule. A capacity bound needs an explicit overflow policy;
fixing or padding attempt counts alone does not preserve the unbounded native
retry protocol. Lifted alias scheduling and production CPU/Metal key admission
also remain. No production migration, speedup, or reusable-key claim follows.
