# Shared BLAKE3 commitment roots

The joined parent uses one canonical eight-word source per trace-tree or FRI
commitment. Routed transcript root absorption returns exact read multiplicities;
every corresponding Merkle opening consumes the same source once per word.
The preprocessed-tree source remains a public trusted-key anchor. All other root
sources use the existing bounded private-word AIR with value-independent fixed
columns. Original public transcript and Merkle-group APIs retain their defaults.

The existing byte_route AIR provides root equality: an identity route consumes
the computed hash output and emits at the canonical root with multiplicity p-1.
This is a second consume in M31. Its four affine constraints bind all four bytes;
source/word identities distinguish roots and words. The root producer accounts
for transcript reads plus the exact number of complete authentication paths.
No AIR equation or identity digest changed, and full 256-bit roots are preserved.

Focused serial validation exited 0: 16/16 steps, 7/7 tests passed. Covered
byte-route tuple/direct-constraint checks; private
root fixed-column invariance for single-leaf and four-leaf groups; namespace
collision rejection; native routed-root transcript parity and public boundary
counts; original public FRI-group proof; and complete joined parent proof.

Scope remains experimental and per-capture. The preprocessed root is obtained
from an independently verified native proof in this fixture; production key
admission is a separate remaining obligation. Query routing, nonces, rejection
and schedule geometry, reusable production keys, and parent-of-parent/Metal
qualification remain. Production stays Poseidon, with no end-to-end speed claim.

Next query work must include both arithmetic and path direction choices. DEEP
already exposes canonical query_position and query_bit bindings. Routing only
those values privately would leave host-selected Merkle left/right placement in
fixed schedules. That placement must consume constrained query bits before a
reusable schedule can be claimed.

| Target | Tests | Runtime | Peak runtime RSS | Compile |
| --- | ---: | ---: | ---: | ---: |
| test-blake3-byte-route | 3 | 664 ms | 8 MiB | 6 s |
| test-blake3-routed-transcript | 2 | 4 s | 352 MiB | 24 s |
| test-blake3-fri-group | 1 | 3 s | 381 MiB | 24 s |
| test-blake3-combined-fri | 1 | 29 s | 6 GiB | 36 s |

Command: `python3 scripts/zig_serial_build.py --cwd src/integrations/riscv_cpu
test-blake3-byte-route test-blake3-routed-transcript test-blake3-fri-group
test-blake3-combined-fri -Doptimize=ReleaseSafe --summary all`.
These are test diagnostics, not BLAKE3-versus-Poseidon speedup measurements.
Touched Zig files pass formatting; `git diff --check` passes. Terminal build
output is in tests.log. The source snapshot and SHA256 manifest preserve this
stage independently of later worktree changes.
