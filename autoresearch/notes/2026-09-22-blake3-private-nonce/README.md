# Shared private PoW nonce

The canonical frame writer exposes integer/nonce u64 values through two ordered
LE u32 word callbacks. Native serialized bytes, domains, and protocol identity
remain unchanged. Existing authenticated payload routing now admits those two
roles. Transcript PoW optionally consumes an external nonce source; routed
integer absorption consumes the same source. Canonical PCS operation construction
selects the identical caller for both and preserves its transactional behavior.

The joined parent owns two bounded private-word rows with combined read counts
from the PoW and absorption receipts. Their nonce values no longer enter fixed
columns. Existing public integer/PoW APIs retain their default behavior. PoW's
zero-bit check remains fixed and constrained. No AIR equations or identities
changed. Namespace 4_000_004 holds the parent's two nonce words.

Focused serial validation exited 0: 16/16 steps and 6/6 tests passed. Coverage: canonical frame regression, routed transcript proof
with 4 PoW bits and a nonce whose upper 32 bits are nonzero, public transcript
sequence regression, and complete joined parent proof. The routed unit also
checks manual protocol encoding for 0/1/u32-max/high-bit/u64-max nonce values,
fixed-column independence between zero and u64-max, exact word read receipts,
and rejection of a nonce source that aliases transcript circuits.

Still incomplete: rejection/draw-counter schedules, lifted-column alias
consistency without per-capture preprocessing, production key admission,
CPU/Metal parent-of-parent qualification and end-to-end performance. The parent
fixture uses its existing test security parameters; no query/PoW reduction or
production migration is claimed. Production still uses Poseidon.

| Target | Tests | Runtime | Peak runtime RSS | Compile |
| --- | ---: | ---: | ---: | ---: |
| test-blake3-framing | 1 | 464 ms | 1 MiB | 3 s |
| test-blake3-routed-transcript | 2 | 4 s | 355 MiB | 25 s |
| test-blake3-transcript-sequence | 2 | 4 s | 394 MiB | 22 s |
| test-blake3-combined-fri | 1 | 30 s | 6 GiB | 37 s |

Command: `python3 scripts/zig_serial_build.py --cwd src/integrations/riscv_cpu
test-blake3-framing test-blake3-routed-transcript test-blake3-transcript-sequence
test-blake3-combined-fri -Doptimize=ReleaseSafe --summary all`.
These are test diagnostics, not proof speedup measurements. Touched Zig files
pass formatting; `git diff --check` passes. tests.log and source hashes preserve
the terminal evidence for this stage.
