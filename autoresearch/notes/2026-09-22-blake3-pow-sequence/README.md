# Native BLAKE3 PoW transcript verification — 2026-09-22

The previous turn integrated raw queries into transcript sequencing. This turn
adds native proof-of-work verification using the same private-state frame router
and bytewise mask AIR.

For difficulty bits 0..32, the first little-endian u32 of the canonical PoW hash
must satisfy word AND low_bits_mask == 0. The existing mask AIR exposes explicit
low-bit constructors supporting width 32; query constructors remain restricted
to domain logs 0..31. Its semantic digest is unchanged. A public zero boundary
binds the masked output; unused digest words have no consumers. No new AIR or
lookup table was added.

PoW verification changes neither state nor draw counter. Nonce absorption is a
separate integer operation, matching the separation in core/pcs/verifier.zig.
The sequence's PoW frame binds state, difficulty and nonce through native framing.
Public operation payloads remain fixture statement inputs; states are private.

Focused command:

```sh
python3 scripts/zig_serial_build.py --cwd src/integrations/riscv_cpu test-blake3-query-mask test-blake3-transcript-sequence -Doptimize=ReleaseSafe --summary all
```

The full fixture now has twenty operations, ten secure challenges, nine raw
indices and an 8-bit PoW predicate. It checks a draw following PoW verification,
then nonce absorption and another draw, establishing both counter preservation
and reset. The nonce comes from the native grinder. Unit cases reject a native
invalid nonce and difficulty 33, accept zero difficulty without advancing draws,
and check 32-bit masks with zero/full-width words. A valid 32-bit PoW hash is not
fabricated: that boundary is tested at the exact mask component.

These development proofs use eight proof queries, blowup 1 and zero outer-proof
PoW. The verified inner 8-bit predicate is a test fixture, not a production
security setting. Query path admission, private payload/source admission,
production identities, Metal and parent-of-parent qualification remain.
Production still selects Poseidon; no production speed claim is made and the
full recursion goal remains active.

All three guarded tests pass, including the complete core-verifier sequence
proof. Mask tests ran in 583 ms; sequence tests including the proof took about
4 seconds, max RSS 394 MiB on M5 Max. Formatting and diff checks pass. Changed
manual sources remain below the source-size ceiling; older snapshots are intact.
