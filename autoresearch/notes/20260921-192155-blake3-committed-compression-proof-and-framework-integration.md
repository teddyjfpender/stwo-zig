---
title: BLAKE3 committed compression proof and framework integration
author: Teddy Pender
created_utc: 2026-09-21T19:21:55Z
---

# Committed BLAKE3 compression proof — 2026-09-21

Progress on the priority BLAKE3 migration. Production defaults, frozen rosters,
security profiles and existing keys remain unchanged. The wider recursion goal
is still active.

The standalone CPU test now proves and verifies all seven compression rounds
(56 G calls), 16 feedforward XORs, and 48 public boundary words. It includes the
actual production bitwise (2^18 rows) and byte-pair (2^16 rows) providers. All
commitments, transcript draws, composition and FRI use the experimental BLAKE3
suite. The verifier reconstructs preprocessing from the canonical SSA schedule
and public input/output words, checks the committed root, replays challenges,
and invokes the core STARK verifier. It does not trust witness-supplied fixed
columns. A substituted root and a changed public output are rejected.

New boundary AIR: four main byte coordinates, eight fixed columns, four degree-2
roots and one signed recursion-wire emission. Initial words emit their canonical
consumer count; output words consume one. Semantic digest:
`9ea716f35720f161794bbdead035331efaaf25dadf69f34f2bdd2e8f091e76fb`.

Integration findings and fixes:

- Same-row framework export now permits a genuinely relation-only component
  (the XOR component). It still requires nonempty lookup entries/batches and
  rejects stray direct nodes when direct roots are empty. The independent
  layout already admitted this form; both now share the same direct-graph check.
- The framework generator treats omitted rows as inactive. G's constant-weight
  lookup requests remain active on zero padding, so the fixture supplies the
  complete padded row domain to interaction generation and counter registration.
  Omitting one padding request gives a nonzero global claim.
- The shared column projection now gives its runtime start offset an explicit
  usize type, supporting AIR declarations with comptime integer column counts.
- Core verification consumes the proof. The fixture transfers ownership once;
  it does not free the proof after verification.

Three guarded tests pass in ReleaseSafe:

```sh
python3 scripts/zig_serial_build.py --cwd src/integrations/riscv_cpu test-blake3-proof test-blake3-framework -Doptimize=ReleaseSafe --summary all
```

The proof test ran in about 2 seconds with 338 MiB maximum RSS; framework checks
ran in about 1 second. These are test-run diagnostics, NOT a controlled benchmark
or a claimed migration speedup. Parameters are eight FRI queries, blowup 1,
last-layer log degree 0 and zero PoW. They are deliberately small integration-test
parameters and cannot be compared to canonical CSP or production recursion.
Compilation took 18 seconds for the proof test and 7 seconds for framework tests.

Not yet implemented/qualified: full constrained block/chunk/tree/root framing,
scheduled transcript and Merkle recursion, production protocol/key/artifact
admission, Metal BLAKE3 kernels and complete parent-of-parent qualification.
No complete recursive proof speedup is claimed.

Source conformance retains the same 103 pre-existing finding identities, with
no new identities. Evidence files and source snapshots are SHA-256 pinned by
manifest.json. Earlier evidence directories were not changed.
