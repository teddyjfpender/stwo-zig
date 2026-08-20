# 2026-08-12 — E-020 BASE_ALU_IMM production SSOT

## Scope

ADDI, XORI, ORI, and ANDI now enter production through one authenticated typed
authority. The authority owns architectural result and x0 behavior, all 35
witness columns, all 22 direct roots, and all 16 ordered relation events. The
legacy executor fails closed for these four opcodes and the generated retirement
registry cannot silently fall back after classification.

The retained authority is pointer-free and allocator-free. Cold construction
authenticates `typed_addi`'s complete semantic digest and the complete-family
`typed_base_alu_imm_witness` recipe. Hot evaluation performs numeric, fixed
dispatch only.

## Runner transaction

The runner publishes the architectural register write, two state-chain events,
PC, and trace row as one failure-atomic transaction:

1. decode-word identity and typed retirement are checked without mutation;
2. rs1/rd aliases, x0, subclocks, predecessor clocks, and gap capacity are
   compiled without allocation;
3. trace and state-chain capacity are reserved before any logical write;
4. a cold allocator return triggers complete live-state revalidation;
5. the warm publish path uses only assume-capacity writes.

The generic E-017 compiler remains the cross-family oracle. Production uses a
fixed two-event projection so it does not move the generic transaction's
impossible third-event and memory storage. A dedicated differential gate proves
the compact source/destination clocks, values, and reservations equal the
generic compiler for all four opcodes and both alias classes.

## Compatibility and independent evidence

- The new evaluator is symbolically node-identical to the retired
  Stark-V-shaped direct and lookup evaluator. The comparison reconstructs the
  legacy ordered relation adapter in test-only code, so it does not compare the
  typed authority with itself.
- Column names, serialized DAG nodes, direct roots, relation geometry, batch
  size, and protocol identifiers remain unchanged.
- The compatibility manifest currently reports exactly one intentional drift:
  `formal.exports[addi].sha256`. This is a source-closure authority receipt,
  because production now imports the typed authority rather than the legacy
  semantics module. The shared artifact is deliberately not regenerated while
  the combined formal generation and adjacent family migrations are live.
- The proof A/B gate proves and independently verifies both generated and
  legacy witness arms and requires byte-identical proof and transcript output.
- The live pinned Sail bridge checks a sequence covering all four operations,
  signed-immediate boundaries, rd/rs1 aliasing, and x0 discard.

## Exact gates

```text
Debug runner:       319/319 passed
Debug AIR:          668/668 passed
ReleaseSafe AIR:    668/668 passed
ReleaseSafe runner: 319/319 passed
ReleaseFast AIR:    668/668 passed
ReleaseFast runner: 319/319 passed
Required-live Sail: 319/319 passed
Proof bytes:        56096
Proof SHA-256:      3566c06e37bc5cec6737fe41a85a8833ef0582f5237a9271355e7372489cb394
Transcript:         764acde3058f3bdfe01b999b21a99dc6bd7bdbbe192b474f71f3f5993877fb3b
Channel draws:      1
```

Representative ReleaseFast medians:

```text
retirement:     359959 ns typed / 448625 ns legacy = 1.2463x
witness 2^10:    138791 ns typed /   138709 ns legacy = 0.9994x
witness 2^14:   2234583 ns typed /  2230292 ns legacy = 0.9981x
witness 2^18:  35867917 ns typed / 35896000 ns legacy = 1.0008x
direct:         3675209 ns typed /  3705166 ns legacy = 1.0082x
```

The first generic-transaction runner implementation measured 0.5124x. The
fixed two-event compiler first raised this to 0.9770x. The final fused compact
publication path removes Plan materialization while preserving validation,
cold reservation/revalidation, generic-compiler equivalence, and every
failure-atomic check; the canonical paired run reached 1.2463x. The executable
test now enforces the stated strict 0.97x floor over warmup plus thirteen paired
samples. No allocation occurs on the warm path.

The aggregate ReleaseFast AIR root executed the witness and direct gates
successfully, including the former noisy BASE_ALU_REG case. The executable and
documented performance admission now agree.

## Residual boundary

The only unfinished administrative action for this family is the serialized,
combined artifact regeneration after the live formal build and neighboring
family identities settle. Until then the mismatch is explicit and bounded to
the formal source-closure hash; no compatibility artifact is overwritten by
this tranche.
