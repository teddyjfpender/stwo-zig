# 2026-08-12 — LUI and FENCE production single-source authorities

## Question

Can the first two opcode families cross from typed witness generation into the
original proposal's stronger production boundary—one authenticated definition
for architectural execution, witness rows, direct AIR, ordered relations, and
formal/runtime export—without changing proof meaning or regressing the hot
path?

## Context and exact boundary

LUI and FENCE were deliberately chosen as complementary pilots. LUI has one
destination-register transition, x0 discard semantics, immediate range
evidence, and seven ordered relations. FENCE is the empty-effect edge case: it
advances only `(pc, clock)`, has no register/memory access, and carries three
ordered relations. Together they test both a real access transaction and the
smallest legal retirement.

The production capabilities are
`typed_lui_authority.zig`/`lui_retirement.zig` and
`typed_fence_authority.zig`/`fence_retirement.zig`. A compile-time
`generated_retirement.zig` registry owns decoded dispatch. The old semantic
evaluators are explicitly named `*_legacy_test_oracle.zig` and are absent from
production exports.

## Commands and evidence

The following gates passed on the shared branch:

```text
zig build --build-file src/frontends/riscv/build.zig test-runner \
  -Doptimize=Debug
zig build --build-file src/frontends/riscv/build.zig test-runner \
  -Doptimize=ReleaseSafe
zig build --build-file src/frontends/riscv/build.zig test-runner \
  -Doptimize=ReleaseFast
STWO_ZIG_REQUIRE_SAIL_ORACLE=1 \
  zig build --build-file src/frontends/riscv/build.zig test-runner \
  -Doptimize=ReleaseSafe
zig build --build-file src/frontends/riscv/build.zig test-air-semantics \
  -Doptimize=Debug
zig build --build-file src/frontends/riscv/build.zig test-air-semantics \
  -Doptimize=ReleaseSafe
```

The pinned formal toolchain prepared an exact RV32IM Sail theorem backend with
identity
`074d61135954f165c3490630aec286f28638ba99f1c64c92056bd3c29c05c21a`.
This is a live Sail/Lean boundary, not a reuse of stale committed evidence.

Exact independent proof gates retained the existing protocol:

| Family | Bytes | Proof SHA-256 | Transcript | Draws |
| --- | ---: | --- | --- | ---: |
| LUI | 53,233 | `d08ac8d7dd90d63683ba75f63194101662967981ae2380ebcc16cac3568d5d0f` | `cdf8abf6152bcf3a17fd02f9a15bbc809424b751567348604841146e02fc29ab` | 1 |
| FENCE | 55,922 | `d40169c9015b816f043da0f7c8b613ca0b950b7f01e408ca4ec2583b34c82864` | `a1c12df7dd49f82e44219e982299a47ecd23c670b05a9fb5d9a75bfde5dc91db` | 1 |

The post-optimization FENCE proof reproduced the same bytes, hash, transcript,
and draw count.

## Performance observations

The first generic direct integration returned the largest family's direct-root
array by value. FENCE's fixed typed evaluator was 4.59x faster in isolation,
yet the production wrapper paid avoidable stack-copy traffic. Production row
loops now use `buildDirectInto`/`evaluateInto` with caller-owned storage and
consume only `values[0..len]`.

A current paired ReleaseFast diagnostic reported:

| Surface | Typed/current | Legacy/reference | Ratio |
| --- | ---: | ---: | ---: |
| FENCE production direct | 629,333 ns | 673,375 ns | 1.0700x |
| FENCE lookup construction | 1,425,667 ns | 1,423,083 ns | 0.9982x |
| FENCE atomic retirement | 714,583 ns | 781,458 ns | 1.1013x |
| LUI production direct | 1,795,042 ns | 1,830,625 ns | 1.0198x |
| LUI lookup construction | 1,928,666 ns | 1,946,709 ns | 1.0094x |
| LUI atomic retirement | 132,333 ns | 143,792 ns | 1.0866x |

These are local paired diagnostics, not whole-proof promotion receipts. A
ReleaseFast all-family AIR run passed 634/635 tests and stopped only on the
existing noisy BRANCH_LT witness microbenchmark after a 0.9472x small-sample
result. No semantic, proof, transcript, or migrated-family performance gate
failed. The timing gate is retained rather than weakened; it must be rerun in a
quiet isolated process before interpreting that sample as a regression.

## Soundness and ownership observations

- Registered opcodes cannot fall back to handwritten execution.
- Capacity is reserved before any CPU, trace, or state-chain publication.
- A cold allocator return forces complete snapshot revalidation.
- LUI resolves x0, aliases, strict access clocks, predecessor clocks, and gap
  rows before publication.
- FENCE proves its access transaction is canonically empty and never reserves
  or mutates state-chain storage.
- Independent tests use the retired formulas or Sail rather than comparing two
  calls through the same typed authority.
- Formal source-closure changes caused by retiring a production source are
  regenerated explicitly; geometry, relation order, and protocol identity stay
  unchanged.

## What this does not establish

This closes E-018 and E-019, not E-020 through E-022. Fifteen family-level
execution/AIR authorities, complete generated composition metadata, and final
retirement of the handwritten composition layer remain. The full clean-source
performance receipt and current-HEAD formal receipt also remain distinct from
these focused activation gates.

## Decisions/tasks affected

- ADR-0038 records the reusable activation and dispatch boundary.
- E-018 and E-019 are done.
- E-020 is active with BASE_ALU_IMM as the next family.
- E-021 is active at 2/17 registered families.
- The original-scope map records witness completion separately from
  execution/AIR single-source completion.
