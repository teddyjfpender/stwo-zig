# 2026-08-10 — C-011 Poseidon2 semantic corpus

## Question

Can the committed portable RV32IM Poseidon2 guest serve as the independent
native side of the `CUSTOM-0` permutation corpus, and what is the strongest
honest differential available through the current runner APIs?

## Exact fixtures inspected

- `vectors/riscv_csp/guests/poseidon2_m31.elf`
  (`b1e31859875643a964afdcd2b2f78022b847f170a38c2e679b53aa7af5220b8a`);
- `vectors/riscv_guests/poseidon2_m31/src/main.rs`
  (`4382737040a0b25c66f774ec104b6e74e86674fd4876d5352768453e5a9ccb9e`);
- `vectors/riscv_csp/inputs/field_m31_{2,4,8,12,16}.bin`; and
- `vectors/riscv_csp/manifest-v2.json`.

The manifest classifies this guest as `csp_field_native_extension`, says
`uses_precompile: false`, and pins the input convention as a little-endian
element count followed by that many canonical M31 words.

## Exact ABI blocker

The committed guest does not expose the function implemented by
`stwo.p2perm.m31.v1`:

| Property | Committed RV32IM guest | `CUSTOM-0` ABI v1 |
| --- | --- | --- |
| Input | `n` scalar elements | exactly sixteen state lanes |
| State initialization | sixteen zero lanes | caller-supplied state |
| Operation count | one permutation after every absorbed scalar | exactly one permutation |
| Absorption | add each scalar into lane zero | none |
| Noncanonical word | reduce modulo M31 | reject |
| Full-round constant | `1234` in every lane | pinned per-round, per-lane constants |
| Internal diagonal | `2^(lane+1)` | pinned Stark-V diagonal constants |
| Round ordering | add, external matrix, then S-box | initial external matrix, then add, S-box, external matrix |
| Output | first eight lanes, 32 bytes | all sixteen lanes in place, 64 bytes |
| Machine profile | `rv32im-zkvm-v1`, no admission note | `rv32im-zkvm-poseidon2-v1`, exact admission note |

Consequently, zero-padding a CSP input to sixteen words does not make the
native guest and precompile comparable. They are different functions with
different public interfaces. The runner also correctly rejects the committed
base-profile ELF when selected through `runPoseidon2Extension`; silently
executing it as the extension would weaken profile identity.

Producing a true guest-versus-guest comparison requires a new portable RV32IM
guest that implements `riscv.poseidon2_m31.permute.v1`, accepts and returns all
sixteen lanes, and advertises the base profile. That artifact does not exist in
the committed fixture set. C-011 must not present the current sponge guest as
that artifact.

## Implemented independent boundary

`c011_scalar_reference_test_support.zig` is a test-only scalar oracle. It:

- imports neither the production permutation nor its constants module;
- carries a separate transcription of the parameters pinned at Stark-V
  `d478f783055aa0d73a93768a433a3c6c31c91d1c`;
- performs field multiplication with native `u64` arithmetic modulo
  `2^31 - 1`, independent of the production M31 implementation; and
- evaluates the external linear layer by literal 4-by-4 matrix
  multiplication, rather than reusing the production addition schedule.

`c011_elf_test_support.zig` emits one exact extension-labelled ELF containing
one `CUSTOM-0` retirement per state. Every call has a distinct 64-byte state
region, so inputs cannot be overwritten before later calls. The base runner
must reject that ELF, and only the explicit extension runner executes it.

`c011_semantic_equivalence_test.zig` compares the scalar oracle with actual
runner call records and final architectural memory for 21 states:

| Class | Cases |
| --- | ---: |
| zero-ish | 3 |
| M31 boundary | 3 |
| structured | 3 |
| deterministic SplitMix64 | 5 |
| exact duplicate relation values | 2 |
| committed CSP inputs, zero-padded only for corpus coverage | 5 |

All inputs are checked to be canonical. Duplicate states occupy distinct
addresses and remain distinct calls, while their independently calculated and
precompile-produced outputs agree exactly. Package ownership prevents the
frontend test module from embedding files in the repository-level `vectors/`
tree. The five committed CSP inputs are therefore transcribed into test-owned
states, reconstructed in their original count-plus-words wire encoding, and
checked against all five manifest-pinned SHA-256 digests. The committed ELF is
not copied into the frontend package merely to make this test convenient.

## What this establishes

- The actual profile-labelled runner implementation agrees on this corpus
  with an independent scalar implementation of the advertised 16-lane
  function.
- Architectural in-place memory and the frozen call record agree with the
  oracle for every lane.
- Boundary, sparse, structured, seeded-random, duplicate, and committed-input
  values are represented without invoking the production permutation from the
  test side.
- Base and extension execution remain explicitly separated.

## What this does not establish

- It is not universal equivalence over all `M31^16` states.
- It is not a replacement for a new portable RV32IM guest exposing the exact
  v1 permutation ABI.
- The permanent frontend test does not execute the repository-level committed
  native ELF; its source, manifest, output contract, and profile establish the
  incompatibility, while the package-owned test exercises the comparable
  function.
- Reusing committed CSP input values does not equate the CSP sponge with the
  precompile.
- It does not prove that the separately transcribed constants are correct;
  their pinned source and semantic digest remain the authority.
- It does not exercise proof generation or verification; C-009 owns that
  boundary.

## Integration

The new test deliberately does not edit the shared runner inventory. Add this
single import when the integration root is available:

```zig
_ = @import("runner/guest_precompile/c011_semantic_equivalence_test.zig");
```

No production module import is required. The scalar oracle and ELF emitter are
reachable only through the test file.
