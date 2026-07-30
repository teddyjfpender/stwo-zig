# Session 08: Cairo Source Authority Scale-Out

Date: 2026-07-25
Product state: disabled
Performance claim: none

## Objective

Replace the one-component `add_opcode_small` demonstration with the largest
proof-independent Cairo semantic tranche that can be derived mechanically from
the pinned Rust sources. PIEs may measure runtime coverage, but may not select
or supply semantic programs.

## Source Pair

The Cairo source remains:

- repository: `https://github.com/teddyjfpender/stwo-cairo.git`
- revision: `6a9c1c895b821eb5542843e7d9398e02e8f378d0`
- tree: `17fbbfc61fc51e0697c4e1f3cd39885784a027f2`

The checkout declares Stwo revision `1dad88f1c3a714ac26c8ad57812429ac58541909`,
but its tracked Cargo patch overrides that declaration with a local Stwo
workspace. The Cairo branch uses APIs absent from `1dad88f`; therefore the old
manifest's `1dad88f` authority was not a compilable source pair.

The diagnostic compatible pair and dependency binding are now explicit and
separately authenticated:

- declared Stwo revision:
  `1dad88f1c3a714ac26c8ad57812429ac58541909`
- resolved Stwo revision:
  `1d1d10c31fdac45c9ecb7aee9d3e8935b5cf8035`
- resolved Stwo tree:
  `55cbec6c408dfc4e81c722deca9f5526d3785536`
- binding kind: `clean_local_path_patch`

The generator resolves and checks the patched workspace rather than trusting
the overridden `rev` text. A declared/resolved mismatch requires an explicit
`--expected-oracle-stwo-revision`; dirty or differently pinned Stwo sources fail
closed. The manifest and authority digest authenticate the repository, both
revisions, the effective tree, and the binding kind as distinct fields. The
coverage checker re-derives each field from the checkout; the old ambiguous
single `stwo_revision` schema is rejected.

This pair is diagnostic until a clean full stwo-cairo build and component
differential suite are retained. It is not a release or performance authority.

## Mechanically Admitted Catalog

The pinned `witness_genericize --census` scans 67 source components:

| class | count |
| --- | ---: |
| contains `write_trace_simd` | 64 |
| immediately rewritable | 37 |
| source-checked generic program | 35 |
| needs trait extension | 2 |
| skipped | 28 |

Two immediately rewritable files do not yet contain an on-disk generic block:

- `pedersen_builtin_narrow_windows`
- `range_check96_builtin`

They are excluded because fresh generation has not passed an independently
compiled Rust differential. Neither occurs in the four canonical SN PIEs.

The committed catalog contains the other 35 files byte-for-byte from the clean
Cairo checkout. Before packaging, one bulk `witness_genericize --check` must
accept every file. Geometry comes from the source census. Relation destinations
and the closed producer/capacity graph are derived from checked
`SUB_FEED_LAYOUT` facts, including:

- opcode producers into `verify_instruction`;
- Blake compression into round and XOR, then round into G;
- Pedersen builtin, aggregator, and window-18 chains;
- Poseidon builtin, aggregator, round-chain, cube, and range-check chains.

The derived edges match the existing hand-maintained Zig topology. Nonuniform
or noncontiguous feeds abort generation.

The registry is a source catalog, not a proof-selected exact list. Admission
accepts an active plan only when every active component is registered and every
active producer edge matches the catalog after inactive producers are filtered.
Unknown components, missing active edges, writer drift, path escape, artifact
mutation, and registry mutation fail closed.

`partial_ec_mul_generic` is recorded as a backend-neutral AOT writer. The old
`native_metal` plan tag was Metal policy leaking into frontend authority and had
no execution consumer.

## Four-PIE Effect

The sealed runtime evidence still has a 57-component union. The source catalog
covers 33 active components, reducing missing semantic packs from 56 to 24.
The full canonical blocker list is:

- `blake_round_sigma`
- `ec_op_builtin`
- `memory_address_to_id`
- `memory_id_to_big`
- `pedersen_points_table_window_bits_18`
- `poseidon_round_keys`
- `range_check_11`
- `range_check_12`
- `range_check_18`
- `range_check_20`
- `range_check_3_3_3_3_3`
- `range_check_3_6_6_3`
- `range_check_4_3`
- `range_check_4_4`
- `range_check_4_4_4_4`
- `range_check_6`
- `range_check_7_2_5`
- `range_check_8`
- `range_check_9_9`
- `verify_bitwise_xor_12`
- `verify_bitwise_xor_4`
- `verify_bitwise_xor_7`
- `verify_bitwise_xor_8`
- `verify_bitwise_xor_9`

Three have no `write_trace_simd` source writer:

- `memory_address_to_id`
- `memory_id_to_big`
- `verify_bitwise_xor_12`

Most of the remaining fixed lookup writers use the unsupported two-tuple
`(row, lookup_data)` skeleton. `ec_op_builtin` additionally requires FeltW27
effects and partial-EC deduction support. These are generator/tooling tasks, not
permission to reuse proof-derived programs.

## Decoder Boundary

The four-PIE coverage record was regenerated from the original sealed ZIP,
adapted-input, and normalized shape evidence while preserving the captured
decoder identity. It remains inadmissible:

- captured decoder Stwo: `c7e69453bb176344f13f7d6bdd63c1f3267e566f`
- semantic source-pair Stwo: `1d1d10c31fdac45c9ecb7aee9d3e8935b5cf8035`
- captured Cairo decoder checkout had dirty `Cargo.toml` and `Cargo.lock`
- 24 active source semantic programs remain absent

The binary hashes still match their pinned capture. A new decoder capture must
come from a clean, build-bound source pair; substituting clean source metadata
for an old binary is forbidden.

## Gates Run

- 35-file Rust `witness_genericize --check`
- deterministic second generation with identical manifest/registry identities
- 20 focused Python generator and coverage tests
- canonical four-PIE checked-record validation
- full Zig test closure: 415 transitive sources
- active-subset and missing-edge adversarial Zig admission tests

## Next Source Tasks

1. Build the complete clean Cairo/Stwo diagnostic pair and retain its binary,
   source, lockfile, and toolchain binding.
2. Add a differential for the two freshly rewritable builtin programs, then
   admit them to the source catalog.
3. Add a fixed-table two-tuple skeleton to `witness_genericize`; onboard the
   range checks, round constants, and XOR tables as one oracle-gated tranche.
4. Add native source writers for memory address/id, memory big-value, and
   XOR-12 aggregation.
5. Extend the evaluator for FeltW27 and the EC deduction surfaces before
   admitting `ec_op_builtin`.
6. Re-capture all four shapes with clean pair-bound binaries.
7. Keep the Cairo CUDA product disabled until all 57 active components, AIR
   composition, transcript barriers, and the final Rust verifier pass.
