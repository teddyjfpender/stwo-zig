# Session 14: Complete SN2 CUDA lowering admission

Date: 2026-07-25

## Question

Can the CUDA request compiler authenticate every Cairo-specific lowering needed
by the exact adapted SN PIE 2 request without implying that the proof executor
is complete?

## Result

Yes. The exact 162,102,548-byte adapted input now compiles with:

- 58 of 58 authenticated base-writer entries;
- 58 of 58 authenticated interaction instances;
- 279 of 279 authenticated constraint placements;
- 271 unique constraint AOT bodies and eight authenticated reuses;
- zero entries in the missing-lowering list.

The request remains non-executable and non-production. Closing the lowering
inventory removes only `component_aot_lowerings`; the following blockers remain
explicit:

- `proof_derived_semantic_authority`;
- `resident_stage_hooks`;
- `terminal_proof_assembly`.

No SN PIE CUDA proof or proving-speed claim follows from this result.

The prepared request now also owns the exact trace-dispatch and resident-memory
plans. The trace schedule has 58 logical entries and 57 launch owners:
`partial_ec_mul_generic` is a member of the `ec_op_builtin` composite and is
therefore never scheduled twice. This is not a physical kernel count because a
single owner may launch a multi-kernel native stage. Its identity is
`d3ce13f4f2dbeaafe83ae42fa01b110adaa355103119c1f3bc2578e73f19b83e`.

Executable binding found two omissions in the first resident estimate:
forward/inverse transform twiddles and one 96-byte progressive Blake state per
lifted leaf for mixed-height commitment trees. The corrected exact SN2 plan is:

- 107 identity- and lifetime-bound slots;
- 3,717,220,288 coefficient cells;
- 7,434,440,576 LDE cells;
- 67,100,534,068 logical bytes across all lifetimes;
- 58,028,465,180 peak-live bytes;
- 58,028,465,964 allocated resident bytes;
- 878,280 decommitment-assembly words;
- 2,077,800 words of Rust-pinned decommitment capacity;
- 2,102,610 terminal container words, including the 34-word SWPC header.

The corrected plan still fits an 80 GiB H100. It does not fit a 24 GiB RTX
4090, so the 4090 remains the component-parity and stage-development device.

## Trust boundary

The admission receipt now binds a single SHA-256 lowering-closure identity over:

1. the exact 58-entry base catalog identity;
2. the exact 58-entry/57-owner trace schedule identity;
3. the exact generic relation topology/catalog identity;
4. the exact 271-body constraint product identity;
5. the digest of any unresolved lowering entries.

The base catalog incorporates each writer's canonical ordinal, component
instance, geometry and implementation-specific identity. Recorded writers bind
their semantic hash, program identity, generated source identity, cache key,
kernel name and module-global requirement. Fixed, memory and native EC writers
bind their own authenticated plans.

The constraint catalog resolves every generated body against the immutable
product manifest and hashes its semantic hash, cache key, kernel name, program
identity, generated source identity and placement-catalog identity. This makes
the successful lookup closure durable in the request receipt instead of
recording only a zero missing count.

## Fail-closed behavior

`AdmissionReceipt.validate` accepts zero missing lowerings only when the
component-lowering blocker is absent and all other blockers remain. It rejects:

- an empty statement, program, plan, lowering-closure or missing-list digest;
- a blocker mask inconsistent with the missing count;
- any claim that execution or production admission is already true.

The empty missing list still has a domain-separated, nonzero digest.

## Evidence

Exact input:

`/private/tmp/SN_PIE_2.6a9c1c89-1d1d10c3.stwzcpi`

Pinned properties:

- size: `162102548` bytes;
- SHA-256:
  `fe78e1549f66c2c175d075fad5e0c1ea174df29f9331684e654ef9e9c8821704`;
- Stwo Cairo revision:
  `6a9c1c895b821eb5542843e7d9398e02e8f378d0`;
- Stwo revision:
  `1d1d10c31fdac45c9ecb7aee9d3e8935b5cf8035`.

Focused exact-input gate:

```text
Cairo CUDA compiles the complete authenticated SN2 structure ... OK
All 20 tests passed.
```

Receipt-state gate:

```text
Cairo CUDA admission remains fail closed and binds every missing lowering ... OK
All 20 tests passed.
```

Repository guards:

```text
source conformance: 5 explained legacy findings
(5 active_native_backend, 0 deferred_todo), no new violations
git diff --check: clean
```

## Next boundary

The lowering compiler has done its job. The next admissible claim requires an
identity-bound resident session that:

1. materializes the complete mixed-height trace schedule;
2. commits every trace tree without host copyback;
3. binds constraint and relation outputs into composition;
4. executes OODS, quotient, FRI, PoW and decommitment in the same proof-owned
   device transaction;
5. emits canonical proof bytes through one terminal device-to-host read;
6. matches Zig SIMD proof bytes and passes the pinned Rust CPU verifier with
   zero runtime compilation and zero CPU fallback.
