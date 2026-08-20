# 2026-08-14 — native V2 segment proof custody

## Outcome

The native CPU prover and verifier now have a version-separated V2 transaction
for authenticated resumable RISC-V segments. The focused evidence executes two
real, adjacent runner segments from one declared program:

- the first segment is non-final and carries a continuation;
- the second resumes that continuation and is final;
- both statements use the same authenticated program/job/session authority;
- both proofs independently verify under the V2 transcript; and
- the non-final verification publishes a recursive capture only after native
  AIR, PCS, Merkle, and FRI verification succeeds.

The V1 entrypoints and transcript remain separate. Selecting V2 is a
compile-time call-site decision, so the ordinary recursion-off RISC-V benchmark
path does not acquire a runtime branch or V2 statement construction.

## Verifier-owned handoff

`VerifiedSegmentV2CaptureForEngine` transactionally publishes:

```text
accepted proof capture
+ verifier-derived VM AIR context
+ owned authenticated PublicDataV2 wire
+ sealed native public LogUp sums
+ versioned verified-statement receipt
```

The owned wire is copied only after verification and is re-authenticated before
use. The capture does not retain caller-owned statement storage. Its VM AIR
context carries the exact active component/infra descriptors, detailed claims,
relation draws, and authenticated profile needed by recursive row 18.

`capture.validate()` checks all mutable sidecars before recursive witness
construction. In particular, it independently recomputes the V2 statement
authority from the authenticated wire and verifier-captured geometry. The
receipt identity is deliberately only defensive mutation custody; it is not
treated as adversarial authentication. The recursive outer proof must also
execute this authority computation and close its Poseidon requests against the
shared typed provider.

Publication is failure-atomic. A bad statement version consumes the submitted
proof but leaves the caller's capture destination byte-for-byte unchanged.
Wire-digest, native-public-sum, and receipt-identity mutations are rejected at
their owning validation layers.

## Public boundary

V2 does not reuse the V1 memory-boundary compensation. The native statement
retains the exact entry/exit continuation Merkle trees while the V2 public
LogUp boundary accounts for retained nonzero continuation leaves and canonical
empty roots. This prevents the same entry/exit memory tuples from being
counted once through V1 and again through the V2 segment wire.

## Focused evidence

Both commands passed after the capture API was frozen:

```text
zig build test-riscv-segment-v2-native-proof \
  --build-file src/integrations/riscv_cpu/build.zig \
  -Doptimize=Debug

zig build test-riscv-segment-v2-native-proof \
  --build-file src/integrations/riscv_cpu/build.zig \
  -Doptimize=ReleaseFast
```

The gate has an exact one-test identity guard, uses lane-local Zig caches, and
front-loads proof-independent ingress mutations before either expensive prove
call. These runs are correctness evidence, not a performance promotion or an
ETHProof CSP benchmark result.

## 2026-08-15 recursive leaf closure

The production recursive leaf now includes all of the previously open surfaces
in one independently verified outer proof:

1. exact V2 scheduled-transcript parity for rows 0--9;
2. V2 statement/public authority for rows 10--17;
3. the verifier-captured VM composition at row 18;
4. the existing PCS/DEEP/FRI/Merkle authority for rows 19--34;
5. in-circuit recomputation of V2 authority hashes through the shared row-34
   Poseidon provider; and
6. exact 36-row, 47-domain global relation closure before publication.

The append-only proof cohort has 39 components: the frozen 36-row universal
roster, two authenticated V2 boundary sources, and one committed
verifier-input provider. Exact tuple classification reports 102,099
contributions, zero unmatched tuples, and zero red domains. The independent
verifier accepts a 91,722-byte canonical proof. The one-worker ReleaseFast
development observation was 1.155 s proving and 0.831 s verification; it is
correctness and iteration evidence, not an ETHProof CSP performance receipt.

The post-fix evidence used the focused provider gate, the opt-in composition
differential, and the lean real-proof runner:

```text
zig build test-recursion-segment-publication-provider-v2 \
  --build-file src/frontends/riscv/build.zig \
  -Doptimize=ReleaseFast -j1

STWO_RECURSION_DIAGNOSE_COMPOSITION=1 \
  zig build run-recursive-segment-v2-concrete-outer-proof \
  --build-file src/integrations/riscv_cpu/build.zig \
  -Doptimize=ReleaseFast -j1

zig build run-recursive-segment-v2-concrete-outer-proof \
  --build-file src/integrations/riscv_cpu/build.zig \
  -Doptimize=ReleaseFast -j1
```

The opt-in composition differential initially reported 38 matching components
and one mismatch at row 38, `segment_publication_input_provider_v2`. Setting
the diagnostic folding challenge to zero isolated constraint 7, the component's
sole framework LogUp recurrence. The provider witness wrote main and
preprocessed values in logical row order, while the framework had already
written interaction values in circle-domain commitment order; copying all
three trees paired the right multisets in the wrong rows. Direct boolean roots
survived that permutation, which is why only LogUp failed. The installation
boundary now scatters Tree 0 and Tree 1 exactly once through `committedRow` and
copies Tree 2 unchanged. A focused regression pins a non-identity scatter and
byte-identical interaction installation. The complete differential is now
green 39/39, and the real proof independently verifies all 47 domains.

## 2026-08-15 temporal replay and V3 composition handoff

The successful verifier transaction now also mints a pointer-free recursive
witness schema that retains the exact source-specific preimage needed after
child ingestion: non-core/core authority identities, the core layout and call
buffer identities, the exact core call count, and the relation-dependent
public-wire boundary. Its independent prefix identity is sealed into the
recursive witness and publication chain. Version, padding, zero identities,
count bounds, field canonicity, every retained field, and the prefix identity
have focused rejection coverage.

Two independent downstream consumers have crossed the real 39-row proof gate:

1. `TemporalChildTranscriptReplayV2` reconstructs the complete SegmentV2
   transcript from Tree 0/1 through all 94 relation draws, 39 interaction
   claims, the public-wire boundary, Tree 2/composition, PCS/FRI/PoW, and all
   queries. It reaches the verifier-published transcript identity without a
   caller checkpoint, claim, or challenge. Prefix and terminal-state mutations
   reject.
2. `SegmentV2RecorderBridgeV3` joins the exact 39+2 claim profile to a sealed
   Segment V3 descriptor, rebuilds the sampled-value layout from the verifier
   capture, retains all 41 claims and 47 relations, and exposes a concrete
   witness plus allocation-free 39-row symbolic-recorder handoff. It performs
   full artifact preflight and binds the schema-2 prefix by its already
   validated identity rather than duplicating that hash.

The combined concrete gate independently proved and verified the same
91,722-byte artifact before both handoffs accepted it. A dedicated normal
development gate keeps transcript/non-FRI iteration to a few seconds:

```text
zig build test-recursive-temporal-nonfri-v2 \
  --build-file src/integrations/riscv_cpu/build.zig \
  -Doptimize=ReleaseFast -j1

zig build test-recursive-binary-segment-v2-composition-profile \
  --build-file src/integrations/riscv_cpu/build.zig \
  -Doptimize=ReleaseFast -j1
```

This establishes exact transcript replay for rows 0--9 and the Segment lane of
the V3 composition recorder. It does not yet make rows 0--9 available under the
temporal parent typed AIR, nor does it provide the binary/empty lanes and one
shared heterogeneous graph authority.

## Remaining temporal-parent boundary

The verifier-minted leaf publication satisfies `temporalChildReady()`, but
`completeParentReady()` is deliberately false. No proof yet consumes two
ordered adjacent SegmentV2 leaves and verifies their temporal two-to-one
parent. Accordingly `temporal_parent_verified = false`,
`whole_frontend_verified = false`, and `proof_system_soundness = false`.
