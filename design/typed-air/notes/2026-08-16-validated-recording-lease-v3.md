# 2026-08-16 — one-pass validated recording lease for temporal row 18

## Finding

`Row18AuthorityV3.init` consumes one immutable
`RecordedHeterogeneousCircuitV3`, but the current public API makes it replay
the complete recorder authority audit around every derived view:

| Operation in one successful row-18 construction | Full recording audits |
| --- | ---: |
| explicit `recording.validate` | 1 |
| `configurationSnapshot` | 1 |
| `validatedAuthority` | 1 |
| two `evaluateSegmentInto` calls | 2 |
| `validatedView` | 1 |
| two `validatedLane` calls | 2 |
| **Total** | **8** |

This is cold-path work, not a proving-protocol cost.  It nevertheless directly
inflates focused recursion gates and iteration time because the validation
walk includes configuration, graph, binding, sample-layout, and authority
checks over the same immutable recording.

## Proposed capability

Add an opaque, borrow-only `ValidatedRecordingLeaseV3`.  Mint it with exactly
one complete audit:

```zig
pub fn validatedLease(
    self: *const RecordedHeterogeneousCircuitV3,
    manifests: TrustedManifestsV3,
    air_program_ids: AirProgramIdsV3,
) !*const ValidatedRecordingLeaseV3;
```

The lease aliases the opaque immutable recording storage; it allocates
nothing, owns nothing, and cannot outlive that storage.  Only the audited
constructor returns the capability.  Its methods expose the operations needed
by row 18 without accepting a second configuration or authority candidate:

```zig
pub const ValidatedRecordingLeaseV3 = opaque {
    pub fn configuration(self: *const @This()) ConfigurationV3;
    pub fn graph(self: *const @This()) CircuitGraph;
    pub fn authorityIdentity(self: *const @This()) [32]u8;
    pub fn lane(
        self: *const @This(),
        verifier_id: u32,
        circuit_id: u32,
        statement_scope: u32,
    ) RecursionLane;
    pub fn evaluateSegmentInto(
        self: *const @This(),
        segment_layout: *const CaptureLayoutV3,
        witness: WitnessV3,
        padded_sample_scratch: []QM31,
        input_scratch: []QM31,
        node_scratch: []QM31,
    ) !void;
};
```

`evaluateSegmentInto` must still validate the child-owned inputs on every
call.  It should:

1. run `segment_layout.validateSelfConsistency()`;
2. compare proof kind and layout identity with the recording-owned
   `SampleInputAuthorityV3`;
3. validate the sample authority itself;
4. bounds-check and zero-pad sampled values;
5. validate/write the concrete witness inputs; and
6. evaluate the immutable graph.

It skips only the already completed global recording/configuration/graph
authority audit.  This distinction is important: the lease amortizes stable
authority, not attacker-controlled child evidence.

## Row-18 migration

`Row18AuthorityV3.init` should mint one lease, then derive configuration,
authority identity, graph, both evaluations, and both lanes through it.  The
owned row-18 authority should retain the original recording plus the identities
it already snapshots; it need not retain the lease.  `validateAgainst` should
mint a fresh one-pass lease before replaying the two external child chains.

The row writer remains unchanged.  Construction still produces one row-18
authority and one authenticated clone, and no hot writer may trigger a global
recording audit.

## Required evidence before adoption

- A test-only counter must prove one and only one full recording audit per
  successful `init` and per explicit `validateAgainst`.
- Mutating a child publication, capture, witness, capture layout, or sampled
  value after lease minting must be rejected before graph output or bundle
  publication.
- Mutating or splicing trusted manifests and AIR program IDs must prevent
  lease minting.
- Existing graph outputs, lane identities, row-18 authority identity, and
  protocol digests must remain byte-identical.
- Debug and ReleaseFast receipts should compare the historical eight-audit
  schedule against the one-audit lease.  Wall time is diagnostic; the exact
  audit count is the regression authority.

This proposal changes no transcript, AIR, manifest, proof wire, or protocol
identity.  It is an authority-caching and DevEx optimization at the native
construction boundary.
