# Active schema5 Keccak admission call-path audit

2026-09-08 source review; semantic gate and real leaf11 proof remain required. Legacy/CSP limit16 is unchanged. Explicit fixed_program_narrow_v1 selects maximum18; canonical log remains derived from actual rows (5509calls ->17; 9828calls ->18).

Producer: full_leaf prepared transaction, replay producer and optional prepared-authority parity use explicit-profile Witness and canonical Statement constructors. Native incremental_ethereum_orchestration_v3 canonical preparation/proof admission/Assembly use the admitted profile. Witness passes its limit to generateShardWithMaximumLogSize; actual Keccak component assembly uses initWithMaximumLogSize.

Serialization/decoding: full_leaf proof artifact encode validates extension under input.profile.circuitProfile. Decode structurally parses extension, then decodeProfile performs full profile/statement/extension validation before allocating claim/proof. Raw ethereum_proof_artifact_wire decoders impose no legacy16 limit. ExtensionClaim.validate checks structural maximum18; independent Statement/Assembly admission enforces selected16/18 and canonical row/log relation.

Transcript: active field transcript emitPreTree0/PostTree1 required two explicit-profile mix calls (Tesla fixed). Field transcript legacy snapshot test-support calls remain legacy intentionally.

Fresh verification/capture: incremental_ethereum_verifier_v3 admits the profile before native Assembly. Newly explicit ContextV1 initVerifiedAuthenticatedLookupV2WithCircuitProfileV1 and validateAgainstAuthenticatedLookupV2AuthorityWithCircuitProfileV1 receive profile.circuitProfile at construction AND retained capture validation. Existing overloads delegate legacy16. VMContextV2 variants receive independently admitted base.profile.circuit_profile. No Context field or identity encoding changed. This closes both late extension.validateV2 calls at the private context constructor and shape validation.

Recursive Tree0/context: deriveExpectedPreprocessedRootInternal and ethereum_preprocessed operate on structurally validated geometry without a hidden16 limit; fixed-program/root owner obtains shape and PCS from the independently admitted profile. Recursive Keccak graph uses component.log_size and exact semantic counts rather than a hardcoded16. No remaining legacy V2 admission call was found on this active route.

Excluded legacy families: candidate-leaf, omitted-provider and old standalone segment orchestration/geometry/artifact APIs still use default16. Active orchestration imports ethereum_segment_geometry only for requireTree1ResidencyWithPolicy, which computes PCS memory from supplied logs and has no Keccak admission. Their old inspection constructors are not called by active full-leaf schema5 production.

New narrow inline regression in ethereum_leaf_context_v1.zig:
`Ethereum leaf context log18 admission remains explicit through retained validation`.
It assembles verifier components with9828calls/log18, checks legacy constructor/retained validator rejection, explicit constructor+retained validation acceptance, and changed-context rejection. It uses synthetic zero component claims and establishes geometry admission only, never proof acceptance. Existing context placement/identity test remains required alongside it.
