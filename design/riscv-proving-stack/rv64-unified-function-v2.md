# Unified FUNCTION13 V2 challenge draft (diagnostic)

This adds a **challenge/root-binding API**, not an accepting V2 execution or RAM
receiver. The qualified binary-only two-shard aggregate continues to select V1.
The diagnostic ALU+BINARY CPU profile must keep its open route fail-closed until
its complete physical aggregate is independently qualified.

V1 retains three independent typed vectors (ALU/BINARY/SHIFT). V2 uses ONE vector
because all truth facts already include a globally disjoint operation ID:
ALU0..9, BINARY16..18 and SHIFT32..37. These are pure functional properties;
RAM/delegation needs separate time/origin/context semantics and is unsupported.

The wire protocol has a distinct metadata tag, `functional13_unified_v2=3`.
Tag2 remains unsupported RAM. This is not a new production CPU hot-path selector.
The canonical receiver-selected policy is the single authority
`word16_cpu.profile.identity(.alu_binary_v2)`. Context validation requires that
policy and the canonical opcode map. The explicit expected-policy argument must
also match it; reading a packet's arbitrary policy back into the call cannot
weaken the check. Program, request and concrete geometry remain separately bound.

APIs in `rv64_distributed_v1/manifest.zig`:

- `deriveUnifiedFunctionV2(expected_policy)` returns one
  `function_bus.Challenges` value, derived from the complete ordered Manifest.
- `resumeWorkerUnifiedFunctionV2(a,ordinal,scheme,channel,expected_policy)`
  re-exports the worker's ACTUAL stage-one PCS roots and matches its retained
  transcript before returning that vector.
- `resumeReceiverUnifiedFunctionV2(ordinal,proof,channel,expected_policy)`
  checks roots observed in the actual proof and reproduces the same transcript
  transition. It still does not verify the physical proof.

The new derivation and stage-two transition have explicit V2 domain tags. V1
methods reject the V2 protocol; V2 methods reject V1. The valid V1 mixes, family
tags, secure draws and transcript order remain unchanged. The complete Manifest
continues to bind full64-bit identities, schemas, roots, geometry, counts/caps,
relation epoch and opcode map. Physical claims must subsequently enter the local
transcript before interaction roots and constraint coefficients; a real receiver
must verify all AIR/FRI and close every physical relation before acceptance.

The precommitted shared tree is schema-defined. It can be the full operand/main
tree, as in the small qualified V1 fixture, or a future *qualified* global-query
projection. Every global tuple coordinate AND its weight/count must exist in
that pre-alpha tree. Later execution trees must consume those exact columns or
prove an actual fresh local join; labels, native journals, claimed equality and
matching root metadata cannot substitute for physical authentication. No global
claim may use unconstrained post-alpha tuple copies.

This API does not solve stage-one residency. It does not implement durable PCS
spill, coefficient reconstruction, large-worker scheduling, aggregate security
union budgeting, or global memory. See `rv64-global-query-precommit-v2.md`.

Diagnostic tests use actual small PCS commitments for CPU-query, ALU and BINARY
roles. They check completeness, common vector agreement, typed version/policy
rejection, opcode-map changes, peer-root changes, wire roundtrip and repeated
stage transition rejection. An intentionally invalid proof shell demonstrates
that the receiver method returns transcript inputs without certifying a proof.
No physical V2 aggregate is claimed by those tests.
