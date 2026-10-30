# Degree-bounded native lookup layout

Status: explicit opt-in implementation, focused correctness gate PASS15. The existing V6/V7 defaults and canonical identities remain unchanged. Actual MUL original proofs (with and without accesses), checkpoint restore, fresh verification, independent fixed profiles, recursive OODS equations and cold/live transcript framing pass. A complete recursive execution root and retained real-window performance under the new mode remain unqualified by this gate.

## Problem match and decision

The retained Ethereum native-window diagnostic identified two MUL lookup pairs, original ordinals 9/10 and 11/12 in `range_check_8_11`, with symbolic recurrence degree five. Their eight-row shard forces the joint native composition from split two to split three, despite its small size. These are source-derived geometry observations, not a measured improvement for the proposed layout.

The local encoding research describes degree-safe batching in `stwo-proximity-autoresearch-challenge/research/encodings/NOTES.md` under “Continued ALU search: degree-safe lookup batches”: pair affine requests while leaving quadratic requests separate and bind the mapping into protocol identity. Here the useful transfer is the inverse transformation: retain every existing canonical pair except those exceeding degree four. Split only those pairs into ordered singleton claims. This adds two QM31 interaction planes (eight M31 columns, 64 raw cells for eight rows) to the observed MUL shard while permitting a degree-four lookup roster. Halving the joint composition domain is a hypothesis until the actual admitted component maximum and complete proof are checked.

The cheapest falsifier is exact symbolic degree and complete entry coverage, followed by arbitrary-point rational algebra. A genuine proof with an independently derived new key is required before selecting the mode. More aggressive reordering or fusion is deferred: it adds transcript and coverage changes without being needed to remove this degree cliff.

## Authority and equations

`block_v7_degree_bounded_relation_layout_v1.zig` first constructs the existing V7 canonical layout, which independently constructs and validates the complete V6 roster before applying V7's explicit actual-event RAM policy. It therefore cannot introduce a new omission set.

For each paired request, the original arithmetic DAG derives numerator degrees `n0,n1` and denominator degrees `d0,d1`. The numerator degree retains the original register/RAM space or one-minus-space weight. Recurrence degree is `max(1+d0+d1, n0+d1, n1+d0)`. A singleton has absent numerator zero and absent denominator one. Only a pair exceeding four is split; any resulting singleton still exceeding four is rejected. Clock, range, program, x0 and all other canonical entries remain in their original order and preserve their exact metadata.

The independent coverage helper rebuilds this deterministic layout and compares every slot, including the inner opcode ordinals, partition, geometry, degree and custody weight. The new digest includes the old canonical digest, version, explicit mode, degree ceiling and every emitted physical slot. Original aggregate sums are not accepted as substitutes for the new physical claims.

For two terms, the algebra gate checks `D = D0*D1` and `N = N0*D1 + N1*D0` at extension-field points. Rational equality is asserted only when denominators are nonzero; degenerate challenges must retain the original rejection behavior. It does not claim that rational cancellation is defined at zero denominators.

## Qualification boundary

The focused root is `block_v7_degree_bounded_relation_layout_test_root.zig`. It covers all opcode families with ordinary and local-x0 symbolic layouts, exact MUL geometry, missing/duplicated/mutated slot rejection, zero witnesses and degenerate challenges. A transcript grammar gate changes each physical sum while compensating another and checks that the transcript changes. This is evidence about framing, not a new original-proof verifier.

Before runtime activation, a finite V7 profile must select the mode independently; producer and verifier must derive the same layout and new identity; codecs, recursive symbolic equations, fixed schedules and key derivation must use the new physical roster; and genuine original/recursive gates must reject changed physical claims. The existing composition-split-three completeness path remains the control. No query count, PoW, masking or global-closure requirement is reduced.

## Finite integration

The implementation adds `Pin.layout_mode`, defaulting to `canonical_v1`, and a shared `Pin.layout()` dispatcher returning the existing owned slots/digest shape. The second mode is `degree_bounded_q2_v1`. Selection must come from independent admitted metadata and be retained by deep clones, wire reconstruction and receiver policy; a received claim length is never a selector.

All production layout construction sites now use that same selector: native entry identity and exported partition sums, native proof admission, native component assembly, native/caller union generation and recursive fixed-profile derivation. Complete, multi-window and shared-Keccak codec geometry also derives from the pin. Existing checkpoint production stays canonical by default; the proof transport still takes independently admitted source metadata rather than trusting a received mode. The canonical branch preserves its exact current digest and transcript bytes. The opt-in digest already includes a separate domain/version and the complete canonical parent digest, so the changed roster enters the epoch before challenges. The original source transcript continues absorbing every new physical sum before the interaction commitment.

Qualification must cover actual MUL with and without an access witness, an independently constructed original verifier and exact global closure. Original and changed layouts represent the same semantic statement but different proof transcripts, so their proof bytes are not expected to match. Scalar/domain/OODS parity and reconstructed public partition sums must match each layout's own equations. A compensated pair of singleton claim mutations must fail fresh verification, not only a host-provided checksum. Recursive fixed/live parity and fresh root verification remain a separate final gate.


## Recorded focused result

`vectors/reports/block-v7-degree-bounded-native-20261030/receipt.json` records the ReleaseSafe combined gate, immutable binary hash, scoped source hashes and raw logs. All 15 selected tests pass. The q3 control and q2 variant retain identical execution statements and first fixed/main/access roots; the changed epoch identity and physical interaction roster deliberately produce a different proof transcript. The q2 branch is collected into actual checkpoint files, the original producer is destroyed, then those commitments are restored for proving. Mismatched record/expected layout modes reject before restoration. Fresh verification uses decoded proof storage and independently owned statement metadata.

The same combined gate also qualifies sparse initialization against the independently resealed untouched-output-cell attack: both the honest and forged cases regenerate valid original memory STARKs under their own selected policies. The forged case fails exactly `UnclosedV7WindowState` after cryptographic verification. This is an open memory theorem check; complete execution/provider closure remains the final receiver's responsibility.

The focused inventory contract passes. The broader inventory still reports historical omissions: 907 before this scoped registration, 903 afterward, with no newly omitted files. Four existing controls are now explicitly attached to their product roots; unrelated omissions were not suppressed.
