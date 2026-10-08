# Problem match: make the measured 32 GB policy usable per request

The verified 5090 trials require choosing an allocation mode and memory
placement based on the *compiled arena geometry*, not a PIE identifier. The
current experiment switches several process-global environment variables;
that is unsuitable for a long-lived prover handling distinct request shapes.
The user-visible objective is the same exact proof with device headroom and
input-to-publication time within 4.5× the saved H200 receipt.

Implement one explicit compact-device profile. A larger arena reserve should
select managed memory before a later constraint allocation exhausts HBM.
Then the proof session should use its authenticated physical arena size to
choose one of two measured placements: a 75% preprocessed-tree spill for the
roughly 30–32 GiB plans, or all three trees plus 50% main-coefficient spill
for the roughly 35 GiB plan. The first tier has three different builtin mixes
with exact Rust-verified proofs; the second has two repeated exact runs on a
5.34M-step PIE. Plans materially larger than the qualified second tier must
be rejected early or use a separately declared slow capacity policy; do not
silently claim the economics target for the 41.19 GiB 6M-step geometry.

Multi-leaf batches ordinarily retain an additional 2.17 GB fixed-coefficient
device image. That default must be disabled under the compact profile: the
medium tier has only about 1–3 GiB of free HBM and the large tier about
1.5 GiB. The checked host asset snapshot remains available across requests;
an explicit request to keep the device image must conflict rather than
silently reducing the capacity margin.

The profile must be opt-in, hardware-capacity checked, use no PIE IDs, never
modify statement/transcript or validation, and reject conflicting manual
placement settings. Re-run at least one case from each tier using the single
profile flag. The H200 comparisons remain historical/source-different, and a
new epoch would be needed for ranked hardware claims.
