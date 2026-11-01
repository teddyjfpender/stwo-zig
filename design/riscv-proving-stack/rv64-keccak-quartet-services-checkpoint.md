# Keccak quartet services integration checkpoint

Unqualified source work based on423a135cb. Deferred at explicit priority change
to production GKR+128. Existing standalone quartet kernel Safe suite passes
(six-test floor,38s); services Safe/Fast and driver builds initially stop on a
local-name shadow, corrected in this checkpoint without a subsequent build.
No services proof, prefix, complete-block timing or default promotion is claimed.

The source threads the existing BatchPolicy through trusted setup and an
independently supplied word16_keccak_truth_policy config field (default triple).
No producer bundle field selects policy. Quartet mixes its existing policy tag
before roots/challenges; default transcript remains intended unchanged. A concrete
adapter tagged with the existing policy enum reuses the existing quartet AIR,
with dynamic INTER widths/offsets and owned-transfer checks. Legacy shared-K
routes reject the alternative explicitly. Four new services test sources cover
same4n degree5 authority/masks, partition-independent claims, fresh mixed proofs,
legacy parity, resealed policy replay and false-output IO closure.

Read-only geometry: permutation INTER2596→1948, pure truth INTER2604→1956,
MAIN1925 unchanged. Degree5 raw constraints have quotient bound4n−5 and already
use the same log+2/split2 authority as production triple. The earlier two log18
truths would remove339,738,624 native cells and648 OODS samples per proof. Those
are exact layout counts, not measured speedups or whole-protocol128-bit security.
