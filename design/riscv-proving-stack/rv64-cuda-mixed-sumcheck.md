# Resident mixed-height OM31 sumcheck

This is the mixed-oracle sumcheck inside one native GKR layer. It follows
`sumcheck_field.proveBatch` and `gkr_circuit_field` exactly; it is not an alternative
lookup protocol, a complete GKR child, or an Ethereum proof path.

The existing PR311 command proves one oracle. A native GKR layer instead mixes
several oracles with different variable counts. A short oracle contributes a
constant half-claim until the common remaining variable count reaches its own.
It then starts folding with the common transcript challenges and its own Eq
correction. Independent single-oracle transcripts cannot replace that behavior.

Let `S` be the current mixed claim, with fixed weights `alpha^i` in original oracle
order. An oracle with `k` variables initially contributes its claim times
`2^(max_variables-k)`. For the currently inactive oracles let `beta` be the sum
of their weighted current claims divided by two. Active interpolation receives
claim `S-2*beta`; its raw evaluations are the weighted sums of active evaluations,
including each oracle's own accumulated Eq correction. The emitted round
polynomial is this corrected active polynomial plus the constant `beta`.

The corrector is linear in the claim and both raw evaluations. All active
oracles use the same current `y` coordinate and global zero-prefix product.
Therefore correcting their weighted sum once equals the native weighted sum of
individually corrected polynomials. Adding the inactive constant afterwards is
necessary: inactive constants do not obey the active interpolation's prescribed
root. This gives the same polynomial and `q(0)+q(1)=S`, including zero or unit
mixing weights and cancellation to an empty polynomial.

After drawing the single shared challenge, inactive cached claims halve. Each
active oracle updates its own Eq correction and folds its matrices; newly active
oracles start with correction one. The common prefix advances over every round.
Only the mixed active claim is needed because the parent GKR prover consumes
terminal masks, not the sumcheck helper's individual claimed-evaluation array.
The native fixture checker nevertheless checks every terminal mask against the
native gate evaluator and the correct Eq suffix before accepting its reference.

The device state freezes every oracle's initial height. A later descriptor may
not silently alter it. All pointer/range/alias checks happen before enqueue;
the typed whole-batch wrapper also checks every workspace before its first
mutation. Device field, pole, schedule and height failures are sticky. Subsequent
records are cleared and tagged invalid. Enqueue success does not establish proof
success: the owner joins, checks the terminal header and independently verifies
proof fields before publication. All owners remain borrowed through that join.

No intermediate polynomial, claim or challenge is copied to the host. The host
schedules public geometry; device buffers carry every numerical dependency.
There are at most 64 oracles, 27 sumcheck variables, and one bounded launch-metadata
packet per round. The profile is native raw-Blake/mod-M31 over OM31; no QM31
substitution, extra transcript draw or altered field reduction is introduced.

Qualification uses the actual native prover, a fresh native sumcheck verifier,
and the actual native gate/Eq checks. The GPU output must match every coefficient,
trimmed length, challenge, terminal mask, final mixed claim and channel checkpoint.
The receipt is `vectors/reports/rv64-cuda-om31-mixed-sumcheck-20261102/`.

Remaining integration is explicit: device parent-layer begin/close, fraction-tree
traversal and point carry; source-authenticated fraction projection; joined AIR
and truth composition; and the remaining resident PCS/proof assembly. Native
Ethereum acceptance, composed security-profile qualification and full-block GPU
performance are not established by this sumcheck checkpoint.
