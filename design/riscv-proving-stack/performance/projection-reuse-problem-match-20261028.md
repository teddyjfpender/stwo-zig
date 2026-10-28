# Exact reuse of already proved relation batches

Task: remove repeated native/companion lookup equations without weakening any
global closure, register window, memory bridge, or physical-claim binding.
The existing joint STARK shares PCS work but still proves both equation sets.

Inputs/model: typed opcode entries, canonical physical batches, independently
derived companion slots, and native physical claims; linear scans over small
per-component schedules. Work is measured in omitted interaction cells and
constraints, then matched proof and verification timings. The retained Ethereum
roster has 67 execution segments and 622 base proof files; fixture timings are
not an Ethereum forecast.

| Candidate | Relationship | Guarantee/fit | Risk |
|---|---|---|---|
| Reuse identical native batches | Exact common-subexpression elimination | Same signed rational function, same main columns and relation challenges | Incorrect alias if selector or physical batch differs |
| Remove all native lookup components | Replacement of a constraint basis | Larger potential; requires complete entry coverage including memory and x0 | Not yet established; do not activate |
| Close one aggregate instead of partitioned buses | Relaxation | Removes partition equations | Loses scoped checks; rejected |

Selected transfer: exact common-subexpression elimination at the authenticated
physical batch boundary. A companion sum may alias only a whole native physical
batch with identical ordered entry ordinals, domain and weighting. A partial
batch, mixed-domain batch, conditional register selector or local-x0 rewrite
does not qualify. Prover and verifier derive aliases independently from the
same pinned typed metadata; every transported alias must equal the native
physical claim. Both original native proof equations and all other companion
equations remain. Physical claims remain mixed before interaction commitment.

The Rust Stwo prover composes supplied component equations into one proof:
[primary implementation](https://github.com/starkware-libs/stwo/blob/dev/crates/stwo/src/prover/mod.rs).
That permits sharing proof machinery; equation elimination additionally needs
the exact identity above (derived here, not asserted by upstream). ZisK's
[memory AIR](https://github.com/0xPolygonHermez/zisk/blob/1e22630bb7e143c30705a1603ed87cfd3da8c6ec/state-machines/mem/pil/mem.pil)
retains independent ordering and continuation obligations. Those are not
redundant lookup projections and are outside this optimization.

No external implementation is copied. Production code belongs in the lab
frontend, not autoresearch. New explicit transcript version; legacy and prior
joint paths remain available as differential oracles. Reuse is restricted to
the joint STARK, where native physical equations are freshly verified.

Prediction/falsifier: each alias removes four base-field interaction columns
and one companion constraint over its component domain. No end-to-end 10x claim.
If few cells are aliased, stop pursuing this as a major speed lever and use the
coverage evidence to design the full single-pass relation basis. Benchmark
diagnostic and canonical parameters separately; random PoW must not masquerade
as a deterministic speedup.

Validation: all exported receipts must match separate and unpruned joint
proofs; mutate an alias independently and mutate cancelling native physical
claims; both must reject. Exercise register modes 0/1, RAM/no RAM and all opcode
families in schedule tests. Preserve exact scoped global accounting. Full
block closure and new recursive keys remain separate qualifications.
