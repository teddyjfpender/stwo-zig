# RV64 optimization objective and qualification ledger

The active user objective is the six-workstream table in attachment
`f3d2e92e-bb71-443c-9fff-16e0a93ad9c0/pasted-text-1.txt`. Recovery of the
previous agent wave is complete; this objective requires further engineering.
Completion must be established from the current code and actual qualification
receipts, not from projected multipliers or the recovered agents' intent.

## Accepted steering

* Device execution, provisioning and GPU qualification are deferred by the
  user. Harden the frontend, core and CPU route first, while reducing work and
  preparing explicit lifetimes and portable constraint authority for residency.
* Production targets **128-bit whole-protocol security**. Keep the current
  q70/P26/blowup1 profile as a benchmark control, without a whole-protocol
  128-bit claim. Query count alone is not an adequate security certificate.
* Expansion reuse is off the shortlist unless measured composition FFT work
  justifies a bounded implementation. DEEP already combines coefficients before
  transforms; openings already use pruned, half-scratch expansion.
* Production GKR must enter through the services lane, initially covering
  proof-local relations. Preserve global RAM, Keccak IO and secp Wire LogUp
  arguments. Cost recursion and validate global lifted-domain masks first.
* Reuse the existing N-lane scheduler, admission estimates and lane CPU
  telemetry. Truths-first is rejected after complete-block A/B evidence: the default lanes were already balanced and reordering increased physical footprint.

## Required outcomes

| Workstream | Required evidence before completion | Current state |
| --- | --- | --- |
| LS32 | Current-layout implementation; complete register-writer citations including LUI/AUIPC; real invalid-witness physical proofs with balanced CPU/REG/OWNER relations and false RAM ancestry; cross-shard services case; separately closed RAM with invalid local REG; invariant guards; fresh prefix/full-ISA/full-block qualification and measured cost. | Schema7 qualified and integrated: balanced invalid-witness proofs, complete block, all 52 writer citations, 17 CSP cases and 1,032,240-step/all63-opcode Sail agreement. Native cells fall by 588,775,424 (2.814%) from schema6. |
| Production GKR | Recursion cost gate; services integration replacing actual local interaction work; authenticated terminal claims against committed MAIN on the global lifted domain; explicit bounded allocator/pool ownership; transcript/shape/claim rejection tests; fresh execution and recursive receiver qualification; production security budget. An isolated range mini-AIR alone does not satisfy this row. | Experimental OM31 services lane now proves the complete pinned block (25 CPU + five truth proofs), with fresh receivers for both q70 control and beta2/q256 engineering candidate. Local GKR claims are bound to committed MAIN; RAM/KIO/Wire remain classic global debts. Packed, pooled numerical GKR and binding are implemented. Whole-protocol security qualification and accepting current-profile recursion remain open; the lane is explicitly experimental. |
| Repeated expansion | Measure composition FFT versus row evaluation and memory traffic. Preserve native-coefficient DEEP folding. Adopt reuse only if bounded end-to-end measurements establish a benefit; otherwise document rejection and pursue structural work reduction. | Earlier losing designs retained as evidence; new unqualified cache experiment stopped pending the measurement gate. |
| Scheduling/ownership | Controlled current baseline; stage/cell/CPU/fault/memory accounting; lane and admission sweep using existing controls; complete-block truths-first A/B; explicit ownership/lifetime bounds and byte/fresh-verification parity for adopted changes. | Phase-specific memory admission, parallel stage-two lanes, bounded parked MAIN, pooled sampling and classic OM31 interaction generation are qualified with full-block exact artifact parity. Capture prefetch has six matched capture-only measurements (1.63x median), with complete proof parity still pending before promotion. Fixed coefficient interning cuts actual candidate receiver requested peak 11.67 to 6.54 GB and RSS 12.82 to 7.37 GB; this is not a whole-prover footprint claim. |
| Service providers | Measure actual standalone Keccak/secp costs and lifted openings; qualify narrower or lower-degree alternatives on real calls with retained relation metadata and all bridge/truth obligations. Preserve legacy acceptance rules. | Metadata/query separation and trusted Word16-only canonical-input variant integrated; legacy input checks retained. Physical noncanonical ghosts verify locally but closed Wire rejects them. Model saves 61,071,360 native cells on the pinned block; no measured speedup or recursion admission claim. |
| GPU readiness | Current protocol/hasher authority, portable base/secure field separation, independently sized providers, measured allocation lifetimes and honest device admission model. Actual GPU execution and end-to-end device qualification remain a later phase by explicit user request. | Source-derived compact lifetime/placement model and CPU ownership contracts committed. Hash-state planning now uses the actual 96-byte type. OM31 device GKR/DEEP/FRI and authenticated device custody remain unsupported. No GPU speed or residency claim. |

## November 2 delivery checkpoint

The experimental GKR route is now an actual complete-block implementation, not
the earlier isolated prototype described in the historical notes below. The
current measured prefix uses 4,194,303 retirements, one CPU proof, no truth
proofs, and the unchanged q70/P26/fold4 benchmark control. Packed arithmetic,
parallel domain evaluation, pooled sampling, bounded inverse work, compact
Merkle state and pooled public auxiliary construction bring its proving time
from 143.34 seconds in the original scalar implementation to 9.35 seconds in
the latest combined observation. All four durable artifacts match exactly and
a new receiver accepts. The matched classic QM31 control is still faster at
5.25 seconds. Neither profile establishes whole-protocol 128-bit security;
OM31 is a wider arithmetic field, not a security certificate. The two-second
stretch target remains unmet.

Complete q70 GKR blocks pass at 335.77 seconds with parallel classic interaction
generation, or 322.84 seconds with opt-in stage-two interleaving. The latter
increases peak RSS and remains opt-in. All 33 durable artifacts match the older
complete control and fresh receivers accept the expected 43-byte output. A
separate beta2/q256/P0/fold4 engineering run proves all 104,253,913 instructions
in 462.64 seconds and passes an independently reconstructed receiver. These
single observations precede the latest compact-state/public-auxiliary changes;
they are not final-source, quiet repeated speedup claims.

The remaining critical gates are measured net GKR performance against an
appropriate control, complete-block parity for the capture opt-in, final-source
benchmarks, a reviewed composed security construction, and an accepting current
OM31/GKR recursion receiver. GPU qualification remains deferred by the user.
Receipts live under `vectors/reports/rv64-compact-aux-20261102/`,
`rv64-om-ethereum-20261102/`, `rv64-full-candidate-20261102/`, and
`rv64-fixed-coefficient-intern-20261102/`.

## Evidence and controls

The frozen current baseline is source `259f49ff8`, binary SHA-256
`eb681aa741b038f3d821356410b7e6acd5b1182ac079cb0f59ed0b58f0967796`.
It uses the pinned 104,253,913-instruction guest, 25 CPU proofs and five separate
service proofs. CPU proofs already use native2n; service native4n does not lift
the CPU proofs. The native PCS uses prefixed BLAKE2s, not Poseidon2.

Three full runs with the team's other heavy work suspended produced identical
proofs and all 34 checked artifacts, and each fresh receiver accepted the
completed block. Wall times were 148.14 / 156.99 / 159.97 seconds; proving times
126.93 / 135.64 / 138.85 seconds. The observed wall range is approximately7.5%
of the median: this is a repeated reference, not evidence for a small speedup.
System, page-fault and memory counters must accompany later comparisons.

Stage elapsed sums overlap; nested process counters are not additive. Darwin
maximum RSS, private physical footprint, mapped bytes and retained logical
payload are separate quantities. Small native cell counts do not establish
small lifted Merkle leaves or cheap recursive verification.

The objective remains active until its required engineering and qualification
are complete. Device qualification is explicitly deferred, not silently
reported as achieved. Deferred candidates remain visibly unqualified.

## Measurement-led next steps (current schema7)

The security comparison precedes structural adoption: the finite-field budget
applies to existing LogUp as well as GKR. Cost an actual degree8 extension
against a properly analyzed repetition construction across every weak argument.
Two separately generated Fiat–Shamir proofs are not automatically a doubled
computational-security construction. Neither a benchmark nor a policy enum is a
production certificate.

Composition FFT/row helpers now have opt-in timing. The first schema6 prefix
receipt reports 57.76% FFT within these common helper intervals only; intervals
overlap and exclude service kernels and setup. This does not justify reviving
an expansion cache. Add per-job interpolation/extension accounting to the CPU
commit backend and read it beside existing streaming leaf-hash scopes.

Evaluate bounded current-worker MAIN prefetch before interaction generation,
with default zero cap and nonfatal advice failure. Darwin page-in counters do
not identify a particular mapping, so reduction must be established by a matched
run, not inferred from a large fault count alone. Separately test the opt-in
cooperative composition queue on a complete block, retaining exact artifacts
and a fresh receiver. Parallel sampled evaluation must score retained compact
coefficients rather than cleared evaluation buffers.

Production GPU execution remains deferred. Service native4n proofs already have
separate PCS commitments and do not lift native2n CPU proofs. No GPU throughput,
whole-protocol128 security, or accepting production-GKR recursion claim follows
from the currently qualified CPU controls.
