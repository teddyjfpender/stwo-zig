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
  telemetry. Truths-first needs a complete-block A/B comparison before adoption.

## Required outcomes

| Workstream | Required evidence before completion | Current state |
| --- | --- | --- |
| LS32 | Current-layout implementation; complete register-writer citations including LUI/AUIPC; real invalid-witness physical proofs with balanced CPU/REG/OWNER relations and false RAM ancestry; cross-shard services case; separately closed RAM with invalid local REG; invariant guards; fresh prefix/full-ISA/full-block qualification and measured cost. | Isolated schema7 implementation and tests in progress. |
| Production GKR | Recursion cost gate; services integration replacing actual local interaction work; authenticated terminal claims against committed MAIN on the global lifted domain; explicit bounded allocator/pool ownership; transcript/shape/claim rejection tests; fresh execution and recursive receiver qualification; production security budget. An isolated range mini-AIR alone does not satisfy this row. | Prototype qualified; production design and recursion/security accounting underway. |
| Repeated expansion | Measure composition FFT versus row evaluation and memory traffic. Preserve native-coefficient DEEP folding. Adopt reuse only if bounded end-to-end measurements establish a benefit; otherwise document rejection and pursue structural work reduction. | Earlier losing designs retained as evidence; new unqualified cache experiment stopped pending the measurement gate. |
| Scheduling/ownership | Controlled current baseline; stage/cell/CPU/fault/memory accounting; lane and admission sweep using existing controls; complete-block truths-first A/B; explicit ownership/lifetime bounds and byte/fresh-verification parity for adopted changes. | Three current full baseline runs complete; further experiments pending. |
| Service providers | Measure actual standalone Keccak/secp costs and lifted openings; qualify narrower or lower-degree alternatives on real calls with retained relation metadata and all bridge/truth obligations. Preserve legacy acceptance rules. | Metadata/query separation qualified; Word16-only secp canonical-input optimization in progress. |
| GPU readiness | Current protocol/hasher authority, portable base/secure field separation, independently sized providers, measured allocation lifetimes and honest device admission model. Actual GPU execution and end-to-end device qualification remain a later phase by explicit user request. | Current design inventory corrected; no GPU speed or residency claim. |

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
