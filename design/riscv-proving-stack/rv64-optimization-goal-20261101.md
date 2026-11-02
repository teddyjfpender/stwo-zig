# RV64 optimization objective and qualification ledger

The November 2 00:59 UTC priority is a four-hour review of the proposed global
GKR payoff and allegedly missing packed-prover wiring, followed by streamed GKR.
The source audit is recorded in `rv64-current-relation-ownership-audit.md` and
`rv64-global-gkr-architecture-audit.md`: REG/OWNER are already local GKR; known
packed routes are live. Direct separate global GKR saves about 0.664% of current
MAIN+INTER cells after binding, rather than the proposed large multiplier.

The broader workstreams remain tracked from the six-workstream attachment
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
| Repeated expansion | Measure composition FFT versus row evaluation and memory traffic. Preserve native-coefficient DEEP folding. Adopt reuse only if bounded end-to-end measurements establish a benefit; otherwise document rejection and pursue structural work reduction. | Retained expansion caches were rejected on measurements. Compact-coefficient DEEP is preserved; coefficient-sized pruned opening windows now qualify on beta2 (1.891 → 0.722 s median decommit, exact artifacts and six fresh receivers). No retained LDE cache is introduced. |
| Scheduling/ownership | Controlled current baseline; stage/cell/CPU/fault/memory accounting; lane and admission sweep using existing controls; complete-block truths-first A/B; explicit ownership/lifetime bounds and byte/fresh-verification parity for adopted changes. | Phase-specific memory admission, parallel stage-two lanes, bounded parked MAIN, pooled sampling and classic OM31 interaction generation are qualified with full-block exact artifact parity. Capture prefetch has six matched capture-only measurements (1.63x median) and complete-block exact artifact/fresh-receiver parity. Owning CLI source retirement releases all 7.026 GB captured native payload and 2.409 GB ordinary RAM advice; completed worker owners retire after detached results. Fixed coefficient interning cuts actual candidate receiver requested peak 11.67 to 6.54 GB and RSS 12.82 to 7.37 GB; this is not a whole-prover footprint claim. |
| Service providers | Measure actual standalone Keccak/secp costs and lifted openings; qualify narrower or lower-degree alternatives on real calls with retained relation metadata and all bridge/truth obligations. Preserve legacy acceptance rules. | Metadata/query separation and trusted Word16-only canonical-input variant integrated; legacy input checks retained. Physical noncanonical ghosts verify locally but closed Wire rejects them. Model saves 61,071,360 native cells on the pinned block; no measured speedup or recursion admission claim. |
| GPU readiness | Current protocol/hasher authority, portable base/secure field separation, independently sized providers, measured allocation lifetimes and honest device admission model. Actual GPU execution and end-to-end device qualification remain a later phase by explicit user request. | Source-derived compact lifetime/placement model and CPU ownership contracts committed. Hash-state planning now uses the actual 96-byte type. OM31 device GKR/DEEP/FRI and authenticated device custody remain unsupported. No GPU speed or residency claim. |

## November 2 delivery checkpoint

The authenticated OM31 services lane proves the complete pinned block with 25
CPU and five truth proofs, and independent receivers accept the expected 43-byte
output. The current source-pinned q70/P26/fold4 observation is 242.44 s proving,
262.68 s wall and 42.49 GB peak RSS, with capture2, 2×8 lanes, 1 GiB recycler and
explicit tight dense admission. All 33 durable artifacts match the prior 312.38 s
complete observation. Several kernels, ownership and operational settings changed;
this is a combined result, not an isolated GKR-algorithm speedup.

A matched same-binary full-block control with the original 136 B/fact admission
costs 250.84 s proving versus 242.44 s with 104 B/fact. Stage one falls 111.27 → 103.45 s;
stage two stays about 139 s. The smaller reserve enables some CPU shards to overlap,
but adjacent heavy shards still serialize under 36 GiB payload admission. Source
bounds remain separate from process RSS and original capture/setup ownership.
The default remains conservative; all lower-memory modes are explicit opt-ins.

The current real 4.19M-retirement prefix proves in 8.44 s median after packed/pooled
numerical work and active AIR accumulation changes. The same-field classic OM31
control costs 7.95 s source+proving versus 8.46 s GKR in ABBA observations. GKR removes
39.7% of native MAIN+INTER cells, but numerical and terminal-binding work offset
the native saving. **No net CPU GKR win is demonstrated.** Historical QM31 classic
5.25 s is a different-field control. The two-second stretch target remains unmet.

The stride-two lazy checkpoint path has exact proof/fresh-receiver parity. In a
matched two-shard parallel triplet, whole-process RSS falls 30.73 → 20.35 GB (1.51×),
while proving changes 16.23 → 16.71 s. That is one shared-host prefix triplet, not a
whole-block memory claim. A further immutable raw-source replay experiment is
being qualified separately before a lower resource bound or default is adopted.

The beta2/q256/P0/fold4 engineering profile has already completed the same block
in 462.64 s on an earlier source, with independent fresh acceptance. Final combined
source qualification and its current memory/performance tradeoffs are in progress.
Both profiles deliberately report security_qualified=false. Whole-protocol 128-bit
composition/security review and an accepting current OM31/GKR recursive root
remain open. GPU execution remains deferred by the user; CPU ownership, portable
constraint authority and resident memory preparation continue.

Receipts: `rv64-om-ethereum-20261102/fullblock-tight-dense-owned-v1/`,
`rv64-om-classic-control-20261102/`, `rv64-coefficient-window-20261102/`,
`rv64-gkr-tree-checkpoints-20261102/prefix2-triplet-receipt.json`, and
`rv64-full-candidate-20261102/`, under `vectors/reports/`.

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
