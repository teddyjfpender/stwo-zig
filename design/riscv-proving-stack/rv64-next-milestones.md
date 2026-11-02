# RV64 requested architecture milestones

User priority order from the latest request is authoritative. Qualification
means physical proofs and independently expected receiver acceptance; native
execution, a model, or a small aggregate file alone is insufficient.

| Priority | Delivery and current evidence | Required next acceptance |
| --- | --- | --- |
| 1. Base-field SIMD | CPU loads16 column-contiguous rows, localM31 and secureLogUpQM31 share one lane-generic authority, scalarQM31 OODS retained. Checked scalar/SIMD proof parity, all17CSP artifact parity, and two real4.19M-step retained proofs pass. CPU evaluation4.8–5.0x faster in isolatedpairs; full proving1.27–1.54x. | CPU+Keccak+secp full51-batch isolated run and freshreceiver now pass:1225.28s/36.684GB producer,13.59s/3.462GB receiver. K RAM-bridge and RAM Poseidon SIMD also passed the second complete run:1234.76s/36.592GB, freshreceiver13.66s/3.472GB, all52artifacts identical. No measured whole-job speedup from those additional kernels. All17CSP isolated complete proofs/freshreceivers pass with exactoldartifacts; softwareECDSA9.65/9.93s. Kbridge andRAMPoseidonSafe/Fast pass. Report FFT/interaction/commitment separately. |
| 2. Row representation and family geometry | Byte AND/shift lookups and24-bit BYTE clock ranges already deployed; DIV/MUL independently sized; packedPC and opt-in state-derived canonicality qualified. Current actual52-op Ethereum plan385main/148inter in packed/v3. | Measure full-opcode/ECDSA policies consistently, then independently size ALU, BINARY, SHIFT and load/store families; CPU must be an authenticated bus emitter rather than retain generic operation witnesses. Count duplicated operand bus data, table providers, opening masks, degree and padding. Sharedrange16/word16 needs a new explicit schema. |
| 3. Parallel batches and aggregation |51 native batch proofs plus terminal already freshly verified; one proofperbatch closes77,763 servicecalls. Narrowreceiver keys/cache and reuse of producer expected setup implemented. | VM-independent worker and portable compact advice codec implemented; narrow nativefrontier being qualified. Next durable complete work packets; memory-aware process/machine dispatch; joined coverage/PC/register/root/service/terminal receiver. Specialized recursion remains unimplemented. Existing RV32 recursion is not qualified RV64 authority. |
| 4. Recovery-level provider | Pinned post-servicecensus records156lincomb entries for78recoveryinvocations,44928ADD/DOUBLE calls. Exact semantics and failure obligations documented. | One canonical recovery packet and complete scalar/group/wire/RAM proof; remove guest scalar loop and packet traffic. A recover-or-DEFER ABI may leave failure to original constrained guest fallback; false must never assert invalidity. |
| 5. Keccak interaction width | Currentprovider1923main+2596interaction at29rows/pair; dictionary and bounded prefix/correction qualification pass. Original2204/4164 figures are superseded. | SIMD qualified. Explicit quartet standalone proofs qualified:2596 to1948interaction columns, degree5still4n,12.524%smaller five-call proof. Joined Ethereum driver is not activated. Compare degree5larger batches or different limb/XOR design by total cells/domain/openings/tables/receiver, not columns alone. No native-phase skipping at LDE. |
| 6. Secp-heavy slowdown | Shared serial StageRecorder raced across parallel components. Fixedprivate recorders and stage-only joined adoption pass checked realworker/proof/ownership tests. Cleanbatch5 CPUcosets3.58–3.77s, not14s. | Compare freshprivate batch1/5 afterSIMD. Change secp pool-exclusive flags only if actual contention/memory evidence supports it. |
| 7. Metal | Arithmetic lane separation is implemented; GPU evaluation no longer needs scalarQM31 local instructions. Existing Metal/Cairo kernels remain references. | Concretebase-field kernel route, immutable program structure separate from per-request public/FS uniforms, boundedresident ownership, CPU/GPU everyresidual and exactproof parity, then whole-jobbenchmark. No RV64GPUclaim yet. |
| 8. Clock cap | Proof clocks currently bounded24bit with4ticks/step; local rebasing admits2^22−1stepbatches. | Two separately authenticated limbs in state tuples and everyCPU/K/secp/RAM/boundary relation, two-limb strict-order carry, high-bit and wrap attacks, newprotocolversion. Onefield32bit clock would alias moduloM31. |

A minimum nine-hour iteration period remains recorded in rv64-delivery.md.
Reaching its boundary does not make these acceptance gates complete.

## Competitor transfers under active qualification

The user added Zisk/Airbender global memory, narrow lookup chips, fixedinstances,
minimal advice and precompile/FrequentOps ideas. Source revisions are pinned;
live web snippets may describe older geometry. Trackthree parallel owners:

* GlobalRAM: a two-phase memory-subtree commitment barrier and exactglobal
  init/read/write/teardown coverage, with localregisters/BYTE retained. No
  replacement of authenticatedroots until physical proofs and finalaggregate
  reconstruct the challenge transcript and bind every source commitment.
* Narrow chips: compare16bitlimbs/bytepair tables and degree-two equations with
  the COMPLETElookupclearing system, provider heights, masks, padding and
  characteristic mass. A degree-two local gadget alone does not halve4nCPU.
* Fixedinstances: packchiprequests acrossCPUcontexts, rather than paddingeach
  CPUbatchto the largestcryptoheight. CPUalreadyhas0.117%rowpadding. Current
  CPUaccountsfor91.65%of main+interaction sourcecells, so widthis the main
  volumeopportunity; globalsRAM primarilyunblocksparallelism.

FreshSailqualification covers14,815vectors/all63opcodes; RustindependentPCS
qualification remains the densefive-instruction adapter with11rejections,
not the completeEthereumAIR. CSP17proofs useinline/inverse-v1; Ethereumuses
D3/canonical-v3. Their column counts and architectures must remain distinct.

NativeFrequentOps census identifies13.0millionoperations in256tuples(6.086%
of all instructions). This is an exactboundedretained-set lowerbound and a
familyprovider researchtarget, not CPUrowdeletion or a measuredspeedup.
The recovery/DMA/SHA transfer review is inrv64-precompile-borrows.md.


## Mandatory sequence after the SIMD landing

The qualified baseline is commit `875861f0d`. New protocol designs must not
silently change its acceptance semantics.

1. **Measure memory per invocation.** Record an interval RSS baseline, sampled
   peak, final RSS and sampling failures in batch metrics and stage JSON. Label
   the process lifetime high-water mark separately. A sampled peak is a lower
   bound, includes unrelated process allocations, and is not device residency.
   Target less than 16,000,000,000 bytes on the measured host. Packet decode and
   native capture require their own interval; worker-only telemetry excludes them.
2. **Establish semantic qualification.** For a new representation, compare
   independently expected execution statements, coverage and closed physical
   claims, freshly verify both artifacts, and pin the new fixture. Randomized
   claims from different transcripts need not be numerically equal. A guest
   service lowering also changes program/PC/instruction counts: qualify its
   independently expected input/output contract and constrained ABI instead.
   Continue requiring byte parity for changes preserving the transcript.
3. **Close one Word16 functional chip end to end.** The pure operation payload
   is thirteen coordinates: globally disjoint operation ID, A4, effective-B4,
   C4. The CPU authenticates ROM classification and effective-B selection;
   providers prove functionality and limb bounds. A shared manifest scopes the
   execution and every physical multiplicity must close. Per-operation row IDs
   do not belong in a pure functional tuple; memory-affecting calls retain
   their separate time/address/call context. Use four-limb register relations,
   not an additional Word16 copy beside the old byte state bus.
4. **Narrow the CPU, including ALU/BINARY/SHIFT.** Delete delegated arithmetic
   witnesses and duplicate generic temporaries only after replacement provider
   claims close. Preserve PC/control, local register consistency, authenticated
   operand/result links and ROM authority. Native planning alone cannot prove
   those links. The active packed Ethereum layout already uses byte clock
   ranges: do not count 96 virtual Boolean clock columns as physical savings.
   Compare 16+8-bit lookups with the full table/domain cost, rather than create
   a monolithic 24-bit fixed table. Every carry bound must exclude M31 wrap.
5. **Qualify the aggregate receiver before global RAM activation.** Workers
   independently commit actual stage-one columns and return PCS roots bound to
   job/program/request identities, schema, roles, capacities and geometry. The
   coordinator validates the complete ordered expected inventory, including
   initialization/teardown, and derives shared challenges from that manifest.
   Stage two cannot start early. Workers rederive challenges and check their
   own roots; no free alpha input is authority. The aggregate independently
   matches observed proof commitments, verifies all proofs, closes weighted
   memory/delegation claims, and checks CPU and terminal coverage. Individual
   open fragments never authorize a global checkpoint. This is a distributed
   root exchange, not a central memory-column buffer.
6. **Measure complete instance economics and then dispatch.** Include main,
   interaction and fixed cells; quotient points and degree; opening masks;
   padding; provider tables; setup; receiver and recursion cost; peak resident
   buffers and scheduling. Pair-batched degree-three lookups may retain a 2n
   domain where triple batching needs 4n. Fewer interaction columns alone is
   insufficient evidence. Root-chain out-of-order workers are a separately
   qualified control-plane milestone, not shared-alpha RAM or recursion.
7. **Lower instruction count with constrained services.** Add DMA copying,
   SHA-256 compression and recovery-level scalar/group work with explicit
   ABI, memory coverage and failure semantics. Hints for inverse/GLV split
   remain advice until constrained. Keep software fallback fully proved.
   Preserve a post-service PC census so each removal has measured attribution.

Quartet driver activation and component scheduling require matched whole-batch
measurements. Overlapping a kernel with CPU work can improve its leaf timing
without moving the composition critical path. Keep current native root-chain
verification in production until the new aggregate receiver is qualified.
