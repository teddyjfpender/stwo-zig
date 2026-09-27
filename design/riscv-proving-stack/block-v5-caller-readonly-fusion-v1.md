# Caller readonly classification fusion v1

This isolated source batch defines B5IC/v1 (`0x42354943`). It changes neither the canonical CPU route nor the base caller arithmetic AIR. Source formatting is checked. The parent's first compiler gate stopped before tests on a shadowed counter capture; the capture is corrected and the source candidate is frozen for another serialized gate. The new fixtures and retained bodies remain unqualified. No compiler or test was run by this agent, and no STARK, segment, guest, device or benchmark job was launched.

The caller fixed/main trees are leased from the real family11 first round. A single access witness tree contains the existing 48 byte/carry columns per RW slot, followed by 71 classification columns per slot: public interval fields5, membership gaps60 and byte alignment bits6. Original addresses, full u64 global clocks, before/after bytes and activity are opened from their authentic source trees. No second event matrix or fixed selector is committed. The classifier contributes16 prefix columns and149 equations per slot to the same interaction/composition/FRI as the existing program, state, six-table/register and access AIRs.

The address alignment equation uses six Boolean bits to prove that the low byte equals four times a bounded six-bit integer. This makes division by four injective on the original bounded u32 byte address, without relying on a host alignment check. Membership gaps remain thirty-bit Boolean integers. Readonly accesses must have both before and after equal the independently derived public input value. SHA activity is the opened fixed selector; Keccak and signer use the opened linear enabler. All classification identities have degree at most3. Existing access constraints, source spans, full-LDE degree recovery and current/+27 Keccak openings remain intact. The domain evaluator recovers only the selected Keccak word32 at each source offset, and takes no inactive field shortcut.

The first-pass `Stage.Prepared.initPhysical` accepts an independently admitted Selection and a real family11 physical prefix. It builds the single access tree and returns a fixed-size `Physical` proposal containing roots, Selection digest, ALL-RW/readonly counts and counter/byte snapshots. No final source files, native instance or provisional Plan is invented. `Prepared.init` admits the final independently pinned actual-source Plan, uses the same kernel and recomputes the physical proposal. The warm stage requires equality before consuming its leased prefix; the original family11 two-tree owner survives for its arithmetic proof. All selected columns, traces, metadata and snapshots are bounded callback-local owners and are released after publication.

`Readonly.Authority.admit` matches Selection and final Plan layout/root/input bytes, ordered subset, caps and independently derived intervals/values. The new family12 identity and family13 access identity bind B5IC ABI, both digests, original caller/execution identities, roots, frame, mode, exact schedules and resource caps. They are not the legacy B5CF/B5EX identities even if physical roots coincide. Both caller arithmetic and composite proof bytes are freshly verified by `Receiver.ForBackend.verifyOwned`; the already-fresh seam is for internal hooks only. Its result is scoped.

The public interval and input-value providers are closed per slot with exact nonnegative u64 multiplicities. Each claim and counter array is independently capped before wire allocation via `Proof.preflightCounts`; the decoder must call this before allocating any of the five claim arrays or their counter arrays. Provider mass equals the original active RW census, and the readonly count equals the selected interval mass. Canonical field encodings, overflow and modulus bounds are checked before rational sums. No scalar receipt is a receiver input.

The output preserves the original **ALL-RW** transition, universal opposite and all14 byte requests per event. It additionally exports independently authenticated mutable/readonly counts and transition sums. Only the mutable transition partition can eventually feed sorted RAM. Neither the universal residual nor byte-demand/provider counts should be reduced. Empty Selection means mutable fallback; all-readonly accesses have zero mutable count/sum but still prove original caller/access/provider obligations. Genuine no-caller/no-RW is a typed sparse absence, not a zero STARK or synthetic caller receipt. A nonempty caller roster always requires real arithmetic and composite proofs.

## APIs

- `Protocol.Authority{selection,plan,input,limits}.admit(a) -> Plan.Owned`.
- `Stage.ForBackend(B).Prepared.initPhysical(a,realPhysicalPrefix,statement,totalSteps,frame,Selection.Pins,input,Limits) -> Prepared`; retain `.physical`, then release all transient owners.
- `Prepared.init(a,realBoundFirstRound,frame,Authority) -> Prepared` and `Stage{sink,frame,authority,expected:Physical}.provePreparedWarm(a,*Prepared,WarmCaller)`.
- `Proof.ForBackend(B).proveForCallerFirstRound(a,*FirstRound,inputs,*Family.FirstRound,frame,witnessRoot,sealed,pins,entries,Authority,metadata) -> Proof`.
- `Receiver.Pin` extends the ordinary independent caller pin with `readonly:Authority`; `verifyOwned` consumes genuine `Family.Proof` plus genuine `B5IC.Proof` and returns `{caller,fused}`.
- `fused.partition` exposes `all_rw_events,mutable_events,readonly_events,mutable_sum,readonly_sum,selection_digest,plan_digest,sealed_digest`. Existing `fused.memory` remains the ALL-RW receipt.

## Qualification scope and remaining canonical integration

The new root is `src/frontends/riscv/block_v5_caller_readonly_unit_test_root.zig`, filter `block-v5 caller readonly`. Seven named nonproving fixtures cover authentic SHA source parsing/high clocks/selected writes, empty-subset writable fallback, stale public authority/subset/caps, all real SHA/Keccak/signer slot masks and OODS equations, independent quotient coefficient evaluation parity for all three kinds, malformed field encodings/counters, all metadata/interaction allocation failures, typed sparse absence and actual producer/fresh receiver/physical/warm body retention. Candidate source cells are not accepted base AIR proofs; body retention generates the real verification code without executing STARK verification.

Before RAM filtering can be activated, one cohesive canonical batch must:

1. Extend the matched recipe/job policy with independently admitted Selection and final actual-source Plan, with a noncircular two-pass binding. Family12/13 must use B5IC entries rather than the old grammar.
2. Replace the caller pipeline collection/warm hooks and staged replay with the physical proposal API, preserving the arithmetic matrix once, ALL-RW byte demand and exact caller/table/register counters. Strict artifact/store/policy codecs must version the format and enforce all five array counts and counter budgets before allocation.
3. Make the native classifier equally authentic; no readonly records may leave RAM until **both native and caller** sources classify their original ALL-RW accesses.
4. Route the one fresh scoped caller result through Program/Table/MemoryJoin exactly once. Keep universal/byte closure ALL-RW, require separate all/mutable/readonly census, and use only mutable transition sum/count for RAM/source first-touch/endpoints.
5. Preserve the complete initial input and full RW root authority. Mutable first-touch/final files may omit classified readonly addresses only after every selected access is proved unchanged; no input-address heuristic is allowed. Final full-state/root and global per-window register obligations remain required.
6. Qualify the complete transport/consumer path and actual fresh STARK equations before choosing B5IC as canonical. The isolated source batch does not establish complete block authority or performance improvements.

The metadata/counter limits bound declared owned matrices, not whole-proof RSS or PCS/FRI scratch. Large source geometries require independently admitted limits; no claim is made that the default512MiB metadata budget admits every production caller profile.

The serialized nonproving command for the parent to run is:

```sh
python3 autoresearch/notes/2026-09-24-ethereum-block-delivery/test_sha_memory_proof.py --root src/frontends/riscv/block_v5_caller_readonly_unit_test_root.zig 'block-v5 caller readonly'
```

This command has not been executed by this agent. Narrow body-only filter: `block-v5 caller readonly actual producer`; physical collection body plus absence filter: `block-v5 caller readonly physical selection`. The source/bus mutation fixture uses raw field corruption after valid construction to test malformed wire values; it does not violate a checked field constructor contract.

Provider counters are dense per-slot arrays in this bounded source slice. Their aggregate cap is checked before allocation and the warm producer may hold one witness array plus one owned proof copy. Very large public subsets/slot rosters may therefore fail the independently admitted counter budget; a sparse authenticated provider wire is a distinct future optimization. There is no silently uncapped large-subset fallback.

Root qualification now passes11/11 focused checks (seven named and four
imports), recorded in `caller-readonly-qualified-v1.json` and
`caller-readonly-unit-v2.log`. All10 candidate source/document pins matched
before this annotation. Actual CPU producer/base-plus-composite receiver,
physical stage and warm ownership bodies compiled without proof invocation.
The original compiler failure is retained in the candidate. Canonical
transport, mutable RAM subtraction and complete proof acceptance remain
unqualified; no segments or devices ran.
