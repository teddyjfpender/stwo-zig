# Whole-request memory census: frozen M6 negative and accepted D2 geometry

**Status: read-only source/log audit. No GPU job, no new proof, no measured saving, no <=28 GB process qualification.** Reproducer `derive.py` asserts the allocation arithmetic and emits `derived.json`. Raw excerpts include line numbers and SHA256 of each original stderr. Audit source base is `aa19b47f6`; the historical selected image is a25cc3b23ae21994e01cf0e332f1f79b666c402197bc5ed84920bf7575226e45 and driver 9cf6589f1b479f4c6b1049cc98860c55bfbb2fa680e4716ffd976748f782a2f6 from the Root 9531c5c16 freeze. Later source is not claimed to have been compiled into those assets.

## What failed, exactly

The negative is **M6 native/default 17-leaf** `daemon-24628607-r2-combined-m6-v2`, not the accepted D2/coalesced 14-leaf run. Runtime ordinal 7 is first **Keccak TRUTH** after seven CPUs. Role ID 0 is local to a function family, not globally CPU role 0. Shape: FIXED32 + MAIN1923 + INTER1152+408 =3515 source columns; one auxiliary makes3516, evaluation log20. Neighbor roles chi log23 and xor5 log18 confirm the source family. Exact RC payload:

| allocation part | bytes |
|---|---:|
| 3516 dense columns ×2^20×4 |14,747,172,864|
| auxiliary staging 2^18×4 |1,048,576|
| twiddle 2^19×4 |2,097,152|
| six descriptor words/column |84,384|
| **one arena payload** |**14,750,402,976**|

Legacy staging would add3,685,744,640 B; direct source columns already avoid it. It cannot be counted as a new improvement.

Warm stderr lines1643–1654 first fail with10,296,200,704 B arena live. Immutable trim releases359,763,648 logical B and lowers physical live by682,335,232 B (20 large chunks plus11,246,592 small bytes). Logical payload sums and physical arena occupancy differ.

After trim, the exact failure snapshot is:

| quantity | bytes |
|---|---:|
| arena cap (22 GiB) |23,622,320,128|
| small slab (included in cap) |536,870,912|
| live large (286 chunks) |9,596,567,552|
| live small |17,297,920|
| **total live** |**9,613,865,472**|
| available large (402 chunks) |13,488,881,664|
| available small |519,572,992|
| requested RC rounded (440 chunks) |14,763,950,080|
| **large shortfall (38 chunks)** |**1,275,068,416**|

This reconciles the selected allocation failure exactly, before allowing additional RC buckets/metadata. No sampled NVML inference is involved. Both idle and active upper PCS cache bytes are zero at this snapshot, so another idle-cache eviction cannot close this particular failure.

## Which retention is live or avoidable

`ResidentOwner` contains exactly three persistent allocation populations: upper blocks, scoped leases, cached domain planes. At this failure its upper blocks contribute zero; retained9,373,928,128 minus leases9,138,817,728 equals **235,110,400 B cached domains**. `pcs_native.cu::domain` keys these by(log,seed), generates them on device and retains them until owner destruction. `trimUnused` explicitly leaves domains intact. They are not needed while Keccak RC runs; a joined phase-boundary domain eviction API could regenerate them at the next PCS call. No such API is implemented here. The inventory of individual(log,seed) keys is unlogged, so a guessed decomposition of this number would be unsound.

The remaining scoped leases **cannot be assigned exactly to owners from this receipt**. Logs record kind totals at some trace peaks, not a generation/range/scope inventory at the failure. Nsight contains no matching allocation inventory. Therefore this report does not label all9.14 GB as unused native retention.

Source-derived lifetime bounds explain major populations without pretending they were simultaneously live at the failure:

- CPU replay defaults to four retained segments per physical device. Headline7CPUs distribute4/3, keeping all MAIN plus stage-one P8 projections across the shared manifest. Census payloads MAIN+P8 sum4,979,797,376 /3,913,915,392 B by GPU, before other owners. At phase2, P8 is replaced by binding coefficients; do not add both to one steady-state bound. The existing replay-all flag changes retention/time tradeoffs and requires an independently planned choice before launch.
- Each CPU's old global evaluation witness remains until `CpuWorker.complete` exits even after TC has copied it into an independent INTER coefficient lease. Source proof and opt-in default-OFF candidate are separately committed as **ce88816fc**. Eligible published payloads total1,026,137,088 B over all seven CPUs, split657,912,832 /368,224,256 B. These are not simultaneous or measured savings; independent allocation rounding and request timing matter.
- Old native binding coefficient ownership is also distinct from the adopted INTER coefficient copy. Retiring that owner would require a separate proof of all binding/GKR readers. This census does not alter it.
- First Keccak truth has source payload MAIN2,025,062,400 B, INTER1,774,190,592 B, FIXED94,109,696 B across three own-height components. MAIN/INTER are authenticated coefficient inputs to current RC/PCS and cannot be freed without replay/recompute. FIXED may be host-reconstructible/immutable depending on the selected source adapter; its census mass alone does not establish a mandatory resident device lower bound. Compact Keccak ingress is another3,883,600 B for19,418 calls; its owner persists until truth completion.
- Native v1 GKR uses projected fractions plus metadata and `max(decoded MAIN/FIXED+twiddle, traversal workspace)` once the joined projection retires decoded inputs. One observed ordinal0 workspace is7,973,247,488 B for124,093,760 facts and total requested payload12,440,724,428 B. This is a per-proof envelope; it excludes other retained owners. The recomputed-frontier variant remains N-dependent, not a bounded chunk-streaming implementation.
- Outer recursion retains its source MAIN/INTER and fixed coefficients through its RC/PCS consumers. Whole-role workspace max reuse reduces temporary overlap but does not license releasing source generations early. GKR Eq/source/frontier liveness has separate owners. A total-cells scalar is not an allocation plan.

## Accepted D2 is a separate schedule

`daemon-24628607-r2-combined-d2-coalesce-v1` uses the same a25/9cf image assets with automatic arena27,313,307,648 B. It has the same Keccak role0 arena payload, but different TC/PCS geometry and overlap/retention timing. A selected trace INTER commit logs1,774,190,592 B coefficient payload plus9,567,251,968 B scratch,19,065,362,624 B managed live lease and19,690,741,760 B arena live. These are stage snapshots, not whole-process peaks or the M6 failure's live set.

D2 composition logs `separate_coefficients=true log_blowup=2`: retained coefficient268,435,456 B, commit scratch1,090,519,168 B for Keccak. The audited pure `composition_cost.zig` rejects separate coefficients with beta2, and `pcs_allocation_cost.zig` models rolling only when header5==1 although the selected runtime can use rolling beta2. Thus current model adapters do not yet cover this accepted profile merely by setting `known=true`. Trace commit's separate-coefficients predicate is independently beta1-only and should not be confused with composition's selected branch.

## Exact process <=28 GB remains open

Both selected runs initialize with total33,679,736,832 B and free32,480,886,784 B. Raising the CUDA stack1024→12544 leaves29,473,570,816 B free: **3,007,315,968 B whole-device delta**. Total device use before arena is4,206,166,016 B. Adding a22GiB arena gives27,828,486,144 B, only171,513,856 B below28,000,000,000 B **as whole-device arithmetic**, not a process-owned upper bound. Later module/graph/context allocation growth is not covered. Auto arena alone plus that pre-arena use is31,519,473,664 B. Arena capacity does not certify the process gate.

The selected image's12544-byte maximum is genuinely used by native secp witness. Existing selected-kernel census shows lower post-native usage but does not establish arbitrary-geometry coverage, reclaim behavior, or a safe phase-limit policy. Stack lowering remains unactivated. Two logical lanes remain held.

## Minimal complete admission contract

The existing physical planner API already separates per-allocation rounded small/large occupancy and successor envelopes; the missing work is coverage and actual lifetime ownership, not a second per-proof cap:

1. Before launch, freeze source-profile geometry for native capture/replay, each TC/INTER/RC/PCS/GKR stage and recursion node. Record each actual allocation size, kind, generation/scope and release event; independently round every allocation. Include mixed-height padding, metadata, twiddles, output coefficients and source retained across the successor stage.
2. Observe physical occupancy across **all** resident sessions; charge retained MAIN/FIXED, active/idle immutable/cache/domain owners once, and retire a token only after its joined physical free. Host capture/plan/retirement costs require an audited bound, not arbitrary slack.
3. Admit with live retained plus new retained plus max(current temporary, whole successor envelope), separately for small/large. A source that fits alone but strands its consumer must fail before source launch. Busy decisions release locks/cache leases; unknown formats/costs or uncovered owner classes refuse.
4. Wire native and recursion producers into the same ledger. Current outer controller makes `requires_native_complete=true` and `memory_admission_enabled=false`; an environment flag cannot make this path globally admitted. Pure cost plans currently have `host_cost_known=false`; no production coverage claim is justified.
5. Cover fixed stack/module/driver allocation outside the arena with a proven selected-kernel/profile policy and an exact process peak gate on both dev blocks. Static22GiB+4GiB external arithmetic is27,917,287,424 B with only82,712,576 B model margin; it is not measured proof that actual external use stays under4GiB.

Sparse signed-constraint RC may remove the dominant dense14.75GB allocation. Its parent allocation union, power order, constraint sign/coverage and padded FFT bounds need independent review. The reported4.295GB payload/~130ms FFT figure is a model, not a tested request improvement. Pairing it with explicit early retirement is promising but no <=28GB result is established here.
