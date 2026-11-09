# Dense Fq12 through existing sparse calls: bounded result and tradeoff

This is an opt-in client experiment, not a selected guest or a new service.
The decomposition `b=S0+v*S1+v²*S2` is correct for `v³=9+i,w²=v,i²=-1`:
S0 uses (b.c0.c0,b.c1.c0,b.c1.c1), S1 uses (b.c0.c1,0,b.c1.c2),
S2 uses (b.c0.c2,0,0). Multiplication by v and v² rotates both Fq6 halves
with the existing nonresidue. Both x/y scalars are one, so all calls retain
the unchanged 640-byte Miller-line packet, tag and canonical-writer authority.
Native Montgomery fallback remains ordinary Arkworks arithmetic; RV64 canonical
representation is enforced by the existing sparse wrapper's compile-time guard.

## Qualified isolated experiment

A noncyclotomic Fq12 square followed by a multiply, with twelve nonzero canonical
coordinates per operand, has identical native, independent Python schoolbook,
VM and Unicorn outputs. VM/Unicorn also agree on all registers, PC, exact steps
and every service count. Control: **19,344 instructions, 30 Fp2 calls**.
Candidate: **8,988 instructions, six sparse calls** (2.15x isolated retirement
improvement). Service RAM transitions including bulk helpers fall 1,082→876.
No complete heavy execution or proving was run.

Native algebra tests additionally cover all 144 ordered pairs of the twelve
basis positions (including v/v² wraps), zero, one, p−1 coordinates, 64 mixed
values, in-place squaring and equal-valued operands. The fixture is explicitly
nonunitary: no cyclotomic square assumption is introduced. Synthetic DP output
is distinct from OP execution acceptance. A wrong physical sparse output remains
covered by the existing service authority; this diagnostic does not replace
its physical mutation suite.

## Total work is not the retirement count

Source-derived OM31 widths: FP2 is 478 MAIN + 1296 INTER, four FIXED, one row per
call. Miller local-GKR is frontier33+24 over20 rows per call and arithmetic370+56
over32 rows per call. These are physically committed cells, excluding FIXED,
GKR facts, LDE/composition and lifted Merkle hashing.

| Experiment field work | Control | Candidate |
| --- | ---: | ---: |
| Active field committed cells | 30×1774 = 53,220 | 6×14,772 = 88,632 |
| Active CPU packet bridge coordinates | 30×4 = 120 | 6×20 = 120 |
| Packet RAM word events | 480 | 480 |
| Global Wire35 messages | 30×6 = 180 | 6×32 = 192 |

The field-cell cost rises **66.5%**, despite the retirement gain. A classic
Miller truth uses even more interaction cells and must not be conflated with the
local-GKR candidate. CPU bridge geometry/fixed-table pads and CPU retirements
also matter; equal active bridge rows do not guarantee identical committed pads.
Six sparse calls still prove 24 redundant point-scaling relations for x=y=1.

The retained heavy census has 5,439 Fq12 squares and 1,764 Miller-owned seed
products: nominally97,020 Fp2 crossings. Replacing them would add21,609 sparse
calls, raising22,185→43,794, and add691,488 arithmetic micro-op rows. Zero/one
shortcuts may reduce actual removed Fp2 calls, so97,020 is not a measured removal.
At nominal counts, packet bridge coordinates rise388,080→432,180, packet RAM
events rise1,552,320→1,728,720 and Wire messages582,120→691,488.

One explicit padding scenario illustrates why a full source roster is needed:
331,163 Fp2 calls fit log19; nominal residual234,143 fit log18. Their committed
field cells fall930,086,912→465,043,456. At the retained1023-call Miller shard
cap, independent minimum arithmetic log15/frontier log8 gives22→43 Miller leaves
and347,258,880→680,558,592 committed field cells. Combined field cells fall only
1,277,345,792→1,145,602,048 (**10.3%**), before CPU/bridge changes or extra GKR.
This scenario assumes one independently sized FP2 tree; it is not an executed
planner output. Resource-derived sharding can change the result.

Each added Miller leaf has403 MAIN +80 INTER columns, plus the same local GKR
and recursive verifier. FP2 remains in the roster; its smaller height does not
remove its1774-column opening width. Adding21 wrapped Miller leaves can offset
CPU leaf savings. The number of CPU segments saved is unknown without a new
full instruction count. No recursion or total-prover speedup follows from2.15x.
The candidate must stay opt-in until that complete cost is qualified.

## Better next boundary

A dedicated square/multiply tower program could replace the three sparse calls:
reuse bounded canonical field micro-ops and immutable DAG authority, but admit
only the actual twelve-operand square or twenty-four-operand multiply frontier.
That would remove redundant point scaling and reduce packet reads/writes. The
existing sparse schedule is96 micro-ops per product; Arkworks decomposes square
into12 Fp2 products and dense multiply into18. A source-owned signed-product
micro-op can potentially represent these in24/36 modular relations, but current
positive-product DAG restrictions can require additional split rows. These are
design counts, not a proved replacement. Degree≤3, strict no-wrap carries,
canonical writers, complete SSA fanout closure and RAM/Wire authority must all
be requalified. No new tag, ABI or source-suite admission is introduced here.
