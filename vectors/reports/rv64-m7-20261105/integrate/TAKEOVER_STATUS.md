# M7 takeover status

M7 is **in progress**, not delivered. No full M7 proof format is promoted.
The PR branch remains at the handoff while tested work is accumulated on
`codex/rv64-m7-integrate`. Production performance observations below are
from a loaded shared two-RTX-5090 pod; they are not quiet-run best records.

| Work | Verified evidence | Remaining gate |
|---|---|---|
| CUDA oracle capacity | [M] build, 65/128-instance numerical fixtures, all six M6 artifact sets identical, fresh receivers accept both blocks | production native GKR format |
| Compact native ingress | [M] CPU metadata 56 to 17.5 B/row, GPU/CPU reconstruction parity and memcheck, production proof parity and fresh receivers | headline native time remains about 4.45 s; owner idle and other ingress remain |
| Capture program views | [M] warm program construction roughly 76-89 ms to 0.49-0.55 ms; RSS 34.159 to 33.327 GiB in that isolated A/B; proof parity and fresh receivers | whole-request/capture target not established |
| Device enqueue | [M] proof parity and fresh receivers; about 128 to 104-105 blocking calls/node; launches still roughly 1.7k/node | ten calls, 500 launches, GPU graphs/transcript, actual two-proof capacity |
| Leaf tape/cache | [M] v3 check and both production arms pass every M6 fingerprint and fresh receivers; warm headline median 19.326 -> 17.809 s on matched binary, shared-pod loads differ; combined RSS 23.962 GiB | opt-in; 22 GiB capacity gate running; host prep still median 611.6 ms; V1/V2 negative results retained |
| Outer GKR | [M] anchored Eq/cyclic prefix differential and forgery tests, source mass gate, lazy projected GPU callbacks and memcheck | hybrid AIR/PCS/controller/child verifier/production corpus |
| Fold v3 and compression | [M] circuit/native state/CPU/truth/chain hash agreement; typed summary combine constraints and forgery mutants | full leaf admission, production fold/membership/root binding, pure-STARK C1/C2 and fresh compressed receiver |

The M6 same-session warm control is [M] 13.44/13.52 s for 26235156 and
18.82/18.93 s for 24628607. The M7 target remains <=8 s request and <=120 KB
final proof. V3 has provisional shared-pod request improvements; no isolated
speedup or proof-size improvement is claimed. The classic M6 default proofs
remain the comparison target.

Two recursion lanes with corrected pending admission still failed the
headline memory gate at the 22 GiB arena. Independent owner sessions plus
a wide-stage mutex also failed on the small block because both proofs
retain traces outside the mutex. These failures are preserved. Hybrid
interaction-width reduction or further lifetime/streaming work is required.

Only the two development blocks are being used. There has been no basket
loop or final scale-up. Receipts and append-only progress ledgers accompany
each performance commit; source snapshots distinguish independently tested
streams from an as-yet-unqualified combined binary.
