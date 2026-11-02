# Current relation ownership and committed work

The pinned block 24,628,607 retires **104,253,913 guest instructions** and uses **7,372,614 gas**. This audit uses the accepted 25-CPU, five-truth OM31/GKR bundle and the current source layout. It uses no newer guest or private branch. The historical [work comparison](../../vectors/reports/rv64-ethereum-20261101/committed-work-comparison-v1.json) supplies only the pinned steps/gas; its older QM31 cell totals are not reused.

## Relations already moved

| Relation | Current owner and closure |
|---|---|
| REG6 | Proof-local GKR: six CPU terms and the shard's register-boundary provider |
| OWNER19 | Proof-local GKR: CPU requests balanced against LS and service bridges |
| FUNCTION13 | Proof-local GKR: CPU dispatch and ALU/BINARY/SHIFT/JALR/MUL/DIV providers |
| ROM, ranges, AND, SHIFT, selection | Proof-local GKR, including negative multiplicities from their providers |
| RAM14 | Classic OM LogUp across shards: LS, public boundaries and service RAM bridges |
| KIO11 | Classic OM LogUp between CPU Keccak bridges and permutation truths |
| Wire35 | Classic OM LogUp between CPU secp bridges and both product/linear truth roles |

The concrete local catalog and both sides of each relation are in [fractions.zig](../../src/integrations/riscv_cpu/word16_global_execution/services/gkr_local/fractions.zig) and [roster.zig](../../src/integrations/riscv_cpu/word16_global_execution/services/gkr_local/roster.zig). Registers are not part of the cross-shard RAM argument. Their public shard snapshots are chained independently by `word16_global_execution/protocol.zig::validateMaterials`, including all initial/final registers and execution coverage. Global queries and pure claim slots are declared separately in [global_cpu.zig](../../src/integrations/riscv_cpu/word16_global_execution/services/gkr_local/global_cpu.zig).

## Actual native committed cells

A cell here is one base M31 coordinate, so an OM31 value occupies eight cells. Counts exclude composition, FRI and GKR working planes. The ROM log20 is confirmed by the existing native-domain profile, not merely an upper estimate.

| Proof family | MAIN | INTER | MAIN + INTER | Cells / guest retirement |
|---|---:|---:|---:|---:|
| 25 CPU shards and their providers | 9,029,950,720 | 3,971,281,408 | 13,001,232,128 | 124.707 |
| Five service truths | 1,200,669,440 | 3,259,756,544 | 4,460,425,984 | 42.784 |
| Complete execution | 10,230,620,160 | 7,231,037,952 | 17,461,658,112 | 167.492 |

INTER is not synonymous with remaining classic lookup work:

| INTER purpose | M31 cells | Share of INTER |
|---|---:|---:|
| CPU proof-local GKR Eq/prefix authentication | 3,271,442,944 | 45.24% |
| Truth-local classic lookups | 3,127,439,360 | 43.25% |
| Cross-shard classic RAM/KIO/Wire | 832,155,648 | 11.51% |

The first row is the existing 16-column authenticated terminal binding, not unconverted REG/OWNER inverses. The second row is primarily the wide Keccak local lookup argument; it is distinct from KIO. These are the large remaining INTER shares.

The [global GKR audit](rv64-global-gkr-architecture-audit.md), commits `1e1ec30bc` and `7272b3c0b`, costs the separate authenticated global-child alternative. Even deleting every global classic column without replacement would remove only **4.77%** of current MAIN+INTER. Keeping the required 16-column binding per namespace/role saves **115,871,744 cells, or 0.664%**. LS, INIT/TEARDOWN and Keccak bridge pairs already cost 16 columns per namespace: replacing them with another 16-column Eq/prefix binding gives no committed-cell reduction. Numerical GKR and binding work must also be paid. This is not evidence for a large global-GKR multiplier.

A global conversion would require independently authenticated terminals, pure namespace closure, all pole guards and a new challenge schedule. The existing manifest binds already-verified local receipts before drawing shared global challenges; moving those same global terms into that earlier local child would create a dependency cycle. See the linked protocol audit rather than assuming the existing local binding can be reused for free.

## Normalization and storage

| Scope | Native cells / retirement | Native nominal 31-bit payload / gas |
|---|---:|---:|
| CPU proofs only | 124.707 | 54,666.93 bits |
| Truth proofs only | 42.784 | 18,754.98 bits |
| Full MAIN+INTER | 167.492 | 73,421.91 bits |
| Full MAIN+INTER plus per-proof FIXED references | 181.156 | 79,411.97 bits |

The FIXED reference count is 1,424,594,496 cells. It is a comparison convention, not a claim that immutable setup is reconstructed or committed every time.

M31's nominal 31-bit payload convention differs from actual 32-bit word storage. Full native MAIN+INTER represents **75,790.36 stored bits/gas**. At the same geometry, beta1 (`log_blowup=1`) has twice the represented MAIN+INTER LDE cells and beta2 has four times: **146,843.82** and **293,687.64 nominal payload bits/gas**, respectively. Composition-domain geometry, FRI layers, Merkle nodes, scratch and free allocator cache are separate costs; these numbers do not model their total residency.

Thus 158→100 cells/retirement or 20k bits/gas cannot be accepted as current full-execution measurements without matching guest, component coverage, field coordinates and native/LDE definitions. Roughly 20k is near the present *truth-only* native rate; that does not identify the source of any colleague's estimate. Cell counts are neither a proving-time estimate nor a whole-protocol 128-bit certificate.

The [machine-readable receipt](../../vectors/reports/rv64-current-relation-ownership-20261102/accounting.json) pins the source authorities, accepted bundle and diagnostic output. Its independent namespace arithmetic equals the diagnostic's global outputs; the three INTER categories sum exactly to the current physical count. Streamed-bottom GKR changes working ownership and admission, not these committed cells.
