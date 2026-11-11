# Complete 87-line G2 preparation source

This isolated source program links all 64 homogeneous doubles and 23 additions of one exact BN254 preparation. It uses one global typed SSA namespace, including both final Frobenius correction additions. It is a conditional canonical-input arithmetic fixture foundation, not a pairing, curve/subgroup/infinity, VM or production admission.

The program is independent of Q. Its ATE order, signs, operation classes, every read/writer ID, fanout and line interpretation are immutable source data. It has 2,065 values: 13 initial values, 10 prefix writes, 1,536 double writes, and 506 add writes. Every dependency precedes its unique writer. Positive and negative local SSA mass are exactly 8,130, and the maximum source-owned writer fanout is 256. The exports are 522 canonical line preimages and six final homogeneous coordinates. No state is passed between 87 separately wrapped proofs: the source describes independently sized tables in one composite proof.

The only variable initial input is canonical Q (four Fq values). The other nine initial fields are source literals: one/zero, half, twist B and the two Frobenius twist pairs. Ten explicit canonical quadratic/linear relations derive −Qy, psi(Q)x/y, psi²(Q)x and −psi²(Q)y. These Q-dependent values are private canonical writers, not free native corrections or setup constants. Their coefficient envelope fits the existing 498-column double row. The point/line normalization is unchanged: double exports canonical (h,j,i) with factors (−1,3,1); add exports (lambda,theta,j) with factors (1,−1,1).

The source witness owns heap-backed rows and constructs them in true transition order. Its double table has 1,546 active rows (ten prefix plus64×24), while the add table has 506 (23×22). Both generators G2 and2G2 match all87 line outputs via independently pinned SHA256 digests from the existing complete-pairing Python oracle, as well as exact final homogeneous coordinates. All2,052 scalar rows pass the original bounded carry and canonical-writer checks. Prefix result/quotient/carry mutations reject, and result+p passes exact carries/ranges but fails canonicality.

The qualified mixed-height geometry is:

| Role | Active rows | Log | MAIN | Local binding INTER |
|---|---:|---:|---:|---:|
| Double and prefix | 1,546 | 11 | 498 | 32 |
| Add | 506 | 9 | 626 | 32 |
| Initial/export frontier | 541 | 10 | 33 | 16 |
| Shared BYTE table | 256 | 8 | 1 | 16 |

The physical qualification below confirms 1,476,864 padded MAIN+INTER cells. Six GKR source instances contain 1,352,960 padded facts: separate BYTE double/add/table and SSA double/add/frontier. Their52-byte/fact checkpoint model is70,353,920 bytes, not a whole-worker memory bound. BYTE query mass is724,356. This planning charge is separate from measured liveness and does not replace whole-worker admission. Physical binding, masks, geometry and adversarial evidence follow below.

A conditional public fixture may pin Q-specific bytes in FIXED to qualify arithmetic; such a key is input-specific and must never be called a reusable production chip VK. Production must keep variable canonical Q in MAIN and bind it to the authenticated CPU/service Wire source. Source constants alone are immutable setup data. Complete pairing endpoints, subgroup/curve/infinity checks, memory authority, security accounting and recursive acceptance remain open.

The guarded source regression is:

```sh
zig build test-riscv64-op-g2-preparation-source -Doptimize=ReleaseSafe -j1
```

Its minimum test count is 14. It does not run or admit a whole preparation proof.

## Physical mixed-height source qualification

The complete preparation now proves in **one native composite proof plus one six-instance GKR child**. The ReleaseSafe fresh-source gate passes at the planned logs 11/9/10/8 and widths: double 44/498/32, add 36/626/32, initial/export 35/33/16 and BYTE 1/1/16 (FIXED/MAIN/INTER). There are 1,476,864 padded MAIN+INTER cells, 144,640 FIXED cells and 1,370 opening columns. All complete constraints, including source-weighted SSA numerators and mixed-height terminal masks, pass degree-three qualification.

The final source-pinned artifact is 149,848 native +36,340 child bytes (186,188 total). Its measured peak requested allocator footprint is 59,541,610 bytes under an unchanged 2 GiB cap; this is requested heap accounting, not RSS, and excludes readonly program/stack. No wall-time speedup is claimed.

The source argument is challenged only after MAIN is sealed. BYTE and SSA close separately. Fresh reception independently rebuilds the exact ordered initial/export frontier, polynomial/ID/fanout ROM and FIXED root. Fifteen physical controls reject, including changed source IDs/initial bytes, wrong writer fanout, wrong cross-state read ID, changed line IDs, reordered complete line records, and a coherently dropped export plus decreased writer fanout. Reordering demonstrates why unordered SSA closure alone is insufficient: the independent expected source order must remain authenticated.

A negative-Q prefix result+p is propagated through every later double/add and both correction tails. Its BYTE and SSA child still verifies and all exported modular outputs are unchanged; nevertheless its canonical writer fails physical OODS. The captured unverified native proof is independently rejected as `OodsNotMatching`. Both honest and forged artifacts are retained with hashes in `g2-preparation-physical-v1.json`.

This closes the arithmetic/dataflow foundation for one preparation. It does not close subgroup/curve/infinity policy, the complete pairing residue endpoint, authenticated CPU/service input/output memory, recursion or production 128-target security. The Q-specific FIXED fixture key is intentionally input-specific and not a reusable chip VK; production must put variable Q in canonical MAIN and bind it to the real Wire/owner authority. No new VM tag/default/profile is admitted.
