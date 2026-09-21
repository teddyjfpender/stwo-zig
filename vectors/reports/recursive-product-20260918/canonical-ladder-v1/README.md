# Current 1/2/4/8 receipt ladder

Single observations. Production sums child process durations, excluding build/lock waits and hostile verification. RSS is maximum child process RSS. Root verification is measured inside the fresh verifier; request time also includes parsing and admission. These are small execution fixtures, not Ethereum blocks.

| Segments | Backend | Production (s) | Peak RSS (GB) | Root proof (MB) | Root verify (ms) |
|---:|---|---:|---:|---:|---:|
| 1 | cpu | 8.05 | 2.90 | 2.498 | 75.21 |
| 1 | metal | 7.69 | 2.56 | 2.498 | 75.48 |
| 2 | cpu | 28.86 | 3.88 | 2.424 | 65.22 |
| 2 | metal | 21.42 | 4.35 | 2.424 | 66.60 |
| 4 | cpu | 67.49 | 3.90 | 2.295 | 65.83 |
| 4 | metal | 52.52 | 4.39 | 2.295 | 64.95 |
| 8 | cpu | 143.74 | 3.90 | 2.308 | 65.42 |
| 8 | metal | 109.66 | 4.39 | 2.308 | 67.84 |

All trees use independently pinned inputs. New two- and eight-segment parent keys were established by separate setup before their candidate proofs. Eight-segment setup verified six intermediate proofs to derive the final key without creating a root proof. Fresh CPU verification accepts each final serialized root after producer exit. CPU/Metal artifacts match at each size.

The four-segment extraction regression passes 384 cases. New two- and eight-segment qualifications pass 164 and 824 cases respectively, including independent changed-memory statement substitution on every leaf. One-segment evidence is linked from summary.json. The q193 profile remains a development fixture, not a production-security claim.

The historical setup audit scripts record the local orchestration. Their initially generated relative paths were corrected for the macOS /tmp to /private/tmp alias before qualification; retained admissions use normalized paths and verified pins. The maintained entry point is scripts/riscv_segment_v2_detached_tree_gate.py with the retained admission and independently pinned executable paths.

Remaining implementation work: shared preparation ownership, typed GPU interactions, the formal semantic-rebind successor, and broader workload/security admission.
