# Bounded sampled-value scheduling

Pre-change diagnostic: the existing experimental switch reduced CPU Keccak/128
sampled evaluation from about 1.12 seconds to 0.178464 seconds, with identical
proof bytes. Its three-sample complete transaction median was 4.737507 seconds.
This alone was not a default qualification: the old experiment overlapped tree
workers with unreserved inner weight/dot workers.

The shared host PCS now selects sequential tree waves when a sampled evaluation-
form column has log size at least 18. Within each tree, weight construction and
column dot products share an explicit proof-pool lease; each wave drains before
the next submission. Small or coefficient-backed-only proofs keep tree-level
scheduling. No case name, hash suite or frontend selects this policy.

Weight construction may borrow a caller lease or acquire its own. Worker counts
respect that lease. Unavailable reservations fall back to serial evaluation.
Callbacks cannot outlive output/workspace ownership, including point-on-domain
errors. Scratch allocation shapes are unchanged. No additional thread pool,
coefficient-cache increase or proof parameter change is introduced.

The focused ReleaseSafe sampled suite passed 22/22 tests, including literal
reference parity, exact executed-work receipts, a borrowed two-worker budget,
a fully reserved pool forcing serial fallback, and drained borrowed leases after
failure. Both original and enhanced test runs are retained.

`measure.py` compares retained preceding binaries with this candidate, three
samples per arm, canonical 70 queries / 26 PoW bits, 16 workers, no explicit
warmup. The experimental scheduling flag is cleared for both arms. Artifacts
must match the qualified suite's proof hashes and pass fresh verification.
Both ReleaseFast product builds passed, including the preceding work-counter correction. All 48 measured proofs verified in process; all 16 retained arm artifacts independently verified and match the preceding qualified suite hashes.

## CPU qualification

ReleaseFast build passed. All 24 measured CPU proofs verified in process; all
8 retained arm artifacts independently verified and retain the prior proof bytes.

| Case | Control E2E s | Candidate E2E s | Control sampled s | Candidate sampled s |
| --- | ---: | ---: | ---: | ---: |
| ECDSA precompile | 1.175027 | 1.173042 | 0.017277 | 0.017266 |
| SHA-256/128 | 2.881582 | 2.919877 | 0.055810 | 0.059350 |
| SHA-256/2048 | 6.121019 | 5.283915 | 1.124552 | 0.183522 |
| Keccak/128 | 5.974515 | 5.105069 | 1.120314 | 0.185721 |

Small-case median differences are not established changes by three fixed-order
samples. The large cases show roughly 6x improvement in sampled evaluation;
end-to-end gains are smaller because other phases are unchanged.

Current CPU Keccak median phase observations: witness 1.112450 s, admission
0.441850 s, proving 3.004686 s, fresh verification 0.514768 s. Proving includes
fixed commitment 0.212082 s, main commitment 0.538924 s, hash interactions
0.565593 s, interaction closure/commitment 0.567183 s and core STARK 1.123046 s.
Stage medians need not add exactly to a whole-sample median. The remaining gap
to original CSP performance is not explained by sampled evaluation anymore.

## Metal qualification

| Case | Control E2E s | Candidate E2E s | Control sampled s | Candidate sampled s |
| --- | ---: | ---: | ---: | ---: |
| ecdsa_secp256k1-32 | 1.964997 | 1.949444 | 0.298241 | 0.286304 |
| sha256-128 | 3.068465 | 3.123020 | 0.057439 | 0.055396 |
| sha256-2048 | 6.316128 | 5.476615 | 1.128038 | 0.188560 |
| keccak-128 | 5.968896 | 5.111196 | 1.130416 | 0.193150 |

This optimizes host sampled-value fallback inside the mixed Metal product; it is
not a claim of a new GPU kernel. Candidate products and the matching Metal bundle
are retained with executable hashes in each result record. Memory allocation
shapes for each plan are unchanged, and large tree waves no longer overlap their
workspaces. No new full CSP suite or recursion-parent performance qualification
is claimed. Original CSP performance and the broader recursion goal remain open.
