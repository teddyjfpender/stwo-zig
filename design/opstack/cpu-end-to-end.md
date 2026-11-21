# CPU proof latency for OP Mainnet and Mantle

The November 21 cohort measures native production, recursive production and
fresh root verification on an Apple M5 Max with 18 cores and 64 GiB. It used
16 native workers in one lane and a 1,048,575-step shard limit. Each row is one
observation. Archive commit d1934ae1ecd35a6952069d267acce696e8c460c5
provides the qualified D2 native and M7 recursive benchmark route. The proof
profile targets 128-bit security under documented assumptions. The maintained
OP product currently exposes native proving.

| Chain and block | RV64 steps | Native s | Recursion s | Root verification s | Total s |
|---|---:|---:|---:|---:|---:|
| OP 120,794,432 | 796,520 | 7.21 | 50.83 | 4.08 | 62.11 |
| OP 121,049,889 | 5,501,937 | 31.85 | 186.59 | 17.17 | 235.61 |
| OP 121,057,303 | 5,928,533 | 36.12 | 237.56 | 19.24 | 292.92 |
| OP 121,003,241 | 15,681,272 | 97.94 | Disk guard | — | — |
| OP 121,135,704 | 20,087,994 | 129.99 | Time cap | — | — |
| Mantle 103,132,217 | 3,237,854 | 15.82 | 83.60 | 6.49 | 105.91 |
| Mantle 103,132,921 | 3,264,567 | 17.02 | 136.57 | 10.63 | 164.22 |
| Mantle 103,133,561 | 3,279,437 | 17.01 | 138.56 | 6.23 | 161.81 |
| Mantle 103,133,753 | 10,253,419 | 47.84 | 200.12 | 17.27 | 265.22 |
| Mantle 103,133,433 | 11,534,260 | 60.57 | Time cap | — | — |

All ten native proofs and seven recursive roots passed fresh verification.
The two time-capped recursive producers ran for five minutes. The disk
guard retained a 10 GiB floor. The receipts, per-stage and guest data, and
shareable report remain in the operator evidence bundle
`opstack-cpu-benchmark.zip`, outside the source tree.

Recursion accounted for a median 81.1% of accepted wall time. Leaf wraps
and parent folds summed to 572.1 s and 411.2 s respectively. Across the
native cohort, lookup GKR took 102.1 s and composition evaluation 75.6 s.
Gas alone gave 54.1 s leave-one-block-out error for native wall time, versus
7.9 s for RV64 steps and 4.5 s after adding SHA-256 and Keccak counters.
The richer fit transferred poorly in whole-chain holdouts.

## Larger shard results

The larger-shard arm uses the same D2/M7 executables, inputs, guests, workers
and watchdogs. It raises the limit to 4,194,303 steps. The optional
one-proof-per-service-family arm uses the existing geometry planner. Each
row includes fresh root verification.

| Chain and block | Service grouping | CPU / service shards | Native s | Recursion s | Root verification s | Total s |
|---|---|---:|---:|---:|---:|---:|
| OP 121,049,889 | One per family | 2 / 4 | 33.32 | 99.48 | 10.12 | 142.92 |
| OP 121,057,303 | Baseline | 2 / 7 | 28.57 | 111.17 | 11.50 | 151.24 |
| OP 121,057,303 | One per family | 2 / 5 | 33.94 | 107.85 | 10.12 | 151.91 |
| OP 121,003,241 | Baseline | 4 / 7 | 86.00 | 188.92 | 19.05 | 293.97 |
| OP 121,135,704 | Baseline | 5 / 6 | 121.22 | 205.26 | 23.82 | 350.30 |
| OP 121,135,704 | One per family | 5 / 4 | 105.60 | 159.80 | 18.84 | 284.25 |
| Mantle 103,132,217 | Baseline | 1 / 2 | 18.85 | 47.08 | 4.61 | 70.54 |
| Mantle 103,132,921 | Baseline | 1 / 2 | 19.11 | 47.69 | 4.64 | 71.44 |
| Mantle 103,133,561 | Baseline | 1 / 2 | 18.77 | 47.46 | 4.54 | 70.77 |
| Mantle 103,133,753 | Baseline | 3 / 2 | 38.27 | 75.72 | 9.04 | 123.02 |

The Mantle contract-creation block took 53.6% less time through its fresh
receiver. OP 121,057,303 took 48.4% less time. On OP 121,135,704 service
grouping saved another 18.9% relative to the matching 4M-step run. Its
capped 1M-step control already spent 430 s before root verification, so
it provides a lower bound on the elapsed work and no completed baseline.
Grouping also reduced the number of service shards on 121,057,303. Its total
rose from 151.24 s to 151.91 s as native production took longer.

The capped Mantle block 103,133,433 completed at 2,097,151 steps per shard.
Its six CPU proofs and three service proofs took 50.74 s, recursive
production took 130.90 s and the fresh receiver took 13.38 s, for 195.02 s
total. Its 4M-step attempt exceeded the GKR allocation limit. Both 8M-step
OP attempts failed statement validation before proof production. The larger
geometry needs a compatible statement, packet, clock and recursion rollout.

The opt-in [16-worker preset](../../tools/opstack/presets/cpu-16workers-single-lane.json)
uses the trial's component admissions and native schedule. Native and
recursive producers were separately guarded at 24 and 46 GiB RSS and a
10 GiB free-disk floor. The largest accepted 4M-step grouped run peaked at
35.71 GiB sampled RSS during recursion. The preset is a native resource
configuration. The recursive runs retain their archive binary provenance.

## Guest and proof roster trade-offs

The archived Kona guest that computes SHA-256 in software retains the same
public output on all five inputs. With 4M-step shards and one proof per
remaining service family, the complete timings were as follows.

| OP block | RV64 steps | Native s | Recursion s | Root verification s | Total s | Lower than 1M baseline |
|---|---:|---:|---:|---:|---:|---:|
| 120,794,432 | 923,894 | 6.95 | 29.84 | 3.44 | 40.24 | 35.2% |
| 121,049,889 | 5,710,492 | 34.44 | 81.63 | 8.47 | 124.54 | 47.1% |
| 121,057,303 | 6,141,333 | 35.10 | 94.08 | 9.31 | 138.49 | 52.7% |
| 121,003,241 | 16,195,261 | 82.94 | 117.04 | 13.31 | 213.29 | Capped control |
| 121,135,704 | 20,684,774 | 106.07 | 148.53 | 18.33 | 272.93 | Capped control |

Comparing the same 4M-step grouping, software SHA reduced OP 121,049,889
from 142.92 s to 124.54 s and OP 121,057,303 from 151.91 s to 138.49 s.
Both requests retired more guest instructions while using one fewer native
service proof. The recursive prover and fresh receiver used the original
outer proof profile. This is evidence for selecting services by their total
production and recursion cost.

For OP 121,135,704, changing the native schedule from one lane of sixteen
workers to two lanes of eight reduced native production to 85.16 s. All
eleven native proof and authority files and all twelve recursive proof files
matched byte for byte. The two-lane run measured 221.50 s through the fresh
receiver. Recursion also ran faster during that sample, so the scheduling
comparison attributes 20.91 s to native production.

On the same earlier software-SHA input, the two-lane scheduler estimated
more than 16 GiB for most pairs of first-stage workers. An explicit 21 GiB
estimate cap admitted those pairs. Stage one fell from 43.03 s to 27.65 s
and averaged 1.89 busy lanes instead of 1.09. Native production fell from
85.16 s to 68.28 s, with matching native proof and authority bytes. Sampled
native RSS was 16.70 and 16.69 GiB, respectively, under the same 24 GiB
RSS watchdog. The experiment sets `schedule.memory_cap_bytes` to 22548578304
with two lanes and eight workers per lane. The estimate cap is specific to
the measured host and input geometry.

The optimized Mantle guest reuses authenticated bytecode and parent header
hashes. Its existing `crypto-services` build uses the shared RV64 secp256k1
public recovery implementation. The guest outputs matched all five pinned
inputs, and the larger samples produced freshly verified roots.

| Mantle block | Guest steps before / after | Service grouping | Native s | Recursion s | Root verification s | Total s |
|---|---:|---|---:|---:|---:|---:|
| 103,133,433 | 11,534,260 / 6,044,132 | Baseline | 29.02 | 99.29 | 8.45 | 136.77 |
| 103,133,433 | 11,534,260 / 6,044,132 | One per family | 25.68 | 80.76 | 6.92 | 113.36 |
| 103,133,753 | 10,253,419 / 7,506,644 | Baseline | 31.10 | 81.96 | 7.55 | 120.61 |
| 103,133,753 | 10,253,419 / 7,506,644 | One per family | 29.69 | 80.62 | 7.36 | 117.66 |

On block 103,133,433 the grouped guest used two CPU proofs and four service
proofs. It used 41.9% less time than the accepted 2M-step configuration and
completed within 35.03 GiB sampled RSS. The original attempt consumed 361 s
before stopping. The 4M-step bulk-memory trial cut guest steps on 103,133,753
and took 145.46 s overall, versus 123.02 s for the matching control. Bulk
memory was kept out of the Mantle guest configuration.

The maintained Mantle build passed native host, RV64 and independent Unicorn
agreement on all five inputs. With one proof per service family, 103,133,433
took 23.44 s for native production, 68.15 s for recursion and 6.96 s for
independent reception, for 98.55 s overall. The compiler emitted
a distinct ELF identity from the scratch trial. Every proving request pins
its own guest and derives its symbols from that ELF.

Across the seven inputs with a complete 1M-step control, the best observed
configurations at the same native and outer proof settings reduced the sum
from 1287.80 s to 575.33 s, a 55.3% reduction. The median paired reduction
was 56.3%. These are per-input selections. Two observations each on OP
121,057,303 and Mantle 103,133,753 put their median reductions near 51%.
All ten inputs completed fresh root verification in at least one of the
larger-shard configurations.

## Recursion experiments

Three retained native bundles were wrapped using a separate outer profile
that combines up to three adjacent non-Keccak service proofs in one
circuit. The receiver derived the group spans and authenticated the complete
original worker roster. The totals below combine measured native production
with the new recursion and receiver stages on those exact native bytes.

| Block | Native workers | Wraps / folds | Recursive s | Fresh receive s | Combined s |
|---|---:|---:|---:|---:|---:|
| OP 121,003,241 | 8 | 6 / 3 | 98.49 | 12.92 | 194.35 |
| OP 121,135,704 | 8 | 7 / 3 | 116.55 | 15.18 | 216.89 |
| Mantle 103,133,433 | 6 | 4 / 1 | 55.39 | 5.76 | 86.83 |

The direct-root experiment wraps the entire native roster in one proof. It
completed for two-worker OP 120,794,432 and three-worker Mantle 103,132,217.
The direct circuit for Mantle 103,133,433 used 19.21M raw QM31 rows. OP
121,135,704 used 31.65M QM31 rows and 21.24M Blake G rows. Both padded to
2²⁵ QM31 rows and exceeded the experiment's 2²⁴ row admission.

Pairing the first four CPU workers on the earlier OP 121,135,704 guest reduced
three folds to two. The two paired leaves used 9.22M and 9.52M raw QM31
operations, each padding to 2²⁴. The paired route took 227.56 s including
retained native production and a fresh receiver, versus 216.89 s for the
service-only grouping. The pairs need cuts of 834,754 and 1,128,686 QM31
operations to reach 2²³ before testing this route again.

The flat-coset FRI and seven-level cap experiment reduced the three-child
OP parent's raw QM31 work to 4,139,841, inside 2²². Its 4,252,160 Blake G
gates missed the same boundary by 57,856. The four-child parent stayed at
2²³ for both components. The complete retained-native comparison took
220.05 s on OP 121,135,704 and 88.14 s on Mantle 103,133,433. Both roots
passed fresh verification under the separate experimental outer profile.
The later terminal-degree trial stopped at the first four-child parent with
`MerkleCapMismatch`. Repairing the coset encoding in the host cap constructor
and circuit brought that arm through fresh verification at 224.13 s on the
same native proofs. The three-child field count rose from 4.14M to 4.38M and
crossed the 2²² padding boundary. The earlier 220.05 s observation remains
the faster of the two flat-coset runs.

Overlapping leaf wraps with two pools of eight preserved all eleven recursive
proof files byte for byte. On the large OP control's native bytes, recursive
production took 114.52 s versus 116.55 s, and peak sampled recursive RSS rose
from 31.53 GiB to 38.59 GiB. This observed scheduling gain is small beside the
work targeted by source packing.

Compact final folds reduced the fold count from three to two on six-worker
OP 121,057,303 and Mantle 103,133,433. Fold work increased from 31.27 s to
38.85 s on OP and from 33.22 s to 38.16 s on Mantle. These results favor
planning from padded circuit work and memory over counting fold nodes.

The current CPU compatibility executable completed OP 121,135,704 with both
native profiles and the same classic outer profile. Both runs used the
software SHA guest, 4M-step partitions and two native lanes of eight workers.

| Native blowup / queries / PoW | Native s | Recursion s | Fresh receive s | Total s |
|---|---:|---:|---:|---:|
| 4 / 54 / 20 | 93.04 | 122.79 | 15.80 | 231.64 |
| 2 / 108 / 20 | 62.40 | 173.26 | 15.35 | 251.01 |

The lower blowup reduced native production by 30.64 s and added 50.47 s to
recursion. The larger native opening workload has to be addressed before
using this trade-off for end-to-end proving.

The Kona trial inlines canonical empty and blinded trie references in both
RLP directions and compares the first byte before the exact witness-key suffix.
On OP 121,135,704 it retired 16,758,270 steps with SHA service calls, down
from 20,085,743 on the matched pre-optimization build. The witness comparison
alone removed 120,703 steps and put the request below the four-shard limit of
16,777,212. The accepted recursive route used four CPU proofs and six wraps.

| Chain and block | Trial | Native s | Recursion s | Fresh receive s | Total s |
|---|---|---:|---:|---:|---:|
| OP 121,135,704 | Smaller Kona guest, software SHA, classic outer | 79.12 | 119.63 | 14.86 | 213.61 |
| OP 121,135,704 | Maintained Kona guest, SHA service, classic outer | 72.74 | 109.89 | 13.57 | 196.20 |
| OP 121,135,704 | Smaller Kona guest, SHA service, grouped outer | 71.73 | 99.51 | 12.84 | 184.08 |
| OP 121,135,704 | Maintained Kona guest, 21 GiB scheduler estimate, grouped outer | 63.53 | 102.34 | 13.41 | 179.29 |
| OP 121,003,241 | Smaller Kona guest, software SHA, grouped outer | 63.69 | 98.39 | 12.07 | 174.15 |
| Mantle 103,133,433 | Maintained guest, grouped outer | 27.57 | 63.51 | 5.96 | 97.04 |

These are fresh complete runs. The 184.08 s result combines the guest change,
shard threshold and grouped wrapper. It uses 16.9% less time than the earlier
221.50 s run. The 174.15 s result uses 18.4% less time than 213.29 s. For
the largest OP case, grouping on the same smaller software-SHA guest ran
in 227.34 s versus 213.61 s for the classic outer profile. Grouping depends
on the actual roster and padded row counts.

The maintained guest kept the four-shard geometry at 16,758,770 steps.
Its full run used the normal current CPU compatibility executable with the
classic outer profile. The previously built software-SHA guest used 231.64 s
on that executable. The optimized maintained source reduces this elapsed time
by 15.3% and peak recursive RSS was 31.59 GiB. The locked encoder and decoder
tests passed 18 cases. The full-digest lookup test passed with equal key
prefixes, an invalid preimage and a missing suffix. The maintained ELF matched
the pinned output in the native host, RV64 and independent Unicorn comparison
on all five inputs.

The 179.29 s run produced the same ten native proof and authority binary files
as the 196.20 s run using this exact maintained ELF. The grouped circuit
combined the eight native workers into six wraps and three folds. Sampled peak
RSS was 16.34 GiB native and 31.53 GiB recursive. This reduces the 221.50 s
reference by 19.1%.

The next latency targets are 110.75 s for OP 121,135,704, 106.65 s for OP
121,003,241 and 56.68 s for Mantle 103,133,433, half of the corresponding
221.50 s, 213.29 s and 113.36 s completed references.
The OP reference spends 100.35 s in native production and root verification
alone. Work on source openings needs to reduce native commitment cost and
recursive verifier work together. A useful acceptance gate is a complete
leaf and parent below their next padded row boundary, followed by a fresh
block run with the same guest and security parameters.

## Recursion architecture review

The largest OP block's best complete run used 63.53 s for native production,
102.34 s for recursion and 13.41 s for fresh reception. Holding the native
and receiver stages fixed leaves about 33.8 s for recursion at the 110.75 s
target. Cutting native and recursive work together reduces that requirement.

Start with the native source openings inside a recursive leaf. Keep the existing
AIR and public worker statements. Derive the commitment layout from the admitted
role, original degree and the ordered, globally lifted masks. Pack power-of-two
groups of compatible short columns. Authenticate both adjacent circle rows and
derive the original DEEP contribution from their even and odd parts. Bind the
packing layout, commitments and original OODS samples before drawing the DEEP
weights. The current `stacked_deep.zig` and engine tests exercise this algebra.
The [S-two whitepaper](https://eprint.iacr.org/2026/532) supplies the correlated
agreement framework for composing different domains. The soundness review must
cover pair agreement in the packed scheme. One candidate is to view a uniform
conjugate-pair position as a line-code symbol and retain separate degree
corrections for its even and odd coordinates.

The retained proofs show 11.20M Blake G gates for source row hashing on the
large OP blowup-four arm and 22.40M on blowup two. The tuned Kona software-SHA
guest still opens source rows costing 10.96M. These counts exclude paths, FRI
and padding. Applying the packed layout to the archived Ethereum shapes
predicts 89% fewer opened-row compressions across its seven CPU workers and
59% fewer across its full roster. On Mantle 103,133,433 the service proofs use
74% of the source row hashes. CPU packing alone has a lower ceiling on that
workload. Pair a complete CPU INTER opening with an independently qualified
service layout, starting from the retained arith256 proof and a secp shard.
The engine and circuit must agree on logical column and mask ordering before
changing MAIN, which the local GKR proof already authenticates.

Mantle also has a specific opportunity to remove a service proof. The guest
hashes the entire raw input for its public output. Standard SHA-256 padding
yields 1,669 compression blocks for the 106,772-byte input to 103,133,433.
The measured count is 1,690. The same difference of 21 holds for all five
inputs. A new input ABI could initialize the digest alongside the original
bytes from the receiver's independently checked input identity. Bind both
to the same initial memory authority. The guest would then hash its remaining
small values in software and could avoid the SHA service proof. Qualification
would require the same output and complete proof acceptance, and rejection of
an altered digest or raw input with an otherwise consistent proof envelope.

Batching native FRI across workers is a separate protocol experiment. Retain
independent FIXED authority and each worker's composition identity. Freeze the
ordered workers, individual commitments, OODS samples and local DEEP transcripts
before drawing the group mixing challenge. Bind each recomputed prefix digest
and its draw counter. For a first gate use two adjacent CPU workers with an
identical top Circle domain, FRI degree, lifting and rate. Prove FRI once for their mixed DEEP
oracle and check both authenticated source answers at every shared query. The
group transcript draws its queries after committing the FRI oracles and grinding.
Every worker still has its original degree bound and a checked local statement.
Establish a separate correlated-agreement and transcript budget before comparing
different degrees or claiming a block-wide security target. Budget field sampling
bias, the number of groups and outer nodes, and the proof-of-work grinding term.
Further deferral of low-degree tests to the final root is a separate protocol
change. [Circle STARKs](https://eprint.iacr.org/2024/278),
[DEEP commitments](https://eprint.iacr.org/2024/1752).

A bounded engine fixture produced one shared Circle FRI proof for two synthetic
same-height sources with separate OODS transcripts and authenticated openings.
The verifier rejected a reordered member, an altered OODS sample and a corrupted
source opening. All 139 polynomial tests passed including this fixture. The
fixture uses smaller parameters than the real-shard experiment below.

### Real-shard proof work

The two adjacent OP 121,135,704 CPU workers cover 4,194,303 steps each
and share a 2²⁴ FRI domain. The guarded diagnostic reproduced the original
proofs byte for byte and also checked one combined Circle FRI suffix at 54
new query positions against both sets of original source commitments.
The original pair spent 7.42 s of summed worker time on quotient, FRI and
openings. The shared diagnostic spent 7.39 s on these steps, including a
0.70 s array mix and both new source-opening checks. Replacing the scalar
mix with packed OM31 and the existing worker pool took 0.039 s for that
stage in the next run. In that run summed work was 6.93 s for the packed
shared suffix and 7.63 s for the unchanged original pair. Both numbers sum
two overlapping quotient workers. A fresh process accepted the serialized
shared suffix and rejected a changed source opening. It independently
verified the original native bundle before admitting the prefixes. The
experiment still produces the original native proofs. Sharing one FRI
tail would save about 5% of the pair's wire bytes before group framing.
The next gate is removing one
recursive FRI verifier while still binding both sets of source openings.

The earlier paired CPU leaf on the same block used 9.22M field operations
and padded to 2²⁴ rows. Counting the real pair's FRI suffix estimates
435,600 fewer Blake G gates and about 303,000 field operations removed before
group framing and uncounted query work. The two source leaves still cost
2.89M Blake G gates and their OODS absorption costs 0.49M. The field cut
falls short of the 834,754 operations needed by the earlier pair to reach
2²³. Measure the actual paired graph and its full padded inventory before
running another whole-block arm. Joint FRI needs an additional DEEP or
other field-side cut if the measured pair lands in the same padding bin.

Reusing the weighted DEEP contribution across exact shift groups cut field
work in both retained CPU leaf graphs. The native proofs and public digests
are the same inputs in each comparison.

| OP worker | DEEP field ops before / after | Total field ops before / after |
|---|---:|---:|
| 0 | 1,718,887 / 1,364,647 | 4,944,753 / 4,590,513 |
| 1 | 1,601,586 / 1,280,826 | 4,634,408 / 4,313,648 |

Both graphs remain at 2²³ field rows each. The combined estimate after
also removing one FRI suffix is 8.60M field operations before uncounted
query work and new group framing. It exceeds the 2²³ row boundary by
about 213,000. The focused circuit tests agreed with independently
evaluated native DEEP answers and rejected an altered opened word.
On the retained two-worker OP 120,794,432 request, the same grouping
saved 426,492 field operations across leaves and the parent. Both
recursive roots passed fresh verification with identical expected outputs
and public frames. Recursive production and reception took 22.72 s for
the control and 24.17 s for grouping in this single matched observation.
The graph savings did not translate into a wall-time gain on this case.

The complete 319-call Ethereum arithmetic leaf provides the first physical
two-tree packing comparison. All three arms use the same outer profile,
three rotated measurements, and fresh acceptance for each final proof. The
canonical native proof reproduced byte for byte.

| Arithmetic leaf | Median wrap s | Wrap peak GiB | Blake G | QM31 operations |
|---|---:|---:|---:|---:|
| Canonical | 2.624 | 4.029 | 648,080 | 731,050 |
| Packed INTER | 2.231 | 2.973 | 515,440 | 670,050 |
| Packed MAIN and INTER, both Circle signs | 2.135 | 2.996 | 446,400 | 769,310 |

The two-tree leaf saved 18.6% of wrap wall time. Its native fixture replay
and openings required additional work. The receiver rejected changed source
pair order, stale packed MAIN authority, a changed INTER commitment, and a
changed outer proof. Production needs the packed MAIN root in the execution
manifest, receiver-owned layout authority, and explicit low-degree checks
for each packed height. The research q54/P20 setting supplies comparison
timings. The extra correlated-agreement, local-degree and grinding terms
need separate accounting before adopting a security profile for either
experiment. [S-two whitepaper](https://eprint.iacr.org/2026/532).

The retained OP secp ADD worker covers 3,951 calls from an earlier guest
run of the same large block. A fresh native check authenticated the original
proof, MAIN and Wire claim against recaptured inputs. Its width-four packed
PCS and recursive constraint graph checked, and reversing the source pair
failed. The graph uses 1.67M Blake G gates and 5.51M field operations. Its
outer producer hit the 12 GiB experiment cap after 4.01 s. Sharing the pair
orientation and fusing weighted DEEP projections cut the graph to 3.97M
field operations. That crosses from 2²³ to 2²² rows with 221,520 operations
of headroom. On the same native witness and 12 GiB limit, the outer proof
took 7.50 s and peaked at 8.92 GiB. A fresh receiver accepted in 0.55 s.
Pair reversal still failed. The original packed arm and fused arm share
the 1.67M Blake G count. The canonical graph uses 2.51M Blake G and 2.86M
field operations. Both canonical and fused graphs pad to 2²² field rows.
The fused graph halves the padded Blake component to 2²¹. The canonical
wrap reached the same 12 GiB cap at 3.70 s. This establishes a memory-fit
gain. Native packed openings took 4.14 s in the separated fixture, so the
integrated native quotient and commitment costs still need measurement.

On the largest OP case, three six-worker native lanes with 29 GiB estimated
admission took 57.64 s versus 63.53 s for two eight-worker lanes with 21 GiB
estimated admission. Both used the 24 GiB sampled RSS cutoff. Peak observed
RSS was 21.40 GiB versus 16.35 GiB. Native authority and proof files matched
byte for byte and a fresh native receiver accepted. Substituting the new
native timing into the measured unchanged recursion and root verification
gives a stitched 173.39 s versus 179.29 s. Longer runs and different inputs
can select different lane settings.

On complete OP 120,794,432, a CPU-only handoff reused live native authority
and the in-memory bundle. The same binary produced identical native and
recursive proofs through both routes. End to end, the separate producers
took 28.23 s and the in-process route took 28.70 s, including fresh root
reception in both arms. The in-process route saved setup recreation and
overlapped native verification. Its recursive work took 18.45 s versus
18.28 s for the entire separate recursion process. The difference leaves
no measured wall saving on this input. Peak producer RSS was 15.44 GiB
in-process and 18.56 GiB across the separate producers.

Using the best earlier complete observation per block as the reference,
the cohort's 10× targets range from 3.25 to 17.93 s. Removing all recursive
production would give at most 2.30–3.39× because native production and the
fresh receiver remain. On the largest OP input those two phases already
take 76.95 s, so they need a further 4.29× reduction even with instant
recursive production.

The fresh receiver continues to derive the exact worker and circuit authorities
from the pinned request. Root acceptance checks the complete ordered spans,
execution manifest, initial and terminal statements, and separate RAM, Keccak
and service claim closure. A portable root-only receiver needs an independently
established authority for its verification-key table. Fold circuits and the
receiver must agree on the child class and exact span digest. Test an honestly
produced proof for the wrong span, order or verifier key, alongside byte-level
opening and framing mutations.

The comparison gate is a full physical CPU leaf and a complete parent at the
same proof settings, followed by fresh complete OP and Ethereum blocks. Track
source opened words, Blake G and field rows before and after padding, native
commitment cost, peak memory, recursive proof size and full request wall time.
For Mantle also measure one service leaf, since the sha and secp roles dominate
its opened width. Apply a lower native blowup only once the recursed opening
cost is in budget. Keep distinct domains for the experiments and reject
cross-profile proofs.

## Performance gates

### Complete candidate comparisons

The 4M-step, grouped-outer run on OP 121,135,704 used the same request,
guest, verifier authority and hardware guards as the earlier native schedule
test. The three-by-six schedule produced identical native files and the
same recursive root bytes. Other local build and test processes were observed
during these runs, so the repeated observation establishes fit and outcome
and supplies no isolated scheduling speedup.

| Native profile and schedule | Native s | Recursive s | Fresh verification s | End to end s |
|---|---:|---:|---:|---:|
| Blowup four, two by eight, earlier control | 63.53 | 102.34 | 13.41 | 179.29 |
| Blowup four, three by six | 64.73 | 109.70 | 14.20 | 188.65 |
| Blowup two, three by six | 52.28 | 152.37 to stop | — | — |

The low-blowup run stopped at an allocation error on the three-service
grouped leaf. Its field graph rose to 14.40M operations and
padded to 2²⁴. Sampled RSS was 33.70 GiB when the producer returned an
allocation error. The comparison retains the same caps and charges native,
outer and independent admission costs separately.

The coefficient-first packed ADD opener reduces the weighted projections
before evaluating them on the query domain. Sharing the twiddles used to
materialize the source trees brings its native suffix from 4.344 s to
1.367 s and peak RSS from 1.314 GiB to 0.674 GiB. Each of the nine timed
outputs matches the 1,174,608-byte control, and a fresh process accepted
both optimized outputs against the existing fused outer proof. Source
materialization and OODS evaluation take 1.068 s of the 1.295 s internal
fast-path span.

Retaining the packed source trees in the producer avoids serializing
115,228,672 coefficient bytes and rebuilding their authority at the opening
handoff. In three paired native runs, production plus fresh leaf reception
fell from 5.917 s to 5.397 s. A separate pair starting from captured packets
also generated a new recursive leaf and freshly received it in both arms.
That comparison took 13.702 s for split processes and 13.083 s with retained
trees. Native and outer proof bytes matched. Sampled native RSS moved from
0.674 GiB to 0.782 GiB. An altered source packet or packed MAIN authority
failed before witness publication. These are service-fixture measurements.

Specializing the outer circuit's OM31 arithmetic by literal wire shape
removes another 201,073 QM31 operations across the two large OP CPU worker
graphs after DEEP grouping. Public digests and Blake G counts match the
controls. The guessed-zero tests pin the same circuit topology as a
nonzero witness. Both individual graphs still pad to 2²³.

The authenticated paired graph checks both retained prefixes, both sets
of source paths at the shared query positions, and a single FRI suffix.
It preserves both independent public digests. It used 8,314,134 raw
QM31 operations, 74,474 below 2²³. The original independent graphs use
two padded 2²³ QM31 components. The paired graph keeps one 2²³ component.
It has 5,618,400 raw Blake G gates and the same total 2²³ Blake padding
as the two separate graphs. A changed right MAIN opening failed with
`RootMismatch`. A swapped roster failed with `JointSnapshotShape`. The
value-mode graph was checked on both real prefixes under the pinned
fixture authority. Two physical wrap attempts stopped at the diagnostic
allocator's 24 GiB requested-live limit. The instrumented run spent
24.07 s and reached 27.18 GiB sampled RSS. The separate 46 GiB
producer RSS guard did not fire.

The scratch runner then used the outer producer's 48 GiB requested-live
budget, kept the 46 GiB external RSS guard, and released captured sources
before wrapping. It produced a 751,192-byte proof in 27.63 s including
graph construction, with 31.85 GiB sampled peak RSS. A fresh process
rebuilt the fixture authority and accepted the proof in 8.15 s at a
sampled peak of 8.81 GiB. A proof-byte mutation failed with
`RootMismatch`.

Both independent leaves passed the same binary's producer and fresh
receiver sequentially. The paired proof reduced the complete two-worker
fixture from 51.58 s to 35.77 s and from 1,501,648 to 751,192 bytes.
Peak producer RSS increased from 22.46 to 31.85 GiB. Time inside the
outer wrapper moved from 19.87 s to 19.17 s. The larger wall saving
comes from the combined process doing one admission and graph rebuild
per phase. This comparison excludes the parent fold and the rest of
the block.

In a second comparison, both independent leaves shared one request,
bundle and setup admission per phase. Each arm used the same binary and
reproduced its earlier proof bytes. Fresh receivers accepted both arms.

| Two-worker fixture | Wrap s | Fresh reception s | Total s | Peak wrap RSS |
|---|---:|---:|---:|---:|
| Independent leaves, shared request | 28.46 | 10.79 | 39.25 | 22.34 GiB |
| Paired proof, shared FRI | 26.87 | 9.12 | 35.99 | 31.33 GiB |

Sharing FRI reduced the two-worker total by 8.3% against the
shared-request control. The two outer prove spans summed to 19.22 s
in the control and took 17.83 s in the paired arm.

### Neutral product admission

A bounded OP-owned CLI experiment used the neutral RV64 pipeline for native
production, recursion and independent root verification. Both requests used
the same binary and a four-child outer policy with the existing cap-three
commitment layout. Both native bundles match the corresponding compatibility
runner's binary files. The OP root proof matches its control byte for byte.
The earlier Mantle control used the outer GKR profile.

| Block | Native s | Recursive s | Fresh verification s | End to end s |
|---|---:|---:|---:|---:|
| OP 120,794,432 | 7.79 | 18.56 | 2.94 | 29.29 |
| Mantle 103,132,217 | 14.66 | 37.49 | 4.10 | 56.26 |

`WideBundleFileChanged` and `RootMismatch` rejected the plain and rehashed
OP native-proof mutations. A changed published root failed with
`RecursiveReceiverArtifactMismatch`. The CLI wiring is experimental. The
benchmark now accepts the neutral completion field and records verified
end-to-end latency directly.

The product integration decision should bind the outer proof policy before
opening input or proof files, through the existing neutral pipeline and the
OP hooks. Keep the current admitted native and outer proof identity for the
first maintained comparison. Choose the default after comparing cold OP
and Mantle requests across the established cohort within the same memory
and security bounds. Grouped FRI and packed MAIN need their reviewed
transcripts and authority framing before entering that comparison.

### Large-block authority handoff

On OP 121,135,704, the in-process producer passed its four CPU and four
service proofs directly to recursion with their live, independently
derived authority. Both arms used the same research runner with grouped
DEEP and a grouped service leaf. Both independently received the complete
root. Their native files match the 179.29 s reference, and the two new
arms match each other's tree and recursive proof bytes. Grouped DEEP
changes the circuit authority from the earlier reference.

| Producer | Native and recursive s | Fresh receive s | End to end s | Producer peak RSS |
|---|---:|---:|---:|---:|
| Split with cold recursion setup | 223.99 | 19.86 | 243.85 | 31.65 GiB |
| Live authority handoff | 279.52 | 13.84 | 293.36 | 28.53 GiB |

The live route saved the second producer's authority build and used
16.35 GiB peak through native bundle publication. Concurrent local
workloads changed between the runs. Native proving alone took 125.40 s
in the live arm and 62.41 s in the split arm. These observations qualify
fit and equivalence and leave the latency comparison open.

The maintained wrapper reuses its independently admitted inventory and
decoded stage-one data for root closure. Both closure passes remain in
place. Fresh separate receivers agree on OP 120,794,432's output, root,
authority, manifest and coverage. Both reject a stage-one execution ID
mutation with an updated transport hash, a changed exported root proof,
and a changed closure frame in the published tree. The input artifacts
retain their original hashes.

The exact maintained guest's PC census attributes all 16,758,770
retirements. It accounts for 2.96M in `memcpy`, 2.74M in secp field
squaring and inversion, and 1.45M in trie decode. Reaching three shards
at the 4,194,303-step limit needs 4.18M fewer retirements. Service work
also matters. The 158 SHA compressions add a 1.95 MB truth proof and
about 2.02M Blake G gates in source-row hashing. Replacing those calls
requires binding the same canonical payload digest before execution.
Switching the current guest to software SHA pushes it above four
shards on this input.

The authenticated pair's next Blake boundary is 2²². It needs to remove
1,424,096 Blake G gates and can spend at most 74,474 additional QM31
operations before losing its 2²³ field shape. Packing INTER alone can
remove at most 989,280 source-row gates. A combined MAIN and INTER
layout needs a real graph census with the original masks and both
source openings before a full-block timing.

### Streamed GKR checkpoint reuse

The OM31 prover can emit the first and second reduced lookup layers in
the same pass. It retains the first layer for one source covering up to
half the padded fact mass. The shared working-plane bound stays at 52
bytes per fact. Eligible sources use three raw reads per fact instead of
five. The 55 engine tests cover the proof, transcript, terminal binding,
read count and allocation failure paths.

| One log-22 CPU worker with service proofs | Numerical GKR s | Native producer s | Numerical GKR requested peak |
|---|---:|---:|---:|
| Control, candidate ran first | 8.84 | 29.70 | 2.96 GiB |
| Fused checkpoints, candidate ran first | 6.34 | 25.38 | 4.96 GiB |
| Control, control ran first | 6.02 | 23.68 | 2.96 GiB |
| Fused checkpoints, control ran first | 5.58 | 23.35 | 4.96 GiB |

Both rotated pairs produced byte-identical native proof files and
passed fresh prefix verification. Sampled native peak RSS was 8.35–8.39
GiB. The separately built-layer version used the same extra requested
memory and ran slightly slower than its matched GKR control.

On the complete OP 121,135,704 request, the fused native producer
followed by the pinned grouped recursion and fresh receiver took
65.43 s, 117.78 s and 13.79 s respectively, for 197.02 s total. All
native and recursive proof artifacts match the 179.29 s reference byte
for byte. The reference remains the fastest complete result.
The subsequent control reproduced the same native bytes in 104.77 s
while other builds ran on the host. That observation does not establish
a matched full-block latency gain.

### Guest shard thresholds and SHA placement

The guest reuses the sealed parent hash, narrows witness searches to the
authenticated digest prefix, decodes canonical blinded trie children directly,
and avoids the overlap branch for disjoint C `memcpy` calls. The `memmove`
caller still checks overlap before using the bulk service. Both rebuilt ELFs
matched the host output and independent Unicorn execution on all five pinned
OP inputs. Each ELF uses its own ABI symbol addresses.

| OP block | Prior retirements | Updated with SHA service | Updated with software SHA |
|---|---:|---:|---:|
| 120,794,432 | 645,734 | 590,275 | 718,201 |
| 121,049,889 | 4,534,881 | 4,219,144 | 4,431,037 |
| 121,057,303 | 4,767,095 | 4,372,128 | 4,585,857 |
| 121,003,241 | 13,090,332 | 12,203,836 | 12,725,100 |
| 121,135,704 | 16,758,770 | 15,590,691 | 16,191,729 |

The CPU shard cap is 4,194,303 retirements. OP 121,003,241 now fits three
shards with the service. Software SHA requires four there. On OP 121,135,704
both builds fit four shards. Software SHA removes 158 calls and one native
service proof on that block. The service build saves 1,168,079 retirements
(7.0%) on the largest input and needs another 3,007,782 to fit three shards.
The software build was a matched experiment using the existing software SHA
implementation. The maintained guest retains its SHA service.

| OP 121,135,704 | CPU + service proofs | Leaves / folds | Native s | Recursion s | Fresh receive s | Total s |
|---|---:|---:|---:|---:|---:|---:|
| Earlier fastest reference | 4 + 4 | 6 / 3 | 63.53 | 102.34 | 13.41 | 179.29 |
| Updated guest, service SHA | 4 + 4 | 6 / 3 | 61.86 | 110.01 | 14.08 | 185.96 |
| Updated guest, software SHA | 4 + 3 | 6 / 3 | 59.38 | 106.82 | 13.82 | 180.03 |

Each updated run completed and passed fresh root verification against the
same expected output. The comparison used the same fused native producer,
grouped recursion runner, shard cap and two eight-worker lanes for both
updated guests. Peak sampled group RSS was 31.53 GiB with the service and
31.28 GiB with software SHA. Removing the SHA proof saved 1,963,778 native
artifact bytes and 2,494,400 raw Blake G gates in the combined service leaf.
Both service-leaf circuits still pad Blake and QM31 to 8,388,608 rows each.
The 5.92 s difference is one comparison; the earlier 179.29 s reference
remains the fastest accepted result for this input.

The updated service guest also completed OP 121,003,241 with three CPU
proofs and five service proofs, including 34 arithmetic calls in their own
provider. The fresh receiver accepted the exact output and all eight workers
through six leaves and three folds. The native, recursive and fresh-receiver
stages took 52.43 s, 102.00 s and 11.63 s, for a 166.06 s stage sum at a
31.64 GiB peak. This improves on the earlier 174.15 s run by 4.6%. That
reference used an earlier software-SHA guest, so the comparison covers the
whole configuration. The stage sum was recovered from the three successful
process receipts after the study script initially expected four service
proofs for this input.

### Packed source openings for paired CPU leaves

A fresh inspection of two retained workers recovered each source column's
height and ordered mask tuple. Their ordinary paired graph uses 5,618,400
Blake G gates and 8,314,134 QM31 rows. Crossing the next Blake padding
boundary requires removing 1,424,096 gates. The existing field domain has
74,474 rows of headroom.

| Lifted MAIN and INTER layout | Modeled Blake G reduction | Margin against Blake boundary |
|---|---:|---:|
| Width four, both signs | 1,308,960 | −115,136 |
| Width eight, both signs | 1,974,240 | +550,144 before framing |

Width eight uses groups with the same tree, height and complete ordered mask
tuple. Both source signs must be authenticated. The Merkle index determines
orientation, and the distinct periodic sample keeps its own shifted
coordinate and denominator. The coefficient-first design reuses its folded
coefficient with a slot power. Recomputing that basis would add an estimated
456,000 field rows. Both the separate-coefficient and periodic-reuse algebra
checks matched 64 oriented queries with three shifts, including an independent
scalar implementation of the M31 extension tower through OM31. The checks rejected
alterations to the opposite opening, orientation, shift, reused coefficient
and slot power. The complete packed circuit still needs a joined graph and
proof-and-receiver qualification.

The existing native Circle fixture now proves a width-eight layout with two
mask points and independent direct columns. It authenticates both siblings
and rejects changes to a sibling, a direct column, an OODS sample and the
FRI witness. The exact four packed MAIN/INTER layouts for the retained OP
workers have 491/254 and 461/241 packed columns.

| MAIN/INTER DEEP graph on the retained geometry | Raw QM31 rows | Change |
|---|---:|---:|
| Ordinary grouped DEEP | 2,539,538 | — |
| Width eight with two per-group weight families | 4,947,861 | +2,408,323 |
| Width eight with shared weights and independent parity mix | 3,315,524 | +775,986 |
| Width eight with shared weights, lines and domain ladders | 2,458,826 | −80,712 |

These trace-only graph counts include coefficient preparation and 54 queries
per worker. The last variant reuses weights and denominators across compatible
source cohorts while preserving the two folded parity contributions and the
original periodic sample. The comparison excludes packed root admission,
Merkle paths, transcript framing and the shared FRI suffix.

| MAIN/INTER Merkle circuit, 54 queries per worker | Ordinary | Width eight | Change |
|---|---:|---:|---:|
| Blake G gates | 3,119,520 | 1,145,280 | −1,974,240 |
| QM31 rows | 267,578 | 262,068 | −5,510 |
| M31-to-U32 rows | 552,420 | 156,276 | −396,144 |

The separate Merkle count uses exact packed widths and sparse cap geometry.
A smaller witness-bearing circuit checked the same opening logic with both
signs and rejected a changed odd row, reversed sign order and a stale root.
The measured source-stage deltas sum to −86,222 field rows, leaving
160,696 QM31 rows and 550,144 Blake gates in the paired-domain budgets before
framing. The producer must derive packed MAIN before the local GKR receipt,
build packed INTER from the same logical coefficients used by composition,
and bind both to the shared-FRI transcript. The exact-stage counts do not
qualify that new proof carrier or establish its end-to-end wall time.

#### Live CPU source commitments

A guarded probe used the retained coefficients of worker zero during a
complete OP 121,003,241 native run. It derived the ordered masks from the
admitted CPU geometry and built both packed commitments on the live worker.
The packed trees used log 24 and a 256 MiB cap per LDE batch. Each opened
54 conjugate pairs and authenticated them with the native Merkle verifier.
Changing either packed root caused authentication to fail.

| Live CPU worker zero | Logical columns | Packed columns | Build s | Open s |
|---|---:|---:|---:|---:|
| MAIN | 3,379 | 487 | 7.190 | 0.301 |
| INTER | 1,880 | 255 | 4.181 | 0.205 |

Using the existing worker pool for dyadic extensions preserved both
roots and brought the packed builds down to 3.203 s for MAIN and
2.026 s for INTER. A separate local GKR proof took 9.396 s against
that packed MAIN root. Its local verifier accepted it in 1.93 ms and
rejected the original MAIN root with `InvalidSumcheck`. This checks
receipt scope before the terminal PCS binding.

The probe added separate commitments while the ordinary transcript owned
execution acceptance. Native production with the probe took 55.32 s.
Recursive production on those ordinary proof bytes took 92.88 s and a
fresh receiver took 11.73 s. The guarded stage sum was 159.94 s. All
native and recursive proof bytes matched the three-lane control.

The stage-one experiment then used packed MAIN as the challenge authority
for all three CPU workers. It reduced their combined MAIN width from
9,851 to 1,417 columns. The coordinator sealed all three CPU and five
service workers, decoded the serialized manifest and reverified its
digest. Changing any of the three packed roots failed its GKR sumcheck.
The guarded run took 25.57 s and peaked at 16.00 GiB. It stopped before
stage two. The run still built the ordinary MAIN commitments to retain
their logical coefficient owners, so it measures integration rather
than the cost of a replacement producer.

The new physical worker proof needs a packed DEEP/FRI suffix that keeps
the original ordered AIR samples and authenticates both packed signs.
The CPU receiver and recursive leaf must independently replay that same
suffix and derive its layout. Until that gate passes, the 159.94 s
observation measures the ordinary proof with an extra source probe.

### Composed runs on OP 121,003,241

The service-backed guest, 4,194,303-step shard cap and grouped recursion
authority were pinned for these runs. Wall time includes native proof
production, recursive production and a fresh process admitting the root.

| Configuration | Native s | Recursion s | Fresh receive s | Total s |
|---|---:|---:|---:|---:|
| Two eight-worker native lanes | 52.43 | 102.00 | 11.63 | 166.06 |
| Three six-worker native lanes, 18 recursion workers | 46.81 | 93.99 | 11.67 | 152.51 |
| Three six-worker lanes and scoped raw-mod grinding | 49.74 | 96.38 | 11.38 | 157.53 |
| Three six-worker lanes and mixed native-tail root | 44.72 | 94.53 | 10.76 | 150.01 |
| Mixed native-tail root with cap log five | 47.40 | 97.73 | 10.75 | 155.91 |
| Mixed native-tail root with packed terminals and 64-entry arithmetic-tail cap | 49.11 | 102.95 | 11.48 | 163.57 |

The three-lane preset produced identical native and recursive proof
artifacts and cut end-to-end time by 8.2% in this comparison. Native
peak RSS moved from 14.87 to 19.70 GiB. Recursive peak RSS was 31.40 GiB.
The scoped-grinding experiment reused the lane pool and preserved the
canonical nonce in both raw-mod field profiles. The complete run was
5.02 s slower than the three-lane control, so that experiment stays in
the study artifacts. These are single observations at each setting.

The mixed-tail experiment uses its own outer transcript and places the
last arithmetic service proof directly in the root circuit. The receiver
independently derives its ordinal and checks contiguous coverage of all
eight workers. It accepted five leaves and two folds and rejected an
altered native tail index. Native proof bytes match the other three-lane
run. The mixed root used 4,022,037 raw QM31 rows and 4,401,920 Blake
G gates, crossing the 2²² Blake boundary by 207,616. Its recursion
stage was 0.54 s slower than the three-lane grouped control in this
comparison. The fastest complete total includes variation in native
production and fresh reception.

The grouped control spent 53.97 s wrapping and 32.41 s folding, with
5.54 s of setup before recursive production. Moving the arithmetic tail
into the root reduced wrap time to 50.40 s and raised fold time to
36.20 s. The larger root absorbed the saving from one fewer wrap.

Raising the fold cap from log three to log five removed 195,040 Blake G
gates from the mixed root. At 4,206,880 it still exceeded 2²² by 12,576,
and QM31 work rose to 4,384,128 rows, 189,824 above 2²². Both domains
rounded up to 2²³. The larger-cap root also passed a fresh receiver
and rejected an altered tail index. Recursive wall time increased.

Selecting two 32-bit terminal words in one QM31 element saved 26,096
field rows for 108 queries into a 32-entry cap. The circuit rejected
changes to either packed word, the query bits and the root. Applying that
selection to the retained four-child fold removed 835,068 QM31 rows at
identical Blake cost. The field domain still rounded up to 2²³.
The first 64-entry arithmetic-tail attempt stopped at the native
proof-capture cap-depth guard before producing a root.
The separate packed-cap trial enabled the existing 64-slot sparse-cap
layout for its native Blake profile. It produced a complete root, passed
fresh reception and rejected an altered tail index. The root used
4,018,524 QM31 rows and 4,203,760 Blake G gates. Its field domain reached
2²², and the Blake component remained at 2²³ by 9,456 gates. End-to-end
wall time was 163.57 s. These caps remain experimental.

The compact width-eight source test reproduced both commitments and
all authenticated opening bytes for the retained 3,951-call ADD worker.
With 16 MiB LDE batches, sampled peak RSS moved from 150 to 74 MiB on
MAIN and 348 to 181 MiB on INTER. This compact implementation took
about 2.2× longer to build the commitments. It enables a lower-memory
producer experiment. A latency benefit on a full CPU source is open.

A separate keyed BLAKE3 experiment retains prefixed Blake2s leaves and
uses a distinct internal-node hash domain. One node uses 56 Blake G
gates versus 80. A fresh process accepted a small OM31 FRI proof,
matched its captured path in the circuit and rejected six mutations
covering the transcript, source tree and FRI tree. The retained
three-child parent has enough composition path nodes to project below
2²² Blake gates. Its physical recursive proof and timing are open.

The half-latency target for the original 166.06 s result is 83.03 s.
At the three-lane native and receiver times, that leaves 24.55 s for
recursive production. Improvements to the native and receiver phases
can increase that allowance.

Start with independently pinned OP and Mantle inputs from this cohort. Keep
the security profile and expected execution output fixed. Measure changes
in segment size separately from changes to guest instructions or recursion
kernels. Record native and recursive proof counts, peak memory, proof bytes,
and cold receiver time. Every successful arm needs fresh root verification
and the selected corruption controls. Compare common inputs through the same
stages including failures. Establish a bounded complete result for the large
inputs before extrapolating the speedup to them.

These measurements cover L2 execution. An SP1 replacement also needs anchored
L1 derivation, chain-specific data availability, adjacent range aggregation,
and a practical settlement verifier. Track the performance work and acceptance
criteria in [issue 491](https://github.com/starknet-innovation/stwo-zig/issues/491).
