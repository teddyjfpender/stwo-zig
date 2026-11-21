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
`MerkleCapMismatch`. It produced no accepted root or latency result.

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
fixture uses smaller parameters. The real-shard protocol and its composed
security argument are the next experimental gates.

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
