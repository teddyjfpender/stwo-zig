# Same-field ordinary CPU control

This is a benchmark-only ordinary CPU0 proof, not another production protocol or
an Ethereum-block acceptance path. It separates the cost of local LogUp versus
local GKR from the simultaneous QM31 to OM31 field change. The executable is
`rv64-om-classic-control`, with `produce CONFIG JOBS NEW_OUT` and
`verify CONFIG OUT`. It pins OM31, q70, P26, beta1 and fold4 independently of
producer metadata. Both commands rebuild the trusted image/program/key. Output
explicitly says benchmark-only, no production protocol and no security certificate.

The producer imports exactly packet0 through the existing capture, collector and
source factory. It rejects service calls and bridge geometry. The original FIXED
and MAIN are unchanged. RAM uses the original physical global authority and is
closed separately; INIT/TEARDOWN claims are recomputed from the public cell list.
All local lookup families, ROM and the public-register boundary use the original
fraction emitters. The independent receiver checks all local claims against the
physical proof and their batched closure, plus the RAM closure and expected
initial image/registers. Balanced mutations of local claims remain invalid.

There is one joined component per role and one local accumulator. An immutable
symbolic degree catalog pairs only affine denominators and affine weights. CPU
FUNCTION and ROM projections are quadratic and remain strict single inverses;
OWNER is affine. Every inverse is checked even for a zero weight. The resulting
CPU local interaction width is 80 base columns. All constraints remain degree at
most3 on the existing2n domain. Original FIXED FIRST/LAST anchors are sampled;
this differs from GKR's derived anchors but does not add or change the committed
FIXED tree. The control's own transcript tag prevents cross-protocol acceptance.
The local relation challenge draw reuses the production child scope authority.

The large-block recycler has a4GiB free-cache cap; one48GiB requested-allocation
budget owns the CLI, and16GiB bounds generated interaction buffers/scratch.
These are allocation admissions, not an RSS guarantee. All witnesses use the
existing bounded parallel classic producer. Native metadata is retired after
local/RAM generation and before proving. The CLI writes bounded canonical
8-coordinate claims, a public RAM sidecar and an OM physical proof. Prefix
endpoints are proved against metadata; this control does not claim an independent
whole-block terminal or43-byte Ethereum output.

Qualification includes actual tiny ADDI/SD/LD/XOR MAIN+RAM proof and independent
fresh setup/verification, balanced claim tampering, changed register endpoints,
corrupt proof bytes, budget-refusal ownership cleanup, degree-aware grouping and
canonical eight-coordinate transport. The existing native/packed table-authority
regression is rerun after the pure stateless helper extraction. Actual first-shard
measurements and byte/root/statement parity are recorded separately; neither a
small fragment nor a mixed-field comparison is a whole-execution speed claim.

## Matched ordinary Ethereum CPU0 measurement

Source46dde216e,4,194,303 retirements, same OM31/q70/P26/beta1/fold4,
16 workers and resident MAIN. Sequence GKR/classic/classic/GKR runs in fresh
processes under the shared heavy-proof lock. The lock does not control unrelated
host workloads or thermals. Values below are means of two runs. Both independent
receivers accepted every run. Declaration, complete compact request, FIXED root,
MAIN root and public RAM bytes match exactly. Proof bytes across the two protocols
are not expected to match.

| Measure | OM classic local | OM local GKR |
|---|---:|---:|
| Source plus proving |7.954s |8.459s |
| Source |0.327s |0.325s |
| MAIN commit |0.909s |0.917s |
| Classic I generation (local+RAM / RAM only) |0.724s |0.065s |
| Local GKR input/numerical/binding |— |0.189/1.703/0.299s |
| Composition (inclusive stage scope) |2.158s |1.844s |
| PCS quotient build+commit |1.095s |1.227s |
| Native MAIN+INTER cells |1,013,854,976 |611,595,008 |
| Physical proof bytes |945,856 |679,424 |
| Additional stage-one child file |— |88,400B |
| Peak RSS |11.819GB |18.261GB |

`Control.prove` excludes source generation; coordinator proving includes it.
The first row corrects that boundary difference. GKR has39.7% fewer native
MAIN+INTER cells but is6.3% slower in this sample and uses more peak memory.
Given the prior approximately7.5% host spread, there is no qualified throughput
win. Classic already uses degree-aware paired inverses, one prefix per component
and the bounded parallel producer; this is not an intentionally serial baseline.
GKR's lower native work does not yet outweigh its numerical/binding overhead.
Smaller proof/cell counts must not be presented as measured CPU acceleration.
These are ordinary first-shard controls, not a full services block or beta2 test.
The prior mixed QM31-classic/OM31-GKR comparison additionally changed field width;
this control establishes the independent representation comparison.
