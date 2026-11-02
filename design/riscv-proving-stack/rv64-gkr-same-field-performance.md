# What the matched OM31 control establishes

The historical QM31 prefix time is not an argument-only control for OM31 GKR.
The isolated classic OM31 CPU0 receiver now supplies that missing comparison:
the same4,194,303 retirements, full request/declaration, original FIXED and MAIN
roots, public RAM bytes,16workers and q70/P26/fold4 parameters. Both receivers
freshly accept every run. Both remain unqualified for whole-protocol128
security. The control is a benchmark, not another production protocol.

| Matched CPU0 measurement | Classic OM31 | OM31 GKR |
| --- | ---: | ---: |
| Source + proving, mean of two observations | 7.954s | 8.459s |
| MAIN + INTER native cells | 1,013,854,976 | 611,595,008 |
| Physical proof bytes | 945,856 | 679,424 |
| Additional local child bytes | none | 88,400 |
| Observed peak RSS | 11.819GB | 18.261GB |

These shared-host observations do not establish a speedup. The6.3% timing
difference is within prior host variation. Native cells fall39.6763%, but they
exclude numerical GKR, its product tree, Eq generation, terminal projection and
known auxiliary-polynomial construction. They also do not measure lifted leaf
hashing, opening masks or fixed setup. A ratio of committed cells is therefore
not a ratio of total proving work.

The classic local/global interaction stage is about0.76s in this observation;
its scope also includes allocation/setup/source retirement. GKR's local
numerical and binding work is about2.17s. The smaller native proof saves work,
but that saving is offset by this added computation. Composition alone falls
about2.158→1.844s in the matched receipt. Scope details matter: the classic
helper excludes source construction from its proof timer, whereas the GKR
coordinator includes it. The table adds classic source time before comparison.

As a limited Amdahl illustration, removing all2.17s of current local GKR while
holding the rest of its pipeline fixed leaves about6.29s. Relative to7.95s,
that is only about1.27x. This is not an impossibility bound: changing the
binding/native representation would change that remaining work. It does show
why speeding only numerical GKR cannot deliver the earlier1.6x expectation on
this measured pipeline, let alone a two-second complete shard.

The current bridge uses an eight-coordinate Eq witness and an eight-coordinate
prefix per local role. Eta batches the two immutable terminal marginals, but
the Eq recurrence and its authenticated connection to original MAIN still
cost committed columns, masks and arithmetic. A future native multilinear
commitment or other binding construction could change that architecture; it
is a separate proof-system/security/recursion job, not an omitted parallel
loop. Cross-shard RAM/KIO/Wire remain explicit obligations throughout.

Measured engineering work remains useful: packed gate scheduling lowers
numerical time, pointer accumulation removes wide temporary copies, and
coefficient-sized openings reduce higher-rate decommit time. Paired folds
reduce pool waves. Checkpointing trades recomputation for lower working memory
and may permit more concurrent workers. None independently establishes a net
GKR throughput win or a whole-prover memory multiplier. Actual full-block and
device measurements must decide those claims.

Evidence:
`vectors/reports/rv64-om-classic-control-20261102/receipt.json`,
`rv64-gkr-packed-gates-20261102/qualification.json`,
`rv64-active-om-air-20261102/service-prefix4-ab.json`, and
`rv64-coefficient-window-20261102/qualification.json`.
