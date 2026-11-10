# Native B2/q144 versus B4/q72: bounded source-cost gate

No native crypto/profile/key change is implemented. Both shapes have nominal
144 query-times-blowup FRI bits, which is not a composed128-bit certificate.

The retained selected796,406-step CPU geometry has4 trees with177/1357/880/16
columns, native global log20, and B4 tree heights22. This model keeps the entire
CPU AIR, local GKR verifier, claim/mask binding and public frame, emits genuine
R7 eight-role source equations, and changes only the hypothetical PCS shape to
B2/144 queries (tree heights21). Both captures are NEW dummy advice. The original
B4 key/statement is retained only to provide the constant-size framing structure;
this is intentionally NOT normalized/admitted as a B2 source key or valid proof.
No inverse/congruence/mask check is removed, but dummy values are not required to
satisfy those equations. The original retained B4 native bundle is freshly
verified independently before the source view is used.

| CPU verifier cost | B4/q72 | hypothetical B2/q144 |
|---|---:|---:|
| R7 trace cells |161,345,536|314,437,632|
| QM arithmetic raw rows |1,531,147|2,511,423|
| QM arithmetic padded log |21|22|
| P2 permutations |51,190|89,719|
| Native OM multiply rows |104,786|110,186|
| DEEP dot terms |274,608|549,216|
| Uncompressed queried column values |174,960|349,920|

All cell totals include FIXED + MAIN + INTER M31 cells **before LDE**, summing
independently padded role heights (range16 floor65536, all other role floors16).
The eight-role order is EQ, QM31 arithmetic, M31→u32, P2, range16, native OM31
multiply, native OM31 dot, and QM31 input. Their exact widths are:

| Width | EQ | QM | u32 | P2 | range16 | OMmul | OMdot | input |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| FIXED |2|8|3|73|1|9|10|2|
| MAIN |4|12|4|476|1|24|17|4|
| INTER |8|16|24|192|8|24|24|8|
| B4 log |15|21|12|16|16|17|19|17|
| B2 log |16|22|12|17|16|17|20|18|

B4 breaks down as28,389,376 FIXED +69,156,864 MAIN +63,799,296 INTER.
B2 is55,521,280 +135,086,080 +123,830,272 respectively. This is not a new
measurement of the historical217,378,816-cell CPU leaf: that earlier receipt
`native-dot/actual-small-cpu-source-v2.json` used the old inline CPU source class
(native declared masks108/550/368/16). This model uses the selected detached-CPU
class (177/1357/880/16 columns). The643,035,136-cell actual selected terminal
root is the **joint four-member group** (CPU +detached +Keccak +SHA), not this
single CPU. Same cell convention does not make these different sources equal.

Recursive cells grow1.949x and P2 calls1.753x; DEEP dot terms double. Native
FIXED/MAIN/INTER/composition LDE cell counts halve exactly. That reduces transient
expanded arrays and hashing work, but does NOT halve retained coefficients, raw
MAIN, GKR storage, boundary memory or whole-process RSS. A query buffer doubles;
path height decreases by one. Encoded proof-byte growth cannot be obtained by
simply doubling counts because the native wire uses multiproof/shared paths,
query collisions and FRI folding. No exact native proof-size/RSS/time claim is
made without a real, newly qualified native suite/proof.

Decision: do not implement this as an immediate native optimization. The isolated
CPU wrapper almost doubles, unlike terminal-only B2 (which has no recursive
parent). Current native MAIN/INTER hashing is40.2% of the real4M prefix runtime;
halving those stages alone would at most save20.1% of its native wall time,
before accounting for doubled openings/FRI. This selected wrapper result is a
warning, not a theorem that B2 can never win: direct groups may absorb extra raw
work on an existing padding plateau, or a taller native tree may save more hash
work for the same verifier geometry. Those **whole-group and heavy-class
crossovers are unmeasured**. Neither justifies a protocol/profile switch now.
The safer active direction remains eliminating guest/provider work and fixing
byte-preserving P2 implementation costs.

Reproduce the source gate (retained native directory, not source-only directory):

```sh
STWO_OP_NATIVE_PROFILE_CONFIG=/absolute/path/selected-config.json \
STWO_OP_NATIVE_PROFILE_NATIVE=/absolute/path/retained-native-directory \
zig build test-riscv64-op-terminal-blake -Doptimize=ReleaseSafe \
  -Driscv-test-filter='native B2 full CPU' -j1
```

The test is env-gated and makes no new proof. The checked JSON receipt records
all eight-role raw/padded counts and native per-tree LDE counts. This is a partial
end-to-end model: only one actual CPU verifier is costed, not Keccak/detached/SHA,
group folds, source-key setup, execution or a complete block.


## Exact selected mixed four-member plateau follow-up

A second bounded source gate emits the complete actual four-member R7 group,
then the same group with ONLY the CPU PCS shape changed to hypotheticalB2/q144.
Detached sponge, Keccak and SHA remain B4. It uses the same member emitters,
structural/native-multiply/dot scopes and canonical group finalizer, deliberately
without source normalization/admission of the candidate. The retained B4 native
bundle is freshly verified first, including full global/terminal closure.

The source baseline reproduces the retained actual group raw vector exactly:
`[73080,5173527,3451,173939,65536,321145,1515168,335498]`. The CPU-onlyB2
counterfactual is`[91926,6153803,3451,212468,65536,326545,1789776,428270]`.
Both pad to`[17,23,12,18,16,19,21,19]`, with exactly113,324,032 FIXED +
276,381,696 MAIN +253,329,408 INTER = **643,035,136 cells**.

Thus the measured source-emission plateau hides the isolated CPU wrapper's
1.949x padded-cell increase. This is stronger than an additive estimate: the
whole group is emitted/finalized with normal shared structural handling. It is
still NOT a physical/correctness or wall-time result for a B2 native suite.
Raw QM arithmetic increases19.0%, P2 calls22.2%, and dot terms18.1%; source graph,
usage metadata and witness generation can cost more even when committed padded
cells remain equal. No exact native proof-size, memory or time saving is claimed.

This reopens only a conditional, bounded future mixed-profile experiment for
this selected source class. The native manifest currently requires uniform
profiles; the candidate is intentionally NOT a legal admitted source. New policy,
keys/transcript and security review are mandatory before any implementation.
Four-CPU homogeneous groups or heavy source classes may cross padding cliffs;
this mixed small group does not settle those workloads. No new profile/proof was
implemented and no production guard was overridden.

Reproduce with the same CONFIG/NATIVE variables above and filter
`native B2 selected four group`. The JSON follow-up receipt stores both complete
raw/padded eight-role censuses.


## All four members B2: exact source-only follow-up

Setting`STWO_OP_NATIVE_PROFILE_ALL4=1` changes all four hypothetical native PCS
shapes, still without a new profile/key/proof or normalized source admission.
The baseline raw vector again matches the retained actual group exactly.
UniformB2 yields`[126558,8601317,3451,311423,65536,335473,3030336,570272]`,
padded logs`[17,24,12,19,16,19,22,20]`:221,589,504 FIXED +539,574,272 MAIN +
492,404,736 INTER = **1,253,568,512 cells**,1.949x the643,035,136-cell control.
QM arithmetic, P2, OMdot and input each cross a padding cliff. This confirms why
CPU-only differs from uniformB2 for this mixed selected group. It remains a source
cost result, not an actual uniformB2 proof or measured end-to-end regression.
The future trusted mixed-suite audit is in
`design/riscv-proving-stack/op-native-mixed-pcs-policy-audit-20261110.md`.
