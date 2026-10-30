# Native fold-one FRI in the existing circuit AIR

New module: `src/frontends/circuit/builder/blake3_fri_reuse_v1.zig`.
Status: all 19 focused ReleaseSafe tests pass, including genuine q8 and q70
standalone native FRI proofs and independent circuit satisfaction.
No production or qualified generic Cairo verifier is changed.

The canonical RISC-V parent profile declares 70 queries, PoW 26, blowup log 1,
last-degree log 0 and fold step 1 in
`src/frontends/riscv/recursion/blake3_execution_parent_protocol.zig`. The Cairo
production circuit registry instead uses fold step 4 for outer circuit proofs
(and fold step 1 for Cairo originals). These are separate identities. The new
finite geometry explicitly admits fold step 1 and a constant terminal only;
other schedules fail closed. Its structural digest binds degree log, blowup,
query count, terminal bound and schedule. A future leaf verifier must derive
this geometry independently, not take a producer-nominated shape as authority.

`commit` absorbs every FRI root and derives its QM31 fold challenge from the
constrained BLAKE3 channel, then absorbs the terminal coefficient. The finite
implementation requires the first sampler block for each alpha to be accepted;
all eight raw words are checked. A rare rejected block fails closed. A future
fixed-capacity retry grammar can widen this admitted subset without allowing
host authorization of a fold challenge.

`decommit` uses authenticated raw query wires and supplied first-layer input
values. It reuses the existing pure circle query-selection arithmetic to obtain
bit-reversed canonical circle points. At every layer it checks that the carried
value is the coset member selected by the query bit, hashes both QM31 evaluations
under native LEAF frames, reconstructs the pair subtree and authenticates its
upper path against that layer's root. All roots, coset values, sibling digests
and terminal coefficients are circuit wires.

The first fold uses the inverse y-coordinate after clearing the circle pair
bit. It computes `(even + odd) + alpha * (even - odd) / y`, with the native
unnormalized butterfly. Later folds use the inverse x-coordinate after clearing
the current line pair bit, then advance x by `2x² - 1`. This reuses existing
QM31 operations, circle point selection and circle double-X arithmetic. FRI
indices shift ordinarily between rounds; the special circle-pair-preserving
PCS physical-tree projection must not be substituted here. Every final carried
value equals the transcript-bound constant terminal coefficient.

`verifyStandalone` fixes the native standalone FRI sequence: commit roots and
terminal polynomial, draw raw queries, then authenticate/fold all openings. The
native PCS inserts its PoW predicate and nonce absorption between FRI commit and
query selection. The split `commit`/`decommit` API preserves that insertion point.
A standalone q70 FRI qualification does not claim a q70/26 complete STARK proof;
PoW, DEEP/OODS and typed AIR binding belong to the complete PCS/statement adapter.

The fixture creates a nonconstant 16-coefficient circle polynomial, evaluates it
on the canonical 32-point circle domain, and calls the genuine CPU native FRI
prover. It transports the resulting genuine FRI body through the existing native
postcard codec, then freshly decodes and verifies it before using its expanded
values as untrusted circuit witnesses. The surrounding empty PCS carrier is
explicitly a transport artifact, **not** a valid STARK proof. Original prover,
codec and native verifier owners are destroyed before circuit construction.
The circuit independently derives all challenges, hashes, queries, folds and
terminal equalities; a host verification capture grants no recursive authority.

Qualified gates include q8/q70 native host parity, fixed native postcard-carrier
SHA-256 pins, complete root/alpha/terminal-absorption/query sequence parity, wrong
fold, terminal coefficient, carried input, root/path and nominated challenge,
independent geometry/shape rejection, NoValue topology equality and value-only
replay.

A stronger forgery preserves every authentic layer/root, changes only the
terminal coefficient, then reopens genuine layers at the queries derived from
that false-terminal transcript. Native verification fails specifically with
`LastLayerEvaluationsInvalid`, after all authentication and folding steps. No
successful verifier capture exists. Prover auxiliary data is expanded solely
as untrusted witness material; the circuit independently rejects the terminal
claim. This demonstrates that native host verification is not the authority
for the low-degree check.

Retained byte artifacts and source/geometry/log hashes are recorded in
`vectors/reports/riscv-cpu-architecture-20261029/circuit-native-fri-kernel-v1/qualification.json`.

Complete original PCS transcript admission, DEEP/OODS,
nonconstant terminal bounds, wider fold/packed-leaf profiles and typed RISC-V AIR
verification remain open until separately assembled and qualified.
