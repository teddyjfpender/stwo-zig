# Complete native unlifted PCS opening kernel in the circuit AIR

`src/frontends/circuit/builder/blake3_pcs_reuse_v1.zig` passes all 19 focused
ReleaseSafe tests. It assembles the qualified BLAKE3 transcript, physical-tree
Merkle and native fold-one FRI kernels. It changes no generic Cairo verifier,
production registry, original proof layout or VM source mode.

The finite geometry binds all ordered physical trees, column degree logs,
ordered `(row_log, offset)` masks, security/FRI parameters and terminal schedule.
The FRI domain is independently computed from the maximum **sampled** column,
not a nominated proof height or the largest physical tree. It accepts native
unlifted fold step 1, constant-terminal profiles and up to 256 physical trees;
explicit lifting and Cairo's fold step 4 are rejected. Roots, sampled values,
queried cells, sibling digests, nonce halves and FRI material are circuit wires.

The cohesive standalone sequence is native config absorption, ordered roots,
constrained OODS seed and rational circle map, all sampled values in
(tree,column,mask) order, constrained DEEP beta, FRI roots/challenges and terminal
coefficient, raw-32-bit PoW verification and nonce absorption, raw query draws,
all nonempty physical-tree paths, derived DEEP quotients, and full FRI opening
and fold verification. The same query/root/cell variables cross these boundaries.
There is no proof input that nominates a trusted DEEP answer.

`verifyAfterOods` is a composition seam for a future RISC-V-specific root/claim
prelude. That caller must derive the seed/point in its authenticated native
transcript grammar and use the same root wires. The tested standalone entry
performs those operations itself. It is a PCS opening theorem, not typed AIR,
CPU/register/RAM closure, an accepted leaf registry, or a complete VM proof.

## Native DEEP details preserved

The adapter uses native complex-conjugate line coefficients directly:
`a = beta^k * (conj(v)-v)`, `c = beta^k * (conj(py)-py)`,
`b = beta^k * (v*(conj(py)-py) - (conj(v)-v)*py)`.
For base-field query `(x,y)`, each contribution is
`(c*column(x,y) - a*y - b) / ((prx-x)*piy - (pry-y)*pix)`.
Real/imaginary components and division are constrained QM31 arithmetic, with
the denominator embedded from CM31. The same nondegenerate line condition as
native is enforced. Summing individual responses equals the native grouped law
by field linearity; it avoids dependence on Cairo's four-tree response types.

Exactly two masks add a periodicity response **before** the declared responses.
It reuses sample 1 at its point plus the native lifting-period generator.
Three masks do not trigger that special case. Beta powers advance globally in
tree/column/expanded-sample order, including repeated points. Samples themselves
stay in their original flattened order for transcript absorption. The fixture
exercises one, two and three masks, heterogeneous column logs, repeated points,
an unsampled higher-domain physical tree and an exact declared empty tree.
Empty trees are absorbed but confer no opening authority; every nonempty tree
is authenticated, including columns that contribute no DEEP samples.

## Genuine proof qualification and limits

The fixture builds five native PCS trees containing nonconstant polynomials,
with sampled degree logs 1 through 4 and a higher unsampled degree-log-6 tree.
The independently derived FRI domain log is 5. It uses the genuine CPU native
PCS prover and official postcard codec, then freshly decodes and verifies the
whole PCS opening proof with the native verifier. Prover auxiliary material is
expanded solely as untrusted witness values and paths. All original prover,
decoder and native verifier owners are destroyed before circuit construction.
No host proof-capture verdict or supplied alpha/DEEP answer is accepted by the
circuit kernel.

Both q8/PoW0 and **q70/PoW26** pass complete circuit satisfaction with exact
native OODS seed/point, DEEP randomness and every derived DEEP answer, FRI alphas,
raw query order, final channel digest and draw count. The q70 proof is 2,685
bytes with nonce 23,851,469; q8 is 2,511 bytes. These are genuine PCS proofs,
not empty carriers, but contain no typed AIR/VM claim. Their sizes or kernel
runtimes must not be extrapolated into full-block or recursive-root cost.

Controls reject altered OODS evaluations, queried cells in the higher unsampled
tree, roots, FRI witnesses, a false nominated DEEP value, and a known-invalid
q70 PoW nonce. Wrong mask/sample inventory, explicit lifting and fold-step-4
geometry fail closed. NoValue topology and gate-free value replay are exact.
The current channel/FRI profile checks one accepted sampler block per challenge;
a rare field-sampler rejection fails closed and needs a separately qualified
retry grammar before claiming coverage of all original proofs.

Artifacts, source/geometry/log hashes and the genuine q8/q70 byte proofs are at
`vectors/reports/riscv-cpu-architecture-20261029/circuit-native-pcs-kernel-v1/qualification.json`.
The next mathematical boundary is RISC-V-specific typed AIR/composition
verification and exact CPU/public/RAM/caller closure, then proving that verifier
circuit under a freshly authorized key and feeding actual circuit proofs into
the existing bounded fold tree. Existing APIs may be copied and molded for
that statement; forcing the four-tree Cairo schema is unnecessary.
