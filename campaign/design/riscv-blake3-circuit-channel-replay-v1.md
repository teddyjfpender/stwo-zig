# Exact BLAKE3 transcript replay in the existing circuit AIR

`src/frontends/circuit/builder/blake3_channel_reuse_v1.zig` is a new finite
kernel adapter. It changes no generic verifier contract, original proof or
production registry. It is not a complete recursive leaf wrapper.

The channel starts from the exact experimental-v1 INIT frame. Roots, U32 words,
U64 halves, QM31 inputs and PoW nonce halves enter as circuit wires. Only the
operation grammar, payload lengths, difficulty and draw-counter schedule are
structural constants. Absorption resets the draw counter; raw draws preserve
the full digest and advance the 64-bit counter. Frame prefixes/tags come from
the authoritative native module. Large frames use the existing constrained
compression/chunk/parent kernels with BLAKE3's exact asymmetric tree rule.
Canonical native framing is word aligned, so no byte decomposition is needed.

Native field draws reject the entire eight-word digest if any raw word is
`0xfffffffe` or `0xffffffff` (2P or 2P+1). For each range-typed U32 wire, the
circuit decomposes its two 16-bit limbs. Rejection is exactly the product of
bits 1 through 31, with bit 0 free. The block acceptance flag is the product
of all eight word-acceptance flags. Accepted words reduce modulo M31 through
the existing arithmetic gadget, retaining exactly two preimages per field
value. A one-QM31 draw still checks all eight raw words. Odd batched draws
consume the same whole blocks and discard the same spare coordinates as native.

A bounded draw schedule provides one to eight attempts per block. Every
nonterminal attempt is constrained rejected, and the terminal attempt is
constrained accepted; the host cannot authorize skipping a valid hash or
accepting an invalid one. Attempts alter topology, so a future wrapper must
independently authorize the exact schedule/key, or implement a fixed-capacity
conditional grammar with equivalent constraints. More than eight attempts or
a frame over 2^20 words is explicitly unsupported. These limits reject inputs;
they do not weaken checks on admitted inputs.

PoW hashes the exact POW frame and constrains the requested number of trailing
zero bits in the **raw** first 32-bit digest word. Difficulties 0 through 32
are supported; reduction modulo M31 is not used for the predicate. Nonces are
wires, and only validity is required, as in the native verifier. `verifyPow`
leaves the state unchanged. `pow` verifies and then absorbs the nonce as U64,
matching the native PCS's separate verify-and-mix sequence.

Qualification covers native state equality after every absorb, raw draws,
64-bit draw indices and nonce values, single/pair/odd secure packing, reset,
block/chunk/asymmetric-tree boundaries, all sampler boundary words in every
lane, fabricated acceptance/rejection schedules, invalid PoW, intermediate
state tampering, root-dependent values with identical topology, NoValue
compilation and gate-free replay. These are circuit-satisfaction kernel tests;
actual original PCS/AIR verification and registry qualification remain open.

The focused ReleaseSafe gate passes all 17 tests. Retained evidence is
`vectors/reports/riscv-cpu-architecture-20261029/circuit-blake3-channel-replay-kernel-v1/qualification.json`.
