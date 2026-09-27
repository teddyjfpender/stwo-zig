# Authenticate every leaf in a FRI folding group

Task: replace host-only folding-subtree digests with typed leaf hashes and typed
internal-node hashes, connected to canonical field-byte producers.
Inputs: power-of-two leaf count, constant words per leaf, contiguous caller word
range, upper authentication path and public index/depth/root. Actual fold4 PCS
capture provides 16 QM31 values split into four leaves; upper path remains private.
Canonical problem: exact complete binary Merkle subtree construction followed by
an authentication path. Reuse canonical frame witness/router and existing AIRs.
Mapping: leaf payload ranges -> framed hash nodes; pairs -> private digest routers;
subtree root -> upper path. Each node is computed once, O(leaves + path depth)
hashes plus payload bytes, versus separate O(leaves * path depth) proofs.
Source: native src/core/fri.zig buildFriLayerQueryCapture and
src/core/fri/merkle_queries.zig packing; previous pinned BLAKE3 migration research.
Selected transfer: shared subtree DAG with exact wire-use counts, not independent
paths that duplicate ancestor hashing. No new cryptographic primitive or AIR.
Prediction: all captured values can feed canonical field encoding, four typed
leaf hashes, three typed subtree merges and the captured upper path in one outer
proof. Trusted fixed columns must depend on shape/root and caller identities,
not private value/digest bytes. A false source tuple or false root must fail.
Validation: native captures fold1/2/4; complete fold4 group proof, preprocessing
parity, negative namespace/shape and changed value checks, focused test only.
Limits: source tuples in the fixture are public auxiliary inputs. Connecting
production DEEP/FRI arithmetic, transcript admission, Metal and keys remains.
