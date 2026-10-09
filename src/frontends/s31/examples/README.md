# S31 examples

Examples are grouped by the concept they demonstrate. Each `.s31` source stays
beside its checked normalized `.s31.json` relation and matching assignment
(`.valid.json`). Some early examples provide only the normalized relation.

| Directory | Programs |
| --- | --- |
| [`arithmetic/`](arithmetic/) | Field arithmetic, polynomials, reductions, and simple recurrences. |
| [`boundary/`](boundary/) | A private four-lane circuit-to-chip recurrence with one public aggregate. |
| [`arrays/`](arrays/) | Static arrays, views, slices, and matrix operations. |
| [`control/`](control/) | Boolean values, selection, and mixed computations. |
| [`hashes/`](hashes/) | Preimages, Merkle trees, BLAKE2s, and Poseidon2. |
| [`wide/`](wide/) | Checked and wrapping 256-bit operations. |
| [`math/`](math/) | Fixed-width scalar integer operations and typed overflow modes. |
| [`payments/`](payments/) | Hash-based Tongo-style note ownership, checked value conservation, delivery and replay protection; validity prototype, without a proof confidentiality guarantee. |
| [`bitcoin/`](bitcoin/) | Header hashing, proof of work, linked headers, and a checked ChainWork transition. |
| [`keys/`](keys/) | Placeholder keys for build-time examples. |

The `cairo*` directories contain comparison programs. Test and benchmark
drivers that select a fixture by name use [`example_path`](../python/example_paths.py)
to find its unique file across these directories. Production S31 packages
always receive an explicit source path.
