# ZisK / Stwo BLAKE3 component comparison

User direction: measure like-for-like middle/lower-level functionality, and make
high-quality, fully constrained hash precompiles the default once qualified.
The active persistent-plan/fusion/direct-emission goal remains in scope.

## First matched primitive

The source-pinned Proofman scalar `compress_xof` and our canonical compression author
receive identical CVs, 64-byte blocks, counters, lengths and flags. The harness checks
all sixteen output words for 1,024 deterministic varied cases, then compares twelve
interleaved batches of 5,000,000 independent compressions. Both arms accumulate every
output word and compare complete batch checksums. A 500,000-call warmup per arm precedes measurements.

This compares the scalar compression core, not GPU kernels, hash proving or whole
provers. Our production streaming commitments use Zig's standard BLAKE3; the local
arm here is the schedule also used by typed arithmetic authorship. Compiler/language
code-generation differences are part of this initial observation. Do not attribute
these numbers to native commitment hashing without measuring that implementation too.

Peer source: Proofman d485fac207679076958b502554fb595568c2f954, clean checkout;
path and file digests are in sources.json. The source snapshot is retained verbatim.
Raw timings and summary.json record the completed serial run.

## A concrete protocol-cost difference

Our node frame encodes a 27-byte protocol ID, one domain byte and two 32-byte digests:
92 bytes, requiring two compression blocks. The peer's node is an unprefixed 64-byte
input with CV=IV, counter=0, flags=11: one compression. These are different functions,
so their total node times must not be labeled a like-for-like hash comparison. The
compression harness isolates the identical underlying operation instead.

The peer converts digest words to canonical Goldilocks values. Our framed byte digest
and M31-based AIR do not have the same representation. Domain separation and output
binding cannot be deleted to reproduce a headline number. Any encoding change is a
separate protocol/security experiment, not a precompile optimization.

## Default hash-precompile work

Current native recursion already proves BLAKE3 with typed G/XOR/routing components.
It does not execute a RISC-V verifier for those hashes. The next architectural
comparison is a compression-specific AIR with local state transitions and packed
lanes, as in the peer's `circuits/blake3.pil`, versus the current generic wire lookups.
The peer documents 51 columns per compression lane (53 for arbitrary initial state),
with 56 clock rows and up to eight lanes. Its Goldilocks arithmetic can directly
constrain 32-bit sums; those equations cannot be copied into M31 unchanged. Compare
field bytes, range/bitwise lookups, degree, padding, commitment work and next-level
verification, not row/column counts in isolation.

Qualification before default promotion must retain all input/CV/counter/length/flag/
output constraints, independent fixed preprocessing and authenticated caller bindings.
Cover partial blocks, chunk boundaries, multi-chunk trees, malformed bindings and
mutations; compare with the current canonical author and native implementation.
Measure proof and fresh verification, CPU/Metal paths, canonical parent-of-parent,
and CSP execution+witness+prove. Avoid a benchmark-only route or host-computed digest
accepted without proof constraints. Existing protocol framing stays unchanged for
the first precompile implementation.


## Results

M5 Max ARM64, Zig 0.15.2; peer C++ compiled by the same Zig toolchain with `-O3
-std=c++17 -mcpu=native`, Zig harness built ReleaseFast. Four batches per arm, all
5,000,000 calls; every full sixteen-word accumulated output matches. All 1,024 varied
raw-compression parity cases also pass. A shorter two-arm pilot is retained separately;
its 500,000-call timings were not mixed into the final distribution.

| Arm | Median ns/call |
|---|---:|
| zisk_scalar | 59.365 |
| stwo_author | 47.040 |
| zig_native_xof | 67.878 |

The std-native arm hashes exactly the same 64 little-endian input bytes and requests
64 XOF output bytes; these match the raw compression's sixteen words under flags=11,
CV=IV and counter=0. Its timer includes its general hash API/byte conversion overhead;
the raw-compression arms take word arrays directly. It is not the framed production
node function and is not a GPU comparison. Both batch loops perform one native call
per hash internally; the C ABI crosses only once per batch, not once per compression.

This local result does not suggest a slower scalar compression author is the main
recursion gap. It instead supports prioritizing proved compression geometry, generic
wire lookup overhead, framing costs and full next-level accounting. No peer hash-proof
benchmark has run yet, and no claim of prover superiority follows from this primitive.

```sh
zig c++ -O3 -std=c++17 -mcpu=native -c autoresearch/notes/2026-09-24-zisk-compression-comparison/peer.cpp -o autoresearch/notes/2026-09-24-zisk-compression-comparison/peer.o
zig build-exe -O ReleaseFast autoresearch/notes/2026-09-24-zisk-compression-comparison/main.zig autoresearch/notes/2026-09-24-zisk-compression-comparison/peer.o -lc++ -femit-bin=autoresearch/notes/2026-09-24-zisk-compression-comparison/compare
/usr/bin/time -l autoresearch/notes/2026-09-24-zisk-compression-comparison/compare
```
