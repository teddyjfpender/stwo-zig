# Resident OM31 FRI proofs and openings

The CUDA lane now commits and folds OM31 FRI layers, derives raw query
positions and gathers compact openings entirely on the device. A fresh native
`FriVerifier` accepts the resulting six proof cases. This is an accepting FRI
subproof, not complete Ethereum execution or an accepting GPU Stark bundle.

## Protocol and residency

The path uses the existing domain-prefixed Blake2s protocol and eight-coordinate
field authority. Fold-step4 retains four-value Merkle leaves. The first layer
folds circle to line and continues with squared alpha; later rounds draw a new
alpha after mixing each new root. Final partial folds follow the native clamp.
The selected production profiles have terminal degree bound zero, so the
terminal kernel checks every remaining evaluation is the same canonical field
value before publishing its one coefficient. Other terminal degree bounds
remain unsupported by this controller geometry.

Query generation uses eight **raw hash words** per draw and masks them to the
domain size. It must not reuse reduced secure-field draws. The channel counter
advances by `ceil(n_queries/8)`, including a partial final hash. The GPU then
gathers complete folding cosets and sibling paths from each retained tree,
using original global query positions and each layer's cumulative shift.

Only compact roots, query positions, terminal data, coset values and paths are
downloaded after GPU completion. There is no full-column/tree readback or
intermediate numerical H2D/D2H. The host assembler sorts and deduplicates these
already-produced bytes into native `FriLayerProof` witnesses. It computes no
prover field values or transcript challenges and feeds nothing back to the GPU.
The native receiver independently derives all challenges and queries and checks
the Merkle openings, fold equations and terminal polynomial.

`fri.zig` derives geometry from receiver-selected degree/configuration, validates
it again before allocation, and rejects inconsistent duplicate readback values
or hashes. Field coordinates decode canonically; hash digests preserve all
32 bits. Typed commands enforce lane/generation ownership and capacity, and
native preflight rejects aliases, undersized outputs and misaligned hash trees.
Output guards and failure-atomic formatting allocation tests are included.

## Qualification

| Degree log | Blowup log | Fold step | Queries | Committed layers |
|---:|---:|---:|---:|---:|
| 8 | 2 | 4 | 65 | 2 |
| 12 | 2 | 4 | 256 | 3 |
| 7 | 1 | 4 | 108 | 2 |
| 6 | 2 | 2 | 64 | 3 |
| 5 | 1 | 1 | 32 | 5 |
| 17 | 2 | 4 | 256 | 5 |

Native circle-polynomial evaluations supply each test's initial FRI column;
there is no CPU folding, hashing, query selection or opening generation during
the GPU flow. Every GPU root, alpha, terminal coefficient, raw query and terminal
channel snapshot matches the native producer. GPU opening readback is then
assembled as a new native proof and independently verified. Both macOS/ARM and
a separately built Linux/x86 native receiver accept all six cases.

Four GPU mutants reject nonconstant/noncanonical terminal data, invalid queries
and sticky failure. Six compact-readback mutations fail framing or consistency
checks. Four additional mutations operate on the assembled native proof itself:
changed field witness, changed Merkle witness, changed commitment and swapped
inner layers. These reach native verification and reject with first-layer
commitment/evaluation errors. Geometry corruption and every formatting allocator
failure are exercised separately in host tests.

Normal execution plus memcheck, racecheck, initcheck and synccheck pass. Each
gate's captures independently pass the Linux receiver and all ten receiver
mutations; captures are byte-identical across all five runs. ReleaseSafe and
ReleaseFast host suites pass 66 tests and compile the actual native FFI. Source,
fixture, object, executable and receiver hashes and full logs are recorded in
`vectors/reports/rv64-cuda-om31-fri-20261103/`.

Reproduction:

```sh
zig build --build-file src/integrations/riscv_cuda/build.zig rv64-fri-fixtures \
  -Doptimize=ReleaseSafe -- export /tmp/rv64-fri-fixtures
zig build --build-file src/integrations/riscv_cuda/build.zig build-rv64-fri-tool \
  -Doptimize=ReleaseSafe -Dtarget=x86_64-linux-musl -p /tmp/rv64-fri-linux
python3 scripts/rv64_cuda_deep_qualify.py --mode fri \
  --fixtures /tmp/rv64-fri-fixtures --build /tmp/rv64-fri-qualified \
  --context-object /path/to/context.o --pcs-object /path/to/rv64-pcs.o \
  --merkle-object /path/to/commitment-merkle.o \
  --native-verifier /tmp/rv64-fri-linux/bin/rv64-fri-fixtures
```

The source fixture tool also supports `verify FIXTURES READBACK` independently.
The dependency objects are the previously qualified context, OM31 fold/leaf and
Blake2s Merkle kernels. Their exact hashes enter the receipt.

## Remaining Ethereum integration

The FRI subproof starts at a supplied FRI column. The separate sampling/DEEP
qualification must be connected to it under the actual complete PCS transcript,
including outer PCS proof-of-work and trace/composition opening requests. These
FRI-only fixtures do not exercise that outer PoW step or establish a whole
security profile. They change no proof-system parameters or security labels.

Execution still needs GPU construction and authentication of every admitted
CPU/truth witness, joined domain composition, physical GKR source binding/root
closure and complete shared-manifest RAM/KIO/Wire closure. A fresh receiver must
accept an actual GPU-produced Ethereum bundle before complete-block performance
or residency can be qualified. Recursion and vendor-comparable block timings
remain separate gates.
