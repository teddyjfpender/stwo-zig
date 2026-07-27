# Session 02: Cairo frontend placement and feed architecture

## Scope

Continue the Cairo system-throughput search by determining whether the large
gap from native Stwo is caused by the frontend, the proof backend, or both.
Retain the official proof protocol, exact proof bytes, the seven-workload
portfolio, and zero-fallback Metal requirements.

## Profiling expansion

Added opt-in nested stage scopes for:

- base geometry, live witness graph, fixed multiplicities, memory tables, and
  base finalization;
- every live witness component;
- witness input materialization, output allocation, output initialization,
  bytecode execution, base lowering, and feed retention;
- fixed and dynamic interaction components; and
- interaction memory and fixed-table multiplicity collection.

The instrumentation is inactive when no recorder is supplied. CPU and Metal
product tests passed, and profiled proofs retained exact bytes.

Artifacts:

- `/private/tmp/cairo-portfolio-profile-413e479f`;
- `/private/tmp/cairo-component-profile-current-v2`;
- `/private/tmp/cairo-interaction-profile-274de4cb-v2`;
- `/private/tmp/cairo-component-breakdown-v2`; and
- `/private/tmp/cairo-direct-feed-portfolio-v1`.

## Placement finding

The official Cairo Metal product accelerates PCS, quotient, and FRI. Base
witness execution, interaction construction, and Cairo AIR composition remain
on the host. This explains why native Metal kernel improvements did not
automatically give Cairo native-like committed-cell rates.

The initial complete-proof profile measured:

```text
workload             CPU ms      Metal ms
all-opcodes          1399.633     1468.499
poseidon             1051.519      962.365
pedersen             3915.226     3760.697
fibonacci-100k       1881.557     1572.172
factorial-100k       2495.791     2226.772
arithmetic-2m        3979.103     3320.931
memory-7m           10611.957     9075.963
```

The approximate frontend share was 12-13% for all-opcodes, 13-14% for
Poseidon, 78-82% for Pedersen, 37-46% for Fibonacci, 36-41% for Factorial,
49-59% for Arithmetic, and 54-64% for Memory.

`/usr/bin/sample` attributed the main active CPU stacks to the witness graph,
BLAKE2s commitments, Cairo AIR evaluation, and circle transforms. A true Metal
device trace was unavailable because `xctrace` requires full Xcode and the
active developer directory is `/Library/Developer/CommandLineTools`.

## Accepted: authenticated Pedersen point reuse

The Pedersen aggregator made 56 window-nine partial-EC deduction calls per
row. Each call recomputed fixed table points. Reusing the exact transaction
preprocessed table reduced complete proving from 3,915.226 to 1,509.376 ms on
CPU and from 3,760.697 to 1,369.378 ms on Metal.

The proof remained 769,097 bytes with SHA-256
`2f22237a78c26b5abaae644979c0caaf3fc7c8bf4587c8b2d050ff42acb71325`.

## Rejected: interpreter loop reshaping

Three interpreter experiments preserved exact proofs but failed the portfolio:

1. An instruction-major liveness-tiled SIMD interpreter made all-opcodes
   locally faster but regressed Arithmetic and was nearly neutral on Memory.
2. A fully expanded row interpreter increased code and instruction-cache
   pressure, regressing the large workloads by 8-11%.
3. Branch-free operand loading was neutral or slower.

All three implementations were removed. The result is evidence that the
successor must be generated/AOT code with backend-shaped storage, not another
generic interpreter switch arrangement.

## Accepted: direct canonical lookup feeds

The component breakdown changed the diagnosis. Memory 7m
`add_opcode_small` measured:

```text
component wall                  2524.950 ms
input materialization              5.526 ms
output initialization             115.268 ms
program execution                 176.498 ms
base lowering                      40.838 ms
feed retention                   2154.826 ms
```

The retained lookup feed was written row-major and then transposed into the
column-major interaction layout. The candidate:

- emits canonical column-major lookup words directly;
- matches the existing Metal generated-witness layout;
- transfers lookup and subcomponent ownership into the producer graph; and
- skips clearing outputs only when static straight-line coverage proves that
  every destination is overwritten.

Partial writers have a regression test and retain zero initialization.

Memory 7m CPU fell from 10,115.634 to 7,140.352 ms in the direct layout screen,
then to 7,039.236 ms after safe clear elimination. The final portfolio row was
6,888.709 ms. Metal fell from 8,702.380 to 5,679.277 ms before the clear
refinement and measured 5,069.174 ms in the final portfolio.

## Final diagnostic portfolio

```text
workload             CPU ms     CPU gain    Metal ms   Metal gain
all-opcodes          1430.705      0.978x    1384.647      1.061x
poseidon             1069.266      0.983x     925.778      1.040x
pedersen             1528.133      2.562x    1355.564      2.774x
fibonacci-100k       1648.315      1.142x    1254.109      1.254x
factorial-100k       2156.506      1.157x    1775.236      1.254x
arithmetic-2m        2810.166      1.416x    2044.014      1.625x
memory-7m            6888.709      1.541x    5069.174      1.790x
geometric mean                     1.323x                  1.458x
```

Every pair verified with byte-identical proof hashes. Metal used 73-79
dispatches and zero CPU fallbacks. This is a one-shot diagnostic screen; it
does not satisfy the multi-round promotion contract.

## Next architecture

The profiles support four system changes:

1. Build-generated CPU witness writers keyed by collision-resistant semantic
   program identity.
2. General Metal AOT witness admission for live Cairo geometry rather than an
   SN2-only resident schedule.
3. One planned arena for base columns, lookup feeds, interaction outputs, and
   commitment ownership.
4. Backend interfaces for interaction and AIR evaluation so Metal does not
   remain a PCS-only accelerator.

The branch has not reached the 10x forcing target. The accepted work advances
the broad portfolio while preserving the exact proof protocol and identifies
the architecture required for the next order of improvement.
