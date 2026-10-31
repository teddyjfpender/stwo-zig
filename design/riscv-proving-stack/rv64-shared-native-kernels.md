# Shared native row and prefix kernels

This slice shares bounded CPU scheduling and native field prefix mechanics. It
adds no instruction machine, constraint factory, policy enum, transcript or GPU
backend. Component row arithmetic, admission, immutable inputs and final owner
transfer remain concrete.

| Operation | Shared authority | Concrete adapter responsibility |
| --- | --- | --- |
| Physical MAIN rows | `providers/native_fill.zig` | Row formatting and typed input validation |
| Histograms | Same kernel: private per-worker arrays, checked ordered merge | Bin sizes and required positive masses |
| Native interaction waves | `providers/prefix_waves.zig` | Chunk arithmetic and physical prefix correction |
| Summary scan | Same kernel: logical ordered field addition and total subtraction | Number of independent carried quantities and ledger checks |
| Ownership | Source retains provisional output until success | Publish INTER and retire metadata only after both joined waves |

The first MAIN adapters are BINARY and CPU. BINARY has one 65,536-bin histogram
with mass `8N`. CPU has 65,536 U16 and 256 U8 bins, each with mass `3N`. Both use
16-row aligned contiguous physical partitions. Their row callbacks are invoked
once per range; the kernel does not dispatch a callback for every instruction.
BINARY additionally establishes its private logical metadata pages before the
start gate. All helper submissions and histogram allocations finish before any
row formatter starts. A partial submission cancels and drains waiting helpers;
borrowed MAIN remains untouched on this failure. Post-join histogram errors
leave histograms unpublished; provisional row output must be discarded.

Each component supplies its exact numerical chunk writer. CPU carries one field
sum. BINARY carries AND and FUNCTION sums and combines them into one physical
prefix. BINARY serial and pooled generation share one numerical chunk writer;
`generateSerial` retains the sequential reference path. Its dictionary inverses
and zero-weight padding poles are checked exactly as before. BINARY has four
paired AND inverses, one FUNCTION inverse and one combined prefix, for 24 M31
interaction columns. CPU remains 40 interaction columns. No MAIN is regenerated
when interactions are built after MAIN release or transfer.

The prefix driver retains caller-assigned logical chunks, including the CPU
round-robin assignment. It runs one joined wave, scans chunk summaries in
logical order, validates component ledgers, and assigns disjoint physical
ranges for the second wave. Every wave has a fresh WaitGroup and exactly one
`completeWave`; asynchronous helpers drain on submission or component errors.
One existing pool lease serves both waves. Each adapter allocates bounded
per-worker scratch once; there is no nested pool or global scratch. An error
can modify private output but cannot publish it or retire source metadata.

This first slice intentionally leaves ALU, SHIFT, LS and boundary adapters
unchanged while their qualified column/range reductions land. Their different
histogram layouts and prefix grouping can adopt these kernels later without
copying scheduling or summary arithmetic. No timing improvement is claimed by
the refactor alone; source cells, physical obligations and proof bytes must
remain unchanged.
