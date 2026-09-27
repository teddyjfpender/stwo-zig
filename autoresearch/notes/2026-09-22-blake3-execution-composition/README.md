# Full-width execution composition and public closure

The successful BLAKE3 execution capture now feeds a single arithmetic DAG for
all native execution and BLAKE3 commitment components. Native instruction,
clock and lookup equations are replayed through their existing generic
implementations. Authenticated BLAKE3 direct/LogUp programs use the shared
composition graph recorder. Constraint order, count, quotient domains and split
composition reconstruction are checked against the same joined verifier roster.

Sampled values, detailed native/hash claims, all universal challenge pairs,
composition randomness and the OODS seed are graph inputs with explicit source
bindings. Public compensation reuses the native public LogUp arithmetic with a
symbolic scalar. Public statement values are specialized to the independently
admitted execution key; this graph does not claim key reuse across statements.
Full-width roots stay bound through the admitted commitment components. No
scalar-root projection or prover-owned Poseidon provider is introduced.

The output constraints assert the reconstructed composition evaluation and the
complete public-compensated relation sum. A retained preparation owns its input
bindings, evaluation and graph, sealed against the admitted key and successful
capture. Its graph uses the existing arithmetic lowering vocabulary.

Qualification uses the real four-instruction execution proof, decoded and
verified through the prepared API. Both graph outputs evaluate to zero. Changed
split-composition samples and detailed claims fail the graph equations, separate
from input/capture seal checks. Public LogUp legacy vectors, public I/O custody,
validation failures and the other shared statement/codec checks remain covered.
The diagnostic proof remains q8/PoW0; no parent STARK or canonical benchmark is
claimed by this qualification.

The same admitted component roster now determines DEEP geometry independently
of the capture. This includes unsampled columns, native current/previous masks,
typed previous/current masks, split composition columns and FRI-extended sizes.
The existing DEEP and FRI graphs evaluate the real capture; FRI preparation is
shared between the earlier native adapter and the full-width execution path.
DEEP-to-FRI answer routes retain explicit scalar use counts.

Transcript routing now joins all 47 universal challenge pairs, composition
randomness, OODS, DEEP randomness and FRI alphas to these graphs. Each transcript
export is consumed once before explicit scalar fanout and secure packing. OODS
feeds composition and DEEP from the same source. Detailed native/hash claims and
samples feed both composition and the transcript's canonical field-byte encoder.
Sample coordinates are shared with DEEP; their source weights include secure
composition consumers and one additional encoding consumer. Routing uses the
existing typed scalar, QM31 packing and field-byte AIRs.

The complete parent is still unfinished. These are prepared graphs and routing
rows, not a new parent STARK. Merkle openings, query/terminal links, the complete
parent roster and its independently authenticated key still need integration
and end-to-end proving. Continuation, distinct child/parent levels, extension/CSP
orchestration and production default promotion also remain unfinished. No speedup
or canonical-parameter recursion result is claimed.

## Qualification

`python3 scripts/zig_serial_build.py --cwd . test-riscv-blake3-execution-commitments test-riscv-statement-codecs -Doptimize=ReleaseSafe --summary all`

Both targets passed after the complete routing batch: execution 1 minute / 4 GiB
peak RSS, shared codecs 37 seconds / 1 GiB. These are build/test times. The real
execution test checks both mask orders, composition/public closure, DEEP and FRI
evaluations, sample packing, challenge fanout, and canonical claim/sample payload
encoding. Altered composition evaluations, detailed claims, shared samples and
exported transcript challenge values are rejected. Encoding fanout is checked
against the prior sample-only producer weights. Earlier composition and PCS
milestone logs are retained separately; `transcript-join.log` qualifies the final
source snapshot. No full repository test suite or performance benchmark was run.
