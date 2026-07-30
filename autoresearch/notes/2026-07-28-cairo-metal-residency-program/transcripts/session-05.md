# Session 05 — increment 3.4: pre-execution geometry and arena activation

Implementation: Claude Opus 4.5. Orchestration: Claude Fable 5.
Head at start `73dc8790`, clean. Raw data `/private/tmp/i34/`, predecessor
binaries `/private/tmp/i34-pred/zig-out`.

## What I expected to find, and why I was wrong about the shape of it

The brief framed this as "the deferred set blocks the arena everywhere; find out
whether it is pre-computable". I took that framing at face value and started by
instrumenting `OwnedClaimGeometry.deferredCount()` and dumping the deferred set
per workload, because the brief was explicit that a negative audit was an
acceptable outcome and I did not want to write a resolver for a set I had not
counted.

The count immediately reframed the increment. arithmetic-2m: 29 components, 0
deferred. memory-7m: 32 components, 0 deferred. all-opcodes: 46 components, 3
deferred. The Phase 1.5 note's blocker was real but it was measured on
all-opcodes only, and the note says so in its own evidence table ("arithmetic-2m
and memory-7m were not run"). Two thirds of the benchmark portfolio never had
the blocker.

That has a consequence I did not expect and which I think is the most useful
thing in this session: **the arena was already engaging on two of three
workloads at `73dc8790`.** I only established that after adding the engagement
telemetry and running the *predecessor* with it — which of course I could not,
so I inferred it from the predecessor's `base_trace_arena_plan` stage duration
instead: 0.009 ms on all-opcodes (refused instantly, nothing allocated) against
20.964 ms on arithmetic-2m and 68.112 ms on memory-7m (allocation happened).
That is indirect but it is not ambiguous — a refused plan cannot spend 68 ms.
So increment 3.2's "landed-but-inert" was a one-workload conclusion generalised
too far, and my increment's genuine new activation is all-opcodes alone.

## Classifying the three deferred components

I did not want to guess the fan-out arithmetic, so I read it out of the
authenticated topology document rather than out of the Rust source. Grouping
`witness_feed_topology_v1.json` by feed target gives the complete fan-in for
every deferred field in the registry, and it is a DAG with one root per chain.
For the blake chain: `blake_round ← blake_compress_opcode × 10`,
`blake_g ← blake_round × 8`, `triple_xor_32 ← blake_compress_opcode × 8`.

The thing I had to get right was whether the multiplicity applies to the
producer's *real* rows or its *padded* rows, and all-opcodes happens to settle
it. `blake_compress_opcode` has 2 real rows (I checked the input JSON directly)
and pads to 2^4 = 16. Real: `triple_xor_32` = 8 × 2 = 16 → log 4. Padded: 8 × 16
= 128 → log 7. The witness reports log 4. So real rows, no ambiguity, and the
other two rows of the chain agree (20 → log 5, 160 → log 8, both matching).

I extended the classification to the whole deferred set rather than just the
three, because the same topology query answers it for poseidon, pedersen and
ec_op for free. All thirteen are pre-computable; there are **zero
execution-dependent** entries. The reason there is no range-check multiplicity
spill in the set — which the brief specifically raised as the thing that would
kill the route — is that every range check and every `verify_bitwise_xor_*` is a
`fixed` field in the pinned registry, so it was never deferred.

## The equality assertion I did not have to write

The brief asked me to run the deferred resolution as a checker and assert
equality against the pre-computed geometry. I went looking for where to put that
and found it already there: `live_graph.validateClaimGeometry` compares every
`.known` claim log size against the executed component's padded row count and
raises `ClaimGeometryMismatch`. Before this increment it skipped deferred entries
by construction; now those entries arrive `.known` and get checked like the rest.
So the resolver made an existing check *cover more*, which is a better outcome
than a parallel checker.

I want to be honest about what that check is and is not. It is fail-closed in the
soundness sense — a wrong prediction aborts the prove and cannot produce a proof.
It is not graceful: it does not fall back. I thought hard about making it
graceful and concluded I could not without weakening something I should not
weaken. The arena is the *storage* for the columns, so by the time a row-count
disagreement is observable the storage is already committed, and the landed
design deliberately makes that a hard error for exactly that reason. Converting
it to a detach would mean mixed column ownership (`arena_backed` is per-trace,
not per-column) and would mean relaxing `validateClaimGeometry`, which is the
check that the statement matches the trace. I decided the right place for
graceful degradation is *before* execution, so the resolver refuses on any
incompletely-determined closure and the product keeps the deferred path. That is
what the admission gate is.

The compensating evidence is that the parity test asserts against
`all_opcodes.claim_summary.json` — the pinned official claim — rather than
against my own measurement, so drift in the registry or the topology fails a test
rather than a prove.

## The headline, and where it stopped

The composition binding smoke does not pass, and I want to be precise about how
far it got because "failed" undersells it.

The library authenticates under the gating policy. `prepareEvalFromLibrary`
resolves a real component part's kernel *by name out of the approved metallib* —
`kernelName(part.semantic_hash)` hits, which as far as I can tell is the first
time in this program a composition pipeline has been resolved from the
authenticated AOT library outside prewarm. `evalPrepared` dispatches against the
resident arena. The host reference runs on the same arena words. The comparison
then reaches a value difference on the first word: expected 1825492331, found
1906854193. That is a convention disagreement in what I fed the two evaluators,
not a missing binding.

Getting to that point cost me the rest of my budget, and it cost it in a way I
did not predict: the first run aborted with `Invalid free` inside
`read_plan.deinit`. That turned out to be a genuine latent bug in product code —
`read_plan.build` returns `offsets[0..offset_count]` while `deinit` frees
`offsets`, and freeing a sub-slice of an allocation is invalid. A checking
allocator aborts on it; the product's non-checking allocator silently mismatches
the free length. The module's own doc comment says `offset_count < read_count` is
the normal case for captured Cairo components, so this was live on every Cairo
prove. I fixed it with a `realloc` and confirmed the three campaign digests are
unchanged, which is what makes it a free-length bug rather than a value bug.

I could have kept debugging the convention mismatch. I stopped because I was at
150 minutes against a 150-minute budget with a 130-minute stop-implementing
instruction, and packaging honestly was worth more than a coin-flip on one more
guess. I left the assertion live and failing. A relaxed assertion that passed
would have been actively misleading to whoever picks this up, and the failure
message localises the remaining work to three candidates.

## Where the test had to live, and why that is its own finding

I wired the smoke into the `else` branch of `src/tests.zig` next to the existing
metal tests, ran `test-native-metal`, and got "Ran 1 test" — the metal-only
branch. Then `test-cairo-metal-product`, which does not compile `src/tests.zig`
at all. Then I read the build graph: **no green step compiles that `else` branch**
— it is selected by neither `metal_only` nor `riscv_only`, and nothing sets both
false. So `eval_codegen_test.zig`, `arena_plan_test.zig`, `prover_test.zig` and
their neighbours compile nowhere and run nowhere today. The Phase 1 note flagged
this for `composition_aot.zig`; it is wider than that.

The brief forbids build changes, so I flagged it and put the test under
`metal_only`, which is the one step that both owns
`stwo_cairo_metal_integration` and filters the `metal:` prefix the test name
carries. `metal-test` has three other failures; I confirmed all three reproduce
at `73dc8790` in a separate clone before attributing my own.

## Measurement, and what I refuse to claim from it

A-B-B-A, cold, caches off both arms, warmup per arm, but **2 blocks not 3** — I
ran out of budget and the reduced protocol is stated in the note rather than
hidden. All three digests reproduce on both arms, all 16 timed samples give one
digest per workload, dispatch counts are unchanged (75/74/79), zero fallbacks.

all-opcodes 0.985x, arithmetic-2m 1.004x, memory-7m 0.876x. The first two are
inside their own arm spreads and the honest reading is "no regression". The third
I will not claim: its predecessor arm alone spans 4,466 to 6,431 ms (1.44x), and
host `loadavg` went from 4.74 to 11.72 across the run. A 0.876x point estimate
sitting inside a 1.44x arm spread is not a measurement.

The commit stage is the one I most wanted and least got: −2.79 ms, −2.24 ms,
+13.97 ms across the three. No win demonstrated. Two of those three rows had the
arena engaged on *both* arms anyway, so they could not have moved for this
reason, and all three deltas are far inside the noise.

The one piece of evidence I now think is cheapest and most valuable and did not
build: a counter in `circle_legacy.m` recording whether `source_is_base` actually
took the page-aligned `newBufferWithBytesNoCopy` alias or fell back to the single
memcpy. `main_trace_commit_arena_bound` proves the arena reached
`commitWithBacking`, but the whole point of the arena is the alias, and nothing
in the product currently observes it. Without that counter the commit-stage
mechanism cannot be attributed even when the timing does move.

## Commits

- `f064c6ef` — resolver, telemetry, parity tests.
- `84c403e0` — binding smoke (failing, deliberately), `read_plan` fix,
  reachability note.
- this note and transcript.
