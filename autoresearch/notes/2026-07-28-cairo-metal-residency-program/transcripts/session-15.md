# Session 15 — increment 3.14, the aggregator geometry regression

Implementation: Claude Opus 4.5. Orchestration: Claude Fable 5.

## Reproducing it took two minutes; the diagnosis took the hour

The crash reproduced immediately at `167e5d30` on both aggregator workloads with
the hook off, which already told me something useful: this is not a device-path
bug at all. The hook only changes who evaluates the composition polynomial, and
`ClaimGeometryMismatch` is raised inside witness execution, long before that. The
brief said "hook-on AND hook-off" and the reason that matters is that it narrows
the suspect list to the arena-planning branch — the only Metal-vs-CPU difference
that runs before the witness does.

The diagnosis then went sideways for a while because I tried to reason about
`poseidon_builtin` from the topology and the claim, and the numbers refused to
make sense: 512 producer instances, `poseidon_aggregator` at log 4. A factor of
32 with no factor of 32 anywhere in the topology. I nearly convinced myself the
feed edge direction was inverted.

What broke it open was going to the code that actually computes a derived
component's row count rather than the document that describes the feed graph.
`live_graph.execute` dispatches on three cases, and the first two are different
kinds of derived input: `proof_plan.compactGeometry` and
`proof_plan.gatheredProducerEdges`. Reading `dependencies.zig` side by side, the
distinction is in the field names — `compactGeometry` carries `key_words`,
`iota_slot`, `multiplicity_slot`. It is a **sorted, deduplicated** LogUp
multiplicity table. Its row count is a distinct-key count. `gatheredProducerEdges`
has no such fields because it just concatenates.

That is the whole bug. 3.4's formula is right for gathered consumers and
meaningless for compaction consumers, and 3.4's classification table put all
thirteen deferred components in one list.

The +5 uniformity across all seven mispredicted components is what convinced me I
had it rather than merely had *a* story: 512/16 = 32 = 2^5, and every single
downstream log is over by exactly 5. A wrong fan-out multiplicity would have
produced a ragged error, not a uniform one.

**Lesson I would pass on: when a pinned document and the observed data disagree,
read the code that consumes the document.** The topology JSON was never wrong.
The topology says who feeds whom, which is a fact about relations; it says
nothing about whether the consumer deduplicates, which is a fact about writers.
3.4 read a relation graph as a cardinality graph.

## Why I did not try to predict the distinct-key count

There is a tempting version of fix (a) that computes the aggregator's row count
from the memory segment contents — count distinct poseidon input triples in the
prover input. It would even work. I did not do it, for a reason that is in the
module's own docstring: the no-copy commit source forbids a per-group contiguity
break, so an *approximate* count is worthless, and an *exact* count means
reimplementing the deduplication the witness writer performs, in a second place,
with byte-exactness as the acceptance criterion. That is a second source of truth
for a number that already has one. Refusal costs a fallback on two workloads.

## Fix (b) is the part of the brief that mattered, and I nearly under-tested it

The brief asked for the cross-check "as soon as the witness-to-statement handoff
would produce it". I spent a while looking for a pre-execution place to put it and
there is not one — the handoff *is* inside `base_trace.buildInto`, per component,
at `source.paddedRowCount()`. So the recovery has to be a retry of the build, and
the question is whether the failed planned attempt leaves anything unsafe behind.
It does not: `Collector` is `defer`-deinit'd, the geometry and arena are
caller-owned, and no commitment or channel state exists yet. The retry is clean.

What I nearly shipped without was **evidence that it fires**. Fix (a) removes the
only known trigger, so after fixing (a) all seven workloads pass and the degrade
path is dead code with a comment claiming it works. That is exactly the shape of
the failure this increment is about. So I built a control binary with fix (a)
disabled by `if (false and …)`, confirmed the arena *engages* on the bad plan, and
confirmed both aggregators still prove to the correct CPU digest with
`base_trace_arena_geometry_declined` recorded. Then I restored the fix, rebuilt,
and `cmp`'d the reinstalled binary against the one that produced the verification
rows to prove the experiment left nothing behind.

I gated the recovery on `oracle_predicted` rather than making it unconditional.
Unconditional recovery would have quietly swallowed a real geometry bug in
`deriveFromProverInput`, and the brief is explicit that fail-closed abort survives
for the case neither predictor caused.

## The corpus trap

`memory-7m` failed on both lanes with `InvalidOutputSegment`, which for about a
minute looked like a second regression. It is a broken fixture: there are two
memory-7m prover inputs on this host, 299 MB each, written eleven minutes apart,
and the 3.13 gate used the one outside the corpus directory. I recorded the
working path in the §7 checklist because the next agent will otherwise reach for
the corpus copy, as I did.

## Cost note for whoever measures next

The two aggregator workloads' first hook-on runs took 69 s and 74 s of prove time
against ~1 s hook-off. That is 3.13's cold-archive cliff again — these workloads
activate poseidon and pedersen AIR components whose pipelines were not in the
on-disk `MTLBinaryArchive`. It is a one-time per-machine cost and it is *not* a
performance finding, but a successor who benchmarks these two rows cold and
reports the ratio will publish nonsense. Warm them first.

## What I did not do

- No re-audit of the ten non-oracle claims in 3.4 beyond the classification table
  itself; §8 of the note corrects the table from the code, not from measurement,
  except where a portfolio row measured it.
- `partial_ec_mul_generic` is left as a prediction with no measurement behind it.
  Closing it needs an `ec_op` workload, which the portfolio does not have, and
  minting one was outside this increment.
- No timing claims. Every run here is a cold single run.
