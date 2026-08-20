# Formal generated-Sail bridge: bounded parallel kernel build

Status: implemented and live-capture validated on 2026-08-12.

## Question

The generated-Sail publication gate compiles an exact 47-source Lean bridge
into a fresh temporary olean directory. The original runner followed the
reviewed dependency order serially, even though ALU, control, memory, shift,
and mul/div proof branches are independent after their shared foundations.
How can the gate expose that parallelism without weakening its fresh-build or
provenance guarantees?

## Design

`scripts/riscv_refinement_lib/sail_lean_bridge.py` now derives the local import
DAG from the 47 reviewed sources and validates that every local dependency is
earlier in the declared `BRIDGE_SOURCES` topological order. It rejects duplicate
module names and forward local imports before launching Lean.

A bounded scheduler then:

1. creates one fresh temporary olean directory, as before;
2. submits a source only after all of its local imports completed successfully;
3. writes each module to a distinct olean path;
4. runs no more than four Lean processes, additionally reserving approximately
   two logical CPUs per process on smaller hosts;
5. fails closed on any subprocess failure, timeout, empty closure, duplicate
   module name, or dependency graph that cannot make progress; and
6. aggregates command output in the reviewed source order, independent of
   completion order, before auditing theorem axioms.

The current graph has 47 nodes, 11 dependency levels, and a maximum independent
frontier of 11 modules. `Publication.lean` remains the unique terminal public
aggregation point.

## Evidence

The live pinned-backend capture built all 47 sources under the scheduler and
sealed the resulting generated-Sail monad receipt. During the run, independent
ALU, control, memory, and mul/div branches compiled concurrently, while the
terminal publication module began only after every imported publication branch
had completed.

Regression tests assert:

- all 47 sources are invoked exactly once;
- output remains in declared order;
- the real import graph is topological;
- the public module has the expected six direct publication dependencies;
- a forward local import is rejected; and
- worker budgets are bounded across host CPU counts.

## Claim boundary

This changes only proof-gate orchestration. It does not change Lean sources,
the generated Sail model, theorem statements, accepted axioms, the fresh olean
directory boundary, or what the receipt authenticates. Parallel tasks share no
output file; dependencies are admitted only after their producing process
exits successfully.
