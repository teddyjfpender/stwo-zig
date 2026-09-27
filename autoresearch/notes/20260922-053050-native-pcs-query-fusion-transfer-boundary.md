---
title: Native PCS query fusion transfer boundary
author: Teddy Pender
created_utc: 2026-09-22T05:30:50Z
---

# Native PCS query-binding fusion admission check

Task: determine how the existing typed PCS opening4 fusion transfers to native
BLAKE3 before changing arithmetic or routing constraints. This is a reuse of the
existing canonical dot4-first matcher, not a new matching algorithm.

Inputs: the actual native DEEP circuit, canonical InputBinding array, and graph
use counts including outputs/exports. The prior native fixture has 16,069 DEEP
nodes and 574 dot4 matches. Production scale remains unqualified.

Transfer: expose the existing read-only census over a graph/binding view so both
owned detached Prepared and native Circuit callers use one implementation. Keep
the old wrapper and all existing match semantics. Report eligible groups through
the existing native audit-only gate; do not select a new AIR yet.

Critical mismatch found in source: detached_pcs_opening4_v1 consumes
recursion_trace_query_value tuples, while native openings supply recursion_wire
scalars with extra consumers in packing/readonly authentication. Single use in
the arithmetic graph alone does not authorize deleting that native producer.
A native integration must conserve these external events or fuse their adapter
as well; the detached component cannot be dropped into the roster unchanged.

Validation: existing matcher/closure tests plus actual native-capture census.
Counts are structural opportunities, not removable native scalar rows or speedup.
This decision check determines the correct integration boundary for the next AIR.
