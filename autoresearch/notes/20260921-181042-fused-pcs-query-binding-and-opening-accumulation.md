---
title: Fused PCS query binding and opening accumulation
author: Teddy Pender
created_utc: 2026-09-21T18:10:42Z
---

# Fused PCS query binding and opening accumulation

Task: replace a four-term arithmetic opening plus its four PCS queried-value input
bindings with one typed degree-two component. Preserve all trace-query coordinates,
QM31 weights, accumulator/output wires and exact lookup multiplicities.
Model: local graph rewriting with single-use intermediate elimination. The existing
opening4 matcher already proves the internal multiply/add nodes are unshared; this
extension additionally requires each queried-value input to have exactly one use.
Uses include graph outputs and cross-circuit exports. Shared query inputs are not
eligible and must retain their original PCS input bindings.

Candidates: bigger generic dot products (do not remove input-boundary traffic);
fuse query input binding with existing four-term accumulation (selected); rewrite
the full PCS protocol (much wider soundness change). Selected component consumes
four recursion_trace_query_value tuples, four QM31 weight wires and one accumulator,
and emits one QM31 output with its admitted multiplicity. Query M31 scalars multiply
individual QM31 limbs, so constraints remain degree two.

Transfer: compiler instruction selection / local DAG contraction with exact fanout,
following the specialized verifier-component approach in the source-pinned upstream
architecture comparison. The native PCS evaluateQuery already hoists batch-common
coefficients, so this does not claim that existing factorization as a new result.
No external implementation copied. Candidate matching is linear in graph and binding
size after existing opening selection, without an optimal packing guarantee.

Derived layout: 29 main + 22 preprocessed fields versus 54 logical fields for
opening4 plus four 26-field PCS input rows (158 total), when all four inputs can be
eliminated. This is a logical-field estimate, not padded committed size or time.
The fused component retains ten relation events; it also removes the four separate
input-binding rows. Actual eligibility/fanout must be measured before integration.

Plan: implement isolated typed AIR with pinned semantic identity, native arithmetic
parity, mutation rejection for every main coordinate and exact relation tuples;
implement conservative matching and census on an admitted real parent. Then wire
new identities/layouts into lowering, roster, CPU/Metal proving and fresh-key tree
qualification. Do not report unchanged-key proofs as verification of a new AIR.
Falsifiers: insufficient eligible terms, higher padded/lookup cost, fanout or source
binding loss, failed degree/parity checks, or no complete-proof improvement.
This checkpoint is not completion of fused recursion until that integration passes.
