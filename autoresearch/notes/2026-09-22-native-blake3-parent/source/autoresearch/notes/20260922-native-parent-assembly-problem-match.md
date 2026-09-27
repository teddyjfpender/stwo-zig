# Complete native BLAKE3 parent assembly

Task: assemble the native VM, DEEP, FRI, public-boundary and global-cancellation
graphs and all prepared hash, byte, query and scalar rows into one parent STARK.
Canonical problem: typed DAG lowering plus exact producer inventory. Reuse the
existing arithmetic lowering plan and typed AIRs, with a dense per-graph node
bitmap to reject duplicate/missing producers in O(nodes+rows). No fallback may
turn missing private inputs into public constants. The remaining VM inputs are
explicitly the segment selector (fixed to one) and detailed physical claims
(private, constrained by aggregate reduction and composition).

Replace superseded challenge, claim and sample rows exactly once. Retain every
private payload's packing/encoding consumers and all path aliases. Materialize
arithmetic with the existing plan, including constant and zero-output terms.
The initial gate uses the established typed CPU BLAKE3 proof harness: complete
LogUp cancellation, real proof, independently reconstructed preprocessing,
wrong-key rejection and core verification. This qualifies a native child parent
at diagnostic parameters, not a reusable production key or parent-of-parent.
Falsifier: any missing producer, wrong multiplicity, unsatisfied constraint,
nonzero lookup total, or failed independent proof verification.
