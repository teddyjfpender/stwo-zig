# Paired ordinary-memory scaling change (implemented and qualified)

Evidence from current source:

- runner/memory_state.zig captureImpl retains initialized/accessed union. Roles
  mark public input only in the first segment. Thus later segments treat the
  entire input as ordinary memory even when they access only a small subset.
- WordState.includeInitial/includeFinal describe ordinary root projections.
  blake3_commitment_witness.build currently also uses them to schedule all word
  lookup boundaries, including untouched private words at clock zero.
- blake3_commitment_shared_emit emits two independent shared sparse hash graphs.
  blake3_shared_path_emit authenticates each graph's private frontier separately.
- The first full-block leaf has88,687 boundaries and a2^24 G domain. Merely
  reducing cycle budgets cannot bound work if every leaf schedules all retained
  memory. Do not confuse the existing four-leaf stream test with this property.

Implemented design (qualification results in README.md):

1. Preserve full ordinary root projections and public-to-continuation custody.
   Emit lookup boundaries only for words accessed in this leaf (final_clock>0).
2. Prove BOTH root paths over one admitted union of touched addresses. Missing
   side leaves (public-input entry, public-output/completion exit) must be
   constrained to zero, matching ordinary projection; never private free values.
3. Authenticate identical private frontier digests for entry and exit through
   shared producer wire identities and summed fanout. This proves untouched
   subtrees cannot change. Independently hashing each root after pruning word
   providers is UNSOUND: it would allow invisible writes to unaccessed memory.
4. With no touched addresses, require equality of admitted ordinary roots.
5. Preserve independent schedule/root admission, change protocol/plan identity,
   and test malicious changed frontier, omitted access, zero/nonzero words,
   first/middle/final public custody, and actual resumed segment proofs.
6. Compare later block leaves, not only the first; verify recursion over those
   leaves. Then determine whether page-sized leaves or hash partitions are still
   necessary. Never simply raise the2^24 domain/memory caps.

Relevant implementation seams:
prover/blake3_commitment_witness.zig (boundary selection only; keep snapshot roots),
prover/blake3_commitment_shared_emit.zig (pair union and missing-side fixed zero),
prover/blake3_shared_path_emit.zig (shared frontier namespace/producer fanout),
prover/blake3_shared_path_topology.zig (canonical address-derived topology),
recursion/air/blake3_memory_custody.zig (existing public root restoration).

ZisK reference inspected locally: state-machines/mem/src/mem_planner.rs and
mem_module_instance.rs explicitly plan memory lanes and continuations. Its
memory state-machine architecture is not equivalent to our two independent
per-leaf Merkle graphs. This proposal is an adaptation to our authenticated-root
contract, not a claim that ZisK implements this exact multiproof.
