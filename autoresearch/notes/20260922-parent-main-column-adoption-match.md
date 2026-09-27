# Parent adopts final BLAKE3 hash columns

Task: finish destination passing into the native parent, retaining canonical
transcript/path order and independently generated fixed preprocessing. Use the
qualified Layout before live emission to allocate combined G/XOR domains once.
Owner holds zero-padded main columns plus generated metadata; transcript/path
adapters borrow disjoint metadata and logical column ranges. Final assembler
checks metadata against independent fixed rows and transfers main ownership only
once every fallible assembly step succeeds. No main-row projection in this mode.

Canonical mapping: destination-passing construction and linear ownership transfer;
no traversal, cryptographic, security-profile or asymptotic algorithm change.
A row-emission mode remains a diagnostic oracle in the same State builder. The
normal entry uses final columns. Memory improvement is a hypothesis: metadata
currently retains full zero-main row storage and columns live earlier. Measure
peak allocation, do not infer a speedup from fewer projection passes.

Invariants: exact domains/logs/offsets, zero padding including G lookup padding,
independent fixed suffix admission, input inventory, shared allocator identity,
failed finish retains columns, successful finish invalidates column ownership,
metadata lifetime outlives borrowers. No double free through State destruction.
Validate full column/fixed parity against the row oracle, bounded threaded handoff,
real proof/key/codec identity and mutation rejection. Keep production profiles,
multilevel/Metal/core-default migration and latency qualification separate.
