# BLAKE3 staged state transfer

Task: continue canonical word-aligned leaf hashing across bounded column batches
and increasing lifted row domains without re-reading earlier columns.
Mapping: serialize the existing BLAKE3 incremental chunk state and binary-carry
CV stack; lift the saved state exactly as the earlier columns are lifted.
Known prefix length (seven words) plus first_column reconstructs filled words,
block index, chunk counter and stack length. No per-row counters are necessary.
For n>0 words consumed, filled=(n-1)%16+1, block_index=((n-1)/16)%16,
chunk_counter=(n-1)/256, stack_len=popcount(chunk_counter).
State layout: CV[8], pending block[16], live CV stack[8*stack_len].
Capacity bound (derived): 24+8*bit_width(floor((total_columns+6)/256)) words,
at most 224 words for the u32 column-count interface, typically much smaller.
Only live stack words are copied; final dispatch writes 8 digest words per row.
Source: previously qualified shared Metal BLAKE3 implementation and official
reference https://github.com/BLAKE3-team/BLAKE3/blob/master/reference_impl/reference_impl.rs
Alternative: a fixed maximum CV stack per resident row wastes memory; retaining
only a chaining value loses partial blocks and completed chunk-tree structure.
Chosen transfer: explicit state stride in a bounded compact-stage runtime ABI,
zero synthetic seeds, checked non-overlapping input/output state arenas.
Complexity: O(batch_columns + log chunks) work per row; O(log chunks) state.
Prediction: exact parity regardless of stage splits; no end-to-end speed claim.
Tests: partial/full block and chunk boundaries, changing lifting logs, multiple
chunk trees, poisoned unused state slots, final digest layout and arena guards.
Open: whole resident-tree scheduler integration and production occupancy.
