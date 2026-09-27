# Metal BLAKE3 direct leaf hashing match

Task and required semantics: hash canonical protocol prefix plus leaf-domain byte
and lifted canonical M31 words, retaining all 256 output bits on Metal.
Inputs/model: existing prepared leaf ABI has u32 column count and offsets;
per-column log sizes <= lifting log <31. Each thread owns one leaf.
Constraints: prefix is 28 bytes, fields are LE32; full and partial 64-byte blocks,
1024-byte chunks and unbalanced chunk trees must match CPU exactly.
Chosen canonical variant: unkeyed incremental BLAKE3, word-aligned input.
Mapping: stream prefix and one field per heterogeneous column into a chunk
state; merge completed chunk CVs by binary carry; retain final block for ROOT.
Complexity (derived): O(column_count) work, O(log chunks) private CV scratch.
A 25-entry stack covers ceil((UINT32_MAX+7)/256) chunks. This is per-thread
scratch, not a resident state allocation for every leaf.
Source: https://github.com/BLAKE3-team/BLAKE3/blob/master/reference_impl/reference_impl.rs
(section 5.1.2 stack algorithm; flags CHUNK_START/END, PARENT, ROOT).
Prior implementation: existing shared Metal compression and canonical CPU
BLAKE3 lifted Merkle hasher. Transfer algorithm, without copying Rust source.
Alternative: single-chunk special case is insufficient for wide traces;
materializing every leaf into temporary contiguous storage adds staging.
Selected boundary: prepared direct leaves only; staged incremental, FRI and
full suite admission remain disabled until their implementations are qualified.
Prediction/falsifier: no speedup claim; every GPU digest must equal CPU across
block/chunk edges, heterogeneous lifts, repeated plans and arena guards.
Correctness plan: widths 1,8,9,10,248,249,250,505,506,761,762,1017,1018,2042;
all rows, two inputs each, zero seeds only, reject incompatible domains.
Open uncertainty: occupancy/private-memory cost at production widths, wide
arena and staged leaf integration, full Metal proof performance.
