Pinned kona-protocol 0.4.5, Optimism commit
`a271fd6b3feb76e49f3453e5a27be4b33a3c7211`, path
`rust/kona/crates/protocol/protocol`. Original manifest is retained as
`Cargo.toml.upstream`; inherited package/dependency settings are resolved in the
standalone manifest. Upstream MIT license and repository license are retained.

The default decompressor algorithm and eager allocators are unchanged.
`stwo-lazy-brotli-alloc` selects safe demand-initialized owned buffers, with the
same per-type maximum live cell capacities (32 MiB u8, 1M u32, 4M HuffmanCode).
Allocation initializes every requested element; drop returns its exact logical
reservation. This preserves capacity limits but does not reproduce fragmentation
of the previous fixed contiguous pool. There is no uninitialized-memory policy.

`stwo-brotli-census` is native-only bounded diagnostics. It captures at most 32
calls and 64 MiB of actual input plus output bytes. Output size admission and
partial-stream policy still come from the unchanged decompressor. Capture
metadata is not an execution/proof authority. Neither feature is enabled by
default. New modules: `src/brotli_alloc.rs`, `src/brotli_census.rs`; feature hooks
are in `src/{lib,brotli}.rs`. Existing upstream tests are retained.
