# Problem match: reserve for proof allocations beyond the arena

**Task.** Choose the CUDA arena allocation type before proving while keeping
the exact proof graph and device-buffer authority unchanged. The existing
transaction selects managed memory only when arena bytes exceed current free
HBM minus a 256 MiB reserve. Fixed assets, kernel modules, workspace, and
subsequent allocations can make this guard insufficient near capacity.

**Observed boundary.** `15608951_15608963` has a 32,435,887,376-byte arena
reservation. With `STWO_CUDA_MANAGED_ARENA=1`, it reached trace commitment
in about 0.15 s but failed from CUDA allocation pressure in constraint
evaluation. Host-preferring the preprocessed Merkle tree had no effect on
that failure. The arena size is close enough to the 5090's usable memory
that the transaction may choose a native device allocation, where managed
placement hints cannot migrate pages. The allocation mode must be recorded
explicitly before drawing a firm conclusion.

**Exact experiment.** Add a `force` value to the existing opt-in managed
arena selector. The transaction then allocates a managed arena even if the
current free-memory estimate says a native arena fits; all normal source,
slot, stage, and proof validations stay in place. Keep `1` as its historical
"only when over the gate" meaning. Use the forced mode plus one cold Merkle
placement on the boundary PIE, and require the saved proof SHA-256
`76e224838a6b74695aab566f5a5de6391568cd9e8c82acda63039133ca23ffb5`
and a passing pinned Rust verifier.

**Falsifier.** If forced managed memory still fails, the issue is a genuinely
insufficient live working set rather than only the admission gate. A successful
proof must report HBM peak and full timing; this experiment alone does not
establish that forcing managed memory should become the default.

**Implementation correction.** The Cairo product uses a retained execution
cache, not the direct proof-transaction allocator. The first `force` trial
changed only the direct allocator and therefore did not exercise forced
managed memory in this CLI; its failure is not a capacity falsifier. The
execution-cache allocator now honors the same `force` mode and records the
chosen allocation type when memory-phase diagnostics are enabled. Retest on
that source before interpreting the result.
