# Shared CSP pipeline attribution

ReleaseFast CPU, 16 workers, canonical 70 queries / 26 PoW bits. One diagnostic
sample per configuration; these are stage attribution observations, not new
suite medians. Base pipeline now supports the same opt-in
`STWO_RISCV_EXECUTION_PROFILE=1` recorder as extension proofs.

| Stage (seconds) | ECDSA precompile | SHA-256/128 | Keccak/128 |
| --- | ---: | ---: | ---: |
| Main commitment | 0.093428 | 0.230813 | 0.496220 |
| Hash interactions | 0.132936 | 1.512027 | 2.379029 |
| Interaction closure/commit | 0.107530 | 0.242552 | 0.499350 |
| Composition evaluation | 0.291737 | 0.240920 | 0.521013 |
| Sampled-value evaluation | 0.017102 | 0.052014 | 2.393179 |
| Proof of work | 0.096500 | 0.022756 | 0.072972 |

SHA and Keccak profiled artifacts are byte-identical to the retained three-sample
suite artifacts and independently verify in fresh CLI processes. See commands,
binary digests and stage trees in `base-profiles.json`; build passed in `build.log`.
ECDSA uses the preceding product build; its profile is separate diagnostic evidence.

## Shared source findings

`framework_interaction.zig:generatePreparedOwnedColumnsTiledWithWorkspace`
evaluates every tile, performs its inversions and emits row sums sequentially.
`blake3_commitment_columns.zig:interactions` invokes this for each hash component.
The proof worker count does not parallelize these loops. Bounded independent tile
workspaces plus an exact global prefix scan are the next implementation target;
outputs must remain byte-identical, padding lookups must remain active, and all
started jobs must drain before failure cleanup.

The shared coefficient-retention budget is 1 GiB and admits whole trees, so larger
proofs can switch to barycentric evaluation of committed LDE values. In that path,
inner parallelism is currently disabled by default based on an older neutral A/B.
A same-binary Keccak diagnostic with
`STWO_ZIG_EXPERIMENTAL_PARALLEL_BARYCENTRIC_WEIGHTS=1` reduced sampled-value
evaluation from 2.393179 to 1.510870 seconds with identical proof bytes. It did
not affect the hash-interaction bottleneck. This single observation does not
justify globally promoting the switch; retain it as evidence for bounded work
scheduling and investigate the remaining sampled-value cost.

No proof parameters, hash equations, statement binding or default scheduling
policy changed in this attribution checkpoint. Original CSP performance remains
unrecovered; the broader recursion goal is active.
