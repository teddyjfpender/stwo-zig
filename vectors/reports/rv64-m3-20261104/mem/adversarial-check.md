# Stream mem: independent adversarial check (2026-11-04)

Checked head `9a68fa347`. Labels: **[M]** measured here, **[D]** derived, **[E]** estimate.

## Re-runs under the GPU lock (small blocks only)

These runs use the same stack the implementer handed to integration: driver `e99bbc7f`, lib2 `94b2cf19`
and receiver `38c70ff8`. The chunk sizes were chosen to force column boundaries the default 2^27 schedule
never produces. At the default size, each 2^24-row chunk holds exactly 8 columns, so the Blake2s pending
offset is always a multiple of 8. Here the commit and the PCS rebuild are both cut into odd chunks.

| Run | Chunk words (commit / PCS) | Max calls per tree | byte_identical vs v7 | Fresh receiver | Request wall |
|---|---|---:|---|---|---:|
| `26235156-2gpu-adv-odd3` | 50,331,648 (3 x 2^24) | 47 / 47 | **true** [M] | **accepted** [M] | 67.3 s |
| `24628607-2gpu-adv-odd7` | 29,360,128 (7 x 2^22) | 132 / 132 | **true** [M] | **accepted** [M] | 121.3 s |

Both runs match the v7 controls in every artefact: native bins, bundle, recursive tree, every recursive
proof and the root. The 24628607 wall is slower because tiny chunks multiply the state-bank traffic.
That is expected and says nothing about the default schedule. Receipts are `*-adv-odd*-receipt.json`.

## Code review findings

- **Stream ordering (no defect).** In the PCS rebuild, the LDE, `open_values`, the seeded Blake2s and the
  layers all run on lane 1, so reusing a chunk is ordered behind the reads of the previous one. The Zig
  commit path does the same on its lane 1 and joins before it releases any lease. `free_u32` joins every
  lane before `cudaFreeAsync`. Physical admission calls `sync()` before it evicts, and it evicts only
  blocks that are not `used`. Composition direct reads retained leases after `context.join()`; nothing
  releases a source between the coefficient phase and `domain_fft`. Preprocessed retirement happens at
  proof granularity.
- **Openings (no defect).** Values are column-major (`values[col*Q+q]`), so offsetting by `c.first*Q`
  is exact. Paths come from the finished tree. The rebuilt root is still read back and compared.
- **Fixed: explicit pool trim missed the long pool.** `stwo_exec_context_pool_trim` trimmed only the
  per-request pool, so pages freed from the long-lived pool stayed reserved after an opt-in phase trim.
  Fixed in `810b1f466`, nvcc-checked. Phase trim is off by default, so lib2 behaviour is unchanged. The
  fix is not yet in any built library.
- **Open (minor): physical admission overcounts.** `available = free + sum over both pools of
  (reserved - used)`. Unused reservation in the long pool cannot serve a scratch allocation. Use
  `stwo_exec_context_pool_split` and count only the target pool. This is likely part of the 4 remaining
  recovered OOMs.
- **Overclaimed test.** The host test "chunked progressive Blake2s equals one-shot" checks
  `std.crypto` Blake2s incremental update over the planner's ranges. It does not exercise the device
  kernel, the seed/absorbed fields or the lifting of seeds. The GPU byte-parity runs, including the
  odd-chunk ones above, are the real evidence.

## The 26235159 extrapolation

- Confirmed [M]: `4,211,082,218 x 4 = 16,844,328,872`. The same request appears on 24628607 (legacy) for
  the role 4/5 arena (eval_log 24), and the direct path cuts it to 2,810,184,682 words (11.24 GB).
- Slightly optimistic [D]: the baseline uses owner-retained 12.34 GB. The v3 forensic receipt measured
  pool used 12.66 GB at the first request, so headroom is about **5.6 GB**, not 5.97 GB.
- Ambiguous [D]: the v3 receipt shows pool used rising to 27.5 GB and then a later N2B status 2. The
  allocation may have succeeded after trim, with the failure in the following N2B. In both readings, more
  headroom at that point helps, but "0.37 GB which failed" is a reconstruction.
- Under-covered [E]: on 26235159 only 6 of 149 outer nodes completed. The fold/truth nodes and the rl+2
  role (18.44 GB arena plus about 4.4 GB of leases, about 22.9 GB) have never run at that size. The
  "22-23 GB per-node peak" is an estimate for the first failure point only, not a fit proof. The ordered
  scale-up must still stop on the first failure.
