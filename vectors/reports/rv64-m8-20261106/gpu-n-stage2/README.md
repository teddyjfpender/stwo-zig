# m8-gpu-n-stage2: native Stage 2, device seal, device encoding (piece of rv64-m8-gpu-native.md §3.2/§3.5/§3.6)

Branch `codex/rv64-m8-gpu-n-stage2` (from `codex/rv64-m8-gpu` @ 28ae81a58). GPU receipt: `gpu-tests-01.json`.

## Landed (behind the GPU-native path only; default path untouched)
| piece | files | evidence |
|---|---|---|
| device ProofEncoder (H11/H13): exact `WP.encodePhysical(decodeWords)` bytes into the slab region, plus `pcs_status` / `encode_bounds` words | `NAT/rv64/jobs/native_encode_proof.cu`, `rv64/jobs/native_encode.zig` | [M] 8/8 shapes byte-identical, 76/76 faults rejected, 1.07-1.92 ms GPU/proof vs 131-233 ms host (synthetic, segment-scale) |
| device checks (H10): `root_match`, `global_status`, `composition_accept`, `channel_order` (words_zero), `public_claims` (RAM boundary reduction), felt patch | `NAT/rv64/jobs/native_encode_checks.cu` | [M] parity + negatives |
| device seal (H8): m6_v2_gkr chi chain from exchange root slots, `global_seal`, seal slot publish; `drawShared` on device | `NAT/rv64/jobs/native_seal_chi.cu`, `rv64/jobs/native_device_stage2.zig` | [M] chi and 63 shared felts equal the manifest authority |
| Stage2Job / SealJob / Factory / ClassFraming, Stage-1 handoff contract, `native_device.zig` stage2/seal hooks | `rv64/jobs/native_device_stage2.zig` | host type-check only (no end-to-end GPU run yet) |

## Not done (honest)
- `oods_constraint` on device: needs a point-eval instance of the AOT composition codegen. Its word stays `unset`, so publication refuses.
- Stage 2 end to end on real segments: needs n-stage1's handoff regions (checkpoint, binding, semantic) and a warm-built `ClassFraming` per class.
- PCS framing section 15 / scope identity were host-rebound per request on the hybrid path; not yet verified as unused on device.
- Truth MAIN roots have no exchange slot (interface request filed).
