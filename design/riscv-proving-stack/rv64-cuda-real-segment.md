# Real Ethereum segment GPU bootstrap and remaining resident work

Block 24,628,607, segment zero (4,194,303 retirements), now passes the existing
producer and fresh CPU receiver with GPU composition and PCS. The CPU proof is
byte-identical to the CPU control: SHA256
`9752fd800a763ea0cb528cebea5ec6282b159b8b0ad4697e1925de8e37e6c048`.
The prefix has one CPU proof and six truth proofs. It is not a complete block.
The exact profile is the default `conjectured128_b2_q108_p20_fold4`, not the
separate q256 documented-assumption profile or a security certificate.

| Measured operation on RTX 5090 | Result | Scope |
|---|---:|---|
| Real CPU0 PCS before native-height hashing | 224.409 ms | Resident GPU interval |
| Real CPU0 PCS after native-height hashing | 124.831 ms median, nine runs | Identical proof readback |
| GPU composition, 35 roles | 137.866 ms | LDE and joined constraints; three roles stay on CPU |
| MAIN + INTER native cells | 562,386,016 | Fixed and composition cells excluded |
| All four PCS coefficient trees | 667,400,960 cells | Separate denominator |
| PCS allocation counter | 12,681,778,464 bytes | Plus 240 MiB live native-height prefix scratch |

The 125 ms PCS interval is **not** the complete segment proving time. GKR,
trace construction, truth proving, native commitments and some composition
remain on CPU. The transitional boundary serializes coefficients to a helper
process; initial export/helper times were 1.21/8.67 seconds. Neither the fully
resident goal nor the complete-proof 150 ms target is established here.

## Integration

`build-rv64-ethereum-gpu` builds the same Ethereum producer/receiver with
proof-scoped callbacks. It does not implement a second statement or verifier.
`STWO_RV64_GPU_PCS_HELPER` selects the explicit GPU PCS operation;
`STWO_RV64_GPU_COMPOSITION_HELPER` optionally enables the joined GPU equations;
`STWO_RV64_GPU_WORKDIR` names temporary storage. Failure of a selected PCS
operation is terminal. The native receiver still checks every physical proof,
all local/global relations and the execution framing.

The PCS hook borrows native coefficients/points synchronously and transfers
owned native proof containers back to the existing prover. It validates roots,
configuration and mask shape before publishing the advanced channel. It is
restricted to native OM31/prefixed Blake2s, and rejects other revisions/fields.
The returned proof deliberately carries no auxiliary reconstruction data.

Real composition uses receiver-derived component metadata and the existing
typed constraint authorities. Native auxiliary columns are carry[8], first,
second, whereas the generated IR expects first, second, carry[8]; the adapter
permutes that boundary explicitly. The helper supports the original/native
and already-permuted framing as separate header flags. This fixes the first
combined-run constraint failure without changing equations or transcript.

Linux publication now opens a readable directory before fsync. The previous
path-only descriptor returned EBADF after the complete bundle was written.
The failure was reproduced independently; it was not suppressed.

## Resident path still required

The CPU/hybrid path is a reference and integration bridge, not the endpoint.
Remaining work is persistent in-process device ownership, GPU GKR and terminal
binding, compact-record trace expansion for all roles, GPU truth witnesses and
AIRs, and device composition bucket merge/interpolation/commit without host
readback. Source commitments must be constructed once, not repeated on CPU
and GPU. Large GKR scratch must retire before PCS capacity is admitted.

The GKR numerical-stage interface now preserves native verification of the
returned child proof/artifact/channel; it does not by itself provide the GPU
implementation. Full block/basket, resident lifetime accounting and aggregate
receiver qualification remain open. Four-GPU or ZisK-equivalent performance
has not been measured.

Evidence: `vectors/reports/rv64-cuda-real-segment-20261103/`. Full ReleaseSafe
services-GKR tests pass. GPU primitive checks were not repeated for unchanged
kernels; actual proof hash parity and fresh receivers cover this integration.

### Joined-domain coverage after the first real segment

All 49 joined CPU component layouts now pass native OM31 domain parity on
64-row fixtures, in both one-tile and three-tile launches (98 comparisons).
The formerly unbuildable case 41 uses 32 residuals per noinline root group
and canonical M31 atomic accumulation. This bounds compilation live ranges;
it does not change residual order or the native reverse-RLC coefficients.
Cached cases 43 and 44 are also included in the all-layout helper.

This qualification is separate from the first accepted real-segment receipt:
that historical run evaluated 35 components on the GPU and three components
on the CPU. Removing those three fallbacks is covered by the 49-layout
numerical qualification and host tests, not yet by a new full real-segment
timing. The measured hybrid path still writes coefficient jobs, reads quotient
buckets back, and merges/interpolates them natively. Fully resident bucket
lifting and composition finalization are a subsequent integration gate.

### Resident composition interface

`Scheme.device_om31_composition_stage` is the earlier composition boundary.
Its callback receives the actual alpha, geometry and native trace metadata and
returns a borrowed `device_pcs.Tree` whose columns contain scoped device
coefficient descriptors. The engine checks the native split count, coefficient
height, exact lengths, common owner and nonzero generations; it mixes the
returned Merkle root and forwards this virtual final tree directly to the device
PCS stage. It creates no dummy host coefficient polynomial. The stage owner
retains the descriptors and leases through the proof call. Unsupported field,
hash, revision, mixed host/device composition configuration, or missing device
PCS is an error.

The native `composition_role_on` entry launches the 49 qualified AOT layouts
under the existing context registry. `composition_finish_on` validates every
bucket and output before enqueue, zeroes a global accumulator, lifts independently
sized buckets with the native circle-domain index, and runs GPU interpolation
and splitting. Its coefficient output is already in native chunk/coordinate
order for the PCS device-column handoff. These entries are qualified against
native domain and interpolation fixtures; end-to-end resident segment
qualification is still required. Classic truth recording now uses the same
parameterized Keccak/secp equation authority with dense native OM31 residual
parity, not copied GPU-specific cryptographic equations.

The resident composition callback now drives these operations on the same
in-process service owner thread. It reuses scoped retained FIXED/MAIN coefficient
leases, constructs public auxiliary columns on device from narrow checked
transcript metadata, evaluates every admitted joined layout, retains the
composition coefficient lease through PCS, and reads back only its 32-byte
Merkle root. The callback is compiled and its numerical pieces pass their native
fixtures; a complete segment through this callback is the next acceptance gate.
It still accepts host coefficient ingress for columns not retained on device,
and CPU witness construction, binding, global-interaction generation and initial
commitments remain separate work. `log_blowup` must match the chosen PCS profile.
