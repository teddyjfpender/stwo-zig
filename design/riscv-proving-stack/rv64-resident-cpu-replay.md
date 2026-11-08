# Bounded resident CPU replay

Status: CPU tests and production semantic checks pass. Real GPU proof parity,
GPU mutation tests and the large-block basket remain qualification gates.

The optional `STWO_RV64_GPU_CPU_REPLAY` policy is admitted only with the native
resident pool, device source, device terminal binding and deferred binding.
Default retained execution is unchanged for already admitted small blocks.

Stage one proves the original local GKR once. It then checkpoints the deferred
eight-column projection with GPU Merkle roots framed by the native-verified
binding authority, and releases both the MAIN coefficient lease and projection.
Only compact transport, the native GKR proof/artifact and its narrow terminal
state survive the global manifest barrier. Numeric witness columns never pass
through host parking or readback.

Stage two regenerates MAIN through the same source kernels and compares its
commitment with the original stage-one root before publishing coefficients.
It replays the original relation draws and projection, checks the exact native
source-channel boundary, and derives the projection from the saved authenticated
terminal state. The projection checkpoint must match before it can be finalized
into Eq/prefix columns. GKR traversal is not repeated; transcript, statement and
global-manifest bytes are unchanged.

CPU/JALR capture copies own only narrow transport. Normalized facts and RAM
events remain owned by the original capture until replay joins; the coordinator
then retires them. Each replay owner has an explicit release path, including
failed replay and poisoned-session host metadata cleanup. Session scope and
generation checks remain mandatory on every device view.

The coordinator charges compact transport, proof/artifact reserve, owner headers
and narrow binding metadata to its retained frontend bound. Replay contexts
also enforce a 24 GiB compact transport cap per device. The native device cap
remains unchanged; regenerated witnesses, transforms and GKR projection scratch
still require phase-local admission. No numerical MAIN/P8 inventory accumulates
with the total CPU worker count. Router scope slots still count CPU ordinals;
49 CPU workers fit the existing 64-slot policy.

Qualification before performance claims:

- unchanged root, projection checkpoint, manifest and all physical proof bytes;
- fresh independent receiver acceptance;
- changed replay root, terminal state, projection and scope rejection;
- cleanup and block-end zero request leases after success and failure;
- measured host/device peaks and full 15-block admission, including truth replay.
