# First main-based RTX 5090 qualification

Base `6050903d0` (consolidated PR312), one RTX 5090, CUDA 12.8.93,
driver 595.91.07, SM120. RunPod CLI provisioned the pod at $1.19/hour;
reported total including storage is $1.207/hour against the $40 budget.
No API credentials are stored in this report.

All three PR311 real-device drivers pass all four Compute Sanitizer tools:
memcheck, initcheck, racecheck and synccheck. Resident sizes cover logs
2/3/4/8/9/10/16/20/22; full sumcheck covers through log20. Independent tail
batches cover 1/2/4/8 jobs, canaries, aliases and failure isolation. Numerical
arrays remain on device; compact validation readbacks are outside timings.

The unmodified tail harness initially failed: its coordination-stream D2H
could run before a compute-lane writer. Synchronizing after enqueueing D2H
cannot establish that ordering. Joining before validation readback fixes it;
a deferred-producer/immediate-read host regression covers the defect. Native
arithmetic kernel sources are unchanged. Original failure logs are retained.

The existing transform, Blake2s and FRI/PoW CPU-oracle smokes also pass.
The new calibration harness reports 3 warmups and medians of 11 CUDA-event
samples, with allocations/initialization outside timing and no hot array
uploads/downloads. Domain inputs are synthetic nonzero values; this is kernel
calibration, not a cryptographic LDE/proof correctness or whole-prover claim.

| Kernel, log24 output / 32 columns / blowup log2 | Median |
|---|---:|
| LDE | 10.8033 ms |
| Blake2s leaves | 1.6638 ms |
| Merkle tree | 1.0105 ms |
| One QM31 line fold | 0.2785 ms |
| Deterministic 26-bit PoW control | 18.0151 ms |

There are 134,217,728 input coefficient cells and 536,870,912 output evaluation
cells. **LDE + leaf hash + Merkle = 0.1004 ns per input coefficient cell**;
LDE alone is 0.08049 ns/input cell or 0.02012 ns/output evaluation cell.
The separate denominators prevent a fourfold normalization error. PoW is
reported in ms, not cells, and the native OM31 candidate uses P0. Existing
QM31 FRI is only a control: it does not establish 128-bit OM31 PCS performance.

See `qualification.json`, `platform.txt`, raw logs and the exact build/run
scripts. The scripts use the session's explicit `/workspace` layout. No full
Ethereum GPU proof, GPU recursion or production promotion is claimed here.
The next work is actual witness/projection ingress, mixed-instance GKR and
OM31 resident PCS/composition followed by fresh complete-block reception.
