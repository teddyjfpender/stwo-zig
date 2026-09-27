# Rejected intermediate cache policy

The first candidate passed 23 focused tests, an ECDSA smoke and 48 canonical
comparison proofs plus 16 fresh verifications with unchanged proof bytes.
Overlap improved complete time by approximately 3–11% in this sample.
However, admission of large idle composition buffers raised observed process
peaks to 1.87/5.60/10.16/9.92 GiB across the four cases, in both arms.
The prior checkpoint measured approximately 1.74/4.53/8.04/7.79 GiB.
Those cross-checkpoint numbers are diagnostic, not matched causal estimates.

This version is not retained. The final candidate permits at most two active
plus idle residents, and caches only buffers of at most 128 MiB each. Larger
composition allocations are freed on release. Raw files and binary are kept
here for audit. Commands in receipts retain their original pre-archive paths.
Scripts were captured at their original three-level notes path; rerunning
archived scripts requires adjusting ROOT and artifact locations.
