# Focused Metal quotient experiment

These are **development-build diagnostics**, not the clean suite qualification.
The full ECDSA guest is identical before/after, with canonical CSP input and
70 queries / 26 PoW bits. CPU and both Metal variants produce the same artifact
SHA-256: `714d8e1d68db54f4b981a308029567cb7a1230841fadda6ae8cb45d1756770e5`.
The retained `.proof` files permit direct byte comparison.

The stage profile placed approximately 852 ms in FRI quotient construction and
commitment. Runtime diagnostics showed 307,395,600 source bytes, 14,338 columns,
45,014 sampled views, 21 batches and 2,097,152 lifted rows. The existing grouped
GPU kernel was declined because its 153,697,984-byte intermediate exceeded half
the source bytes by **184 bytes**. The direct kernel therefore reread short
columns over the lifted domain.

The selection now compares estimated evaluated cells: source-length × view-count
per group, plus lifted rows × group-count, against lifted rows × view-count. It
requires at least a 2× reduction, checked arithmetic and the existing 1 GiB
intermediate cap. No kernels, AIR, transcript, nonce, security parameters or
proof bytes changed. All quotient work remains on Metal.

The grouped kernel reduced measured quotient GPU time from 748.171 ms to
8.006–8.513 ms, and full guest execution plus proving from roughly 1.55 s to
0.814–0.818 s. Final timings come from the separate clean qualification reports.
