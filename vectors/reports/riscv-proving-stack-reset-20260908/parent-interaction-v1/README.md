# Parent interaction CPU comparison

Three alternating, cold-process baseline/candidate pairs pass 28 fresh checks
per request. All three serialized proof/key/claim artifacts remain identical
for every request. Median root request: 13.551693 seconds baseline versus
13.483111 seconds candidate (about 0.5%; no material improvement established).

The candidate reuses the existing batch-inverted Poseidon writer and adds
optional subphase attribution. One profiled candidate spends 2.121 seconds on
source tuple projection and 1.474 seconds on typed interactions, versus 0.0167
seconds on Poseidon interactions. The next optimization should follow those
measured costs. Metal candidate A/B is not completed.

`root-cpu-v2-paired.json` records all six accepted runs. Each adjacent command
receipt pins binaries, inputs, environments and the independently supplied
verifier/key. Producers exit before verification. `replay_roots.py` is the
checkpoint-specific replay driver, not a new supported proof endpoint; its
pending Metal candidate/bundle paths have not been built.

The initial CPU candidate is retained as an admission failure and excluded
from performance results. Compilation overlapped a temporary source edit whose
bytes enter the compact Poseidon AIR identity. Current native source was
restored, the candidate was rebuilt, and v2 passes all comparisons. The original
post-build snapshot explicitly records that it cannot identify the rejected
binary's intermediate source state.

See the [pause handoff](../../../../design/riscv-proving-stack/pause-checkpoint-20260909.md)
for the current source coverage, unfinished gates and resume order.
