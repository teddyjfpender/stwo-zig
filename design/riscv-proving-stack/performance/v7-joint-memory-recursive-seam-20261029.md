# Joint memory recursive verifier qualification

**Historical seam result superseded:** the first outer-parent attempt rejected
the interval challenge link. The native epoch draws the two interval challenges
with two separate hash blocks; the initial recursive prefix incorrectly batched
them. A later mix reset hid this from final-channel comparison. No incorrect
parent proof was accepted. The corrected prefix uses explicit single-half output
roles, and the focused regression compares every exported challenge limb before
any reset, plus duplicate/missing-half routing checks. The outer parent remains
unqualified until its corrected genuine test passes.

The memory proof combines RAM shards, initialization intervals, range16 and
terminal reads into one original heterogeneous STARK, before recursion. The
original public transition relation stays open until the independently proved
native/caller source closes it. This is not an Ethereum-block completion claim.

The hardened original fixture uses five RAM shards, 16 guest memory events and
13 terminal reads. Its original proof is 99,491 bytes. The qualification uses
execution epoch version 3, joint layout/protocol version 2, and the first-halt
RAM constraints (88 main columns, 161 equations, 29 physical claim planes).

The ReleaseSafe genuine-capture gate passed on 2026-10-29:

- Destroy producer matrices before verifying the original serialized proof.
- Rebuild original fixed columns from independent ELF/terminal policy.
- Retain an owning verifier capture, without depending on original proof storage.
- Reconstruct exact commitment geometry and sample masks from original components.
- Evaluate the joint composition, DEEP and FRI circuits on the genuine capture.
- Require identical live and independently compiled fixed transcript plans.
- Change the first-round root, epoch and physical claim operands; the admission
  identity changes, while the fixed transcript plan remains identical.
- Reject compensated physical-claim changes that preserve aggregate closure.

Reproduction:

```sh
python3 scripts/zig_protocol_test.py \
  src/frontends/riscv/block_v7_memory_joint_test_root.zig \
  -OReleaseSafe -fstrip \
  --test-filter 'v7 joint original memory STARK'
```

A dedicated exact parent adapter and complete cold fixed-roster compiler now
exist. They reuse the original arithmetic, hash paths, PCS openings and public
wire equations. The detached receiver also rebuilds the original policy-fixed
commitment: geometry alone would not authenticate the contents of fixed columns.
The separate parent test is the next qualification boundary; the seam result
above does not certify its outer proof until that test passes.

```sh
python3 scripts/zig_protocol_test.py \
  src/frontends/riscv/block_v7_memory_joint_test_root.zig \
  -OReleaseSafe -fstrip \
  --test-filter 'v7 joint memory independently keyed'
```

Neither test is a performance measurement. Production canonical security,
complete v7 native/caller/global-provider recursive closure, and Ethereum-scale
root throughput remain separate obligations.
