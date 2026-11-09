# Direct native-verifier groups (closed)

The existing four-member detached fixture spends56% of measured node proving
on three recursive folds. This experiment appends the complete source-owned
native verifiers to one context, then hashes their full frame digests through
the existing canonical adjacent-pair tree. It does not create or verify
intermediate recursive child proofs. Complete execution admission remains a
separate receiver obligation.

`source.Stream` accepts aligned groups of1,2or4 consecutive native members.
Each append validates ordinal/profile/manifest, reconstructs the PCS shape from
the concrete independent source key and emits into a caller-owned context.
Borrowed captures, statement arenas and native proof buffers expire after the
callback. Only circuit graph/value metadata survives. Builder scopes are entered
and exited per callback; they never stay globally bound while other workers run.
A failed append poisons the stream. Finalization and source-wide Var fanout close
once per group. The source-only and witness paths use the same emitters.

The dedicated production `emitInto` APIs preserve standalone operation order.
The truth production view now lives in `truth_local_gkr/leaf.zig`; the historical
test module reexports its exact type. The retained660,292-byte CPU/frontier leaf
still accepts under its independently rebuilt original source identity, and the
group-of-one source graph exactly matches the standalone graph.

The1/2/4 source gate includes power-of-two padding and all six R6 roles:

| Direct group | FIXED cells | MAIN cells | INTER cells | Total cells |
| --- | ---: | ---: | ---: | ---: |
|1|19,896,320|42,541,056|42,254,336|104,691,712|
|2|39,727,104|85,016,576|83,984,384|208,728,064|
|4|79,388,672|169,967,616|167,444,480|416,800,768|

The four standalone wrappers alone cost520,104,448 cells, including native OM31.
The direct group saves19.86% against those wrappers and eliminates all three
additional fold proofs. Their cells are not counted in that lower-bound saving.
This counts committed source trace cells, not LDE/scratch/RSS or proving time;
FIXED setup may be reused by identity. Numerical/source parity, canonical frame
digests and child ninth-limb refusal pass under a12GiB budget, with664.2MB peak
requested allocation and zero teardown. No physical group proof or block speed
ratio is established by this source gate.

```sh
zig build check-riscv64-op-native-group -Doptimize=ReleaseSafe -j1
zig build test-riscv64-op-native-group -Doptimize=ReleaseSafe -j1
```

The bounded physical gate now proves all four native verifiers directly. Its
711,340-byte proof takes44.984seconds after12.920seconds of cold source/key
construction. A separately rebuilt source key verifies it and rejects changed
output, corrupted proof, and an independently verified old-topology root proof.
The public root is identical to the retained seven-node tree. The old tree
encodes1,274,831,872 cells versus416,800,768 here (3.059x fewer), including all
three eliminated folds. Requested peak is9,296,996,721 bytes under32GiB, with
zero final live allocation. This is a fixture qualification during concurrent
engineering, not a controlled OP block timing or a whole-block speedup.
See `vectors/reports/rv64-opstack-cpu-20261109/direct-native-group4-physical-v1.json`.

Before promotion: complete independent
execution/coverage/terminal/output admission, bounded group selection on actual
source classes, composed security accounting and full OP measurements. Admission
stays closed and the security label remains a128-bit target under documented
assumptions, with `security_qualified=false`.
