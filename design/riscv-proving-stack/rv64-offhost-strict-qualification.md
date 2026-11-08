# Off-host strict qualification of sealed resident cases

`scripts/rv64_resident_offhost.py` admits a copied case without rewriting its
original production plan. It compares the plan's canonical identity with the
sealed `produced.json`, hashes explicitly supplied local copies of the original
Linux driver and CUDA library, and independently pins the qualified CPU receiver.
Only the receiver upgrade and strict-verification strategy may differ under the
existing `production_identity` rule. I/O mappings never change expected hashes.

Supply a complete copied case including producer logs and `produced.json`, the
original plan and byte-identical request, and the two producer assets. Original
absolute guest/input paths must already exist locally with the pinned hashes.
The script preserves raw original plan/request copies and records all mappings.
Its operational request changes only `workers`, default 4. The default live heap
cap is 32 GiB; the qualified receiver's separate recycler contract is 4 GiB. A common
process lock allows only one receiver at a time. The caller owns staging and
queue execution; this script never starts a producer or uses a GPU helper.

```sh
python3 scripts/rv64_resident_offhost.py \
  --plan /local/original-plan.json --case /local/1gpu/BLOCK \
  --request /local/original-request.json --block BLOCK \
  --driver /local/copied-linux-driver --library /local/copied-runtime.so \
  --output /local/qualifications/BLOCK
```

The default receiver and SHA are the separately qualified ARM binary. An explicit
upgrade requires a new receiver path and expected SHA. Every selected production
pin, proof/tree snapshot and log hash is checked before launching the receiver.
The same strict process fresh-verifies native proofs and restores every recursive
node; the existing basket `check_trial` and `qualify_recursive_trial` gates are
reused through their shared-receiver override. Missing proofs cannot be generated,
repaired or relabelled warm. All original case files and provenance hashes must
remain unchanged afterwards; result acceptance is written only after those checks.

Receiver timing/RSS and the exact command, worker override, budgets, source pins
and path mappings are recorded separately from unchanged producer measurements.
Unit tests exercise mapped I/O authority, pre-launch plan/asset/input/proof
mutation refusal, one receiver invocation, artifact repair and new-proof refusal.
No heavy build or hardware qualification is needed to test this adapter.
