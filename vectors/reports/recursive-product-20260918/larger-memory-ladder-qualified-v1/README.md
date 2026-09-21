# 16-address recursive ladder qualification

The maintained 1/2/4/8-segment CPU and Metal/AOT trees all pass, with independently
admitted workload statements, topology and keys. Producers exit before fresh
verification. All 78 key/claim/proof artifacts are identical across backends.
The 1,110 checks comprise the complete node gates and two focused
genuine/alternate-statement calls per node. The alternate seed retains the same
boundary topology and wire lengths, and is rejected under the original keys.

The final parent keys were derived before root candidates existed. Intermediate
proofs required by setup were freshly verified. See the per-rung key-setup
reports. A single-segment root needs no parent proof.

## Measurements

Single observations, excluding compilation, lock waits and hostile cases from
production times. RSS is process peak memory; root verification uses the
standalone CPU verifier. These are not statistical speedup claims.

| Segments | CPU production (s) | Metal production (s) | CPU/Metal peak RSS (GB) | Root proof (MB) | CPU/Metal root verification (ms) |
| --- | ---: | ---: | ---: | ---: | ---: |
| 1 | 8.686 | 6.634 | 2.897 / 2.569 | 2.482 | 73.93 / 74.12 |
| 2 | 28.882 | 21.940 | 4.077 / 4.525 | 2.419 | 67.27 / 65.16 |
| 4 | 69.502 | 49.595 | 4.085 / 4.533 | 2.288 | 64.09 / 66.01 |
| 8 | 145.881 | 106.461 | 4.086 / 4.533 | 2.297 | 66.65 / 65.65 |

## Replay and development loop

1. Export execution-model-checked expected statements and topology with
   `recursive-segment-v2-leaf-key-setup --export-workload CONFIG SHA256 NEW_DIRECTORY`.
2. Derive leaf keys with the pinned `setup-manifest.json` emitted by that command.
3. Run `scripts/riscv_segment_v2_tree_key_setup.py` with pinned tree inputs,
   leaf-key receipt and producer/verifier binaries. It emits admission.json
   without a candidate root proof.
4. Use `scripts/riscv_segment_v2_detached_tree_gate.py` with the pinned admission
   and CPU or Metal binaries. The normalized admissions and their dependencies
   are retained under admissions/ and inputs/. Original binary hashes, arguments
   and local proof paths are in the tree reports.
5. Use `scripts/riscv_segment_v2_statement_substitution.py` for two fast verifier
   calls per node against retained genuine proofs and independently admitted
   alternate-seed inputs. This avoids repeating the malformed-proof suite.

The implementation patch records the current src/scripts/build/design changes
against the base commit in summary.json. Per-role executable and admitted-input
hashes are retained in setup/tree reports; protocol compatibility is checked
through actual independent verification, not equated with build provenance.

## Scope

These workloads touch 16 memory addresses and retire 35/98/227/482 instructions
for the four rungs. They exercise authenticated memory continuation and recursive
root publication, but are small development receipts, not Ethereum workloads or
production-security qualification. Native fixed-table and all 29 typed parent
interaction dispatches are confirmed in device-dispatches.json; parent Poseidon
and range-provider interactions still use CPU generation.
