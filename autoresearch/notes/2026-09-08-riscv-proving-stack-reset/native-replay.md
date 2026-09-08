# Retained native segment19 diagnostic

Prepared read-only on 2026-09-08 at checkpoint `87a3965f`. No native replay, build, controller resume, or parent proof was launched. This is a single diagnostic of the functioning native route; accepted campaign artifacts remain immutable.

## Existing measurement and decisive question

The original producer request is `.git/local-ethereum/retained-campaign-v2-rw-heap-121x2097152-20260907/metal-field5-block-v2/attempts/leaf-000019-0000/request.json` (SHA256 `15fb81cfa70583fda5df4d24eca0fe8547ec12a6490277434fcc08b367d90c09`). Its sibling `stderr.log` records:

| Measurement | Original result |
|---|---:|
| Complete native request | 544.138102292 s |
| Capture admission before producer | 102.717304750 s |
| Producer | 387.470816792 s |
| Prove within producer | 351.929739458 s |
| Composition evaluation within prove | 259.335809 s |
| Semantic Metal kernels | 86.391 ms |
| Lookup Metal kernels | 18.585 ms |
| Fresh CPU verification within request | 50.485271667 s |
| Lifetime peak footprint | 31,859,924,488 bytes |
| Metal dispatches / host fallbacks | 91 / 3 |

The roughly 105 ms GPU kernel totals do not account for 259 s composition wall time. They exclude host evaluation, allocation/zeroing, domain preparation, dispatch setup, transfer/synchronization, joining workers, merging and finalization. The new run should distinguish these before selecting a rewrite. The existing lifetime peak reported again in the verifier phase is not verifier-only memory. The later standalone accepted verification measured about 1.32 GB peak; do not substitute it for this whole request's memory.

The selected segment covers global cycles `[39,845,888, 41,943,040)`, exactly 2,097,152 cycles, in the 121-segment campaign. This request replays authenticated retained execution; it does not rerun the whole Ethereum block or mint a new accepted campaign leaf.

## Retained identities and reuse

The original product is `.git/local-ethereum/prepared-leaf-metal-product-v7/bin/ethereum-prepared-leaf-metal-v1`: 11,098,000 bytes, SHA256 `9b16b0ad0f6cba79aa7582bb634055d43845bcb1f91781daaece8f7f1da53e1b`. Its `build-receipt.json` records ReleaseSafe, successful build and source checks before/after; source manifest `.git/local-ethereum/prepared-leaf-metal-source-v7/manifest.json` is `3b9ab4c9b99a6de7de90d49168d898c6e4dad4cb35d26fe49888b05ba3c3a6ec`. All **5,759** files in that frozen manifest were rehashed during this investigation, as were the product, build log and identities below. The frozen product supplies the measured baseline but cannot emit newly added instrumentation.

| Retained input | SHA256 |
|---|---|
| `authority/materialization-v2.json` | `e9d9ba5619d5780155bf7f23e3475a1af0aae85ec74a0660b837c0cdbb237f4e` |
| `sources/segment-000019.stwesg31` | `756008c8752199a5a319af2bd6c28acf3ea53d4c5cabc720c77ebc748fee8beb` |
| Segment19 compact tape, 15,251,277 bytes | `5925fc49cbfbc6599c570746a6e6009f442e6e95577bdd7d6dc108d18791f488` |
| Segment19 public wire, 59,745,824 bytes | `e02293a6d387a287be2dff4a94120c3b20db0359eac24fec992970b6309cf209` |
| Selected admission JSON, 28,530 bytes | `0ffaff40cb8d7f590e268190b8dbc9d5a0e29187eb19521a45d37569e81f4b3f` |
| Original accepted proof, 72,328,554 bytes | `0db6f28766333703ed2f55d6f16757c28e0843c61db870d728455dce960046a6` |
| ELF | `f81e30505c2ae1ab16e693933bef65f6fbae94ca6e04b4bc66688a068cddce16` |
| AOT manifest | `320f1b944927e173c5d2972ab0cb69f68129d135f40838976c2cde653bf180c3` |
| AOT Metal source | `1c722c8e8541664962469e3277d21b98837b9e8c88c0141c887d0b6163b8b372` |
| AOT metallib | `9a32b36496d66eb0d0889949ec7f6d06f95a25d9aa6bd16695ca4d9e2d1f171d` |

The compact/publication inputs live under `capture/publication-parent/ethereum-incremental-capture-v4`; the selected admission and its six files live under `metal-field5-block-selected-admissions-v1/leaf-000019`, both relative to the retained campaign root above. Both copies of compact/public-wire bytes matched. Selected transition/reference file hashes are retained in the selection's own authenticated structure. Materialization's source request, execution journal, input and expected-output paths/hashes were also rechecked. Before launch, repeat these input checks, including ELF and every opened reference; this note is not an admission capability.

Reuse the existing AOT bundle `.git/local-ethereum/ethereum-fixed-program-narrow-aot-v1/bundle` when adding host timers only. The producer's `validateRuntime` requires authenticated AOT origin, exact manifest, nonempty metallib identity and the compiled `ethereum_fixed_program_narrow_v1.sourceDigest()`. That rejects a changed shader/profile against stale AOT. The planned instrumentation touches `base_polynomial_composition.zig` and `base_polynomial_host_graph.zig`; kernel/codegen profile stays unchanged. Recheck that final diff before the build. Do not rebuild the AOT bundle merely for logging; do not bypass its runtime admission if it rejects.

## Ownership boundaries to preserve

1. **Execution and retained-input admission:** `ethereum_incremental_full_leaf_replay_command_v4.zig:419` opens explicit campaign geometry; `ProgramV4` admits ELF and fixed-program ownership; `OwnedMintInputV4.openCanonicalBytes` and validation bind campaign, retained segment source, compact tape and public wire. `ethereum_selected_leaf_admission_v1.zig:58` opens and validates an existing selected receipt, then the caller cold-opens referenced transition/wire artifacts. This is the roughly 103 s capture preparation region, separate from composition.
2. **Prepared AIR and transaction:** the same replay command owns producer/CPU-verifier lifetimes and publication. The prepared profile supplies typed component provers and retained traces; `src/prover/prove.zig:510` owns the complete `composition_evaluation` stage. `src/prover/air/component_prover.zig:676` and `composition_execution.zig` carry execution policy, task recorder and composition-work capture to the backend without redefining AIR constraints.
3. **Backend runtime:** `src/integrations/riscv_metal/ethereum_prepared_leaf_metal_v1.zig:105` initializes authenticated Metal once, instantiates `ProverEngineForBackend(MetalCommitBackend)`, and shuts it down after the transaction. Its release hook checks unchanged runtime identity/lifecycle and actual Metal dispatch before publication. `runtime/backend_composition.zig` chooses the base-polynomial path; `runtime/base_polynomial_composition.zig:193` owns capability partitioning, resident-source checks, domain scratch, batch metadata, device outputs, host workers, joins, merging and finalization. `base_polynomial_host_graph.zig` owns the explicitly profiled host execution path; ordinary execution policy must remain unchanged for this measurement.

The important compositional boundary is typed AIR/component capability → execution request → backend-owned resident work. Keep source validation at ingress and retain owned scratch/output lifetimes. No new validation flags, driver-level protocol description or Ethereum-specific global worker policy is needed to measure it.

## Small build loop and diagnostic commands

After the two-file instrumentation review, use the existing backend test root:

```sh
python3 scripts/zig_serial_build.py --cwd src/backends/metal \
  test-composition-task-profile -Doptimize=ReleaseSafe --summary all
```

`composition_profile_test_root.zig` and `build.zig:135` select 12 existing tests covering host attribution, declined resident route, separate semantic/lookup buckets, allocation failure, dispatch barriers, wide offsets, partition parity and domain scratch. One barrier case uses the real Metal runtime; this is not an entirely device-free test target. A runtime logging edit belongs here, not in a recursive lifecycle root. If instrumentation adds a focused meaningful test, include its name in this existing filter; then record the resulting count rather than assuming 12.

Build the instrumented native producer using the existing integration target, after that gate passes:

```sh
python3 scripts/zig_serial_build.py --cwd src/integrations/riscv_metal \
  install-ethereum-prepared-leaf-metal-v1 -Doptimize=ReleaseSafe \
  --prefix "$PWD/.git/local-ethereum/native19-stack-reset-v1/product" --summary all
```

Pin the reviewed source revision/diff, successful build output and new executable before the diagnostic. If root freezes the reviewed source, use its `scripts/zig_serial_build.py` and integration directory in the same command. The new executable hash is intentionally not invented here. No additional option/AOT parser test is needed for a logging-only runtime edit.

The concrete rerun reuses the original argv, changing only the executable, proof/metadata destinations and a copied selected-admission directory. Run this **only once**, after root authorizes the reviewed instrumentation and the shared heavy lane is free. It uses the existing lock helper and ordinary subprocess lifetime; no controller or new runner framework:

```python
import json, os, pathlib, shutil, subprocess
from scripts.zig_serial_build import build_lock

root = pathlib.Path.cwd()
base = root / '.git/local-ethereum'
campaign = base / 'retained-campaign-v2-rw-heap-121x2097152-20260907'
original = campaign / 'metal-field5-block-v2/attempts/leaf-000019-0000/request.json'
run = base / 'native19-stack-reset-v1'
candidate = run / 'candidate'
candidate.mkdir()  # Must not exist: do not overwrite a prior diagnostic.
selected = candidate / 'selected-leaf-admission'
shutil.copytree(campaign / 'metal-field5-block-selected-admissions-v1/leaf-000019', selected)
argv = json.loads(original.read_text())['argv']
argv[0] = str(run / 'product/bin/ethereum-prepared-leaf-metal-v1')
for flag, value in {
    '--output': candidate / 'proof.bin',
    '--global-metadata-output': candidate / 'leaf.json',
    '--selected-leaf-admission-root': selected,
}.items():
    argv[argv.index(flag) + 1] = str(value)
env = dict(os.environ)
env.pop('STWO_ZIG_BUILD_HELD_LOCK', None)
env.pop('STWO_ZIG_RISCV_METAL_COMPOSITION_PARITY', None)
env.pop('STWO_ZIG_RISCV_METAL_SEMANTICS', None)
env['STWO_ZIG_STAGE101_STAGE_PROFILE'] = '1'
env['STWO_ZIG_RISCV_METAL_COMPOSITION_TIMING'] = '1'
with build_lock(label='native19-stack-reset'), \
     (candidate / 'stdout.log').open('xb') as stdout, \
     (candidate / 'stderr-and-time.log').open('xb') as stderr:
    result = subprocess.run(['/usr/bin/time', '-l', *argv], cwd=root,
                            env=env, stdout=stdout, stderr=stderr)
assert result.returncode == 0, result.returncode
```

The unchanged argv retains worker1, composition budget17,179,869,184 B, PCS retained budget25,769,803,776 B, host admission limit34,359,738,368 B, `authenticated-v1` campaign geometry and `fixed_program_narrow_v5`. Those values reproduce the admitted original request; the 16 GiB value is a composition allocation budget, not an OS process ceiling. Do not start another heavy task while this subprocess lives. Retain its terminal status even on failure and sample footprint separately if desired; no benchmark comparison should include queue time.

The opt-in instrumentation contract from its owner is `STWO_ZIG_RISCV_METAL_COMPOSITION_TIMING=1`, with `metal composition wall:` and `metal composition host:` markers. Wall phases should be nonoverlapping; worker spans and GPU milliseconds are overlapping supplementary measurements, not quantities to sum into total wall time. The flag must leave proof inputs, transcript, worker count and scheduling path unchanged. Verify the finalized marker names before launch.

## Diagnostic acceptance and stop condition

Require the existing complete transaction to serialize, destroy producer state, freshly verify on CPU and publish the candidate, including `ETHEREUM_PREPARED_METAL_V1 ... independently_cold_verified=true`, schema5, expected AOT identity, nonzero actual Metal dispatch and the full request resource line. Confirm emitted leaf19 metadata/public statement still match the retained campaign. The old accepted proof remains a regression artifact; byte identity is useful if deterministic but is not a substitute for fresh verification.

Freshly verify the diagnostic output with the already pinned standalone product, under the same existing lock after the producer exits:

```text
.git/local-ethereum/fixed-program-native-verifier-v6/bin/ethereum-full-leaf-bundle-verify-v1
  verify-leaf-fixed-program-v5
  .git/local-ethereum/native19-stack-reset-v1/candidate/proof.bin
  .git/local-ethereum/native19-stack-reset-v1/candidate/leaf.json
  .git/local-ethereum/retained-campaign-v2-rw-heap-121x2097152-20260907/authority/materialization-v2.json
  e9d9ba5619d5780155bf7f23e3475a1af0aae85ec74a0660b837c0cdbb237f4e
  --workers 1
```

Verifier SHA256 `7492946e72587e719cbd254de7b337bc381a63d62c4561eb61e6298c7e99c62c`, 3,681,536 bytes, was rechecked. Retain proof/metadata hashes before and after verification, actual receipt and terminal status. Do not invoke `accept_candidate.py`, publish into accepted inventory, resume the controller, or reverify0–18: this is a diagnostic candidate only.

Stop after one functioning measured replay and its verification. Attribute the dominant composition wall interval, then choose the smallest change at its owner boundary. Missing telemetry, rejection or resource failure is evidence to inspect, not permission for another long undifferentiated rerun. The saved parent request stays unlaunched during the reset.
