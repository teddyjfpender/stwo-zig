# Recursive framework resident composition

This work continues the strict Metal goal from `5385283a`. It does not establish
a GPU-only proof: Poseidon/range providers and bulk witness/interaction work
remain distinct coverage requirements.

The maintained `test-riscv-metal-recursive-aot` command authenticates the exact
shared leaf/parent catalogs and regenerates or checks the extension. The new
`recursive_framework_v1` AOT profile appends 41 kernels to core, covering 37/39
leaf and 29/31 parent components. Rows 34/35 remain explicitly unsupported in
its coverage report. Generated kernel identity excludes physical column
placement; the admitted job still binds every physical column and parameter.

Runtime dispatch binds existing committed or composition-domain buffers directly.
It checks exact runtime ownership, logical tree selection, offset/extent and
parameter windows before submission. Domain groups close over all referenced
columns in each expanded tree, including columns already at the target size;
these are re-evaluated from retained coefficients, never relabeled. The shared
twiddle tower supplies borrowed smaller views rather than repeated preparation.

The new bundle is local under
`.git/local-riscv-proving-stack/recursive-framework-aot-m4-v1`, with manifest
`0e8b67dc70c8d699ba155f16a6fedcd8541c4615326796c7c120c62a64646403`.
`aot-bundle-pin.json` records source, AIR, manifest and metallib measurements.
The standalone test requires this explicit bundle/profile and manifest pin:

```sh
STWO_RECURSIVE_FRAMEWORK_AOT_BUNDLE="$PWD/.git/local-riscv-proving-stack/recursive-framework-aot-m4-v1" \
STWO_RECURSIVE_FRAMEWORK_AOT_MANIFEST_SHA256=0e8b67dc70c8d699ba155f16a6fedcd8541c4615326796c7c120c62a64646403 \
python3 scripts/zig_serial_build.py test-riscv-metal-recursive-resident \
  -Doptimize=ReleaseSafe -Dmetal-core-aot-bundle=.git/local-ethereum/aot-m4 --summary all
```

Small-tree producers/gates accept `--aot-profile recursive-framework-v1`; parent
gates use `--metal-aot-profile`. The default remains core. Receipt checks must
match the explicitly selected profile as well as the manifest pin. The host
path for an existing core-only bundle does not export the recursive catalog
just to discover unavailable kernels.

## Remaining provider work

Legacy universal Poseidon already has shared direct/lookup exports; its direct
kernels need AOT coverage before enabling the capability. Compact universal
Poseidon can use the existing mixed direct/lookup exporter, generalized around
its native evaluator. Both use independent per-batch running sums and claims.
The range provider additionally needs arbitrary preprocessing/main bindings and
zero direct roots. Its native independent-prefix recurrence must not be cast
into the typed framework's same-row-prefix contract.

Production proof and resident test evidence is recorded beside this document.
A missing or failing gate is not covered by the isolated generated-kernel tests.

## Complete proof evidence and measurements

Both `complete-tree-metal-4-parity` and `complete-tree-metal-4-timing` pass all
136 fresh acceptance/rejection cases after producer destruction. Every one of
their 21 proof/key/claim artifacts is byte-identical to the retained e5 Metal
baseline. The top-level receipts record exact commands, environment, binary
pins, report hashes and artifact hashes. Four wrappers dispatch 37 framework
components each; each parent dispatches 29 and reports two host components.
This is the existing 227-instruction, one-address fixture with four native
proofs, four wrappers, two intermediate parents and one root. It is not an
Ethereum block or a production-security benchmark.

The unshadowed observation is **71.690 seconds production**, **75.593 seconds
for the complete hostile-input gate**, and **4,377,559,040 bytes maximum RSS**.
The CPU parity diagnostic intentionally repeats evaluations and takes 118.775
seconds production; it is not a performance comparison. The previous core-only
observations were 65.035 and 65.835 seconds. The new profile therefore establishes
coverage and correctness, not an end-to-end improvement. It remains explicit
opt-in; the default core profile is unchanged.

`measurements.json` includes a root comparison using the same frozen producer,
same retained children, same admitted key and unchanged proof bytes. Each root
passes its 28-case fresh verification gate:

| Phase | Core profile | Recursive framework profile |
| --- | ---: | ---: |
| Complete producer request | 10.954 s | 12.220 s |
| Composition evaluation | 0.994 s | 2.282 s |
| Framework grouped expansion/dispatch wall time | — | 0.126 s |
| Framework kernels | — | 0.0114 s |
| Remaining Poseidon host worker | Included in prepared host route | 2.208 s |
| Remaining range host worker | Included in prepared host route | 0.0132 s |

These are single diagnostic observations, not paired medians. The newly mixed
route sends the remaining Poseidon provider through the legacy host evaluator;
the core route declines resident composition and uses the prepared host route.
The main thread waits 2.078 seconds after framework dispatch. The regression is
therefore concentrated in the remaining provider execution, not a seconds-long
framework kernel or export step. Provider GPU support is the next priority.

Strict tree and parent requests using the new profile remain negative gates:
the tree rejects with `MetalHostWitnessGenerationForbidden`; the parent rejects
with `MetalHostRecursivePreparationForbidden`. Their commands and logs are
retained. No full strict success is claimed.

## Focused checks and source scope

- Generated kernel/device checks: 24 tests, including 108 GPU cases and 29,568
  checked coordinates (`kernel-identity-device-tests.log`).
- Mixed-domain runtime checks: 19 tests (`mixed-domain-tests.log`).
- Borrowed twiddle views and existing polynomial checks: 54 tests
  (`twiddle-tests.log`).
- Actual exported AIR through production resident AOT: 64 coordinates,
  six negative controls (`resident-aot-tests-v2.log`). The earlier test-only
  pointer-type compilation failure is retained in `resident-aot-tests.log`.
- Exact generated catalog check (`catalog-check.log`); earlier missing root
  build registration and corrected generation are retained separately.
- Explicit CLI profile propagation: three Python tests
  (`profile-routing-tests.log`).
- Local formal source correspondence remains unchanged
  (`formal-source-check.log`); this does not add a new soundness theorem.
- Full build configuration closure passes all 21 catalog scopes and both CPU
  and Metal aggregate installation/linkage exercises (`configure-closure-v2`).
  The original missing-step failure is retained in `configure-closure.log`.
  Both tests are now registered even when prerequisites are unavailable.

For future registration-only edits, the checker accepts `--configure-only`:

```sh
python3 scripts/check_build_configure_closure.py --configure-only
```

This checks the catalog, graphs and ownership without compiling both aggregate
binaries. It writes a distinct partial schema and default receipt path, with
`installs_exercised=false`; it cannot substitute for full installation evidence.
The default complete command is unchanged. Five focused Python tests cover
both modes, both platform branches and default/explicit receipt selection.
The complete gate above ran before this CLI-only addition; its default behavior
is covered by those tests. No timing improvement is claimed for the new option
until a live focused run is measured.

`producer-source-snapshot.json` records the source observed for the successful
producer build. Later changes to the two root `build_support/products` files
register the standalone resident test; those files are not used by the standalone
integration producer builds. The test-only FFI pointer correction likewise did
not change producer source. `checkpoint-source-snapshot.json` records final
changed source, including these test/build additions. These distinctions keep
the successful binary evidence separate from later harness changes.
