# CSP guest benchmarks

`scripts/riscv_csp_benchmark.py` measures the current focused CPU or Metal
RISC-V product using the authenticated `vectors/riscv_csp/manifest-v2.json`
guests and inputs. It uses the canonical secure profile: 70 FRI queries,
26 PoW bits, log blowup 1, last-layer log degree 0, and fold step 1.

Two execution modes are available: ordinary software RV32IM and full typed
ECDSA precompile guest proofs. Both use the canonical CSP input and secure
parameters. The accelerated guest calls the existing Ethereum recovery
instruction, enforces low-S and key equality in RISC-V, and binds caller memory
and public I/O into the proof.

Inspect available workloads without building or launching a prover:

```sh
python3 scripts/riscv_csp_benchmark.py --list-workloads
```

`--execution-mode software` remains the default. `--execution-mode precompile`
accelerates ECDSA and retains software proofs for other targets. ECDSA inputs
unsupported by the fast success guest, including the negative fixture, receive
full software proofs. Host parity selection is a routing hint; the verifier
checks the authenticated guest and proof. Provider-only timings are separate.
The extra source/ELF authority is `vectors/riscv_csp/ecdsa-precompile-v1.json`.

## Run CPU and Metal

Build ReleaseFast products in a clean source checkout. The existing provenance
checks require the prover and trace diagnostic to be built from that checkout's
HEAD with clean compiled-source identities.

```sh
python3 scripts/zig_serial_build.py stwo-zig-riscv-cpu stwo-riscv-metal riscv-trace-dump -Doptimize=ReleaseFast
python3 scripts/riscv_csp_benchmark.py --backend cpu --execution-mode precompile --workers 16 --report-out /tmp/csp/cpu.json
python3 scripts/riscv_csp_benchmark.py --backend metal --execution-mode precompile --workers 16 --report-out /tmp/csp/metal.json
```

Metal requires macOS and the product's authenticated AOT installation. External
installation prefixes work with `--cli` and `--trace-cli`; evidence records their
absolute paths when they are outside the checkout.

For a focused validation loop, use `--targets ecdsa_secp256k1 --sizes 32
--warmups 0 --samples 1`. Such a run is partial validation evidence, not the full
16-case suite or a statistically qualified speed comparison. Normal defaults
are one warmup and ten measured samples per case.

## Evidence and correctness checks

Version 5 reports identify software execution. Accelerated reports use
`stwo_riscv_csp_accelerated_benchmark_v1` and label the actual mode per row.
Every positive case executes the pinned input, produces a proof through the
focused product's `bench` command, and verifies the retained artifact in a fresh
CLI invocation. In addition to exact security parameters and backend admission,
the runner checks:

- The artifact's ELF and input hashes match the selected workload.
- The proof statement is the complete single guest execution with the expected
  instruction count.
- The statement's public input words hash to the canonical input, and its public
  output words decode to the expected result.
- Every measured sample was self-verified; the retained verifier receipt matches
  the proof, statement and implementation identity.
- Every software Metal sample attests resident polynomial dispatch; every
  accelerated Metal sample records actual GPU dispatches and CPU fallbacks.

ECDSA's bad-signature fixture now goes through **execution, proving and fresh
verification** at the same secure parameters. The result is a valid proof that
signature verification returned the expected zero output. These validation-only
runs use no warmup and one sample and do not enter the performance rows.

Proving duration remains mean execution + witness construction + cryptographic
proving. Verification is separate. Provider-only timers, recursion, build time,
and command-start latency do not replace that metric.

Each invocation creates a unique `<report-stem>.evidence-*` directory beside the
report. It retains raw benchmark reports, proof artifacts, prover logs, fresh
verification receipts and `progress.json`. Completed rows survive later failures.
A failed run does not publish a new complete report; progress explicitly records
failure or pending publication. Successful reports name their evidence directory.
Use separate report paths when comparing runs.

Historical reports retain their original schemas. The A/B and recursion report
readers accept v5 while preserving their native-recursion checks. The old
recursion shape-audit fixture is a separate source-pinned artifact and must not
be relabelled to imply current qualification.

## Focused accelerated proof gate

```sh
STWO_CSP_FIXTURE_ROOT="$PWD/vectors/riscv_csp" zig build \
  --build-file src/integrations/riscv_cpu/build.zig \
  test-csp-ecdsa-guest-proof -Doptimize=ReleaseFast
```

This gate proves and independently verifies the complete guest at 70 queries
and 26 PoW bits, rejects input and ELF substitution and proof mutation, and
checks malformed/high-S routing. The focused product commands are
`ecdsa-csp-select`, `ecdsa-csp-bench`, and `ecdsa-csp-verify`; use the Python
runner for source authentication, canonical fixture checks, fallback proofs,
clean build identity and retained evidence. The benchmark measures execution
(including recovery selection), witness construction and proving; independent
verification is reported separately. Artifact serialization and command startup
are outside the proving metric, as in the software lane.
