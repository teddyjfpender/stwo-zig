# Binding v2 prerequisite gate

**Measured [M], CPU qualification only:** all three gate steps passed on the
Runpod host. `receipt.json` binds the exact tested source-file hashes. The
source snapshot was checked against this worktree after copying the receipt.

| suite | result | build plus test wall [M] | load at start [M] |
|---|---|---:|---:|
| outer GKR, including v2 binding differential and mutation cases | passed | 40.214 s | 21.563 |
| security policy and profile registry | 58/58 passed | 10.535 s | 22.121 |
| original and lazy CUDA-fraction body, host emulation | 7/7 passed | 55.146 s | 22.215 |

The fraction qualification includes 944 lane-major original fraction checks
against the independent native `RawLookupRows` authority (derived [D] from
the four hybrid components' 59 terms and 16 tested rows). Existing paired
fraction tests also passed unchanged.

The first registry attempt failed only because its expected number of GKR
format entries still said five after adding three M7 v2 reservations; that
expectation was corrected to eight. No security gate was relaxed.

No production profile is promoted. No Ethereum block, request latency,
production receiver time, cell reduction or proof compression was measured by
this gate. See `design/riscv-proving-stack/rv64-m7-outer-gkr.md` for the
remaining production wiring and acceptance gates.
