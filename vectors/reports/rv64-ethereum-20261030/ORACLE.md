# Independent RV64 Ethereum execution check

The software-only RV64IM/LP64 guest completes mainnet block 24,628,607 (66
transactions) under independent Unicorn2.1.4. The oracle checks exactly
**835,695,366 retiring instructions**, the independently host-validated 43-byte
output, all 32 final registers and architectural post-store PC **17308** against
the native execution report. No host syscall, cryptographic hook or custom
instruction implementation is installed. This is execution evidence, **not a
STARK proof**, Sail qualification or full-memory state comparison.

[The raw oracle report](unicorn-full.json) binds ELF/input/transport hashes,
initial registers, ELF segment file identities/zero extents, ABI symbols and an
initial-image-description digest. [The build report](build-report.json) binds
the freshly built guest/runtime/allocator/target/lockfile and fresh host
validation, then checks both execution reports before setting its execution
status. It retains `full_block_proof_verified=false`. Its native report hash
references the exact local profile artifact; the large profile remains local.

## Exact count and halt boundary

The first native Unicorn budget is N-1 instructions. Completion must still be
absent. A second native budget of exactly 1 instruction must publish the valid
halt store and expected output. This independently checks N without a Python
callback on every instruction. Wrong counts N-1/N+1 and changed output are
rejected by [the focused tests](oracle-tests.log).

Unicorn's memory-write callback stops with the store committed but the PC still
at the store (17304). The report records that observed PC and explicitly
normalizes the architectural post-store fallthrough PC to 17308. No extra loop
instruction executes. The native runner's halt boundary and all 32 registers
match. Full RAM bytes are not compared; `ram_state_comparison=false` is explicit.
Unicorn mapping permissions are page-granular; native permissions retain exact
logical region bounds. This agreement does not establish every permission/trap
case or arbitrary-program refinement.

## Reproduction

```sh
/tmp/stwo-rv64-oracle-venv/bin/python -m unittest \
  scripts.tests.test_riscv64_ethereum_oracle -v
/tmp/stwo-rv64-oracle-venv/bin/python -m scripts.riscv64_ethereum_oracle \
  /tmp/stwo-rv64-ethereum/execution-full-config.json \
  --report /tmp/stwo-rv64-ethereum/unicorn-full.json \
  --expected-steps 835695366 --timeout 120 \
  --compare /tmp/stwo-rv64-ethereum/execution-profile.json
python3 autoresearch/benchmarks/guest_runtime/ethereum/rv64/build.py \
  --artifacts /tmp/stwo-rv64-ethereum --prepare-fixture --offline \
  --execution-report /tmp/stwo-rv64-ethereum/execution-profile.json \
  --oracle-report /tmp/stwo-rv64-ethereum/unicorn-full.json
```

The environment pins Unicorn2.1.4. Three tests pass, including exact-count and
output mutation rejection. Repository `scripts/ci.py` discovers the new test
module automatically; the layout test runs without Unicorn and the two engine
tests explicitly skip when the optional dependency is absent. The retained
local log runs all three with the pinned engine. Execution timing in the oracle
report is diagnostic and is not a paired performance comparison.

ELF, canonical SSZ, transport, source witness and expected output copies are
ignored under `vectors/reports/interop_artifacts/rv64-ethereum-20261030/`.
The pinned upstream witness size/SHA256/Git-blob checks and canonical/host output
checks remain reproducible via the guest build script; large binaries and
instruction histograms are not committed as qualification summaries.

## Proof architecture constraints

The [current full statement](../../../src/integrations/riscv_cpu/rv64_full_statement.zig)
rejects `steps >= 1 << 22`. The [clock encoding](../../../src/frontends/riscv/rv64/air/encoding.zig)
uses 24-bit clocks/gaps so strict ordinary integer ordering stays below M31.
This execution's 4-slot clock reaches **3,342,781,464**, above M31's modulus
2,147,483,647. Adding another range byte alone cannot preserve the existing
single-field clock equation; a new limb/carry representation needs constraints
and tuple/closure qualification.

Padding 835,695,366 CPU steps requires **n=2^30** rows. The current degree/geometry
uses a 4n composition domain (log32), while core
`MAX_CIRCLE_DOMAIN_LOG_SIZE` is 30. Existing geometry cannot admit this workload
by changing one step limit. For memory scale only,519 physical columns at n
would occupy **2,229,088,026,624 bytes (2.027TiB)** for one source matrix, before
interactions, FFT scratch, PCS and openings.519 is a previously measured CSP
shape, **not an asserted Ethereum plan width**.

Therefore no whole-block proof latency is extrapolated from execution time or
small CSP proofs. A next proof milestone must either select a genuinely smaller
real-block fixture fitting measured geometry, or introduce reviewed operation
components/clock representation/streamed geometry that reduce total proof work
while preserving program, call/state/RAM and terminal closure in one statement.
Repeated bounded proofs are not an implemented substitute for that single-proof
architecture.
