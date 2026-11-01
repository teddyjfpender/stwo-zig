# Qualification of ordinary RV64IM execution on the OM services lane

The new physical gate reuses the existing 63-instruction opcode-complete program
from `tests/rv64_proof_test.zig`. The instruction array now has one shared
test-only authority, `tests/rv64_all_ordinary_opcodes.zig`; the older proof test
continues using it. Actual machine retirements must contain each ordinary
opcode exactly once before any proof is produced. ECALL and EBREAK are outside
this 63-opcode claim; existing complete services fixtures cover the three
qualified service ABIs separately.

`services/gkr_local/full_isa_test.zig` captures one continuous 63-step tape and
uses the existing collector, global-memory argument, services coordinator and
complete receiver. It exercises ALU, comparisons, binary, shifts, loads/stores,
all M-extension operations, branches, LUI/AUIPC/JAL/JALR and FENCE. A high data
address and a negative 64-bit operand are retained. PC is within the current
32-bit program geometry. It reconstructs a fresh setup, and for beta2 a separate
immutable fixed-authority cache, before verification. A changed final register
and a corrupted physical proof must both fail through the same receiver that
accepted the original proof.

The two suites are a small beta1/P0/12-query fixture control and the actual
beta2/q256/P0/fold4 engineering candidate. The small control is **not** the
production q70/P26 security control. Neither this test nor q256 certifies a
whole-protocol 128-bit target. Timings include real proofs but are bounded
functional observations, not a controlled performance comparison.

## What existing qualification does and does not transfer

| Existing evidence | Reusable authority | Current OM qualification gap |
|---|---|---|
| Legacy authenticated proof over all63 instructions | Same instruction array and machine retirement semantics | Closed by the new complete physical OM gate; one operand pattern per opcode, not an exhaustive edge-case corpus |
| Sail 12,903-case continuous corpus, 1,032,240 retirements, all63 covered (`rv64-ls32-qualified-20261101/corpus-sail-report.json`) | `word16_qualification/sail_image.zig` and `sail_capture.zig`; compare every retirement and expected CPU/RAM endpoint | Its existing proof is the earlier Word16/QM route. Replay the captured corpus through the current OM coordinator and fresh receiver before claiming current-profile Sail qualification |
| Whole 17-case CSP suite with Unicorn agreement (`corpus-csp17-qualification.json`) | `csp_image.zig`, `csp_capture.zig`, opcode/shape counters and independent expected outputs | Current OM complete-suite proof/benchmark not yet run. Reuse capture and geometry selection; do not substitute Ethereum receipts or run the large ECDSA benchmark before the bounded ISA gate |
| Pinned Rust Stwo verification (`rv64-delivery-20261030/rust-requalification-v1.json`) | Independent PCS/FRI implementation and fixture-scoped adapter methodology | Scope is explicitly ADDI/ADDI/SD/LD/ADD, dense-v2/four-coordinate adapter. It does not verify current eight-coordinate OM31, new GKR child/binding, schema7 or all63-opcode AIR |

The next qualification steps are therefore current-profile Sail retirement
corpus replay and one small CSP case with complete fresh acceptance, followed by
the full CSP suite. Independent Rust qualification requires an explicit current
field/protocol and complete AIR adapter; existing Rust agreement cannot be
expanded by changing a report label.

Run the focused gate with:

```sh
zig build test-riscv64-truth-gkr -Doptimize=ReleaseSafe \
  -Driscv-test-filter='OM-GKR services all63' -j2 --summary all
```

The explicit test-root import and selection guard ensure that a filtered
invocation cannot pass after discovering zero named qualification tests.
