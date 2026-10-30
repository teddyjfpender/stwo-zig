# Experimental RV64IM frontend and bounded AIR

`rv64im-execution-v0` is a separate 64-bit execution machine within the RISC-V
frontend package. It is exported as `riscv.rv64`. Existing RV32 machine types,
opcode IDs, proof statements and release capabilities retain their meanings.

The execution milestone supplies semantics and diagnostic records. A separate
[`riscv.rv64_air`](air/mod.zig) now proves bounded partial execution with independently
expected program, register and memory state. The [AIR contract](../../../../design/riscv-proving-stack/rv64-air.md)
defines its 256-step/128-memory-word limits, authenticated state relations,
verifier-derived physical layout and reusable immutable setup. Native CPU proof
and verification live in [`riscv_cpu.rv64`](../../../integrations/riscv_cpu/rv64.zig).
The execution/ELF route is not automatically a proof route:
`profile.proof_supported` and `profile.sp1_abi_supported` remain false.
There is no RV64 continuation, recursive composition or SP1 runtime yet.
Unicorn comparisons establish agreement with that emulator on the tested
cases; they do not establish Sail conformance or cryptographic soundness.

## Execution contract

- All 65 decoded RV64IM instruction variants are explicit. ECALL and EBREAK
  raise traps; the remaining 63 variants retire. Atomics, compressed code,
  floating point, CSRs and instruction-cache fences are not supported.
- Integer registers, PC, effective addresses and arithmetic wrap at 64 bits.
  W operations sign-extend their 32-bit results. Division uses the ISA's
  zero-divisor and signed-overflow results.
- IALIGN is 32 bits. Misaligned data accesses trap. An untaken branch does not
  check the alignment of its unused target. JALR clears target bit zero.
- Memory is little-endian, sparse and permission checked over full 64-bit
  addresses. Distinct addresses above and below 4 GiB cannot alias. Reads in
  mapped, untouched memory return zero; unmapped accesses trap. Loading into
  x0 still performs the memory access and can trap.
- Default limits allow 256 MiB of mapped virtual regions, 65,536 allocated
  4-KiB pages and 256 mappings. Callers can choose smaller limits. Guest
  instructions do not create mappings. Allocation failures preserve both
  architectural bytes and allocated-page inventory, including bulk writes
  that cross existing and new pages.
- ELF admission accepts static ELF64 little-endian RISC-V executables with
  zero ELF flags. It checks file ranges, segment sizes, alignment congruence,
  overlap, resource limits and executable entry containment. Dynamic loaders
  and TLS are rejected. Instruction support is checked at execution, since
  ELF flags alone cannot establish an instruction inventory. Admission computes
  the exact union of initial file-backed pages before any allocation; BSS
  reserves virtual space without allocating backing pages.
- ELF loading creates fresh memory transactionally and zeros BSS implicitly.
  `Memory.initialize` is a loader/host operation; guest stores check write
  permission. A caller supplies any stack/input mappings and initial registers.
- `Cpu.step` returns a retirement record, or traps without retiring. Records
  preserve full-width operands, results, PCs, immediate, previous destination,
  a global retirement clock and aligned before/after memory words. Unused
  register fields and operands are canonical zero, derived from one exhaustive
  opcode-effect definition. These are diagnostic witnesses, not constrained
  proof rows.

## Concrete execution architecture

The frontend uses concrete RV64 types. There is no generic CPU, allocator
framework, specialized execution-mode family or callback-based trace pipeline.
Cached and uncached execution call one retirement implementation.

`Memory` owns sorted permission mappings and sparse backing pages. Mapping
lookup uses binary search plus separate code/data permission caches. Cached
ranges retain exact byte bounds; a neighbouring region cannot inherit rights.
Aligned accesses perform one backing-page lookup through four fully tagged
cache entries. Bulk initialization reserves unpublished pages transactionally,
then copies complete page slices. Host code must not mutate the internal
mapping/backing collections directly. Owning values are moved, not copied.

`Session` owns a bounded instruction-word cache and borrows a `Memory` that
must outlive it and retain its address. The default 1,024-entry decode cache
is keyed by fetched bytes, so code writes cannot reuse an old decoded
instruction. `Session.runInto` fills caller-owned rows and yields on a full
buffer. A trap returns the retired-prefix length and stop reason; neither the
prefix nor global clocks are lost. A zero-length buffer performs no work.
Steady-state execution allocates nothing after its pages and cache are warm.

## Build, test, and run

From the repository root, with Zig 0.15.2:

```sh
zig build test-riscv64-execution
zig build --build-file src/frontends/riscv/rv64/build.zig test
zig build --build-file src/frontends/riscv/rv64/build.zig run -- inspect /path/to/guest.elf
```

The diagnostic `smoke ELF` command uses a deliberately small test ABI: a
64-KiB stack below 8 GiB, result in a0, EBREAK stop and a 100,000-instruction
budget. It reports the breakpoint as a stop reason. It does not declare an
arbitrary guest successful or interpret SP1 syscalls.

The root test target includes existing RV32 decoder tests. The RV64 tests also
join the package's test inventory. Tests cover signed arithmetic, W semantics,
address aliasing, permissions, branch/JALR corner cases, trap atomicity,
resource bounds, ELF corruption and injected allocation failures.

The optional independent oracle is pinned separately from production code:

```sh
python3 -m venv /tmp/stwo-rv64-oracle-venv
/tmp/stwo-rv64-oracle-venv/bin/pip install unicorn==2.1.4
/tmp/stwo-rv64-oracle-venv/bin/python scripts/riscv64_differential.py
```

The deterministic corpus compares all registers, PC and data bytes after each
retirement, includes edge-value Cartesian products and seeded random operands,
uses code/data both above and below 4 GiB, and requires every retiring opcode
to be covered. Generated vectors and the diagnostic executable use temporary
storage and are removed on exit. `--report FILE` retains a small JSON receipt.
The script also compiles `fixtures/arithmetic.c` natively and as RV64IM with
code above 4 GiB, then compares the native result with the guest's a0. This
exercises linked code, PC-relative constants, stack memory and a complete
multi-instruction computation. It does not exercise Kona witnesses.

The oracle corpus runs against both cached and uncached retirement. Additional
tests inject allocation failure at every bulk-growth point, retry a trapped
batch, force cache collisions and code changes, and check write-only subword
updates without granting guest read permission.

For the full CSP comparison and the paired foundation kernels:

```sh
/tmp/stwo-rv64-oracle-venv/bin/python scripts/riscv64_csp_compare.py --work-dir /tmp/stwo-rv64-csp-comparison --samples 7 --oracle --report /tmp/csp-comparison.json
python3 scripts/riscv64_foundations_benchmark.py --report /tmp/rv64-kernels.json
```

The CSP build requires the pinned `nightly-2026-03-04` toolchain, `rust-src`
and cached crate dependencies (`--offline`). RV64IM's tier-3 core is built
from source. Both ISAs use the same toolchain, flags and workload source.
SHA/Keccak use a shared minimal runtime adapter because their pinned upstream
glue selects a native host implementation for RV64. No cryptographic precompile
is enabled. These rebuilt RV32 guests are distinguished from committed suite
ELFs by hashes and exact counts. M31 Poseidon retains its existing RV32-oriented
limb algorithm; this comparison does not redesign it for RV64.

Instruction counts and validated outputs compare the same work. RV32's public
value diagnostic also builds witnesses and committed trees; its wall time must
not be divided by RV64's execution-only time to claim a speedup. Small bounded
AIR proofs now verify; paired CSP proving remains open. [Retained comparison and measurements](../../../../vectors/reports/rv64-foundations-20261030/README.md).

## Next milestones

1. Add the pinned RV64 Sail reference and architectural conformance corpus,
   including rejection/trap comparisons and larger compiler-generated guests.
2. Scale the bounded AIR beyond reference fixtures: independently size opcode,
   RAM and crypto components, replace expensive bit encodings where total proof
   work improves, and qualify complete CSP proofs. All 63 retiring opcodes now
   occur in one verified native proof; this is not broad workload qualification.
3. Extend the expected immutable-program/initial/final state contract to ELF
   and input identity, memory roots, versioned continuations and recursive
   verification, preserving every global closure obligation.
4. Port the current Kona/OP Succinct guest sources to our runtime and crypto
   accelerators. RV64 instruction execution alone does not implement SP1's
   syscalls, patched libraries or recursive proof-verification ABI.
5. Execute the upstream real-block witness first, then the port; compare
   public outputs before measuring witness generation, execution and proving.

The current upstream target is OP Succinct v4.9.3 commit
`b9c24330ad21228cacc310e043c7f504fd388b2a`, Ethereum range ELF SHA256
`223b0bb832ba485325d811a5a6e6e0e3a77dc10eb44377119e6cf0535a069bc4`.
The diagnostic inspector accepts its three load segments. That is an ELF
admission result, not a successful guest execution.

Semantic references: [RV64I](https://docs.riscv.org/reference/isa/unpriv/rv64.html),
[M extension](https://docs.riscv.org/reference/isa/unpriv/m-st-ext.html), and
[Unicorn 2.1.4](https://github.com/unicorn-engine/unicorn/releases/tag/2.1.4).


Focused bounded-proof checks:

```sh
zig build test-riscv64-air test-riscv64-proof -Doptimize=ReleaseSafe
```

These include degree-bound, full-width address, alias, subword, prefix and
allocation-failure checks; public-state substitution; and fresh-verifier
rejection of captured arithmetic-valid register/RAM/permission forgeries.

Execution exports remain dependency-free in `riscv.rv64`; the full frontend
facade exposes `riscv.rv64_air` separately so diagnostic, CSP execution and
benchmark tools can compile without proof-engine dependencies.
