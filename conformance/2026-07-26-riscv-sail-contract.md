# RV32IM Sail Refinement Contract

This document fixes the architectural statement proved by the RISC-V
frontend. It replaces Stark-V as the semantic oracle and is normative for
decode, execution, witness generation, AIR review, and conformance evidence.

## Authority order

1. `riscv/sail-riscv@8c7f2da58de0ba5e4457e4de07e0046f0439f35f`,
   compiled with Sail `0.20.2`, owns instruction decode and architectural
   retirement semantics.
2. `riscv-isa-sim@520a5f185083ac3c97b751501dfac02a6c1f5970`
   is the independent executable cross-check.
3. `riscv-arch-test@426e1598ebc3688eaf9aba7b4a1b8a81dae9807f`
   owns the architectural test corpus.
4. This document owns the zkVM environment: ELF initialization, sparse
   memory, public I/O, rejection, and completion.
5. Stark-V commit `d478f783055aa0d73a93768a433a3c6c31c91d1c`
   may describe legacy opcode IDs and witness/protocol layout only. A
   disagreement about ISA behavior is resolved in favor of Sail.

The machine-readable carrier is
`conformance/riscv/rv32im-sail-profile.json`. The pin gate requires it to
agree with `src/frontends/riscv/isa/authority.zig`.

The Sail simulator starts from `--rv32` and applies, in order,
`conformance/riscv/sail-rv32im-override.json` and
`conformance/riscv/sail-rv32im-tagged-options.json`. Two files are required
because Sail recursively merges JSON objects: the first clears tagged-option
objects and the second installs alignment exceptions without retaining the
default `None` variant. The merged configuration validates and reports the
exact ISA string `rv32im`.

Sail's upstream RVFI-DII v1 harness fixes its transport entry at
`0x80000000`; that value is not an ISA semantic rule. Formal differential
builds apply the repository-owned
`conformance/riscv/sail-rvfi-zkvm-entry.patch`, SHA-256
`1309655496ea8c8aae3cade751b1ba695dd19b2048f6118d28371be693dbb734`, to
`c_emulator/rvfi_dii.cpp` so the harness enters at the zkVM corpus base
`0x00010000`. The patch changes one C++ transport constant and no Sail model
source. The differential runner rejects an ELF with another entry and
behaviorally rejects a simulator that reports another first retirement PC;
it never translates PCs or PC-derived architectural values.

## Architectural profile

The proof-bearing machine is little-endian RV32IM: XLEN 32, base I plus M,
32 integer registers, x0 hard-wired to zero, and four-byte instruction
alignment. A, C, floating-point, vector, CSR, privileged, and Zifencei
instructions are outside the profile and are rejected before witness
construction.

The one observed decode-level narrowing is explicit and machine-readable:
the pinned Sail model retires `FENCE.I` (`0x0000100f`) even when
`extensions.Zifencei.supported` is false and the validated ISA string is
`rv32im`. The zkVM rejects it because Zifencei is outside this proof profile.
The negative corpus checks both dispositions live. This is a conservative
ingress restriction, not alternate semantics for an admitted instruction.

Base-I `FENCE` is an admitted architectural retirement. Because the zkVM has
one sequential hart and no external memory observers, its visible state
transition is `pc' = pc + 4` with no register or memory change. ECALL and
EBREAK are environment control events, not architectural proof rows. The
strict proof runner rejects them; a developer host may service them only on
the explicitly hosted, non-proof execution surface.

Loads and stores are naturally aligned except for byte accesses. A
misaligned instruction target or data access is rejected before any
architectural state, state-chain clock, or memory value is mutated. The
current proof language contains successful retirements, not trap-handler
execution; adding trapped executions requires a separately reviewed trap AIR.

The compatibility program commitment is a byte-addressed sparse Merkle tree
with `2^30` leaves. A committed four-byte instruction therefore has an aligned
address in `[0, 2^30 - 4]`. The program AIR proves this without relying on the
host: it binds `pc / 4` to a 20-bit low limb and an 8-bit high limb through
the lookup tables. This is a protocol-layout restriction, not an RV32
architectural restriction; data addresses retain the separately constrained
32-bit zkVM memory model.

## ELF and completion boundary

ELF32 little-endian RISC-V loadable segments initialize sparse byte-addressed
memory. The entry point initializes `pc`; linker symbols initialize `sp` and
`gp`; all other registers begin at zero. Program bytes are immutable in the
proof-bearing environment. Public input, output, and the halt word use the
linker-defined regions validated by the loader.

Proof execution ends before fetching another architectural row when the halt
word is set or when the configured unretired self-loop sentinel is reached.
Maximum-step exhaustion, invalid encodings, unsupported extensions, system
instructions, misalignment, and undeclared I/O are errors, never successful
completion.

Completion is part of the public statement and is closed on the same committed
relations as execution. A halt completion consumes the final nonzero halt word
at its last memory-access clock. An unretired self-loop consumes the canonical
`jal x0, 0` word at `final_pc` from the program relation; that extra public
fetch is not an architectural retirement and does not increment the public
clock.

## Artifact identity and security profiles

RISC-V artifact schema v4 binds the protocol name, exact PCS configuration,
ELF and input hashes, complete execution statement, and completion evidence in
the expected-statement digest. Independent verification requires the original
ELF. The verifier hashes those bytes, revalidates the release ABI, rebuilds the
decoded-program commitment, compares its root with the public program root,
and checks the completion symbol or sentinel word. An ELF hash is therefore
not accepted as a detached descriptive field.

The exposed PCS profiles use blowup factor `2` (`log_blowup_factor = 1`) and
the following parameters:

| profile | PoW bits | FRI queries | heuristic total |
| --- | ---: | ---: | ---: |
| `secure` | 26 | 70 | 96 bits |
| `functional` | 10 | 3 | 13 bits |
| `smoke` | 0 | 3 | 3 bits |

The last column is the implementation's current conjectural list-decoding
accounting, `pow_bits + log_blowup_factor * n_queries`. It assumes independent
query soundness in the applicable FRI/list-decoding regime; it is not a
reduction or an independently reviewed security proof. Only `secure` is
intended as a security profile. `functional` and `smoke` are test profiles,
and the verifier's requested policy, the artifact protocol, the exact PCS
configuration, the proof's embedded configuration, and the Fiat–Shamir
transcript must all agree.

## Refinement and soundness obligation

For every committed opcode row:

- the program relation binds `(pc, instruction word)` to one strict Sail
  decode;
- register and memory relations bind its pre-state and post-state;
- semantic constraints force the same post-state and next PC as Sail;
- range checks bind every byte, carry, sign, address split, and clock gap;
- the state relation chains row `n` to row `n + 1`;
- public relations bind initial/final registers, PC, clock, program root,
  memory roots, public I/O, and completion evidence.

An honest differential test establishes semantic agreement; it does not
establish this implication. Every family therefore also needs negative
committed-witness mutations. High multiply additionally binds sign witnesses
to operand bit 31 and constrains the complete eight-byte two's-complement
product recurrence.

## Backend dataflow and ownership

```text
ELF + public input
        |
        v
RV32IM runner --retirement rows--> backend-neutral witness/AIR
                                      |                 |
                                      v                 v
                                CPU/SIMD engine    Metal engine
                                      |                 |
                                      +--------+--------+
                                               v
                                      canonical verifier
```

The runner and frontend own host allocations until columns are transferred to
the selected prover engine. An engine owns commitments, device residency,
composition, FRI, and decommitment until it returns a proof. Verification is
backend-independent and consumes that proof. Metal may not fall back to CPU,
and no RISC-V CUDA product is in scope.

## Conformance evidence

Formal evidence compares each retired `(pc, instruction, rd, rd value,
next pc, memory effect)` across the Zig runner, Sail RVFI, and Spike. Reserved
and illegal encodings are negative vectors. The architectural suite executes
through the same runner boundary and then follows execute → prove →
independent verify. Differential fuzz evidence records the generator version,
seed interval, program count, retirement count, exact pins, and zero-divergence
digest.

## Sail-backed tooling

Two script entry points make the pinned model consumable outside the
release corpus gate, and both refuse to answer rather than substitute a
weaker authority when the pinned binary is absent (exit 3, UNAVAILABLE):

- `scripts/riscv_sail_oracle.py` asks one question -- does pinned Sail
  agree with a runner retirement trace? -- with the four-verdict contract
  EQUIVALENT/DIVERGENT/ERROR/UNAVAILABLE that `runner/sail_oracle.zig`
  consumes from tests.
- `scripts/riscv_operand_classes.py` derives the operand classes the ISA
  admits and the AIR's limb structure distinguishes, executes one case per
  class on pinned Sail over RVFI-DII, and commits Sail's architectural
  results to `src/tests/riscv/operand_class_corpus/` for guest-building
  tests (`operand_classes.zig`, the class sweep, the rigidity corpus). Its
  `check` mode regenerates and requires byte identity with the committed
  data; its `audit` mode measures which enumerated classes an existing
  trace corpus touches and lists the pairs it never does.

The corpus differential itself is a fail-closed hosted CI gate:
`scripts/riscv_sail_gate.py` binds the committed evidence to the committed
corpus on every PR and re-derives it against live pinned Sail/Spike whenever
its meaning can change, per
[riscv-sail-differential-gate.md](riscv-sail-differential-gate.md).
