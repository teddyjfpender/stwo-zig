# LS32 qualification on the recovered production lane

Status: focused physical-proof qualification passes in ReleaseSafe and
ReleaseFast. A real four-CPU/three-truth Ethereum prefix accepts in a fresh
receiver. The complete 104,253,913-instruction block also accepts in a fresh
receiver with 25 CPU and 5 truth proofs.

Base: `259f49ff8`. The earlier LS32 design/implementation commits were
`567823623` / `d873812af`, recovered in this branch as `670fe8ebd` / `8d5b588cf`.
The port preserves the newer MAIN70 affine b_low projection, public INIT/TERM
MAIN14/INTER8 binding, DIV result anchors and the current nominal 96-bit q70/P26/fold1 control suite. This does not qualify
the requested 128-bit whole-protocol production security target.
LS INTER48 becomes 32; the LS encoding identity becomes v6 and the complete core
schema becomes 7. Old schema 6 bundles must not silently select the new shape.

## Every register writer and its source authority

All paths below are relative to `src/frontends/riscv/rv64/air/` at this branch.
The complete architectural effects list is `../decode.zig:76` (`effects`).
The inventory regression enumerates every admitted opcode with `writes_rd`;
there are 52 RV64IM register-writing opcodes, grouped exhaustively below.

| Architectural writer | Routing source, file:line | Canonical result authority, file:line |
|---|---|---|
| ADD, SUB, ADDI, ADDW, SUBW, ADDIW, SLT, SLTU, SLTI, SLTIU | `word16_execution/features.zig:40` and `word16_v1/operations.zig:53` classification | `word16_v1/alu.zig:58` derives C from sum/difference/sign/predicate; `alu.zig:143` retains sum/difference U16 memberships; `alu.zig:135` defines the Boolean signed predicate. |
| XOR, OR, AND, XORI, ORI, ANDI | same immutable operation classification | `word16_v1/binary.zig:34` derives C from AND-table bytes; `binary.zig:97` emits every A/B/AND byte tuple. |
| SLL, SRL, SRA, SLLI, SRLI, SRAI, SLLW, SRLW, SRAW, SLLIW, SRLIW, SRAIW | same immutable operation classification | `word16_v1/shift_word.zig:80` queries every limb/microshift; `shift_word.zig:84` retains quotient and signs; `shift_word.zig:109` binds C to chunk arithmetic; `shift_chunk_arithmetic.zig:83` combines disjoint bounded chunks. |
| MUL, MULH, MULHSU, MULHU, MULW | `word16_execution/features.zig:90` onward | `delegations/multiplication/provider.zig:53` includes all RESULT bytes in unconditional BYTE membership; `degree3_provider.zig:10` enforces those queries and the function truth. |
| DIV, DIVU, REM, REMU, DIVW, DIVUW, REMW, REMUW | same raw arithmetic routing | `delegations/division/word16_product/equations.zig:43` retains explicit C4 queries, even after the A/B query trim. Q/absB/product correctness additionally depends on the actual closed MUL/MULHU support facts. |
| LB, LH, LW, LD, LBU, LHU, LWU | `word16_execution/features.zig:73` selects OWNER, not FUNCTION | `memory/load_store_v1/equations.zig:92` through106: C is earlier RAM-before limbs, a fixed-table byte plus signed fill, or 0/65535. The earlier dependency is established by the joint time induction, not a hidden C range. |
| **LUI** | **`word16_execution/features.zig:48`**: ALU ADD, x0 and ROM immediate | `word16_v1/alu.zig:58` and `:143`: sum limbs remain U16 checked. LUI is explicitly included; it is not an unlisted native shortcut. |
| **AUIPC** | **`word16_execution/features.zig:53`**: ALU ADD, ROM PC and immediate | Same ALU sum anchors. PC/immediate limbs are independently derived by the immutable ROM (`features.zig:112`). |
| JAL | `word16_execution/features.zig:59`: ALU ADD, PC+4 | ALU sum anchors. JAL's architectural C is **not** taken from the ROM link field. |
| JALR | `word16_execution/features.zig:66`, `word16_execution/tuples.zig:43` | Architectural C is the ROM-authenticated link PC+4. Its FUNCTION output is next_pc: direct AND for zero immediate, or the unit ADD→AND adapter in `word16_execution/jalr_equations.zig`. |

Additional state-token producers also matter. REG read slots re-emit the same
value at a later fixed clock (`word16_execution/tuples.zig:27`), public initial
registers are split from u64 (`word16_cpu/public.zig:23`), and boundary tuples
are selected through immutable selectors (`word16_cpu/boundary.zig:18`).
Store/ECALL have no architectural register write; their OWNER C is zero in
`memory/load_store_v1/equations.zig:107`, Keccak
`delegations/keccak/word16_bridge/equations.zig:8`, and secp
`delegations/secp256k1/word16_bridge/equations.zig:35`. FENCE has no rd effect
and routes to the zero-input ALU ADD (`features.zig:72`). Branches produce an
internal canonical ALU predicate, rather than an architectural rd write. EBREAK
is not admitted by this execution profile.

Service RAM result anchors remain explicit: Keccak after bytes are covered by
`delegations/keccak/word16_bridge/layout.zig:16`; secp before and after bytes by
`delegations/secp256k1/word16_bridge/layout.zig:36` onward. Their equations
recompose every RAM limb from two queried bytes. No host result or inverse hint
is accepted as canonical merely because the source constructor uses a u64.

## Acceptance and time invariants

REG and OWNER are local to each CPU proof. They carry independently drawn,
CPU-ordinal/manifest-bound challenges; REG does not include an epoch coordinate.
`word16_global_execution/services/statement.zig::CpuClaims.local` closes the
combined local rational identity per CPU, excluding only separately authenticated
RAM and service truth debts. `services/execution.zig::verify` calls it inside
the CPU loop. Only RAM14/KIO/Wire are accumulated across the complete manifest.
Named claim fields are additive ledger shares, not independent certificates.

LS OWNER uses the same Boolean m[0] as the RAM transition. CPU OWNER weight is
active-function and is Boolean. LS tick is OWNER-bound to 4r+4; Keccak and secp
copy their first-coordinate tick/epoch across continuations. SB selection parity
and the byte replacement factor derive from the same one-hot offsets. A new
writer must retain independent result anchors or reopen the joint induction.

The dependency order is `(epoch, clock)`. REG reads go backward within a proof;
load C at 4r+3 depends on RAM at most 4r in the same epoch or an earlier epoch;
RAM stores at 4r+4 depend on B at 4r+2. A balanced interior alias chain cannot create
its first ancestor. The actual negative-proof tests below guard precisely that.

## Actual proof tests

- `memory/joint_write_proof_test.zig` commits a six-instruction LD→REG→SD chain.
  The alias is limb 1 +=65536, limb 2 -=1; limb 0 is left alone because its store-byte
  split remains checked. Alias values propagate through CPU C/B/previous_rd,
  OWNER and LS before/after. Final RAM and register endpoints are restored to
  canonical public values. The test requires all local non-RAM debts to close,
  retained range/selection shares to match, actual fresh physical verification
  to pass, then the closed receiver to reject the sole initial RAM ancestry debt.
- `services/joint_write_proof_test.zig` repeats this across two shards of the
  production services protocol with one sealed manifest/shared RAM draw. Both
  physical proofs must verify freshly and both CPU-local closures must pass;
  only aggregate RAM ancestry must reject. This inventory has no crypto calls;
  separate continuation/byte-anchor guards and existing mixed K/ADD/DOUBLE
  end-to-end suites qualify the crypto writer premises.
- A second services case leaves global RAM fully closed but forges a previous-rd
  REG read. Physical verification must pass and the production receiver must
  reject the local CPU debt. A separately labeled synthetic ledger unit check
  shows equal/opposite local numbers may not be summed before checking each
  CPU; it is not represented as a new valid physical proof.
- `memory/joint_write_invariants_test.zig` guards writer inventory, explicit
  MUL/DIV result query coverage, ALU sum/difference/predicate anchors, BINARY
  byte tuples, SHIFT chunk masks, unit activity, CPU/LS tick binding, all eight
  SB parity cases, and K/ADD/DOUBLE continuation clocks, zero C and after-byte
  inventory. Every new test must run through a declared product test root.

## Qualification results

Both memory and combined-services LS32-filtered products pass in ReleaseSafe and
ReleaseFast. The complete memory, LS circuit and execution circuit products also
pass in ReleaseSafe. The complete combined-services and Ethereum terminal
products also pass in ReleaseSafe, including existing mixed K/ADD/DOUBLE and
geometry/endpoint tests. The exhaustive writer inventory asserts 52 writers in both
modes. These tests include fresh physical proofs, rather than constructor-only
rejection of invalid inputs.

The schema 7 prefix at `/tmp/rv64-ls32-qualified-prefix4-v1` covers 16,777,212
retirements with four CPU and three truth proofs. A separate receiver accepts.
Against the compatible schema 6 control
`/tmp/rv64-wave2-final-legacy-prefix4-v1`, every CPU request, truth declaration,
public memory word, cell digest and complete `cells.bin` agrees exactly. Proof
and transcript bytes intentionally change with the encoding identity. The
prefix reports incomplete coverage; acceptance is not full-block completion.
The complete block has the same exact semantic parity and 43-byte output as the
current schema6 baseline. Native cells fall from 20,925,263,680 to 20,336,488,256:
588,775,424 fewer interaction cells, a 2.814% whole-block reduction. Main and
preprocessed cells are unchanged. The four-proof prefix saves 1.73%; savings
depend on actual load/store occupancy rather than the old architectural estimate.

These are functional control-profile results, not 128-bit security qualification
or a controlled performance comparison. Other compilation and pre-push checks
were active during the run; 168.49s wall and 144.47s proving must not be compared
as a qualified speedup against the controlled baseline. Durable reports, exact
semantic parity and provenance are in
`vectors/reports/rv64-ls32-qualified-20261101/receipt.json`. The build occurred
before the qualification commit with uncommitted tests/docs; the receipt states
that provenance rather than claiming a clean-source binary.

## Full ISA and CSP corpus closure

The existing CSP qualification wrapper proves all 17 pinned Unicorn-agreed
requests on clean source `13c3c0c6e` and verifies each in a fresh process. This
includes the complete positive ECDSA request (1,625,938 instructions) and negative
ECDSA request (1,627,849 instructions). Every case retains exactly the control's
CPU endpoint, epoch, division/multiplication/LS request counts, public RAM words,
complete cell bytes and instruction histogram. The current CPU47 positive
ECDSA control agrees independently as well.

The continuous Sail workload proves all 1,032,240 retirements and all 63 ordinary
RV64IM opcodes, comparing every retirement to the pinned RVFI. A fresh receiver
accepts using the intentionally absent-RVFI configuration: its authority comes
from the pinned ELF and expected CPU/RAM endpoints. CPU state, public RAM/cell
bytes, instruction histogram, division and LS counts match the CPU47 control.
The sole declared request-count adapter is 1,168 to 4,896 multiplication provider
obligations: 1,864 DIV requests now each add two closed MUL/MULHU support facts
(`word16_execution/prepared.zig:117`). These are not extra guest retirements.

The build, binary, configs, oracle and complete case identities are pinned in
`vectors/reports/rv64-ls32-qualified-20261101/corpus-receipt.json`. This closes
the functional full-ISA/corpus gate; it adds neither a controlled performance
claim nor a whole-protocol 128-bit security claim.
