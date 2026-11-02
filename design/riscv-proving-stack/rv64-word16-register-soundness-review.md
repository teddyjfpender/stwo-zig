# Manual review of Word16 register execution

Reviewed on 2026-10-31: raw Word16 CPU (44-column binary control and 46-column
ALU/binary control), indexed 40-column control, their local providers and the
qualified two-CPU/shared-BINARY aggregate. No concrete soundness or receiver
resource defect was found in this read-only review. This is a manual argument
and source inspection, not a machine-checked proof or a new qualification run.

The reviewed main-tree foundation was
`63842eba71930b0755eea5087d7ec540c84764ab`, with the native ALU grouping additions
subsequently committed as `e74aff3b72aebb307db0f6149683681d4ae76859`.
At review completion the main tree was
`262cf7ae664fba8dd310b8a2f82e35d17110bb1e`; that last commit changes the separate
closed-LS domain implementation. This document is committed independently in
the isolated LS SIMD worktree. The SUM-zero ALU encoding in isolated commit
`806d5131061953d56e3ef0d315eae3ef70edc784` is a separate reviewed/qualified slice,
not assumed to have been part of the main-tree CPU audit.

## Sources and acceptance boundary

The principal polynomial authority is
`src/frontends/riscv/rv64/air/word16_cpu/equations.zig`:
`emitActivityFor`, `emitDataFor`, `registerTuple`, `emitRegisterFor`,
`emitFunctionFor` and `emitRangesFor`. Immutable clocks/selectors/ranges are in
`word16_cpu/fixed.zig`; expected endpoints and serialization are in
`word16_cpu/public.zig` and `word16_cpu/boundary.zig`.

Raw control authority is `word16_cpu/rom.zig` (`Setup.initWithProfile`,
`deriveWithProfile`, `effectiveIds`). Indexed control authority is
`src/frontends/riscv/rv64/air/word16_index_control/authority.zig`
(`Authority.init`, `executionTuple`, `executableId`, `idForPc`) and
`word16_index_control/equations.zig` (`resolve`, `emitFor`, `emitRomFor`).
All abbreviated frontend paths in this document are relative to
`src/frontends/riscv/rv64/air/`.

The accepting integration paths are
`src/integrations/riscv_cpu/word16/cpu_verify.zig` (`verifyClosed`, private
`verify`) and `word16_index/proof.zig` (`verify`). An open CPU fragment returns
only FUNCTION debt after local proof verification; its return is not execution
acceptance. The qualified aggregate acceptance path is
`src/integrations/riscv_cpu/rv64_distributed_execution_v1/aggregate.zig`
(`verifyPrepared`) with independently expected authority from its `public.zig`.

## Register chronology and canonical values

1. Activity is Boolean, starts active, ends inactive, never restarts, and can
   stop only at the independently public `steps` index. `Public.validate`
   requires `0 < steps < 2^cpu_log`, with `cpu_log <= 22`. Active ROM membership
   authenticates register IDs, zero-register flags and immediate/branch flags.
   Thus `enabled = active * (1 - zero)` is a unit Boolean on every event.
2. Every enabled after clock is the immutable value `4*row + slot + 1` for slots
   0, 1 and 2. These values are positive, globally distinct inside the leaf and
   below `2^24`. Each expected register has one initial tuple with clock zero;
   boundary tuples bind four canonical u16 limbs of each expected u64 value.
3. Complete REG closure equates CPU-before plus public-final tuples with
   CPU-after plus public-initial tuples. Both sides use unit weights. Each has
   at most `3*2^22 + 32 = 12582944` tuples, strictly below M31's characteristic.
   Consequently coefficient equality modulo the characteristic does not permit
   deleting or adding a whole characteristic's worth of duplicate events.
   This step is conditional on the usual soundness of the randomized typed
   LogUp argument and the physical STARK, not a claim that one evaluated
   rational equality deterministically proves multiset equality.
4. Therefore every participating before tuple is supplied by an initial tuple
   or an actual CPU after tuple. In particular its clock is already a canonical
   integer in `[0,2^24)`, without separately assuming a before-clock range.
   The physical U16/U8 queries bound `gap16 + 65536*gap8` by `2^24-1`.
   The equation `previous_clock + gap = after_clock - 1` has integer sides
   below `2^25 < p`, so field equality is integer equality. It proves strict
   predecessor order. A modularly negative predecessor or a future producer
   cannot satisfy both this equation and the closed argument.
5. Distinct after timestamps give each source tuple at most one successor;
   strict predecessor order excludes cycles and unrooted finite histories.
   Starting at canonical initial register values, reads preserve their value,
   while each write result is canonical through closed FUNCTION truth:
   ALU outputs derive from physically U16-ranged operands/helpers and Boolean
   predicates; BINARY outputs derive from canonical AND-table bytes. The
   discarded old RD is grounded by the same register chain. This supplies the
   canonicality induction used by the narrow CPU, rather than a local assertion
   that unrestricted field coordinates are bytes or limbs.

Register aliases are ordered by slot clock within an instruction. `x0` has no
CPU state events and its read/old-RD values are forced to zero; public initial
and final x0 values and its terminal clock are also zero. An immediate B operand
is instead bound by immutable ROM, and does not create a fabricated x0 read.
An instruction writing x0 may compute a nonzero C which is correctly discarded.
Inactive rows create no REG or FUNCTION events; their fixed clock/gap equations
still have canonical witnesses. Initial/final register equality is therefore not
being inferred from disabled-row junk.

## Control and immutable authority

Raw ROM uses four u16 limbs for both PCs and full-u64 wrapping static successors.
V2 additionally binds immediate B and the taken branch predicate through its
23-coordinate relation. FUNCTION truth gives the branch's Boolean C; ROM binds
that predicate to the chosen edge. The PC chain remains constrained through
inactive padding to the independently expected final PC.

Indexed authority sorts a unique full-u64 address set and assigns one scalar ID
per address, independently of execution. Branch edges share an address ID; they
are not separate address identities. Active ROM facts require executable validity.
Unsupported or undecodable words remain raw-byte identity-bound and nonfetchable.
Static terminal addresses can be mapped without becoming executable.
Canonical padded map rows repeat ID zero's actual full PC, never an invented PC
zero. `resolve` independently resolves expected initial/final full PCs, and the
current/next-ID chain binds those endpoints. The separately typed address-map
relation and public query roster bind any requested ID/PC pairs. Thus neither
48-bit truncation nor a compensated field-limb PC alias is an accepted mapping.

`program/setup.zig:Program.validate` caps expected words, validates aligned,
strictly ordered sparse addresses and bounds contiguous address arithmetic.
Expected program setup owns copied words/decoded metadata. Request endpoints,
steps and register coefficients do not enter reusable fixed polynomials.
Fixed-root equality is checked against receiver-constructed materials, rather
than treating a producer's program digest as decode authority.

## Transcript and closure ledger

Raw integration's `word16/cpu_protocol.zig` mixes expected program and complete
public-statement fingerprints before fixed/main commitments and challenge draws.
`cpu_verify.zig:verify` checks suite/revision/root roster, commits fixed and main,
draws challenges, mixes all physical claims, commits interaction, and then calls
the actual verifier. `cpu_sources.zig:Claims.validateProfile` closes local REG,
ROM, U16, U8 and, in local mode, FUNCTION/AND. V2 ALU's two sidecar claims enter
both this closure and the transcript. Omitted-role claims must be zero.

Indexed `word16_index/protocol.zig` binds expected full public state, resolved
endpoint IDs, program identity, geometry and public map pairs. Its `Claims`
contains sixteen physical claims; `validate` closes the inherited relations plus
map/known-map. `proof.zig:verify` mixes these claims before interaction commit and
constraint draws. Both integrations build component handles in the same physical
shape order as columns/logs, avoiding an independently ordered mask roster.
Strict inverse equations apply even at zero-weight lookup rows.

The distributed v1 manifest binds complete ordered actual fixed/main roots,
statement/job/schema/geometry/context identities and admitted FUNCTION mass before
the shared FUNCTION vector is derived. `resumeReceiver` compares actual proof
roots; it is followed by each physical verifier. Only FUNCTION debts are summed
afterwards. REG/ROM/range debts close inside each CPU leaf and cannot cancel
across shards. `Expected.validate` binds exact coverage, genesis PC/all 32 values,
intermediate PC/all 32 value adjacency and independently expected terminal data.
Local register clocks explicitly reset to zero per leaf; terminal clocks are
locally bounded/proved, not compared with the next leaf's reset clocks.
Consequently worker completion order does not select a dependency or challenge.

## Resource boundary and existing adversaries

Receiver CPU/index paths cap encoded proof bytes and use the central bounded
binary proof decoder. Distributed receipt parsing bounds metadata and proof
files, checks expected geometry/coverage before constructing key materials, and
uses explicit full-width binary PC/register fields. Fixed-tree leases and owned
proof transfers follow the qualified owner/cleanup paths. No concrete resource
error was identified; this was not an exhaustive audit of the generic PCS or
proof decoder internals.

Relevant existing tests, inspected rather than newly rerun for this report:

- `src/integrations/riscv_cpu/tests/rv64_word16_thin_cpu_test.zig`: cubic residuals,
  true aliasing/x0/full64 state closure, high-PC carry/wrap, unsupported opcodes,
  oversized clocks and request-independent fixed data.
- `tests/rv64_word16_thin_proof_test.zig` in the same integration directory:
  physical rejection of wrapped previous clocks, unbounded old RD, changed
  result/opcode/high PC; statement mismatch; fixed-lease allocation/owner tests.
- `tests/rv64_word16_index_control_test.zig`: wrong current/next IDs and operands,
  false/padded map aliases, sparse high64 PCs, invalid raw words, IDs above u16,
  wrapping exits, cubic and packed/scalar residual/proof parity, allocation unwind.
- Frontend `word16_index_control/authority_test.zig`: unique-address/branch-row
  distinction, canonical map padding, raw identity, full64 wrap and allocation
  failures. `word16_cpu/rom_lookup_test.zig`: contiguous/sparse agreement and
  immutable admission checked before decoded-cache access.
- `rv64_distributed_execution_v1/aggregate_test.zig`: jointly altered middle
  snapshots, genesis/terminal/coverage changes, balanced FUNCTION forgery,
  forbidden cross-leaf REG cancellation, hostile geometry before allocation and
  exhaustive receipt-decoding allocation failures. Its `public_test.zig` checks
  the full endpoint and adjacency contract independently.

The abbreviated integration test paths above are under
`src/integrations/riscv_cpu/`. These tests provide evidence, not completeness of
malicious witness coverage or a replacement for the argument's cryptographic
assumptions. This review does not qualify RAM/services, dynamic jumps, full ISA,
a semantic halt condition, global RAM or recursion. Open V2 remains rejected;
the accepted distributed control is binary-only and explicitly two-shard.
