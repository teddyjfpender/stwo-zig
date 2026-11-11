# Independent review: narrow OP Miller provider and runtime

Reviewed snapshots: `8100988d3` (narrow DAG/reference proof), `b332faf3f`
(runtime), `0e74f0d28` (bounded tape envelope) and `64e286fa8` (collector).
The guest baseline is `ae51189a3`, ELF
`72c234488ca510aa864d0bae8d86d4001f5ccd30993be1883bafb3baabc3e930`:
238,226,172 retirements and 15,867,083 service RAM word transitions on OP
121065789. This review did not rerun physical proofs or certify the whole
protocol. Production admission remains closed pending the joined receiver.

Paths below are relative to the repository. Line references refer to the
specified snapshots, not subsequent edits.

## Findings requiring changes

1. **Small-call cost geometry is incorrect in the reference.** In
   `src/frontends/riscv/rv64/air/delegations/bn254_tower/narrow_source.zig:161`,
   `cost()` uses raw ceiling logs, without the source minimum log 8 or the
   arithmetic carry-table minimum log 15. `cost(1)` rejects despite a valid
   frontier8/arithmetic15 shape; `cost(20)` returns an arithmetic log 10 shape
   that `narrow_equations.zig:44` rejects. Fix by sharing a role-specific
   minimum with geometry validation, including the full carry table. Add small
   requests and the 1023/1024 arithmetic-capacity edge to the cost tests.

2. **The cost helper omits committed multiplicity columns.**
   `narrow_source.zig:170–172` counts `Micro.MAIN`368, while
   `narrow_equations.zig:20` commits370 arithmetic columns after adding byte
   and carry multiplicities. It undercounts 2 arithmetic domain columns and
   reports 401 rather than 403 lifted main columns. Derive the helper and
   physical layout from one width authority. The committed heavy receipt uses
   the correct 370 and is unaffected by this helper defect.

Both were reported to the provider owner, who implemented shared minimum/width
fixes and added physical-layout equality tests. Their qualification/commit
belongs to that workstream; this document does not modify its active source.

No additional algebraic bypass was found in the pinned narrow arithmetic.
That conclusion is conditional on the closures below, rather than evidence
that a stand alone valid provider proof authorizes an execution.

## Canonical output authority

`micro.zig:183–189` constrains 15 Boolean carry/borrow bits and 16 little-endian
16-bit chunk equations for `RESULT + DISTANCE + 1 = p`, with no outgoing final
carry. `narrow_source.zig:106–109` supplies 32 RESULT byte queries, all quotient
bytes, 32 DISTANCE byte queries and every carry range query. With these ranges,
all canonicality residuals are strictly smaller than M31 as integers, so their
field equalities establish integer equalities and RESULT lies in `[0,p)`.

This applies to **every** micro-result, including the twelve final outputs.
`dag.zig:25–27` maps final output coordinates to value IDs 34..45.
`narrow_source.zig:64–66` maps precisely those immutable writers to external
Wire35 labels 20..31 with weight+1. Non-final writers have no external output
weight. There is no producer-selected canonical flag or output label.

This is the authority used by the gated OP guest's direct canonical decoder.
The guest asserts canonical field representation. Host-only tests convert the
canonical bytes into their normal Montgomery representation. A checked host
execution alone would not establish this authority: all local range, SSA,
external Wire and RAM obligations must close in the accepted proof.

## Integer arithmetic and arbitrary u256 representatives

The micro envelope at `micro.zig:12–29` bounds three positive products plus
both signs of the linear addend and output. It deliberately over-approximates
every fixed instruction. `curves/spec.zig:283–330` derives quotient widths and
coefficient extrema from full-width byte-bounded u256 operands, not an assumed
canonical input bound. `curves/spec.zig:366–405` derives asymmetric carry
intervals and rejects any positive or negative integer residual bound reaching
M31. This is why replacing byte products with unqualified16-bit products would
be unsound even if it reduced columns.

`micro.zig:174–181` constrains each radix group, including the terminating zero
carry. Quotients and encoded carries have local range authority. Constants
and coefficients come from source-owned preprocessing. Correctness for
arbitrary representatives therefore follows from bounded integer congruence
and canonical output, rather than from native `%p` computations in the witness
generator. The tests at `tests.zig:196–220,248–273` include all-ones u256,
modulus-valued inputs, random inputs and every carry/result/quotient/distance
mutation. They are useful evidence, alongside the source bound derivation.

## SSA, literals, activity and range inheritance

`dag.zig:83–105` computes exact fanouts, refuses reads before writes, duplicate
writers and unused private values, and restricts literal exemptions to zero
and nine. `micro.zig:169–172` fixes literal byte values under their immutable
selectors. These exemptions cannot supply unconstrained data to the DAG.

`narrow_source.zig:110–113` uses unit negative read weights and source-derived
positive writer fanouts in a tuple containing kind, invocation ID, value ID
and all32 bytes. Each final writer is separately exported to Wire35. The
shared SSA claim must close across frontier and arithmetic components; closing
each provider independently is not the protocol.

`narrow_source.zig:155–158` fixes an active prefix: first row active, no later
0→1 transition, the unique1→0 transition at `calls * period`, final row
inactive. Geometry reserves an inactive row and prevents IDs wrapping M31.
Thus activity cannot truncate a partial20/32-row call or admit a second prefix.
Inactive arithmetic advice is irrelevant only because it contributes no SSA,
Wire or consumer range messages.

Frontier values have **no local byte queries**. Their byte authority must come
from the authenticated CPU/RAM packet side of Wire35. Thereafter the acyclic
SSA relation carries byte-bounded values from frontier inputs and locally
range-checked canonical writes to every operand read. This inheritance requires
all frontier/arithmetic MAIN commitments before the relevant challenge draws,
one shared SSA challenge, and independently bound input/output call spans.
A late, uncommitted frontier is not a safe replacement: its unrestricted
field-valued coordinates could be chosen after the tuple-compression challenge.

The reference fixture satisfies the commitment ordering:
`narrow_physical_test.zig:144–152` commits both MAINs before drawing challenges,
then mixes all physical claims into the transcript before INTER commitment.
Its receiver rebuilds fixed roots (`:95–108`), checks SSA closure (`:89`) and
external expected Wire closure (`:116`), then verifies the physical proof.
It uses a 12-query/no-PoW **QM31 toy profile**; it is not the production 128-bit
construction and must not be presented as such.

## Runtime, tape and complete event coverage

`tower_call.zig` at `0e74f0d28:32–48` checks counters/clock, alignment, complete
packet read rights, output write rights and computation before atomic word
storage; CPU state and counters advance only after storage. The packet holds 80
input and 48 output u64 words. The 32-word tail is reconstructed unchanged.
There is no enlarged legacy curve packet.

The runtime dispatch (`session.zig:178–180`) admits 0x40001 only in
`ethereum_services_op_v1`. Existing v3 proof selection continues to use
`isV3`, not the broader runtime inheritance predicate. Prepared capture has an
explicit OP-only seam with matching program and tape profiles
(`prepared.zig:263–267`); ordinary combined selection does not silently choose it.

The OP tape uses a distinct magic/profile pair, checked at
`compact_tape_wire.zig:152–160`. Tower count and bytes are bounded before its
allocation (`:233–247`), reserved words and operation are checked, trailing
bytes are refused, and chronology/IDs/PC/pointer/retirement framing are checked
(`:323–338`). The tape is advice, not independently authenticated execution:
without ROM, a compact step cannot determine whether its operand equal to a
tag was an ECALL. Reverse event coverage therefore belongs to ROM-driven CPU
capture and the collector, not merely to `readTail`.

The collector enforces that ROM-derived CPU service count equals tape payload
count plus payload-free services (`collector.zig:443–449`). It consumes one
OP packet for each matching CPU owner (`:601–615`), reads all 80 predecessors,
validates readonly tails/rights/value chronology, and updates the ledger.
Its terminal count equality (`:622`) rejects unconsumed packets. Combined with
the ROM-derived count equality and owner checks, neither missing nor extra
OP payloads can silently disappear from this path. The existing two-shard
collector fixture validates all 80 predecessor words and rejects altered tail
advice; explicit missing/extra packet tests are a worthwhile remaining join gate.

## Characteristic bounds and128-bit assumptions

`schedule.zig:35–52` counts both sides of the source-owned relations and checks
multiplication overflow before comparison with M31. At 22,185 calls:

| Relation | Absolute source-weighted messages |
| --- | ---: |
| Local byte/carry range | 181,739,520 |
| Local SSA | 7,631,640 |
| External Wire, including counterpart | 1,419,840 |

These are characteristic bounds, **not** extension-field collision bounds or
a 128-bit claim. Runtime event count alone is not a proof budget; production
planning/receiving must reapply source-owned bounds to the aggregate relation
span. The old `micro.validateMass()` helper counts only one side; current
source validation correctly calls `Schedule.mass()`. Prefer removing or clearly
renaming the weaker duplicate helper before a future caller mistakes it for
production authority.

The wider-field/local-GKR adaptation and global shared-challenge accounting are
separate active workstreams. Their receiver must bind the admitted authority
version, profile, roles, geometry, spans, immutable roots, public execution
statement and all claims under the documented128-bit assumptions. No claim
here supersedes the existing fail-closed security policy.

## Cost: narrow width is useful but not itself a native cell win

At frontier log 19 and arithmetic log 20, the committed reference uses 33/370 main
columns and 16/560 OM interaction columns. Its 1,000,865,792 native trace cells
are **1.47× the wide reference's 682,622,976**, while opening width falls from
20,832 to 979 main-plus-interaction columns. It is a recursion/opening
architecture improvement; the native classic proof does more cells.

If local range and SSA interaction commitments are replaced by correctly bound
GKR while retaining each component's eight OM Wire columns, the trace-cell
subtotal becomes 417,857,536: **2.40× fewer** than narrow classic, before GKR
construction, binding and transcript costs. That is a model, not a benchmark,
and fixed setup cells and recursion work require their own accounting.

## What full Miller can remove from the 238M guest

The exact census/source counts identify 85 loop invocations, 22,185 lines,
5,439 Fp12 squares and 1,764 signed-seed dense products **inside** the Miller
program. The previously listed 2,266 dense products also include inverse checks,
residue tails and cached-factor merges outside this boundary.

A Miller-only program therefore subsumes 97,020 **nominal** existing Fp2
crossings (`12*5439 + 18*1764`), not 106,056, and22,185 line crossings. Zero
and scalar shortcuts can reduce actual calls below the nominal formula.
The loop, line wrapper and Fp12-square functions retire 17,817,830 exact self
instructions in the current full census. 16,170 of 17,676 Fp6 multiplies belong
to this boundary; assigning the average observed Fp6 self cost estimates another
29.94M instructions. Operand-dependent paths mean that allocation is a model.
Shared Fp2 additions, canonicalization and copies need caller-sensitive
attribution before giving an exact inclusive total.

A roughly 50–75M retirement saving is plausible before new program marshalling,
about 21–31% of the 238M baseline. It is not measured, and it does not imply 10×
guest or proving acceleration. The protocol could reduce boundary data volume
to roughly 4.37 MB plus descriptors instead of22.72MB for line packets alone,
while keeping prepared coefficients guest-validated and RAM-authenticated.
Full pairing/G2-preparation/residue integration may save more, but widens the
validation and false-result authority surface. Ordinary EVM dispatch alone
still retires 28.38M self instructions.

The structural objective is fewer CPU retirements and global RAM crossings,
a narrow reusable field program, fewer recursive openings and explicit local
closure. Micro-op truth work, padding, GKR binding and recursion must still be
measured together. These counts support that direction; they do not establish
the user's 10× end-to-end target.
