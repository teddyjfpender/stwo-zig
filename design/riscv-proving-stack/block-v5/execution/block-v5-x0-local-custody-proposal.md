# x0 local semantics and register custody reduction

This is a versioned source migration in progress. Canonical x0 elision remains
disabled. The parent qualified the explicit native recipe12/12, including a
genuine three-instruction host fixture, and the first caller scalar recipe
batch4/4. Native borrowed-verifier/recursive callback body generation also
passed4/4 without invoking those functions. These bounded checks establish no
fresh STARK or complete-block authority. No build, proof, device or segment
run was launched by this agent.

Current soundness depends on the register chain. In `typed_addi.zig`, the
destination nonzero bit/inverse and visible-result constraints force an x0
write's next value to zero. The rs1 read has equality, byte/range evidence and
a predecessor gap, but no rs1-address-zero implication forcing its bytes to
zero. `access_schedule.zig:appendRegisterGroup` emits both universal memory
tuples and the range20 gap for every register address, including zero.
Consequently, changing both read limbs and the arithmetic result consistently
is not rejected by a local x0-source assertion; register multiset closure is
the remaining obligation. Existing result-only mutation tests should not be
mistaken for an independent source-zero proof.

The same prerequisite applies to caller pointers. The Keccak and signer
caller direct evaluators constrain pointer alignment/span and activity, but
do not force pointer bytes to zero when their pointer register is x0.
`sha256_memory_caller.zig` authenticates two pointer register addresses, values
and predecessor clocks through its typed memory events, likewise relying on
the register bus for x0. The SHA distinct-register constraint does not itself
exclude register zero. It must remain possible to execute any otherwise
admitted operation whose actual pointer is zero; no new host-only rejection
may replace the arithmetic proof.

`block_v5_native_lookup_request_source_v1` projects every register tuple in
mode1 and separately projects register clock-update helper tuples.
`block_v5_precompile_lookup_source_v1` projects both pointer-register events
for Keccak/signer and every space0 SHA event. `block_v5_register_windows_v1`
currently closes their aggregate per execution window using public initial
and final compensation for all32 registers. x0 values are independently
pinned zero, but its final access clock can be nonzero.

The local ZisK checkout provides a design reference, not admission authority:
`/tmp/stwo-zisk-v1.3.0-alpha/core/src/zisk_inst_builder.rs` maps register0
sources to immediate0 in `src_a`/`src_b` and maps register0 destinations to
no-store. Its RISC-V transpiler also replaces suitable immediate operations
with `copyb` when rs1 is zero. Our original RISC-V ROM bus must continue
authenticating the exact instruction, so this cannot be copied as an
unverified witness transformation.

## Proposed cohesive implementation

1. Introduce an explicit local-x0 semantic ABI in authoritative native/caller
   AIR recipes and the independently admitted template/profile. Reuse the
   existing destination nonzero/inverse hints where present. For each other
   dynamic register operand, add a constrained nonzero selector and inverse:
   `nz*(nz-1)=0`, `address*(1-nz)=0`, `address*inverse=nz`. Under active x0,
   constrain every before/after byte to zero and predecessor clock to zero.
   This avoids a degree31 Lagrange selector or an unproved host branch.
   The typed IR must authenticate the new effect-liveness product through
   its normal validation; selector hints alone are not authority.

2. Gate that register access's consume, emit and predecessor-gap requests by
   `active*nz` in the original native/caller interaction and exact counter
   registration. Keep every instruction clock, access ordinal, program tuple,
   RW effect and semantic operand position unchanged. Dynamic load/store
   spaces require the existing authenticated space selector as well. With
   linear nz, these projections retain the current degree4 ceiling; exact DAG
   degree checks must verify this for every family and paired entry.

3. Use a versioned register-window plan with canonical x0 initial/final values
   and last-clock0. Retain all32 public array fields and bind them to the
   statement, plan digest and B5SS; do not remove identity/count fields. The
   host tracker omits x0 custody records/clock-gap filler and leaves clock0,
   while preserving semantic event ordinals and separate logical/custody
   census definitions. Per-window compensation covers registers1..31 only.
   The full native/caller open claims then contain only those register effects;
   global accounting requires no unverified x0 scalar subtraction.

4. Update the same-root native/caller fused schedules, independent geometry,
   counter source, transport ABI and receiver admission together. Different
   selector columns/lookup liveness must produce different template/key/slot
   identities; old trees cannot be relabeled as the new protocol. Mode0
   compatibility must remain explicitly admitted under its original ABI.
   No extra standalone x0 STARK or unused optional production route is needed.

Affected ownership is native typed authority/access scheduling and witness
materialization, caller SHA/Keccak/signer AIR/witness/profile, tracker/access
transaction reservations and public snapshots, register-window plan/public
compensation, fused source schedules, exact native/caller counters and
independent codec/policy geometry. Lane Proof/Stage/PCS and Metal resident
modules need no x0 changes; sorted RAM is already space1-only in mode1.

## Accounting and qualification boundaries

For each x0 operand occurrence the intended removal is two universal register
memory fractions, one range20 predecessor-gap request, and any associated x0
clock-gap filler. It also removes two register0 boundary inverses per execution
window. New local selector/zero equations and source columns have a cost;
the current block has no independently recorded x0 occurrence census, so this
review establishes no runtime factor or peak-memory improvement. Sorting and
lane proof counts do not improve further from x0 removal in mode1.

Meaningful bounded fixtures must include every ordinary family with rs1/rs2/
rd zero, aliases and load/store dynamic spaces; a consistently forged x0 read
plus correspondingly changed arithmetic result; forged x0 write predecessor;
forged nz/inverse; nonzero-pointer x0 SHA/Keccak/signer callers; genuine pointer0
cases; inactive/OODS field values; host counter and symbolic event-weight
equivalence; exact logical-versus-custody census; register-window separation;
changed x0 public clocks/values; and old/new identity/geometry rejection before
wire allocations. The nonzero-register full bus equation and unchanged RW
tuples must match independently evaluated authentic typed entries. Fresh
native/caller/global proof qualification would require separate authorization;
source tests and codegen alone cannot establish complete proof closure.

## Explicit native recipe source handoff

The source now includes an explicit, opt-in native recipe. Canonical CPU
collection still selects the existing recipe, so x0 custody elision remains
**disabled** until caller, tracker and register-window migration closes.
The explicit native root passed12/12 in the parent's serialized lane; it did
not run a STARK. The additional caller/profile/storage batch below remains
source-only until its own qualification.

`Owner.initLocalZeroWithExternal` selects statement
`x0_local_custody_version=1`. `x0_native_envelope_v1` extracts each authentic
consume/emit/range20 triple from the shipped typed entry metadata, adds two
committed hints per access, and gates exactly those numerators by `space+nz`.
All original tuple values, instruction/access ordinals, entry counts, batch
counts and RW effects remain. The original opcode fill pass emits the hints,
normalizes only the authenticated x0 predecessor source column, and registers
actual new signed table effects. It does not regenerate a second matrix.
Semantic and lookup masks, native shape/template identity, staged column
reconstruction, recursive composition evaluation and same-root projection
DAGs select the identical recipe. Default legacy constructors retain their
existing semantics.

The additional direct equations have degree at most four; this raises native
quotient evaluation from `trace_log+1` to `trace_log+2`. Full committed-LDE
recovery checks all high coefficients before extending in the required
quotient buffer. One immutable transform tower serves interpolation and
final evaluation, and is released before prepared tasks are published.
Native codec and bundle-policy composition caps are derived independently
from the admitted recipe, including the fixed native composition split.
The source increases raw-column capacity by six, without changing any legacy
family's declared width.

The focused nonproving root is
`src/frontends/riscv/block_v5_x0_native_unit_test_root.zig`, filter
`block-v5 x0`. Its fixtures cover all family symbolic degrees, mask identity
mutation, authenticated schedules and real ADDI/XORI cells, coherent nonzero
x0 read tuples, exact signed range20 changes, template/shape mismatch and
public x0 clock rejection. The three-instruction fixture executes only a
small host runner segment when the parent qualifies this unit root; it does
not call a STARK, driver, device or benchmark entrypoint. These tests have not
been run by this agent. The native direct and lookup capability namespaces
are7/8; they avoid retained Poseidon namespaces3/4 and candidate5/6. The parent
separately qualified their offline AOT catalog admission.

## Explicit caller and custody source freeze

The caller recipe is `CircuitProfileV1.ethereum_local_zero_v1=3`, containing
Ethereum statement schema2/ABI2 and the independently pinned local-zero SHA
digest `512c30efdf23c16a4a22a5635e92a764bde2331c1282b08fdd25d42e0e04d914`.
Keccak and signer commit two extra pointer selector/inverse columns; SHA
commits four. Arithmetic and projection evaluators use the same generic
local-zero equations. Keccak/signer main generation and SHA caller generation
fill their original arithmetic matrices once; no additional full matrix is
constructed for the recipe. Semantic caller counts and event ordinals remain
unchanged, including elided zero-weight tuples.

`Assembly.createBlockV5StandaloneForCircuitProfileV1` admits this explicit
profile independently for both Ethereum and Ethereum/SHA component owners.
The existing constructor continues to use the unchanged canonical protocol.
`ethereum_sha_statement_wire.encodeExtensionForRecipe` and
`decodeExtensionForRecipe` require independently selected recipe membership
and bind wire version2/ABI2 plus a distinct combined semantic digest. Their
legacy wrappers accept only the original wire grammar; they cannot relabel
new geometry as old. V5 codecs additionally validate the independently pinned
family protocol and exact statement geometry before proof allocation.

Staged caller reconstruction, exact signed counter registration, extension
program slots and packed-memory descriptors carry the actual selected widths
and recipe version. New slot identities mix that version only for the new
recipe, leaving old identities intact. Register-window plan version2 binds the
native local-zero ABI and matches every independent native and caller recipe;
its compensation covers registers1..31 while all32 public fields remain.
Explicit tracker/session version1 retains register0 clock0, rejects nonzero
zero-register transitions, and preserves every nonzero chain and RW event.

The expanded nonproving root is
`src/frontends/riscv/block_v5_x0_caller_unit_test_root.zig`, filter
`block-v5 x0`. Four new named fixtures supplement the already qualified four:
physical profile/wire rejection plus real component-owner construction;
exact extra-column masks/domain body generation; tracker/window parity and
public clock rejection; and cell-by-cell signed table-counter parity with
transactional coherent pointer forgery rejection. The expanded root is now
qualified by the 13-check integration gate recorded below. It does not invoke
a prover, recursive driver or GPU.

Canonical activation is deliberately deferred. The final coordinated switch
must select B5PF version3/profile3, pass session
`x0_local_custody_version=1` through every first/second/verification pass, use
`Owner.initLocalZeroWithExternal` for native source construction, and derive
register-window version2 from that same admitted policy. First-pass proposals,
staged native/caller matrices, fresh receivers, independent metadata policy
and final per-window/global closure must agree. A profile-only or tracker-only
switch is invalid. Old mode0 helpers retain explicit legacy admission.

Next, caller arithmetic must adopt the same local equations for the two SHA
pointer registers and single Keccak/signer pointer, with versioned physical
column/profile identities and exact counters from those committed cells.
SHA's generated IR, Keccak/signer generic direct/core-event evaluators,
selected-column/fused access recovery and independently capped codecs must
move together. A versioned register-window plan then keeps all 32 public
array fields, requires x0 clock zero, and compensates only registers 1..31.
Only after those pieces and the host tracker agree may canonical collection
activate the new recipe. Base-proof equation counts and matrix width grow;
row-dependent access removal does not currently reduce declared entry or
batch counts. This source work alone supports no end-to-end speed claim.

## Root qualification checkpoint

The explicit native recipe passes12/12 focused checks (six named behavior checks), including a genuine three-instruction CPU fixture with independently declared ROM, source-cell coherent zero-read forgery rejection, unchanged instruction/access ordinals and signed counter census, every-family degree/mask admission, and full-LDE degree-checked recovery. This is a tiny nonproving guest fixture; it does not restart the stopped mainnet proof or produce a STARK. Explicit caller recipes separately pass4/4, deriving SHA recipe digest `512c30efdf23c16a4a22a5635e92a764bde2331c1282b08fdd25d42e0e04d914` with97 constraints/189 unchanged effects. Exact scoped evidence is `cpu-performance-gates-v1/x0-local-native-source-qualified-v1.json` and `x0-local-caller-source-qualified-v1.json` in the Ethereum delivery notes. Canonical profile/witness/window/tracker migration remains in progress and x0 elision stays disabled until its complete custody path is qualified. No runtime speedup is established.

## Explicit caller integration qualification

The expanded explicit-profile root passes13 ReleaseFast checks (10 named and3
import checks), including real selected caller component constructors, exact
hint masks and scalar domain/OODS body generation, profile/key relabel rejection,
register-window/tracker parity and staged counter reconstruction. Every original
lookup count remains except the authenticated x0 gap request. Coherent pointer
forgeries reject before counter mutation. SHA remains97 constraints/189 effects
with digest `512c30efdf23c16a4a22a5635e92a764bde2331c1282b08fdd25d42e0e04d914`.

Evidence: `autoresearch/notes/2026-09-24-ethereum-block-delivery/cpu-performance-gates-v1/x0-local-caller-integration-qualified-v2.json`.
No guest, STARK, device or segment was run. Canonical protocol remains version2
with profile2; elision remains disabled.

## Shared production recipe selection

`block_v5_execution_recipe_v1.Recipe` now selects the shared production
implementation. Product roots may declare `BLOCK_V5_EXECUTION_RECIPE:u32`:
0 selects custody_v2, while 1 selects local_zero_v1. A root without that
declaration retains custody_v2. This is a compile-time product policy, with no
environment or runtime override. Canonical activation remains a separate
change after qualification.

The selected recipe reaches native Owner construction, every session pass,
typed SHA rows, caller profile/protocol version, actual arithmetic/fused
components, staged cell reconstruction, register-window compensation and
counter admission. Source image identity version3 binds the new ABI and
semantic digest; native templates, caller keys, windows and scoped provider
plans retain their independently admitted geometry. Source/Pins, collection,
staged replay, transport policy, Programs, TableJoin, MemoryJoin and Global
reject mismatched recipes. Receiver-policy wire version3 rejects relabeling
new recipe policies as version2. The old product preserves its old identities.

Both qualification roots import the same test implementation:
`src/frontends/riscv/block_v5_recipe_production_unit_test_root.zig` selects0;
`src/frontends/riscv/block_v5_x0_selected_production_unit_test_root.zig`
selects1. Zig's tested file is not its executable `root`: the executable is the
test runner. These roots therefore require explicit `block_v5_recipe_test_runner.zig`
and `block_v5_x0_selected_test_runner.zig`, respectively. The tiny runners
declare the independent policy and delegate execution, error reports and
allocator leak checks to the installed compiler's unchanged standard runner.
Each tested root also asserts its own expected policy against the executable
selector. An omitted or mismatched runner cannot silently qualify recipe0 as1.
The first attempted selected-root compile failed on this missing selection;
it qualified neither recipe. The corrected runner handoff remains unrun.

Root-owned qualification commands (not executed by this source batch):

```sh
python3 autoresearch/notes/2026-09-24-ethereum-block-delivery/test_sha_memory_proof.py --root src/frontends/riscv/block_v5_recipe_production_unit_test_root.zig --test-runner src/frontends/riscv/block_v5_recipe_test_runner.zig 'block-v5 selected production'
python3 autoresearch/notes/2026-09-24-ethereum-block-delivery/test_sha_memory_proof.py --root src/frontends/riscv/block_v5_x0_selected_production_unit_test_root.zig --test-runner src/frontends/riscv/block_v5_x0_selected_test_runner.zig 'block-v5 selected production'
```

Filter `block-v5 selected production` covers recipe/native/caller/
window/source mismatches, authenticated SHA multiplicity upper bounds, genuine
mixed SHA+Keccak first-round commitments and staged recommit, warm immutable
tree leases, exact RW byte demand, and scalar register-window cancellation.
It also retains actual cold/warm Driver, collection, assembly, Pipeline,
arithmetic/fused producer and receiver, codec/store, global receiver and CLI
function bodies without invoking them. No guest, STARK, segment, device or
benchmark is run by these tests.

This production plumbing batch is source-only and unqualified at handoff.
Neither recipe qualification root has been executed. A successful bounded
source/body gate would establish usable matching production paths; it would
not establish a complete STARK or runtime improvement.

## Cohesive production recipe qualification

Both explicit executable recipe runners passed17/17 focused source checks: recipe1/profile3 local-zero and recipe0/profile2 retained canonical. Independent root expectations prevent silently exercising the wrong runner policy. Six named behavior/admission/ownership/body checks plus11 imports per recipe include actual cold/warm driver, CLI, staged codec, native/caller producer and complete global receiver code generation without invocation. Exact source pins and logs: `autoresearch/notes/2026-09-24-ethereum-block-delivery/cpu-performance-gates-v1/x0-cohesive-production-recipes-qualified-v1.json`. Canonical recipe0/protocol2 remains unchanged. No STARK, execution guest, segment, device or benchmark ran; matched complete proofs remain pending.
