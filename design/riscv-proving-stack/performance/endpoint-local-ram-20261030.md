# Endpoint-local RAM architecture

This is an inactive protocol design and algebra implementation. It is not an
original-STARK qualification, a recursion qualification or a speed measurement.
The existing V7 product continues to use its fully verified per-access WORD
memory argument.

## Work removed

Native typed instructions already expose clocked `MemoryAccess` tuples. The
current V7 path projects their ordinary-RAM partition, cancels that partition in
an access sidecar, reconstructs each access as an 11-limb WORD transition, and
proves that transition again in a sorted global memory component. Caller
arithmetic follows the same cancellation/reconstruction pattern. Those byte
copies, interaction columns and per-access global RAM rows are the removal
target, not an instruction micro-optimization.

A source/window instead closes its native and caller RAM relations directly
against one initial/final endpoint per touched address. Only those endpoint
transitions enter the global WORD argument. This retains independently proved
initialization, cross-window value consistency, nonterminal state deltas and
terminal output/halt semantics.

The retained full execution census has 57,876,727 RAM accesses but 5,444,030
address/cohort pairs at 4M-instruction cohorts. That is a 10.63x reduction in
*global event records*. Native instruction proving, new endpoint proving,
lookup providers and recursion still cost work. It is not an end-to-end 10.63x
speed claim.

## Required local equation

For each independently admitted execution window, before combining windows:

```
ordinary native RAM MemoryAccess
  + native RAM clock-gap MemoryAccess
  + original caller RAM MemoryAccess
  + endpoint initial-supplier / final-consumer
  = 0
```

An individual source equation must not be replaced by one equation over all
windows: swapped endpoint suppliers can give equal-and-opposite nonzero source
residuals. Each caller's arithmetic decomposition must also close individually;
one caller's unclosed private arithmetic cannot cancel another caller's.
Registers and instruction-state relations stay in their own per-window closure.

A major implementation trap is V7's deliberate omission of the RAM clock-gap
projection. `block_v7_native_relation_layout_v1.zig` drops precisely the
`.clock_memory_access` projection because its per-access WORD argument already
establishes RAM continuity. Endpoint-local RAM must restore that projection.
Its direct clock AIR and bounded lookup requests already exist. Omitting it
would break the local chain across synthetic clock-gap edges.

## Implemented inactive modules

- `block_v8_native_endpoint_layout_v1.zig` derives complete V6 mode-1 typed
  coverage, including RAM clock-gap projections, under a new B8 layout digest.
  It rejects caller interleaving until joined-window admission is qualified.
- `block_v8_native_endpoint_closure_v1.zig` extracts every ordinary/register/
  RAM-clock partition, preserves all physical claim checks and closes one
  native source with its correctly scoped endpoint supplier. It returns open
  global RAM/range/ROM/table obligations, never a success receipt.
- `block_v8_ram_endpoint_kernel_v1.zig` and its component encode ordered unique
  addresses, positive bounded last-local clocks, initial/final bytes, and an
  exact aligned byte-address representation. Range16 and byte-pair requests
  are required for the advertised integer bounds; direct equations alone are
  insufficient.
- `block_v8_caller_ram_projection_v1.zig` derives its finite active descriptor
  inventory from the existing admitted caller schedule and projects original
  MemoryAccess tuples with their original signs. It retains pair-identity
  equations and one independently normalized physical cyclic claim per slot.
- `block_v8_window_endpoint_local_closure_v1.zig` supplies pure joined-window
  equations and per-caller residual/roster checks. It does not relax native-only
  admission or confer proof authority.

## Callers share the window, not a later source phase

SHA, Keccak and signer bridges currently all emit byte addresses for RAM.
`block_execution_external_access_bridge_v2.zig` explicitly sets
`.address_unit = .byte_address`. Their access clock is the same
`4 * (execution_cycle - 1) + ordinal` encoding as typed native instructions.
Each caller AIR requests a range check on `current - previous - 1`. The generic
caller inventory audit confirms that callers have no separate clock-gap helper
component; native clock-update rows supply those gaps.

Therefore native and caller RAM can telescope *together within their execution
window*. Batched caller proofs must not be treated as executing after all native
instructions: a window can contain native access -> call -> native access ->
call to the same address. Their existing local clocks and values express that
interleaving. Splitting 890 calls into 890 independent native segments would
throw away the intended amortization.

There is a second implementation trap: the existing precompile lookup owner's
Keccak table helper evaluates caller events against zero input/output state
bits. That is valid for its table/register-only projections, but is invalid for
RAM. RAM projections must open the actual selected Keccak input and output word
bits, at current and +27 state-row offsets, using the same formulas as the
existing external bridge. Tests compare nonzero state words to the shipped
Keccak core events.

## Why removing byte-copy sidecars requires an invariant argument

Endpoint initialization/final bytes are range-checked. Native registers begin
with canonical public bytes; typed arithmetic and precompile output equations
must preserve their byte/value invariants. Native/caller consume/emit identities
and strict clock progression then connect each read to its preceding write.
The mutual register/RAM value invariant runs forward in the common local access
clock. A new source key must prove those original instruction/caller equations;
a producer-side `decodePair` check cannot replace them. Before deleting the old
sidecar, qualification must explicitly audit each load/store and caller effect
for address/space equality, numerator signs, strict bounded previous/current
clocks, unique current subclocks and byte-preserving writes. Inactive rows must
remain selector-weighted algebraically at OODS points.

## Global source time

The experimental endpoint kernel now uses `4 * source_ordinal + 3` as its
explicitly new coarse global time. This replaces the provisional
`(source_ordinal << 32) + 1` design. The existing sorted WORD witness
constructor can reuse this bounded phase: its actual
validation requires positive time, `time % 4 != 0`, and time no later than
`4 * finalCycle - 1`. A zero-based ordinal below the number of execution
windows fits those bounds. This mapping must be selected by a new endpoint
protocol and independently admitted ordered cohort roster; it cannot silently
reinterpret the old per-access event census. Terminal output/halt reads remain
after all endpoint transitions. The old public state-delta argument can be
reused only after the new transition and endpoint identities are fixed.

## Integration and qualification order

1. Commit original native columns once, with the new complete relation layout;
   commit endpoint columns and all range providers before drawing challenges.
   Derive endpoint liveness/count and max local clock from admitted geometry.
2. Generate original native projection columns and endpoint interaction planes.
   Close native-only local relations first. Prove them in one original shared
   STARK with ROM, tables and global endpoint RAM. All physical claims enter
   the transcript before interaction commitment.
3. Rebuild the receiver from external ELF/public snapshots and finite metadata.
   Destroy producer witnesses/proofs before fresh verification. Qualify duplicate,
   forked, descending, swapped, malformed clock/address/value and compensated
   physical-claim attacks. Include large clock gaps and repeated addresses.
4. Add the RAM partition to the caller's original arithmetic decomposition.
   Preserve exact Keccak state openings and all original private provider
   closure. Admit one local clock namespace per execution window, then qualify
   genuinely interleaved native/caller execution before enabling that route.
5. Teach the joined recursion compiler to replay the new original equation and
   all providers under distinct transcript domains/keys. Do not reuse old V7
   bundles or reinterpret their event counts. Independently rebuild keys and
   prove fresh complete-window recursive roots before performance comparisons.
6. Record original/recursive proof phase, setup, fresh verification, total
   request time, peak charged/process memory, component counts and artifact
   hashes on the same real native/Keccak/recovery windows as V7. A correct
   smaller geometry is only a stepping stone until those measurements exist.

## Local-source qualification delivered

`block_v8_native_endpoint_components_v1.zig` now assembles original typed
native direct AIR and the restored complete projection roster without an
access-witness tree or WORD sidecar. Its genuine RAM store/load test proves an
original STARK, destroys all producer columns and contexts, reconstructs the
fixed key, verifies afresh and rejects compensated physical-claim changes.

`block_v8_native_endpoint_local_source_v1.zig` extends that original proof with
the actual ordered endpoint AIR and an independently committed range16
provider. Three private main trees and three physical interaction trees share
one merged fixed tree and one STARK. Canonical fixed values are reconstructed
from public native geometry and endpoint count. Every native, endpoint and
range physical claim is absorbed before any interaction root. The selected
ReleaseSafe test passes with real native RAM execution, producer destruction,
fresh verification and source/range closure. It also rejects compensated
endpoint-plane changes that preserve the aggregate range claim. Carry
Booleanity without the thirteenth range request is explicitly rejected.

The diagnostic configuration in these tests is q8/PoW0. This is genuine local
proof qualification, but it is not canonical-security qualification and not a
complete-window theorem: global sorted endpoint RAM, ROM, native tables and
endpoint byte-pair requests are still open obligations. The enclosing B8
whole-window implementation must close those before a complete-window claim.

The caller projection algebra/finite plan passes nonzero Keccak state-word
parity against shipped core events. It also demonstrates that two calls
interleaved with native accesses close one common local window, while treating
the native effects as a separate sequential phase fails. Individual caller
arithmetic residuals cannot cancel across calls. An original caller RAM
projection proof and the joined native/caller admission remain future gates.
