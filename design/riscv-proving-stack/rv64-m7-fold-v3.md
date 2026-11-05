# M7 typed fold and public RAM boundary

Status: implementation in progress, no production profile enabled. Unit
constraints and native hash agreement do not establish a recursive proof.
The complete producer, source-derived key tables, fresh receiver, independent
audit and negative corpus remain promotion gates.

`om31_native/node_summary_v3.zig` defines a fixed 180-word public statement.
The version and length precede T_nat, T_rec, image, request statement, native
chi digest, interval/count, chain/state endpoints, three separate bus claims,
three integer masses, CPU-call/truth counters, sponge/CPU counters, optional
boundary address limbs, step endpoints, expected-state commitment, terminal
output commitment/presence and depth. CPU-call and truth-consumption counters
are separate: truth IDs restart at one; they do not start after CPU call totals.

The current native `Canon.chi` is a 32-byte Blake digest, consumed verbatim by
`manifest.drawShared`. Its eight raw u32 words must not be reduced to eight
M31 residues. Bus coordinates and integer counters instead demand the unique
M31 encoding by reduction followed by an exact raw-word round trip. Digest
words keep the builder's two-u16 u32 encoding. State hashes constrain every
native AIR limb to u16 before assembling/hash encoding the PC and registers.

The combine constraints bind all common authorities and expected commitment,
every interval/chain/state/counter/step adjacency, interval length=count,
integer masses below p, depth and a unique terminal-output presence bit.
Inactive output commitments are canonical zero. These constraints must be
applied to the SAME public wires the child PCS verifier authenticates, after
T_rec membership. Leaf circuits still owe source-bound request admission,
T_nat membership, native verification, native chain step, counter transitions
and CPU-only state changes. None is supplied by constructing this data type.

## RAM boundary representation

To avoid hashing the entire input memory into every recursion circuit, the
proposed root relation removes initial/terminal boundary-component claims
from the leaf's RAM aggregate. It retains every authenticated internal RAM
role. The fresh root computes, from the independently authorized complete
public cell lists and the circuit-bound native chi:

```
expected_internal_ram = -(Boundary.claim(initial, true, shared.ram)
                        + Boundary.claim(terminal, false, shared.ram))
root_NS.bus.ram == expected_internal_ram
```

This is the existing RAM closure rearranged, not an unverified polynomial
evaluation supplied by the producer. The actual fourteen-coordinate tuple is
space, four address limbs, epoch, tick limbs, four value limbs, read and write
rights. Internal before events have positive sign and after events negative;
initial boundary is negative and terminal positive.

Conditional independent algebra review by the proof-format stream requires:

- Every retained internal claim is authenticated under the same circuit-bound
  chi; omitting a role is a rejection, not a smaller aggregate.
- Boundary lists are complete, authorized, sorted and unique, with canonical
  address, value, clock, space and rights encodings.
- The characteristic bound counts all positive uses and public boundary
  terms. A net residual is never a mass bound.
- The original strict clock/epoch transition constraints remain present.
  Unchanged cells can have clock zero at both boundaries and legitimately
  cancel; no argument assumes every terminal clock is positive.
- The root derives chi from the authorized statement and authenticated final
  chain, and the leaves use that same chi to verify the native relations.

Required mutations include missing/duplicate public addresses, wrong clock,
value/rights, chi mismatch, an omitted internal role and mass wrapping at p,
in addition to the full typed-summary, membership and native admission cases.
This review is conditional algebra approval only. The relation is not yet
active in a production prover or receiver.

## Execution identity and compact native public authority

Legacy `FixedSet.executionIdentity` hashes an ordered list of every native
binding. It remains unchanged. The new GKR-only helper instead uses the
distinct domain `rv64-m7/native-gkr-v2/execution-scope/v1`, followed by the
semantic execution base, existing fixed-authority domain, exact candidate PCS
profile identity and `Canon.versionIdentityV2(RUNGS, native_gkr)`. A shared
native/circuit visitor emits this order. The semantic base's existing order
binds configuration, sampler, program, image/input identity, total/max steps,
per-prefix budget and complete genesis/final CPU state.

Conditional independent review permits omitting the redundant ordered binding
list only when source-pinned T_nat membership authenticates each role/key and
the complete ordered segment chain binds VK hash, MAIN and local receipt. The
fold must enforce coverage, counters, state continuity and source-derived
masses, and derive chi after the final chain. Different valid segmentations
can then share a semantic identity. Cross-mode/domain/profile and
reordered/omitted/duplicated-key cases remain production corpus gates.

**Open blocking condition:** today's CPU leaf mixes a guessed legacy worker
statement. Today's root authenticates it by reconstructing the whole public
frame and legacy hash, including complete boundary lists. A typed leaf cannot
leave that seed free while separately guessing the AIR public inputs: it must
bind all those inputs before native challenges. The new native-GKR format
therefore needs a compact, source-owned CPU public-statement visitor shared
by producer and circuit. It must cover every actual native AIR public scalar,
class/program/config/fixed authority and the semantic execution identity.
Public boundary values can be excluded only with the RAM relation above.
The new `Cpu.Statement.chain_inputs` retains the original raw public handles
for this visitor; storing handles adds no guesses to legacy circuits. The
native stream owns the native compact projection. No v3 profile may activate
using a freely guessed legacy digest.


## Current helper implementation gates

The direct compact CPU/truth visitors now exist in `services/native_gkr/`.
CPU metadata includes epoch, cumulative steps, LS/DWORD counts, every family
call/first ID, sponge and bulk counters, and both signed mass halves. The
new chain uses that direct statement digest. Its stage-one receipt is exactly
`Canon.rho(MAIN, null, empty)`: numerical GKR is proved after chi and cannot
enter the preceding chain without circularity. Native/circuit framing agrees.

`typed_leaf.zig` constrains source T_nat membership/header, exact native
ordinal/execution/MAIN/statement/chi handles and separate globals.
`typed_cpu.zig` and `typed_truth.zig` constrain state and cursor transitions.
`typed_integer.zig` prevents counter addition wrapping modulo p. The additive
`mass_authority.emitCpuTerms` visitor preserves every positive and negative
source event; `typed_mass.zig` derives signed totals and absolute bounds from
those count handles, including exact zero high halves. Existing native
mass calculation remains unchanged and agrees in differential tests.

These helpers passed pod unit gates, including substitutions of authority,
MAIN, scope, counters, states, terminal presence and signed masses. They are
not a complete typed leaf. Connecting exact numerical/compact verifier wires
and the source Plan's count/absence/cap projection remains mandatory. Truth
source bounds, conservative per-class security envelopes, real typed proofs,
producer/root wire, fresh reception and independent audit remain open.
