# Register-boundary and scalar-provider arithmetic lanes

This is a point-arithmetic seam for existing Word16 physical roles, not a
recursive receiver. Native public data, protocol identity, domain evaluation,
source ownership and all committed dimensions remain unchanged.

`word16_cpu/boundary.zig` now has one selector/tuple authority over32 Word4
values. The original native `Public` wrapper still expands every full64 value
with `public.word` and emits the same three residuals in the same order.
`PublicFor(C)` preserves that exact native type for Q; external lanes receive
32 initial Word4 values,32 final Word4 values and32 terminal-clock wires.
Initial clocks are hard zero in the arithmetic: there is no free initial-clock
input. The native register challenge alias delegates to `RegisterChallengesFor`.

`boundary_component.ComponentFor(C)` handles only the existing register-boundary,
U16 and byte-provider roles. It samples exact current/previous masks at absolute
column offsets and uses the shared circle quotient denominator. Existing native
`word16_cpu.component` point callbacks delegate these three roles to this path;
its old CPU/ROM paths and all native domain callbacks stay unchanged. The scalar
provider calls the existing typed scalar-range authority; no equations are copied.

The register endpoint tuple is affine in fixed selector polynomials. Public
values and challenge wires are constant with respect to the trace variable.
Its strict product inverse is cubic; scalar provider residuals are at most
quadratic. Existing declared degree3/split1 geometry is retained. Dense secure
finite differences check every residual and a nonzero cubic boundary term.

The focused suite also checks every raw64 limb/register index through independent
one-hot oracles; scalar/PackedM31/PackedQM31 agreement; actual Circuit wires for
endpoint limbs, terminal clocks, claims, challenges and point coordinates;
quotient-scaled point accumulation; missing public inputs and malformed masks;
and native metadata equality with allocation-failure cleanup.

A future recursive statement still must bind these endpoint wires to its public
transcript, derive their canonical limb/clock encodings, enforce native admission
and connect adjacent shards' register VALUES. Local clocks reset to0; final
local clocks must not be copied into the next shard. Native field membership
and local claim closure do not replace manifest/global RAM/truth closure,
expected image/output authority or independently admitted recursive topology.
This slice constructs no recursive proof and adds no accepting open verifier.

The receipt pins native CSP/Sail proof-byte and complete CPU/RAM compatibility
against frozen CPU47/BINARY29 controls, plus fresh verification of the existing
complete25-CPU/5-truth Ethereum block. These functional runs are not controlled
performance measurements; no speed or memory improvement is claimed.
