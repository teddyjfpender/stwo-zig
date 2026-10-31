# Closed finite RAM foundation, experimental v1

This is an actual seven-component STARK over independently expected operations,
complete finite initial image/permissions and terminal cells. It is **not** a CPU
execution proof, a general sparse initialization proof, a service bridge, a
cross-process aggregate or a production replacement for authenticated RAM roots.
There is no accepting open-RAM API. `rv64_closed_ram.verify` verifies the physical
proof and closes every relation against independently supplied expected data.

The schema identity pins `(space, address[4]u16, epoch16, tick16, tick8,
value[4]u16, readable, writable)`. This is distinct from future time64/packed-rights
schemas even if another tuple also has fourteen coordinates. Addresses are full
64-bit little-endian limbs. In this bounded fixture, alignment follows the exact
independently expected owner/image addresses. This does not supply a general CPU
load/store alignment bridge.

## Physical roster

| Role | Log rows | Main | Interaction | Residuals |
|---|---:|---:|---:|---:|
| RAM transitions A | 5 | 28 | 68 | 72 |
| RAM transitions B | 6 | 28 | 68 | 72 |
| INIT, sorted unique | 5 | 23 | 48 | 51 |
| TERMINAL, sorted unique | 5 | 23 | 48 | 51 |
| Expected operation consumer | 5 | 14 | 8 | 18 |
| U16 | 16 | 1 | 8 | 3 |
| U8 | 8 | 1 | 8 | 3 |

One arithmetic-lane authority emits every residual for domain evaluation and
OODS. A dense arbitrary-QM31 finite-difference audit bounds each residual by
three; native SIMD lanes are compared against that same scalar authority with
full extension-field relation challenges. Quotient expansion is 2n. The complete
source has 200,928 fixed, 70,400 main and 536,192 interaction cells, or 807,520
field cells / 3,230,080 bytes before PCS storage. There are 566 OODS masks.
The U16/U8 tables dominate this intentionally small fixture's fixed overhead;
these numbers are not an Ethereum throughput forecast.

## Ledger and authority

Each active transition contributes `+before - after` to RAM and `+owner` to a
separate typed owner relation. The **same Boolean active coordinate** controls
both contributions. Its owner tuple pins ID, address, after epoch/tick, after
value and write flag. The expected owner component contributes one negative
unit for each independently expected operation. No arbitrary multiplicity can
create an unauthenticated RAM effect.

INIT contributes negative initial states; TERMINAL contributes positive final
states. Public coefficient bindings authenticate all fourteen fields of their
rows, with immutable geometry-only row selectors. Boundary address ordering is
proved by four ranged delta limbs, Boolean carry propagation, zero top carry and
an inverse of the nonzero limb sum. This forbids duplicate or wrapping sorted
addresses. The expected image is complete for this finite fixture: there is no
permission-only zero fallback and no omission of nonzero ELF/input exceptions.

Every transition ranges address, before/after value, epoch and clock/gap limbs.
Same-epoch order proves `before_tick + gap + 1 = after_tick` with explicit carry;
cross-epoch order proves `before_epoch + gap + 1 = after_epoch`. All bounded
integer sums are below M31's modulus. Reads preserve all four value limbs and
require readable; writes require writable, including valid write-only cells.
Permissions are the same coordinates on both state tuples. The expected owner
origin is unique per `(address, epoch, tick)`; INIT has clock zero. Unit flow,
unique after origins, sorted unique endpoints and strict predecessor order rule
out forked/orphan histories and dormant cycles. Native uniqueness checks are
checks on independently supplied public authority, not a substitute for physical
owner membership or physical INIT/TERMINAL bindings.

All main columns, including provider multiplicities, commit before the typed RAM,
owner, U16 and U8 challenges. Every physical claim is mixed before interaction
commitment and constraint coefficients. Four distinct sums close separately;
unused physical claim fields must be zero. Positive masses are bounded by this
pinned geometry: RAM 13, owner 9, U16 2,624 and U8 352, all below M31's
characteristic, including inactive-row range queries. Prefix identities retain
strict inverse checks on padding too. A zero pole fails transactionally and
publishes no interaction buffer.

The nine expected operations cover two epochs and four words, including a high
address near `2^64`, a no-op write, read-only clock advancement and a write-only
store. The receiver independently binds the whole terminal value/time/policy,
not a host-computed rational target. q70/P26 is the retained configuration; it is
not an extra claim about an independently calculated aggregate security budget.

## Qualification and remaining work

The dedicated `test-riscv64-closed-ram` gate runs eleven tests in ReleaseSafe and
ReleaseFast. Eleven malicious witness variants attempt real proofs: future
predecessor, duplicate INIT, orphan write, read-only write, bad initial image,
noncanonical high clock, nonzero padding, weight two, wrong owner origin, a
locally valid fork consuming INIT twice, and wrong range multiplicity. The
prover presents a formally closed claim ledger for these attempts; their physical
constraint identities reject it. Receiver tests alter balanced claims, unused
claim tails, a commitment root, counts and independently expected image/output.
Strict-pole retry and exhaustive source-allocation failures exercise cleanup.

The durable fixture tool produces and verifies in different processes with the
expected operation/image authority compiled independently into the receiver.
The tracked qualification report pins proof bytes and sources. CPU/service joins,
physical operation-origin delegation, general initialization authority, complete
multi-instance inventory, distributed challenge barriers and full-block proofs
remain separate unimplemented acceptance obligations for this prototype.
