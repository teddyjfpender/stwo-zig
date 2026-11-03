# Public-boundary log 23 and candidate policy v2

The 15-block qualification discovered a geometry limit before GPU proving:
block 26,235,159 has 4,407,202 distinct public RAM words, and block 24,628,611
has 5,312,502. INIT and TEARDOWN require a trailing inactive row, so neither
fits the previous log-22 prefix. This is independent of CPU segment clocks.

Policy v2 admits log 23 **only** for the independently sized public INIT and
TEARDOWN roles. CPU and ordinary providers retain `MAX_TRACE_LOG = 22`, LS
retains its previous geometry, and GKR's wide-clock CPU gate remains closed.
The boundary has fourteen MAIN columns and the original degree-3 AIR. The
receiver still validates sorted, unique, aligned public addresses, canonical
RAM14 values, expected image/rights, terminal output, and each public boundary
claim independently of aggregate RAM closure. No lookup or clock obligation
is removed, and no prover-selected declaration replaces receiver authority.

Both candidate and conjectured profile identity domains advance from v1 to
v2 and hash `MAX_PUBLIC_BOUNDARY_LOG = 23` alongside the existing caps. PCS
parameters remain q108/P20/fold4 for the conjectured target and q256/P0/fold4
for the separate candidate. Facts distinguish general trace log and public
boundary log; conditional degree accounting uses their maximum. Source
summaries can report trace log 23 only with typed boundary provenance. The
source-derived relation-support, multiplicity, global characteristic/mass,
proof-count and transcript-round admission checks remain mandatory. Larger
real blocks must pass those checks; this change supplies no universal
204-million-step or whole-protocol security certificate.

All newly produced v2 statements and proof bytes change. Historical v1
receipts and pinned binaries remain controls; byte identity across these
policy versions is not expected. Fresh producer and independent receiver
must use v2. The security description remains **128-bit target under
explicitly documented conjectured assumptions**, not certified 128-bit
whole-protocol security. The earlier bounded reviews describe their pinned
v1 geometries and are not measurements of the new larger basket.

Transport permits at most 2^23-1 public words and retains exact streaming
file-length/header checks, canonical field/range checks and receiver-owned
count/geometry checks. Global-LogUp scratch admission and CPU witness generation have explicit
public-boundary entrypoints, constrained to the boundary's single RAM inverse;
ordinary scratch/witness/parallel-plan entrypoints retain log 22.
Ordinary LS `sizeForLog` is unchanged; boundaries
have their own sizing and independently generated fixed columns, byte-equal
to the previous source at admitted smaller logs. Only the native boundary
formatter and its two global-projection wrapper guards advance to log 23;
the arithmetic and projection programs are unchanged.

Focused tests cover the log-22/23 transition and overflow, independent CPU/LS
rejection, forged boundary extent/role, sidecar extent preflight, smaller-log
fixed-column parity, typed source-bound provenance, and rejection of the
historical v1 candidate identity. The product-image update preserves the
original exports and assignment capabilities, replacing exactly those three
objects. Full-block v2 producer/fresh-receiver and largest-block qualification
remain required before claiming this runtime delivered.

GPU logical allocation remains capped at 28 GiB; host/immutable setup and
transient buffers have separate explicit budgets. No host wide-MAIN or
wide-INTER parking fallback is introduced.
