# GKR requested-memory admission

This bound applies to the numerical borrowed-input/moving-layer authority added
in d5037079b. It bounds requested live allocator bytes, including caller matrices,
proof and artifact. It does not bound RSS, allocator metadata, stacks, transcript
storage, service metadata already owned by the driver, or PCS/recursion. Those
require their own leases. HostBudgetAllocator remains the runtime authority.

## Numerical planes

Let s be the secure field size (16 or 32 bytes), N the sum of input fact counts,
I the instance count and V the largest input variable count (1 through 30).
Input costs are sN for GrandProduct/singles, 2sN for generic LogUp, and
(s+4)N for M31 multiplicities. Count each shape separately for mixed batches.

The bottom is borrowed and never mutated. Pair-valued upper layers occupy less
than 2sN; GrandProduct occupies less than sN. At one outer GKR layer, an active
instance with current width m retains at most 2s(n−m) upper-plane bytes (including
its current moved oracle), and the next fixed oracle temporarily allocates at
most sm. Smaller inner sumcheck rounds only reduce those widths. Old oracles
are freed immediately after each successful fix. Instances that have not joined
retain their ordinary upper trees and do not have an oracle yet.

The shared immutable Eq table uses at most m_max/4 secure values, apart from the
constant one-entry case. Its recursive generation overlaps a half-sized child,
so its peak is at most 3sm_max/8 plus one secure constant. This fits the freed
upper-tree slack: m_max is no larger than the sum of active widths. Thus the
non-input dominant planes never exceed 2sN plus the small constant counted below.
At the borrowed bottom, no upper plane remains and the next oracle costs at
most sN, so the same bound holds. Single denominators become generic pairs in
upper layers and are covered by that pair bound. The proof is independent of
instance ordering, differing input heights, and sumcheck padding delays.

Admission deliberately retains more room: (3s+4)N working-plane bytes, in
addition to input. OM31 M31-multiplicity input therefore retains 136 bytes/fact
before metadata, despite the observed dominant 100 bytes/fact. This 136 figure
is a bound only for the new owner lifecycle; it was not an upper bound for the
old cloning implementation (measured 272 bytes/fact).

## Metadata and small polynomial envelope

Reserve 4096 × [(I+1)(V+1) + (V+1)^2] bytes. All arithmetic is checked before
allocation. The coefficient 4096 is an explicit conservative implementation
limit, not a fitted benchmark multiplier. Current type-size assertions enforce
Layer ≤128, Oracle ≤256, Eq ≤128, artifact ≤64, mask ≤32 and polynomial/sumcheck-proof header ≤32 bytes. The authority
is limited to four/eight-coordinate secure fields and variable counts≤30.

The envelope covers:

- Per-instance layer descriptors, mask headers/data, initial layer headers,
  output/terminal claim pairs and the outer shape/index/optional-slice arrays.
  Their count is O(I(V+1)). ArrayList capacities and simultaneous relocation
  buffers are bounded by 8(length+1) each; old/new buffers are both included.
- Per-instance sumcheck oracle descriptors, claim/index arrays and current
  univariate headers/coefficients. Degree is at most 3, hence at most four secure
  coefficients per polynomial. Claims and mask reductions carry at most two
  secure values per instance. Temporary interpolation uses degree ≤3 polynomials.
- Retained sumcheck round polynomials over all outer layers, with at most
  V(V−1)/2 rounds, and their header arrays. This is O((V+1)^2).
- Current assignments, previous/new OOD vectors, Eq's y vector, constant Eq,
  flattened mask buffers and transition overlap. These are O(I+V), included in
  the two envelopes above.

For auditing, each envelope has four 1024-byte units per grid entry; the largest
individual descriptor family is the 256-byte oracle under 8× growth/relocation,
and occurs only in one layer, leaving the V+1 factor for the retained per-layer
families. The coefficient envelope has fewer than 16 simultaneous/retained
secure coefficients per layer/round entry, even counting interpolation scratch
and the combined polynomial alongside per-instance polynomials. This leaves
substantial slack at both field sizes. Future additional owners, larger fields,
higher-degree sumcheck or different allocation policies must revisit this bound.

## Services phases

The services planner uses the numerical plan without constructing any fact
matrix. The later binding phase retains raw inputs and the GKR proof/artifact,
but the binary tree/Eq/oracles are gone. Add 64 bytes per row of binding planes,
16 bytes per instance of slice headers, and the same metadata envelope. Take
the maximum of numerical and binding phases. Binding backing is allocated by
the parent but reserved externally under the same local hard allocator until
explicit PCS adoption. That transfer is not an RSS drop. PCS headers/scratch
and worker-owned durable metadata remain the parent admission's responsibility.

Admission refuses insufficient declared limits before facts are built. A later
hard allocator refusal remains OutOfMemory with didExceedBudget=true; a backing
allocator failure is OutOfMemory with that flag false. Neither is normalized
into malformed-proof acceptance or a challenge retry.

## Qualification

The focused resource suite constructs actual Q/OM GKR proofs for variable
counts 1,2,8,14,16, twelve simultaneous instances, and mixed heights covering
GrandProduct, generic LogUp, M31 multiplicities and singles. It asserts measured
requested peak≤plan. The mixed lifecycle injects failure at every allocation.
Malformed geometry, checked overflow and hard-cap error classification are also
covered. Synthetic microtests do not establish a production RSS or GPU target.

```
zig test -OReleaseSafe --dep stwo_core -Mroot=src/prover/gkr_resource_test_root.zig -Mstwo_core=src/core/mod.zig
zig test -OReleaseFast --dep stwo_core -Mroot=src/prover/gkr_resource_test_root.zig -Mstwo_core=src/core/mod.zig
```
