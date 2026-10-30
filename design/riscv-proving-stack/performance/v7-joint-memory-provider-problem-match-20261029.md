# One original memory-provider proof before recursion

## Measured problem and target

The canonical mixed-verifier census already shows that a native lookup child
alone retains about 1.21 GB of MAIN plus compact fixed rows. Independent range16
verification adds about 0.81 GB. These are verifier-layout bytes, not proving
latency or RSS. Removing the old source-hash pages is necessary but does not
remove repeated transcript, opening, FRI and table-provider verification.

The next implementation combines the v7 RAM shards, initialization interval
provider, range16 provider and terminal-output provider in **one heterogeneous
original STARK**. Each component keeps its own degree and domain size. The first
implementation does not fuse ROM or native lookup; its explicit three-tree
placement can accommodate those original components later.

## Exact preserved authority

- Actual ExecutionPolicy selects ELF initialization, executable ROM, terminal ABI,
  output, public input, job endpoints and security configuration.
- All RAM shards plus the three providers appear exactly once in the finite
  layout. Every fixed, MAIN and interaction column has one canonical placement.
- One fixed-tree commitment and one MAIN-tree commitment enter the whole-job
  epoch before any relation challenges are drawn.
- Every physical claim is absorbed individually, in canonical component order,
  before committing the interaction tree. Aggregated-only claims are forbidden.
- The original RAM, interval, range16 and terminal equations and mixed-domain
  quotient semantics are reused unchanged.
- Fresh verification rebuilds the complete fixed commitment from independent
  policy and admitted geometry, then verifies the original PCS proof.
- Typed link, initialization and range relations and both integer census sums
  close separately. The remaining transition sum and guest-event count are
  explicitly open until actual native/caller proofs close them.

## Protocol and implementation boundaries

Epoch version 2 adds an explicit `memory_joint` family. Complete execution uses
one of two mutually exclusive layouts: the old RAM/interval/range16/terminal
families, or exactly one joint memory family with all four old counts zero.
No old proof or key is admitted under the new layout. The challenge draw order
is unchanged; the epoch version and entry framing change.

The new joint artifact has two first commitments, one interaction commitment and
one composition commitment. It is not a concatenation of old proofs. It owns
bounded claims and a genuine proof, never a transported success receipt.

A finite layout assigns offsets in three trees to each original component.
Adapters rebase only column locations, preserve original masks and equations,
and use the original checked composition-geometry override when aligning degree
splits. No dummy columns, synthetic padding child or witness-derived setup is
permitted. RAM shards remain independently sized; provider tables are committed
once each.

## Qualification sequence

1. Exact layout/column coverage, family absence/duplication and count-mode tests.
2. Original component evaluation parity at arbitrary OODS points and on domains.
3. Genuine joint original proof from the same source fixture as the separate
   provider oracle; fresh fixed-root verification and typed closure.
4. Negative tests for every physical claim, missing/reordered component,
   policy/terminal/initialization change, malformed geometry and changed proof.
5. Actual native-source execution closure using the joint entry in epoch v2.
6. Only then recursive capture/cold setup and canonical geometry comparison.

There is no claimed end-to-end speedup until comparable full proofs are measured.
