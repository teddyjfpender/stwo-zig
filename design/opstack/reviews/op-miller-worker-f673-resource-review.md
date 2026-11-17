# OP Miller worker review at f673592d4

This is an independent source review of the closed Miller truth fragment worker,
its ownership transitions, and retained arithmetic advice. It is not a composed
security certification. No acceptance bypass was found in this review. Production
admission remains closed, and the security label remains “128-bit security target
under documented assumptions,” with `security_qualified=false`.

## Findings

### Resource admission is missing from the fragment worker

`pure_p2_tower_worker.Key.init` admits any valid native heights up to the source
maximum. `Worker.init` then allocates both MAIN matrices, and `complete` allocates
both INTER matrices, without an explicit requested-byte admission policy or hard
allocator cap. A one-call proof can use valid but highly padded log-22 heights.
At those heights the matrices alone require:

| Payload | Exact requested bytes |
| --- | ---: |
| MAIN, `(33 + 370) * 2^22 * 4` | 6,761,218,048 |
| OM31 INTER, `(16 + 560) * 2^22 * 4` | 9,663,676,416 |

These exclude immutable setup, retained coefficients, Merkle trees, extensions,
composition/FRI scratch, and allocator effects. The natural heavy geometry is
much smaller (frontier log 19, arithmetic log 20), but still allocates
1,621,098,496 MAIN bytes and 2,382,364,672 INTER bytes before those exclusions.

Before accepting producer-declared geometry in a durable receiver, admit it
against receiver-owned shape classes and requested-byte limits. Add an explicit
`initWithLimits`/planning seam for the worker, including separate source,
interaction, immutable-setup and PCS allowances. A hard allocator cap should
back the represented-payload admission; do not describe these counts as an RSS
bound. A statement/fixed-root binding establishes correctness of a geometry; it
does not establish that the geometry is affordable.

### Advice retirement is not enforced by the Source lifecycle

`Source.releaseAdvice` clears `inputs` and range counts. `Source.public()` derives
its call count from `inputs.len`, so it subsequently reports zero calls. After
an owned INTER handoff, `interaction` is empty again. The only entry guard in
`generateInteraction` checks `interaction.len != 0`, permitting another wide
interaction allocation from retired, zero-call advice. This contradicts the
comment that no source operation may regenerate after retirement.

The current worker's `consumed` flag prevents this sequence through its normal
`complete` entrypoint. This is a Source API/lifecycle and resource gap, rather
than a demonstrated worker acceptance bypass. Preserve the original call count
as immutable metadata and add explicit interaction-generated/advice-retired
state. Test `take INTER -> releaseAdvice -> generateInteraction` rejection and
verify that public span metadata remains stable after payload retirement.

## Checks supporting the design

- Both FIXED and MAIN are committed before local range/SSA challenges are drawn.
  The local draw binds the complete manifest digest; Wire35 uses its shared
  manifest challenge.
- Every physical claim enters the transcript. The two SSA claims must sum to
  zero. The verified fragment returns only its Wire35 debt; the complete
  receiver must verify the entire inventory and close all global relations.
- A fresh key binds profile, fixed root, ordered per-column native heights and
  widths, source authority version, then statement call count and first ID.
  The explicit per-column heights avoid relying on a lifted root alone.
- The retained advice records values, quotients and bounded carries once.
  Interaction replay reconstructs bytes and canonical-distance/borrow advice;
  it does not rerun field multiplication, modular division or DAG execution.
- Shared fixed-tree leases retain their original allocator through the PCS
  `SharedOwner`. The worker's separate allocator therefore does not transfer
  ownership of cached immutable storage incorrectly.
- The worker poisons itself before destructive seal/complete operations. A
  failure leaves it discardable rather than retrying a partially committed
  transcript. Claim decoding rejects noncanonical coordinates and checks the
  explicit envelope byte length.

These fragment checks do not replace the pending complete CPU/OWNER/RAM/Wire
join, durable whole-execution receiver, full inventory coverage, and timed
native-to-root qualification.
