---
title: BLAKE3 private digest composition passes a complete CPU STARK
author: Teddy Pender
created_utc: 2026-09-21T19:42:53Z
---

# Committed private BLAKE3 composition — 2026-09-21

Previous turn: progress, with a typed private-input bridge and exact wire closure.
This turn includes that bridge in a complete CPU STARK. Production migration and
the original recursion performance goal remain active.

The new gate proves H(H(message)). The first hash's eight public digest boundary
rows are removed; its output emissions instead balance the second hash's eight
caller-word bridge consumptions. Both hashes share the same G/XOR/provider
components but have distinct wire namespaces. Only the original message and
final digest are public statement data. Preprocessing is reconstructed from
those values and canonical lengths/wire schedules, without receiving the
intermediate digest or evaluating its compression rounds.

“Private” here means witness data outside the public statement. This fixture
makes no zero-knowledge/hiding claim, and its intermediate can of course be
computed from the public message.

The fixture roster now generically projects either three typed components or
four with the input bridge, followed by the same bitwise and byte-pair providers.
The proof gate uses this roster for definitions, plans, offsets, components and
claims, eliminating duplicate assembly for the new composition. No production
roster, key, profile or protocol selection was changed.

Validation:

```sh
python3 scripts/zig_serial_build.py --cwd src/integrations/riscv_cpu test-blake3-private-proof test-blake3-proof -Doptimize=ReleaseSafe --summary all
```

All three guarded tests pass. The new test produces a real BLAKE3-backed STARK
and passes the core verifier. A changed final digest and substituted preprocessing
root fail trusted-root admission. Earlier compression and full-hash gates still
pass through the same generalized assembly path. The two-hash composition test
ran in about 2 seconds with 346 MiB maximum RSS; existing proof tests took about
9 seconds. These are dev-loop diagnostics with eight queries, blowup 1 and zero
PoW, not production benchmark results or a claimed recursion speedup.

Remaining: bind the bridge to actual child-proof/caller components; support exact
protocol byte framing and any required word repacking; scheduled Fiat–Shamir
rejection and PoW; recursive Merkle paths; new trusted keys/artifact identities;
Metal kernels and full same-security parent-of-parent performance qualification.
Product defaults still use Poseidon.

Source conformance retains the same 103 pre-existing finding identities. Source
snapshots and passing test logs are pinned in manifest.json; older evidence was
not modified.
