# Private transcript frame hash assembly

Task: integrate symbolic digest routing with full BLAKE3 witness construction.
Exact match: authenticated graph composition already used by Merkle proofs.
Replace every message-input boundary with the shared frame router, retain graph
constants/final digest boundaries, and propagate exact source multiplicities to
upstream producers. Trusted construction uses only frame shape/literal payloads,
never computes or binds intermediate digest values.

Transfer: reusable arena-owned routed-frame witness plus trusted constructor.
Existing typed AIRs and native Frame.write remain sole semantics authorities.
Alternative: duplicate assembly for each transcript domain; rejected because it
risks inconsistent boundary filtering and consumer counts. Complexity linear in
hash graph and routed frame size. No new cryptographic assumptions or speed claim.

Test: two consecutive native integer absorptions in a complete CPU STARK, first
output authenticated privately into the second frame, only final digest exposed.
Wrong final statement rejected by trusted preprocessing admission. Check fixed
columns are independent of placeholder private state bytes. This does not prove
a full dynamic transcript scheduler, private scalar payload serialization, PoW,
query extraction or production recursion admission.
