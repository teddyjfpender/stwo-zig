# Ethereum statement ownership transaction

Status: approved initial contract transaction; implementation in progress.

- Slice: https://github.com/teddyjfpender/stwo-zig/issues/336
- RFC: https://github.com/teddyjfpender/stwo-zig/issues/352
- Recorded decision: https://github.com/teddyjfpender/stwo-zig/issues/352#issuecomment-6749772175
- Owner: ethereum-statement (@teddyjfpender).

The first checkpoint extracts exact existing SHA256 and durable directory-file bodies
from product adapters. Sole-primitive callers bind their real private owner, leaving
product state, input admission, profiles, proof pins and public package APIs intact.
The product package, typed Owner move, consumer compatibility and strict P-3 gate
remain unfinished; this checkpoint does not claim package/workspace acceptance for
the final transaction. Additional public removals/providers require the precise
amended ledger and recorded decision in the RFC before implementation.

Pre-edit target: net code growth zero; at most +800 contained private ownership,
build/compatibility and P-3 wiring. Flags/scripts zero; no new top-level launcher.
Moves receive no removal credit. Hosted CPU and frozen Native proof-byte gates
remain the acceptance safety net; GPU validation is deferred.
