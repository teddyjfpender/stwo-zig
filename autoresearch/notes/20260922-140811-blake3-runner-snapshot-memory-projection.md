---
title: BLAKE3 runner-snapshot memory projection
author: Teddy Pender
created_utc: 2026-09-22T14:08:11Z
---

# Runner-snapshot BLAKE3 memory projection

Added an owned projection from runner memory_state.Snapshot word records into
BLAKE3 sparse bytes and root. Ordinary entry/final boundaries reuse WordState's
public-input/output/completion custody policy. Continuation projection includes
all RW words and cannot be used to manufacture an ordinary boundary statement.
Word statements derive their initial zero clock or retained final clock directly
from the owned record, and prepare through the bound four-byte opening assembly.

The focused ReleaseSafe gate passed in 35 seconds (1 GB reported peak RSS).
Checks cover custody exclusion, distinct ordinary/continuation roots, exact clock
selection, rejected projection misuse, stable ownership after caller mutation,
prepared bytes/clocks and duplicate-address rejection. Input admission checks
sorted aligned 30-bit addresses and canonical field clocks.

The test uses a constructed runner Snapshot, not a newly executed guest. Copying
runner-shaped records is not cryptographic proof of their provenance. Production
RunResult wiring, source/key/artifact admission, full joined word proofs and
continuation protocol migration remain outstanding. Extended-clock protocols
require separate admission rather than truncation through this canonical-clock API.
