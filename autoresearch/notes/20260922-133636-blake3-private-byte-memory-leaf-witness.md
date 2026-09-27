---
title: BLAKE3 private byte-memory leaf witness
author: Teddy Pender
created_utc: 2026-09-22T13:36:36Z
---

# Private byte-memory leaf hash witness

Added live and message-free trusted memory-leaf constructors. The canonical
45-byte leaf frame keeps its domain/version/kind header fixed; only the final
byte boundary is replaced by the existing typed private-input bridge. Its
byte_count=1 constraints force unused coordinates to zero and its wire tuple
consumes the caller's byte source. Hash outputs retain the complete digest.

The focused ReleaseSafe gate passed in 24 seconds (1 GB reported peak RSS).
Checks cover bytes 0, 1, 128 and 255; native hash agreement; live/trusted fixed
metadata; complete hash-wire closure; source-byte substitution; and direct AIR
rejection of each forged unused coordinate. Existing memory-node, identity and
core-frame tests remain in the focused gate.

This is a private leaf component, not production source admission or a complete
memory proof. Tree/path aggregation, full-width public roots, continuation
snapshot bindings and production artifact/key integration remain outstanding.
The bridge consumes an authenticated caller tuple supplied by the eventual
memory component; fixture producers in this test do not replace that obligation.

Qualification correction: the original focused root omitted the memory test import.
Its earlier green run did not qualify the memory tests. The corrected root now
imports them explicitly; the 2026-09-22 memory-path qualification reran byte-tree,
node, leaf and path checks successfully. See 2026-09-22-blake3-memory-path/README.md.
