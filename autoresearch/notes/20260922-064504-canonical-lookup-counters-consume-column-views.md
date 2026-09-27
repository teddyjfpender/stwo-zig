---
title: Canonical lookup counters consume column views
author: Teddy Pender
created_utc: 2026-09-22T06:45:04Z
---

# Lookup-table registration over committed-column views

Task: remove producer table-counter dependence on live row arrays before moving
preparation to main columns. Reuse ColumnRows.read and registerRepeated at count one,
with canonical shape validation shared by interaction and counter consumers. The
view constructor combines already projected main columns with trusted fixed rows.
No new lookup equations, padding rules or copied main buffers. Check complete
counter arrays against row registration on actual hash output and qualify full
native proofs. This infrastructure step alone is not a speedup or row-storage removal.
