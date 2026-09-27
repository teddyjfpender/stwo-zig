# Pre-size dominant native hash-row buffers

Measured canonical diagnostic preparation: live final rows/fixed rows total
118,184,432 bytes; current ArrayList capacities total 127,857,280 bytes; arena
capacity remains 461,490,727 bytes before/after finalization. G rows account for
96,839,680 live bytes (86,464 rows x 560 bytes x live/fixed). Byte routes account
for 7,999,608 bytes; XOR rows for 3,557,376 bytes. Most retained arena capacity is
not current live rows or current buffer slack, consistent with growth history.

Selected transfer: exact preallocation for the three dominant append-only cohorts
whose final lengths are already known as transcript+path row counts. Reserve both
live and fixed lists once before population. No second pass over values, no
speculative capacities, no equation/routing changes. Other cohorts keep canonical
growth until independently sized. Compare preparation-only census first; if memory
improves, qualify complete native proof/handoff separately. No wall-time claim.
