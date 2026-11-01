# Bounded packet capture prefetch

The experimental `Capture.Owner.initWithOptions` overlaps independent packet
reading, validation and native metadata capture on the caller's existing proof
pool. `Owner.init` and options with `max_inflight_packets = 1` retain the original
serial path. No Ethereum CLI default selects prefetch.

The producer uses windows of at most two packets. It preflights file sizes,
reads/captures each packet independently, synchronously joins both jobs, then
consumes their results in packet-index order. Only that ordered consumer checks
genesis, instruction coverage, PC/register adjacency and step budgets, appends
the RAM/service ledger, and retires capture records. No transcript or statement
format changes. A speculative error is ignored only if an earlier valid packet
already completes the requested prefix or reaches the independently pinned
terminal PC. Every speculative result is joined and destroyed on success or
failure. The original serial receiver remains the acceptance authority.

## Ownership and admission

`pool` is borrowed. The caller allocator must support concurrent allocations;
the image, program and packet files must remain immutable throughout the call.
The same borrowed program lifetime required by serial Native capture remains
required by returned Sources. No pool is constructed or discovered globally.
An unavailable lease, cooperative callback or one-worker pool falls back to
serial callbacks. Capture currently consists of CPU metadata copying, local
fact deduplication and JALR construction and submits no nested pool work.
Helpers do not inherit the scoped pool TLS. This audited phase must stay free
of blocking recursive pool acquisition.

Each decoded packet Tape has its own heap-stable `SharedHostBudget`, retained
until the Tape is destroyed. The cap covers the requested decoded packet heap,
not allocator metadata, mapped-file bytes or process RSS. Two slots reserve two
full per-slot caps; insufficient aggregate allowance falls back to one slot,
without lowering the current packet's allowance. `max_inflight_wire_bytes`
bounds the sum of preflight file sizes; each reopen checks the same size, while
existing packet SHA and immutable-file requirements remain unchanged.

Native/Prepared uses the caller's allocator and copies all data it needs from
the Tape. Its allocations deliberately do not retain a temporary slot allocator.
The separate bound is two in-flight admitted `batch_steps` captures; this is
**not** a complete Native heap bound. Completed Native metadata remains retained
as in serial capture. Callers needing an aggregate host cap must provide an
appropriately bounded thread-safe parent allocator and admit the normal retained
Native inventory too. This API makes no claim that packet heap limits bound
combined host memory.

## Qualification and promotion

The focused target is `test-riscv64-capture-prefetch`. It compares complete CPU
metadata, native family facts and ordered advice with serial capture, exercises
held-lease and single-slot admission fallback, decoded-heap and wire refusal,
required corrupt packets, valid duplicated-packet adjacency rejection, actual
terminal-first speculative-error disposal, and allocation-failure cleanup.

These fixtures establish producer semantic parity. Before production default
promotion, run real full-block A/B and require all resulting physical proof,
bundle and RAM cell artifacts byte-identical plus a fresh independently pinned
receiver. Record capture wall time and total wall time separately, on the same
host load. No speedup or GPU qualification is inferred from the scheduling code.
