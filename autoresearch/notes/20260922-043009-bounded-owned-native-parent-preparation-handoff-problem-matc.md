---
title: Bounded owned native parent preparation handoff problem match
author: Teddy Pender
created_utc: 2026-09-22T04:30:09Z
---

# Bounded owned preparation handoff

Task: transfer prepared native BLAKE3 rows between preparation and proving without
an unbounded ready queue or ambiguous cancellation ownership.

Exact match: bounded FIFO producer/consumer channel with backpressure. Reference:
https://doc.rust-lang.org/std/sync/mpsc/fn.sync_channel.html . Extend the usual
item-count limit with a checked retained-payload byte limit. Use mutex/condition
variables; no lock-free algorithm or external code copied. This is a standard
queue, not a new recursion scheduler. Existing level admission remains separate.

Semantics: send transfers an optional owner only on success; receive transfers
ownership out. Graceful close drains ready values, cancellation rejects sends and
releases queued owners. Already received work remains the consumer's obligation.
Destruction requires joining all users. Payload allocators must support their
consumer/cancellation threads. Constant-time ring operations, O(capacity) slots,
O(retained payload) queue storage; cancellation O(queued items plus destruction).

Bound: queued payload retention only. Preparation intermediates, producers blocked
before send, active proving, plans and workspaces require separate scheduler
reservations. Reporting this queue as an end-to-end RSS bound would be wrong.
Use arena capacity plus owned descriptor size for canonical Prepared byte charge.

Alternatives: unbounded queue violates retention requirements; rendezvous prevents
ready buffering; lock-free queue adds ownership/reclamation complexity without
measured benefit at this coarse job granularity. Select blocking bounded FIFO.

Validation: FIFO across ring wrap, exact count/byte limits, oversized ownership
preservation, graceful close, cancellation wakeup and cleanup, allocation failure,
threaded send/receive. Transfer a real canonical native preparation through the
channel and verify resulting parent proofs. Actual preparation/proving overlap
and policy-level admission remain the subsequent integration step.
