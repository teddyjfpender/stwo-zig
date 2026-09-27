---
title: Native commitment staging release qualified: worker peak down 4 percent
author: Teddy Pender
created_utc: 2026-09-22T07:03:56Z
---

# Release commitment staging at its last use

Native parent proving now resets request staging after interaction commitment,
while preserving the workspace lease. Both commitments own duplicated columns;
relation and provider challenge storage is inline. No staging references enter
core proving. Idle retention remains bounded at the configured limit.

The focused ReleaseSafe native gate passed 3/3 tests, 4/4 steps (43 s test run,
1 GiB reported MaxRSS). Both pipeline parent proofs independently verify, including
codec and ownership after worker destruction. Added malformed main-column count,
log and value-length rejection checks all pass. Key remains
`0fa2bf60222d4e62cf05dbed0c8892a8c8ba39a62b960d22abc2e65975f9fc46`.

| Tracked measurement | Before | After |
| --- | ---: | ---: |
| First-request arena entering core | 591,200,877 | 67,108,864 |
| Reused-request arena entering core | 889,716,869 | 67,108,864 |
| Worker peak bytes | 1,667,299,422 | 1,600,143,854 |

Worker peak falls 67,155,568 bytes (4.03%). This only partly recovers the prior
prepared-column regression: still 33,066,237 bytes above the old row-handoff
worker peak of 1,567,077,617. Commitment-stage arena growth remains; the original
allocation-order hypothesis is not fully proven. No timing improvement claimed.

Temporary probes were removed after qualification; instrumented-source preserves
the exact measured producer, source preserves the final version without prints.
Baseline is the current prepared-column implementation, not the historical row
producer. Next investigate commitment-stage scratch capacity and remove temporary
logical witness rows via direct adapter emission. Production profiles, reusable
keys, multi-level recursion and Metal migration remain incomplete.

Standalone ReleaseSafe workspace tests pass 3/3, covering retention, failure
recovery, lease preservation across early reset and subsequent-stage allocation.
