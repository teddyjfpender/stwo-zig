---
title: Native virtual padding counter integration
author: Teddy Pender
created_utc: 2026-09-22T05:55:07Z
---

# Typed virtual padding for interaction generation

Task: remove explicit padded logical-row storage without changing the complete
interaction columns or claimed sum. Prior short-slice substitution failed a full
proof, so equality must be measured against explicit typed padding first.

Selected transfer: evaluate the actual padding Row through the authenticated plan
once, then reuse its row pairs for every absent logical row. This is loop-invariant
code motion and virtual repeated-value input, not a new arithmetic or lookup rule.
Keep the existing null-padding API unchanged for all callers. Add an explicit
optional typed-padding entrypoint and pass cached pairs into the same generation
kernel; preserve preflight, allocation/error cleanup and alias checks.

Compare every interaction column and claim for every native roster AIR against
four explicit padding rows, including proof-kind selectors and partial/empty live
prefixes. The true cause of the prior failure remains under test; do not infer
zero lookup numerators solely from zero main/preprocessed columns. Full producer
integration is allowed only after this differential gate passes.

Producer integration: register repeated padding by evaluating its lookup entries
once and multiplying each numerator by the repeat count in M31/QM31. This equals
repeated field addition in Counter.register. Skip count zero; retain canonical
tuple validation and signed multiplicities. Compare entire table-counter arrays
against explicit padded-row registration, then project borrowed main rows and
use generatePreparedWithPadding with the same typed padding row. The full native
proof gate must pass before retaining the copy removal. No parameter/key changes.
