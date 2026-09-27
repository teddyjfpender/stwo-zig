---
title: Native padded row elimination rejected by full proof
author: Teddy Pender
created_utc: 2026-09-22T05:49:28Z
---

# Padded-row copy elimination: rejected experiment

Attempted to borrow native prepared rows directly for main projection, counter
registration and interaction generation, eliminating padded logical-row copies.
The full native ReleaseSafe build compiled but passed only 2/3 tests. Running the
same built binary directly confirmed ConstraintsNotSatisfied in the BLAKE3 case.
The optimization was reverted; producer source was restored byte-for-byte to the
previous qualified snapshot in ../2026-09-22-native-shared-fusion/source/.
No performance result or retained optimization is claimed.

Source investigation identifies a critical distinction: framework_interaction's
omitted-row paddingPairs uses denominator one, whereas preparedRowPairs evaluates
the real lookup denominators even for zero numerators. The interaction layout must
satisfy typed denominator/inverse constraints, not just the claimed sum. Thus a
short slice's generic padding is not interchangeable with explicit AIR padding
for this producer. This is the leading explanation of the full-proof failure;
no component-level failure attribution has yet isolated it conclusively.

Next implementation must generate virtual padding through the actual authenticated
plan, preserving proof-kind selector parameters, and compare complete interaction
columns against explicit padding before another full proof. Main-column projection
and interaction-row access should be separated so main projection can borrow rows
without changing the interaction semantics. This is still work toward direct final
layout generation, not completion of that objective.

The new independent query-fusion admission tests remain: 8/8 focused tests passed;
see ../2026-09-22-native-query-admission. No current build process remains live.
