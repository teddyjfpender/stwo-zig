---
title: BLAKE3 fixed-address memory boundary lowering
author: Teddy Pender
created_utc: 2026-09-22T14:02:29Z
---

# Explicit fixed-address lowering for the typed memory boundary

The universal relation compiler now has an explicit runtime factory for scalar
representation of verifier-owned address columns. The policy is a compile-time
part of the runtime type and is used by plan revalidation. Ordinary runtimes
retain the existing field-only admission; existing AIR runtime types are preserved.
Only AIRs declaring FIXED_ADDRESS_INPUTS opt in. The memory boundary declares
column 5, whose fixed-row constructor enforces aligned 30-bit addresses.

The focused ReleaseSafe gate now passes (31 seconds, 1 GB reported peak RSS),
resolving the previous InvalidInputGeometry failure. Tests cover default address
rejection, rejecting witness-column and duplicate address declarations, plan
revalidation, aligned/range schedule admission, exact legacy memory-access tuple
and signed multiplicity agreement, and the four emitted byte-wire coordinates.
The typed memory boundary retains its pinned semantic identity.

Fixed-address bounds remain a verifier-preprocessing obligation; this API does
not turn arbitrary witness addresses into canonical M31 values. Production key
admission must use the bounded schedule constructor. Full address-to-path/root
binding, joined memory proof roster integration, continuation claims and actual
RISC-V execution qualification are still unfinished.
