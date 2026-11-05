# M7 independent native owner experiment

Status: opt-in, unpromoted. `STWO_RV64_NATIVE_OWNERS_PER_GPU=2` creates two
independent owner threads/streams/tokens per physical GPU. Every ordinal uses
the same complete backend bundle through both phases, including replay and
coefficient publication. Existing physical devices stay distinct for recursion.
The configuration requires a shared 22 GiB VMM carve, 28 GiB per-owner logical
cap and disabled idle PCS caches. The physical carve bounds all owners together.
All large numerical GKR, composition and PCS phases share one per-device mutex;
source/trace jobs can overlap them. All sessions join request lease audits.

The initial 1 GiB/1 GiB immutable split failed the first small request at outer
fixed-forest admission, after native proving completed. Its native bins match
M6. The revised 5/8 primary plus 3/8 extra split preserves the aggregate 2 GiB
budget and passes the first complete small request with M6-identical native,
recursive and tree bytes. It then fails the headline request: a 14.75 GB scratch
request beside 10.42 GB live allocations exceeds the shared 22 GiB carve.
Retained trace lifetimes extend beyond the large-phase guard. No complete
both-block timing/receiver gate passed, so two owners are not promoted.

The same 22 GiB one-owner control completed six requests in one run, then
failed a later warm headline request in a repeat. This indicates narrow
allocation/scheduling margin in the control as well; it prevents attributing
the full failure solely to extra owners. Keep the raw failure receipts.

Scoped native upload counters attribute the first small request to CPU
267,849,456 B, core 489,800,064 B, bridges 19,694,432 B, bulk/sponge 44,056,296 B,
truth 8,702,184 B, local GKR 33,821,616 B and global parameters 65,220 B:
863,989,268 B total, or 56.45 B/retired instruction. These counters exclude
immutable cache internals and C PCS uploads; they do not qualify whole-native
H2D or the 80 B target. The formatter and proof bytes remain unchanged.

Host routing tests pass: independent sessions can share a physical device,
physical configuration duplicates remain rejected, shared PCS contexts are
refused, and all seven original ordinals retain distinct scope records.
