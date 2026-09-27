# BLAKE3 native parent worker scratch

Task: retain bounded request scratch between proofs without letting output borrow
it. Transfer the existing detached-parent workspace's ArenaAllocator reset policy
to the standalone BLAKE3 producer; keep one proving implementation.

Exact match: reusable region allocation with an exclusive request lease. Existing
implementation: recursive_segment_v2_detached_parent_workspace.zig. No new
allocation algorithm. Arena reset retains at most the configured idle capacity;
failed shrinking falls back to free_all. This is an idle-retention bound, not a
peak-memory admission guarantee. Mutex tryLock rejects concurrent use of one
workspace; distinct workers require distinct workspaces. Plan, rows and workspace
must outlive the synchronous request.

Prediction: subsequent calls reuse retained host staging storage. Existing
proof ownership through the caller allocator remains unchanged. No latency
prediction without a controlled benchmark. Deep proof/PCS allocations remain on
the caller allocator; this stage does not claim to bound total proof memory.

Validation: reject overlapping lease, verify retain/free bounds, force scratch
allocation failure and recover, prove twice using one workspace with separate
output allocator, destroy workspace and plan before independent verification.
Preparation/proving overlap and scheduler memory admission remain next work.
