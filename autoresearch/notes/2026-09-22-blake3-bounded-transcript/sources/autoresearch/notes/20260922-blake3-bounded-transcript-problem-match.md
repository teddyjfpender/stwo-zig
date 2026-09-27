# Bounded transcript counter chaining

Task: join the proved retry/counter fragment into full transcript operation order.
Consecutive secure draws consume the preceding private counter; absorption resets
counter authority to a fixed zero source. Raw queries increment once per raw block
and never rejection-sample. PoW leaves the counter unchanged. Zero-query operations
must preserve the current counter source. Reuse existing frame, counter and retry
AIRs; no new constraints or copied external code.

Canonical match: authenticated state-machine composition / sparse dataflow. Patch
producer multiplicities from the following consumer's exact read receipts, as
already done for private transcript digest state. O(operations + admitted retry
capacity + raw query blocks). A verifier-specified capacity controls fixed shape;
recorded actual attempt counts have no fixed-column authority in bounded mode.
Reject capacity exhaustion explicitly. This does not yet admit a production key
family or eliminate lifted-column alias scheduling.

Validate genuine rejection then consecutive single/bulk draws, absorption reset,
raw query blocks after rejection, empty queries, PoW non-reset, fixed invariance
when attempt metadata changes, native transcript parity, and a complete joined
parent proof. Preserve public/ordered transcript APIs as regression oracles.
