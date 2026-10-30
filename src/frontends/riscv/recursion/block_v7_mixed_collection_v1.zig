//! Collect only a bounded window of genuine original verifiers, then drain
//! them into one OPEN direct batch. Original proofs remain caller-owned;
//! captures and family owners are released before returning the batch rows.
pub const For = @import("block_v7_mixed_collection_family_v1.zig").For;
const Default = For(false);
pub const Limits = Default.Limits;
pub const prepareWindow = Default.prepareWindow;
