//! Full-family compatibility API. One shared implementation also serves the
//! independently admitted active family; this default preserves original domains.
const Impl = @import("block_v7_caller_family_v1.zig").Full.Preparation;
pub const Limits = Impl.Limits;
pub const Prepared = Impl.Prepared;
pub const prepare = Impl.prepare;
pub const prepareFromCapsule = Impl.prepareFromCapsule;
pub const plan = Impl.plan;
pub const planWithShared = Impl.planWithShared;
pub const planFromCapsule = Impl.planFromCapsule;
