//! Full-family compatibility API. One shared implementation also serves the
//! independently admitted active family; this default preserves original domains.
const Impl = @import("../block_v7_caller_family_v1.zig").Full.Transcript;
pub const RELATION_COUNT = Impl.RELATION_COUNT;
pub const prefixFixed = Impl.prefixFixed;
pub const prefix = Impl.prefix;
pub const planReplay = Impl.planReplay;
