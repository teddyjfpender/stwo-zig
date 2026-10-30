//! Full-family compatibility API. One shared implementation also serves the
//! independently admitted active family; this default preserves original domains.
const Impl = @import("block_v7_caller_family_v1.zig").Full.Public;
pub const API = Impl.API;
pub const Values = Impl.Values;
pub const Wire = Impl.Wire;
pub const supply = Impl.supply;
pub const scheduleDigest = Impl.scheduleDigest;
pub const publicInputs = Impl.publicInputs;
pub const reconstruct = Impl.reconstruct;
pub const requireSameFrame = Impl.requireSameFrame;
