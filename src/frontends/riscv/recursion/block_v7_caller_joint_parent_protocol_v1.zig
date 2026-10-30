//! Full-family compatibility API. One shared implementation also serves the
//! independently admitted active family; this default preserves original domains.
const Impl = @import("block_v7_caller_family_v1.zig").Full.ParentProtocol;
pub const Bus = Impl.Bus;
pub const VERSION = Impl.VERSION;
pub const CLAIM_TAG = Impl.CLAIM_TAG;
pub const Key = Impl.Key;
pub const Admission = Impl.Admission;
