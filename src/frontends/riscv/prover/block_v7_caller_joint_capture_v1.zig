//! Full-family compatibility API. One shared implementation also serves the
//! independently admitted active family; this default preserves original domains.
const Impl = @import("../recursion/block_v7_caller_family_v1.zig").Full.Capture;
pub const VerifiedCapture = Impl.VerifiedCapture;
pub const ForBackend = Impl.ForBackend;
