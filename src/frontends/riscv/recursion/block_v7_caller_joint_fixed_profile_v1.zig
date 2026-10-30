//! Full-family compatibility API. One shared implementation also serves the
//! independently admitted active family; this default preserves original domains.
const Impl = @import("block_v7_caller_family_v1.zig").Full.FixedProfile;
pub const Input = Impl.Input;
pub const Owned = Impl.Owned;
