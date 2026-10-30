//! Full-family compatibility API. One shared implementation also serves the
//! independently admitted active family; this default preserves original domains.
const Impl = @import("../block_v7_caller_family_v1.zig").Full.Statement;
pub const PUBLIC_CIRCUIT = Impl.PUBLIC_CIRCUIT;
pub const Statement = Impl.Statement;
pub const init = Impl.init;
