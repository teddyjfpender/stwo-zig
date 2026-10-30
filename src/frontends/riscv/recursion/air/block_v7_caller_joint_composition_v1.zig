//! Full-family compatibility API. One shared implementation also serves the
//! independently admitted active family; this default preserves original domains.
const Impl = @import("../block_v7_caller_family_v1.zig").Full.Composition;
pub const Prepared = Impl.Prepared;
pub const RELATION_COUNT = Impl.RELATION_COUNT;
pub const prepare = Impl.prepare;
pub const Compiled = Impl.Compiled;
pub const compile = Impl.compile;
