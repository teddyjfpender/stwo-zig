//! Full-family compatibility API. One shared implementation also serves the
//! independently admitted active family; this default preserves original domains.
const Impl = @import("../recursion/block_v7_caller_family_v1.zig").Full.Admission;
pub const Limits = Impl.Limits;
pub const Arithmetic = Impl.Arithmetic;
pub const Relations = Impl.Relations;
pub const Prepared = Impl.Prepared;
pub const EquationOwner = Impl.EquationOwner;
pub const zeroClaims = Impl.zeroClaims;
