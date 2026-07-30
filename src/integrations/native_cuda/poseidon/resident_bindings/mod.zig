//! Exact typed binding of a prepared Native Poseidon plan to a CUDA arena.

pub const types = @import("types.zig");
pub const relation = @import("relation.zig");
pub const trace = @import("trace.zig");
pub const Views = types.Views;
pub const bind = @import("bind.zig").bind;

test {
    _ = types;
    _ = relation;
    _ = trace;
    _ = @import("bind.zig");
}
