//! Use the original packed RAM transition equation and failure identity. Every
//! argument is routed to a real fresh root in the enclosing parent verifier.
pub fn close(comptime S: type, sink: anytype, requesters: S, memory: S) !void {
    return @import("../../prover/block_v5_global_join_algebra_v1.zig").Algebra(S).transition(sink, requesters, memory);
}
