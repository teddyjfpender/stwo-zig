const std = @import("std");
const P = @import("integrations/riscv_cuda/resident_native_prover_v1.zig");
fn four(a: std.mem.Allocator, input: P.ForCommitments(4).Input) !void {
    var p = try P.ForCommitments(4).prove(a, input);
    p.deinit(a);
}
fn five(a: std.mem.Allocator, input: P.ForCommitments(5).Input) !void {
    var p = try P.ForCommitments(5).prove(a, input);
    p.deinit(a);
}
test "resident native finite full controller semantic no production admission" {
    _ = &four;
    _ = &five;
    try std.testing.expect(!P.production_ready);
}
