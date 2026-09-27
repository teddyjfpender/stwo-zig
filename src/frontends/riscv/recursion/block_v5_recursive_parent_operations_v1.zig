//! Value-free operation schema of the unchanged closed-parent verifier suffix.
//! The separately admitted public prefix is not replaced or synthesized here.
//! No nonce/challenge/query/claim assignments and no native channel are created.
const std = @import("std");
const Shape = @import("block_v5_recursive_parent_shape_v1.zig").Shape;
const universal = @import("air/universal_challenges.zig");
const claims = @import("blake3_native_parent_artifact.zig");
const roots = @import("air/blake3_root_sources.zig");
pub const Operation = @import("air/blake3_pcs_operation_schema_v1.zig").Operation;
/// Starts immediately after the ORIGINAL admitted public prefix. The same
/// original prefix compiler remains required before this schema is executable.
pub fn appendClosedSuffix(a: std.mem.Allocator, out: *std.ArrayList(Operation), shape: *const Shape) !void {
    try shape.validate();
    var pending: std.ArrayList(Operation) = .empty;
    defer pending.deinit(a);
    for (0..2) |slot| try pending.append(a, .{ .commitment = .{ .slot = slot, .source = try roots.caller(slot) } });
    for (0..universal.RELATION_COUNT) |index| try pending.append(a, .{ .secure = .{ .role = .{ .universal = index }, .consumption = .two } });
    try pending.append(a, .{ .claim_frame = .{ .tag = .{ 0x42354d51, 5, claims.CLAIM_COUNT }, .count = claims.CLAIM_COUNT, .source = .{ .circuit = @import("air/blake3_native_recorder.zig").CLAIM_CIRCUIT, .first_wire = 0 } } });
    try pending.append(a, .{ .commitment = .{ .slot = 2, .source = try roots.caller(2) } });
    try @import("air/blake3_pcs_operation_schema_v1.zig").appendPcsSuffix(a, &pending, shape.config, shape.deepProfile(), shape.friProfile(), 4);
    // Constructor failure never appends a partial suffix to the caller.
    try out.appendSlice(a, pending.items);
}
