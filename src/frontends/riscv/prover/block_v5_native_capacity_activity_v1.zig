//! Exact-prefix AIR. Cumulative values count a boolean prefix in M31; admitted
//! capacities <=2^24 make modular wraparound impossible. Padding is not count
//! authority. The public last count is read through the cyclic first-row mask.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const protocol = @import("block_v5_native_capacity_protocol_v1.zig");
const M = core.fields.m31.M31;
pub const N_CONSTRAINTS: u32 = 4;
pub const DEGREES = [_]u8{ 2, 3, 2, 2 };
pub fn evaluate(comptime S: type, first: S, active: S, previous_active: S, count: S, previous_count: S, expected_rows: S) [N_CONSTRAINTS]S {
    const interior = S.one().sub(first);
    return .{
        active.mul(S.one().sub(active)),
        interior.mul(active).mul(S.one().sub(previous_active)),
        count.sub(interior.mul(previous_count)).sub(active),
        first.mul(previous_count.sub(expected_rows)),
    };
}
pub fn columns(a: std.mem.Allocator, plan: *const protocol.Plan) ![]engine.pcs.ColumnEvaluation {
    const result = try a.alloc(engine.pcs.ColumnEvaluation, 2 * plan.len);
    var initialized: usize = 0;
    errdefer {
        for (result[0..initialized]) |column| a.free(column.values);
        a.free(result);
    }
    for (plan.active()) |shard| {
        const active = try @import("opcode_trace.zig").generateIsActive(a, shard.log_size, shard.rows);
        result[initialized] = .{ .log_size = shard.log_size, .values = active };
        initialized += 1;
        const count = try a.alloc(M, active.len);
        result[initialized] = .{ .log_size = shard.log_size, .values = count };
        initialized += 1;
        // Opcode selectors advance in coset trace order, not natural circle
        // order. The same permutation is used by infra.BitReversalTable and
        // by the authenticated prevRowPoint/previous-domain-index helpers.
        for (0..count.len) |logical| {
            const physical = core.utils.bitReverseIndex(core.utils.cosetIndexToCircleDomainIndex(logical, shard.log_size), shard.log_size);
            count[physical] = M.fromCanonical(@intCast(@min(logical + 1, shard.rows)));
        }
    }
    return result;
}
