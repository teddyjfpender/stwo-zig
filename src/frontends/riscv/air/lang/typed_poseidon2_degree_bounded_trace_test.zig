const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const candidate_mod = @import("typed_poseidon2_degree_bounded_candidate.zig");
const trace_mod = @import("typed_poseidon2_degree_bounded_trace.zig");
const infra = @import("../../infra_trace.zig");
const production = @import("../memory_commitment/poseidon2_air.zig");

test "degree-six parallel-ready trace is byte-identical to candidate rows" {
    var candidate = try candidate_mod.Candidate.init(
        std.testing.allocator,
        .degree6,
    );
    defer candidate.deinit();
    const calls = [_]production.Call{
        production.Call.narrow(1, 2),
        production.Call.narrow(3, 4),
        .{ .input = .{ 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20 } },
    };
    var generated = try trace_mod.generateMain(
        std.testing.allocator,
        &candidate,
        &calls,
        3,
    );
    defer generated.deinit(std.testing.allocator);
    const table = try infra.BitReversalTable.init(std.testing.allocator, 3);
    defer table.deinit(std.testing.allocator);
    const expected = try std.testing.allocator.alloc(
        M31,
        candidate.mainColumnCount(),
    );
    defer std.testing.allocator.free(expected);
    for (calls, 0..) |call, logical_row| {
        try candidate.fillRow(expected, call);
        const committed_row = table.map(logical_row);
        for (generated.values, expected) |column, value| {
            try std.testing.expect(column[committed_row].eql(value));
        }
    }
    for (calls.len..8) |logical_row| {
        const committed_row = table.map(logical_row);
        for (generated.values) |column| {
            try std.testing.expect(column[committed_row].eql(M31.zero()));
        }
    }
}
