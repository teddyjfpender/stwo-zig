//! Pre-write borrowed CPU admission. Only explicit API read inputs are protected;
//! allocator internals and unrelated process owners are outside this contract.
const std = @import("std");
const frontend = @import("stwo_riscv_frontend");
const air = frontend.rv64_air;
const rv = frontend.rv64;
const M = @import("stwo_core").fields.m31.M31;
const Storage = air.crypto.main_storage;
const Retirements = @import("rv64_retirements.zig").Source;
const S = @import("rv64_full_statement.zig");
pub fn validate(main: []M, records: Retirements, calls: []const rv.services.Call, secp_calls: []const rv.ethereum_services.SecpCall, statement: S.Statement, program: *const air.program.setup.Setup, plan: *const air.encoding.Plan) !void {
    if (statement.steps == 0 or statement.steps >= 1 << 22) return error.InvalidRv64FullStatement;
    const size = @as(usize, 1) << @intCast(statement.logSize());
    const cells = try std.math.mul(usize, try std.math.add(usize, plan.main_count, air.full.frame.widthWithControl(plan.execution_profile, plan.control_policy)), size);
    if (main.len != cells) return error.InvalidRv64BorrowedMainShape;
    const slices = [_]Storage.Slice{.{ .values = main, .cells = cells }};
    try Storage.exclude(&slices, std.mem.asBytes(program));
    try Storage.exclude(&slices, std.mem.sliceAsBytes(program.rows));
    try Storage.exclude(&slices, std.mem.sliceAsBytes(program.addresses));
    try Storage.exclude(&slices, std.mem.sliceAsBytes(program.decoded));
    try Storage.exclude(&slices, std.mem.asBytes(plan));
    try Storage.exclude(&slices, std.mem.sliceAsBytes(statement.program.words));
    try Storage.exclude(&slices, std.mem.sliceAsBytes(statement.program.addresses));
    try Storage.exclude(&slices, std.mem.sliceAsBytes(statement.cells));
    try Storage.exclude(&slices, std.mem.sliceAsBytes(statement.memory_clocks));
    try Storage.exclude(&slices, std.mem.sliceAsBytes(calls));
    try Storage.exclude(&slices, std.mem.sliceAsBytes(secp_calls));
    switch (records) {
        .journal => |journal| try Storage.exclude(&slices, std.mem.sliceAsBytes(journal)),
        .compact => |tape| {
            try Storage.exclude(&slices, std.mem.asBytes(tape));
            // Protect complete owned backings, including unused capacity that
            // will be reused for the next batch after clearRetainingCapacity.
            try Storage.exclude(&slices, std.mem.sliceAsBytes(tape.storage));
            if (tape.memory_before.capacity != 0) try Storage.exclude(&slices, std.mem.sliceAsBytes(tape.memory_before.items.ptr[0..tape.memory_before.capacity]));
            if (tape.service_calls.capacity != 0) try Storage.exclude(&slices, std.mem.sliceAsBytes(tape.service_calls.items.ptr[0..tape.service_calls.capacity]));
            if (tape.secp_calls.capacity != 0) try Storage.exclude(&slices, std.mem.sliceAsBytes(tape.secp_calls.items.ptr[0..tape.secp_calls.capacity]));
        },
    }
}
