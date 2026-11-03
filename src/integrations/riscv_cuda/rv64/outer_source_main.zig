//! Original circuit gate kernels and device histogram ledgers under one lease.
const std = @import("std");
const core = @import("stwo_core");
const circuit = @import("stwo_circuit_frontend");
const S = @import("outer_source.zig");
const Native = @import("pcs_native_abi.zig");
const D = @import("stwo_riscv_cpu_integration").rv64_device_pcs;
fn immutableKey(scope: D.Scope, column: usize) [8]u32 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("circuit/om31/fixed-evaluations/v1\x00");
    hash.update(&scope.fixed);
    var index: [8]u8 = undefined;
    std.mem.writeInt(u64, &index, column, .little);
    hash.update(&index);
    const bytes = hash.finalResult();
    var key: [8]u32 = undefined;
    for (&key, 0..) |*out, i| out.* = std.mem.readInt(u32, bytes[4 * i ..][0..4], .little);
    return key;
}
pub fn generate(owner: *S.Owner, raw: *anyopaque, token: u64) !void {
    var ctx = owner.context(raw, token, owner.initial_scope);
    defer ctx.active = false;
    const b = owner.backend;
    const logs = owner.key.logs.toArray();
    const widths = circuit.witness.trace.traceWidths();
    var cells: usize = 0;
    for (logs, widths) |log, width| cells = try std.math.add(usize, cells, try std.math.mul(usize, @as(usize, 1) << @intCast(log), width));
    owner.main_evaluations = try owner.owned(&ctx, cells);
    var at: usize = 0;
    var column: usize = 0;
    for (logs, widths) |log, width| for (0..width) |_| {
        const rows = @as(usize, 1) << @intCast(log);
        owner.main_columns[column] = .{ .log_size = log, .encoding = .evaluations, .device = .{ .words = owner.main_evaluations.words.? + at, .count = rows, .context_token = token, .generation = owner.main_evaluations.generation } };
        at += rows;
        column += 1;
    };
    if (column != 114 or at != cells) return error.InvalidCircuitMainRoster;
    // Gate kernel counts are the last22 native MAIN columns, in the native
    // XOR8/XOR12/XOR4/XOR7/XOR9/range16 table order.
    const counts_start = @intFromPtr(owner.main_columns[92].device.?.words);
    const counts_bytes = @intFromPtr(owner.main_evaluations.words.? + cells) - counts_start;
    try S.checked(b.clear(raw, @ptrFromInt(counts_start), 0, counts_bytes));
    var values = try ctx.allocate(owner.input.len * 4, 0);
    defer ctx.release(&values) catch {};
    const values_words = @as([*]const u32, @ptrCast(owner.input.ptr))[0 .. owner.input.len * 4];
    try ctx.upload(try ctx.borrow(values), values_words);
    var status = try ctx.allocate(1, 0);
    defer ctx.release(&status) catch {};
    try S.checked(b.clear(raw, status.words.?, 0, 4));
    for (owner.key.pp.columns, 0..) |column_data, i| {
        const words = @as([*]const u32, @ptrCast(column_data.values.ptr))[0..column_data.values.len];
        if (words.len == 0) return error.MissingCircuitProverData;
        owner.raw_fixed[i] = try b.service.immutableWords(raw, ctx.scope, immutableKey(owner.initial_scope, i), words);
    }
    try ctx.join();
    var stream: ?*anyopaque = null;
    try S.checked(b.api.lane_stream(raw, 1, &stream));
    var counts: [22][*]u32 = undefined;
    for (&counts, owner.main_columns[92..]) |*out, input| out.* = @constCast(input.device.?.words);
    const pp_widths = [_]usize{ 1, 7, 4, 1, 10 };
    var main_at: usize = 0;
    for (0..5) |component| {
        const indices = try S.lookupIndices(owner.allocator, owner.key, component);
        defer owner.allocator.free(indices);
        var pp: [11][*]const u32 = undefined;
        for (pp[0..pp_widths[component]], indices[0..pp_widths[component]]) |*out, index| {
            const lease = owner.raw_fixed[index];
            try S.checked(b.service.lease_validate_range(b.service.session, lease.words.?, lease.count, lease.context_token, lease.generation, &ctx.scope));
            out.* = lease.words.?;
        }
        var outputs: [52][*]u32 = undefined;
        for (outputs[0..widths[component]], owner.main_columns[main_at..][0..widths[component]]) |*out, input| out.* = @constCast(input.device.?.words);
        try S.checked(b.base(@intCast(component), values.words.?, @intCast(owner.input.len), @as(u32, 1) << @intCast(logs[component]), @intCast(owner.key.pp.first_permutation_row), &pp, @intCast(pp_widths[component]), &outputs, @intCast(widths[component]), &counts, 22, status.words.?, stream.?));
        main_at += widths[component];
    }
    try ctx.join();
    var flag: [1]u32 = undefined;
    try ctx.download(try ctx.borrow(status), &flag);
    try ctx.join();
    if (flag[0] != 0) return error.InvalidCircuitDeviceWitness;
}
