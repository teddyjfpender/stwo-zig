//! Original circuit gate kernels and device histogram ledgers under one lease.
const std = @import("std");
const core = @import("stwo_core");
const circuit = @import("stwo_circuit_frontend");
const S = @import("outer_source.zig");
const Native = @import("pcs_native_abi.zig");
const D = @import("stwo_riscv_cpu_integration").rv64_device_pcs;
pub fn immutableKey(scope: D.Scope, column: usize) [8]u32 {
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
    var range = try @import("nvtx_stage.zig").Range.beginUnlessAdmitted(&owner.backend.service.library, raw, "rv64/recursion/MAIN-assignment", owner.permit != null);
    defer range.deinit();
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
    var values = if (b.assignment) |*assignment| try assignment.generate(owner, &ctx) else try ctx.allocate(owner.input.len * 4, 0);
    defer ctx.release(&values) catch {};
    if (b.assignment == null) {
        const values_words = @as([*]const u32, @ptrCast(owner.input.ptr))[0 .. owner.input.len * 4];
        try ctx.upload(try ctx.borrow(values), values_words);
    }
    var status = try ctx.allocate(1, 0);
    defer ctx.release(&status) catch {};
    try S.checked(b.clear(raw, status.words.?, 0, 4));
    for (owner.key.pp.columns, 0..) |column_data, i| {
        const words = @as([*]const u32, @ptrCast(column_data.values.ptr))[0..column_data.values.len];
        if (words.len == 0) return error.MissingCircuitProverData;
        owner.raw_fixed[i] = try b.service.immutableWords(raw, ctx.scope, immutableKey(owner.initial_scope, i), words);
    }
    // M6 enqueue: the assignment returns joined and immutable uploads join
    // themselves, so the only pending work is lane 0 (clears, staged
    // uploads). Gate kernels go on lane 0 behind it: no host join here, and
    // the status readback below is ordered after them on the same lane.
    var stream: ?*anyopaque = null;
    try S.checked(b.api.lane_stream(raw, 0, &stream));
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
        try S.checked(b.base(@intCast(component), values.words.?, @intCast(owner.value_count), @as(u32, 1) << @intCast(logs[component]), @intCast(owner.key.pp.first_permutation_row), &pp, @intCast(pp_widths[component]), &outputs, @intCast(widths[component]), &counts, 22, status.words.?, stream.?));
        main_at += widths[component];
    }
    const checked_blake_records = try checkBlakeSampleInputs(owner, &ctx, values.words.?, logs[4], status.words.?);
    if (fusedBlakeFlags()) |flags| fusedBlakeShadow(owner, &ctx, values.words.?, logs, stream.?, flags);
    var flag: [1]u32 = undefined;
    try ctx.download(try ctx.borrow(status), &flag);
    try ctx.join();
    if (checked_blake_records != 0) std.debug.print("BLAKE_SAMPLE_INPUTS_CHECK ordinal={} records={} gg_rows={} mismatch={} assignment_unchanged=true\n", .{ owner.initial_scope.ordinal, checked_blake_records, checked_blake_records * 80, flag[0] });
    if (flag[0] != 0) return error.InvalidCircuitDeviceWitness;
}

const BlakeSampleCheckFn = *const fn (*anyopaque, u32, [*]const u32, u32, [*]const [*]const u32, u32, u32, [*]const u32, u32, [*]u32) callconv(.c) c_int;
fn checkBlakeSampleInputs(owner: *S.Owner, ctx: anytype, values: [*]u32, gg_log: u32, status: [*]u32) !usize {
    const assignment = if (owner.backend.assignment) |*value| value else return 0;
    const inputs = assignment.blake_sample_inputs orelse return 0;
    const span = assignment.blake_sample_span orelse return error.MissingBlakeSampleClassSpan;
    if (inputs.len == 0 or span.gg_count % 80 != 0 or inputs.len != span.gg_count / 80) return error.BlakeSampleInputCountMismatch;
    const kernel = owner.backend.service.library.lookup(BlakeSampleCheckFn, "stwo_circuit_blake_sample_inputs_check_on") orelse return error.MissingBlakeSampleCheckKernel;
    const indices = try S.lookupIndices(owner.allocator, owner.key, 4);
    defer owner.allocator.free(indices);
    var pp: [10][*]const u32 = undefined;
    for (&pp, indices[0..10]) |*out, index| {
        const lease = owner.raw_fixed[index];
        try S.checked(owner.backend.service.lease_validate_range(owner.backend.service.session, lease.words.?, lease.count, lease.context_token, lease.generation, &ctx.scope));
        out.* = lease.words.?;
    }
    var tape = try ctx.allocate(try std.math.mul(usize, inputs.len, 26), 0);
    defer ctx.release(&tape) catch {};
    try ctx.upload(try ctx.borrow(tape), @as([*]const u32, @ptrCast(inputs.ptr))[0 .. inputs.len * 26]);
    try S.checked(kernel(ctx.native_context, 0, values, @intCast(owner.value_count), &pp, @as(u32, 1) << @intCast(gg_log), span.first_gg, tape.words.?, @intCast(inputs.len), status));
    return inputs.len;
}

// ---------------------------------------------------------------------------
// fused_blake2s_v1 shadow hook (stream blake-gadget, M5; minimal hook in an
// enqueue-owned file, see /workspace/m3/M5-INTERFACES.md "blake-gadget").
// STWO_RV64_FUSED_BLAKE=shadow derives the hint tape of every Blake2s
// compression of this node from its device values and blake_g_gate address
// columns, then fills the fused_blake2s_v1 trace (all instance rows) and its
// XOR multiplicities into scratch memory; =check also re-evaluates every
// fused constraint on the device. Nothing it writes is read by the prover, so
// proofs stay byte-identical; it is diagnostic and never fails the prove.
const FusedShadowFn = *const fn ([*]const u32, u32, [*]const [*]const u32, u32, u32, ?*anyopaque, *[16]u64, ?[*]u32, u64) callconv(.c) c_int;
/// Fill-scratch rows leased from the session when cudaMallocAsync cannot
/// supply memory (arena on): 4,096 rows x 3,328 columns = 54.5 MB.
const FUSED_WORKSPACE_ROWS: u64 = 4096;

fn fusedBlakeFlags() ?u32 {
    const mode = std.posix.getenv("STWO_RV64_FUSED_BLAKE") orelse return null;
    if (std.mem.eql(u8, mode, "shadow")) return 0;
    if (std.mem.eql(u8, mode, "check")) return 1;
    return null;
}

fn fusedBlakeShadow(owner: *S.Owner, ctx: anytype, values: [*]u32, logs: anytype, stream: *anyopaque, flags: u32) void {
    const b = owner.backend;
    const shadow = b.service.library.lookup(FusedShadowFn, "stwo_fused_blake2s_v1_shadow_on") orelse {
        std.debug.print("FUSED_BLAKE2S_V1_SHADOW status=missing_symbol\n", .{});
        return;
    };
    const indices = S.lookupIndices(owner.allocator, owner.key, 4) catch return;
    defer owner.allocator.free(indices);
    var pp: [10][*]const u32 = undefined;
    for (&pp, indices[0..10]) |*out, index| out.* = owner.raw_fixed[index].words.?;
    const g_rows = @as(u32, 1) << @intCast(logs[4]);
    const workspace_words: u64 = (g_rows / 80) * 26 + 8 + 3 * (1 << 16) + FUSED_WORKSPACE_ROWS * 3328;
    var workspace = ctx.allocate(@intCast(workspace_words), 0) catch null;
    defer if (workspace) |*w| ctx.release(w) catch {};
    var stats: [16]u64 = undefined;
    const start = std.time.nanoTimestamp();
    const status = shadow(values, @intCast(owner.value_count), &pp, g_rows, flags, stream, &stats, if (workspace) |w| w.words.? else null, if (workspace != null) workspace_words else 0);
    const wall: u64 = @intCast(std.time.nanoTimestamp() - start);
    std.debug.print("FUSED_BLAKE2S_V1_SHADOW status={d} ordinal={d} g_rows={d} chunks={d} shape={d} valid={d} fused_rows={d} instances={d} inst_logs=0x{x} gather_ns={d} fill_ns={d} check_ns={d} check_violations={d} xor_lookups={d} scratch_rows={d} fill_bytes={d} mem={d} wall_ns={d} flags={d} logs={any}\n", .{
        status,    owner.initial_scope.ordinal, stats[0], stats[1], stats[2], stats[3],  stats[4],  stats[5],
        stats[14], stats[6],                    stats[7], stats[8], stats[9], stats[10], stats[11], stats[12],
        stats[15], wall,                        flags,    logs,
    });
}
