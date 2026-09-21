//! Transitional host-column ingress/egress for admitted AOT interactions.
//! Fractions, prefix scans and claims execute on the device; the caller retains
//! the existing allocator-owned commitment-column ABI.
const std = @import("std");
const core = @import("stwo_core");
const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
const program_mod = @import("stwo_prover_engine").air.component_prover;
const shared = @import("../shared_runtime.zig");
const runtime = @import("../runtime.zig");
const interaction = runtime.framework_interaction;

pub fn available() !bool {
    var lease = try shared.acquireExisting();
    defer lease.deinit();
    return lease.runtime.admitted_profile == .recursive_framework_v1;
}

pub fn generateInto(allocator: std.mem.Allocator, program: *const program_mod.OwnedFrameworkPolynomialProgramV1, counts: []const usize, sources: [2][]const []const M31, invocation: interaction.Invocation, destination: []const []M31) !QM31 {
    if ((program.layout == .independent_prefix_v1 and program.batches.len != 1) or destination.len != program.batches.len * 4 or invocation.trace_log_size >= 31 or counts.len != 3)
        return error.InvalidFrameworkInteraction;
    const rows = @as(usize, 1) << @intCast(invocation.trace_log_size);
    for (destination) |column| if (column.len != rows) return error.InvalidFrameworkInteraction;
    for (sources, 0..) |columns, tree| {
        if (columns.len != counts[tree]) return error.InvalidFrameworkInteraction;
        for (columns) |column| if (column.len != rows) return error.InvalidFrameworkInteraction;
    }
    var lease = try shared.acquireExisting();
    defer lease.deinit();
    var plan = try interaction.Plan.init(allocator, .{ .program = program, .tree_column_counts = counts });
    defer plan.deinit();
    try plan.prepare(lease.runtime);
    var buffers: [2]?runtime.ResidentBuffer = .{ null, null };
    defer for (&buffers) |*buffer| if (buffer.*) |*value| value.deinit();
    var offsets: [2][]u64 = .{ &.{}, &.{} };
    defer for (offsets) |values| allocator.free(values);
    var trees: [2]?interaction.Tree = .{ null, null };
    for (sources, 0..) |columns, tree| {
        if (columns.len == 0) continue;
        const words = try std.math.mul(usize, rows, columns.len);
        buffers[tree] = try lease.runtime.allocateResidentBuffer(try std.math.mul(usize, words, @sizeOf(M31)));
        offsets[tree] = try allocator.alloc(u64, columns.len);
        const target: [*]M31 = @ptrCast(@alignCast(buffers[tree].?.contents));
        for (columns, offsets[tree], 0..) |column, *offset, index| {
            offset.* = index * rows;
            @memcpy(target[index * rows ..][0..rows], column);
        }
        trees[tree] = .{ .buffer = &buffers[tree].?, .column_offsets = offsets[tree] };
    }
    var generated = try plan.generate(trees, invocation);
    defer generated.deinit();
    @import("../telemetry.zig").recordN(.metal_framework_interaction_dispatch, 4);
    // Device errors have already been checked. No destination is published on
    // a rejected selector, malformed canonical input or denominator pole.
    for (destination, 0..) |column, index| @memcpy(column, generated.column(index));
    std.debug.print("METAL_FRAMEWORK_INTERACTION rows={d} batches={d} gpu_ms={d}\n", .{ rows, program.batches.len, generated.gpu_milliseconds });
    return generated.claim(0);
}
