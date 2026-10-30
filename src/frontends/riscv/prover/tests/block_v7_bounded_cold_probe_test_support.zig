//! Diagnose the final reduction before paying for any recursive proof.
//! Uses real original metadata and the same independently compiled fixed keys.
//! This helper creates no proof and grants no execution authority.
const std = @import("std");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const Source = @import("../block_v7_streaming_execution_v1.zig");
const Complete = @import("../../recursion/block_v7_bounded_complete_cpu_producer_v1.zig");
const Receiver = @import("../../recursion/block_v7_mixed_batch_receiver_v1.zig");
const Direct = @import("../../recursion/block_v7_mixed_protocol_v1.zig");
const Fixed = @import("../../recursion/blake3_parent_fixed_key_v1.zig").ForBackend(Cpu);
const Cold = @import("../../recursion/block_v7_mixed_batch_fixed_join_v1.zig");
const Model = @import("../../recursion/block_v7_parent_resource_model_v1.zig");
const Budget = @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget;

pub fn run(f: Source.Fixture, options: Complete.Options) !void {
    const a = f.allocator;
    const owned = try @import("../../recursion/block_v7_mixed_metadata_v1.zig").Owned.initWhole(a, f.trusted, f.input, options.max_originals);
    defer owned.deinit();
    const input = owned.input();
    const total = try input.count();
    var pins: [32]Receiver.DirectPin = undefined;
    var counts: [32]u32 = undefined;
    var completed: usize = 0;
    defer for (pins[0..completed]) |pin| a.free(pin.wires);
    var first: usize = 0;
    while (first < total) {
        if (completed == pins.len) return error.BoundedReductionDepthRequired;
        // Match the producer's child allocation cap, not just its shape model.
        const budget = try Budget.createRetainingParent(a, options.direct.max_planned_bytes);
        defer budget.destroy();
        var selected = try Complete.selectWindow(budget.allocator(), input, first, @min(options.max_direct_children, total - first), options);
        defer selected.cold.deinit();
        var fixed = try Fixed.deriveCommitted(budget.allocator(), selected.cold.fixed, selected.cold.context, options.profile);
        defer fixed.deinit();
        const key = try Direct.Key.fromGeometry(fixed.key, selected.cold.wires, selected.cold.expected);
        pins[completed] = .{ .key = key, .wires = try a.dupe(@import("../../recursion/block_v7_mixed_public_v1.zig").Wire, selected.cold.wires) };
        counts[completed] = @intCast(selected.count);
        completed += 1;
        first += selected.count;
    }
    const budget = try Budget.createRetainingParent(a, options.reduction.max_bytes);
    defer budget.destroy();
    const ra = budget.allocator();
    var limits = options.reduction.metadata;
    limits.global.max_entries = options.max_originals;
    var metadata = try Receiver.Metadata.init(ra, input, counts[0..completed], pins[0..completed], limits);
    defer metadata.deinit();
    var cold = try Cold.Owned.derive(ra, metadata.policies, metadata.expected, options.reduction.prepare.circuit_capacity, options.reduction.fixed);
    defer cold.deinit();
    const resources = Model.Limits{
        .max_row_log = options.direct.max_row_log,
        .max_retained_bytes = options.direct.max_retained_bytes,
        .max_planned_bytes = options.reduction.max_bytes,
        .scratch_headroom_bytes = options.direct.scratch_headroom_bytes,
    };
    const estimate = try Model.estimate(cold.fixed, metadata.policies[0].key.config, resources);
    const admitted = blk: {
        estimate.require(resources) catch |err| {
            if (err != error.ParentWindowResourceLimit) return err;
            break :blk false;
        };
        break :blk true;
    };
    std.debug.print("V7_REDUCTION_COLD_ONLY profile={s} counts={f} estimate={f} limits={f} admitted={} recursive_proof_created=false\n", .{ @tagName(options.profile), std.json.fmt(counts[0..completed], .{}), std.json.fmt(estimate, .{}), std.json.fmt(resources, .{}), admitted });
}
