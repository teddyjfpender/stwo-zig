const std = @import("std");
const arena_plan = @import("stwo_metal_backend").arena_plan;
const metal_runtime = @import("stwo_metal_backend").runtime;
const schedule_bindings = @import("../schedule_bindings.zig");
const commitment_ordering = @import("../resident/commitment/ordering.zig");
const commitment_telemetry = @import("../resident/commitment/telemetry.zig");
const resident_binding = @import("../resident/binding.zig");
const resident_twiddles = @import("../resident/twiddles.zig");
const Error = @import("../resident/errors.zig").Error;
const M31 = @import("stwo_core").fields.m31.M31;
const circle_poly_mod = @import("stwo_prover_engine").poly.circle.poly;
const canonic_circle_mod = @import("stwo_core").poly.circle.canonic;
const CairoMerkleHasher = @import("stwo_core").vcs_lifted.blake2_merkle.Blake2sPlainMerkleHasher;

const collectTreePurpose = commitment_ordering.collectTreePurpose;
const oneOrdinal = schedule_bindings.oneOrdinal;
const twiddleBankBinding = resident_twiddles.twiddleBankBinding;
const twiddleOffsetForLog = resident_twiddles.twiddleOffsetForLog;
const wordOffset = resident_binding.wordOffset;
const cairo_domain_prefix_bytes = CairoMerkleHasher.domainPrefixBytes();

pub const CommitmentTelemetry = struct {
    gpu_ms: f64,
    lde_gpu_ms: f64,
    leaf_gpu_ms: f64,
    parent_gpu_ms: f64,
    root: arena_plan.Binding,
    command_epoch_stats: ?metal_runtime.CommandEpochStats = null,
};

pub fn execute(
    allocator: std.mem.Allocator,
    metal: *metal_runtime.Runtime,
    resident_arena: *arena_plan.ResidentArena,
    schedule: []const std.json.Value,
    plan: arena_plan.Plan,
    coefficients: []const arena_plan.Binding,
    twiddles: arena_plan.Binding,
    tree_index: u32,
    leaf_seed: [8]u32,
    node_seed: [8]u32,
) !CommitmentTelemetry {
    return executeWithMode(
        allocator,
        metal,
        resident_arena,
        schedule,
        plan,
        coefficients,
        twiddles,
        tree_index,
        leaf_seed,
        node_seed,
        .automatic,
    );
}

pub const BenchmarkMode = enum { automatic, synchronous };

/// Bounded benchmark hook for the exact production commitment graph. Normal
/// proving always enters through executeStreamingCommitment in automatic mode.
pub fn executeBenchmark(
    allocator: std.mem.Allocator,
    metal: *metal_runtime.Runtime,
    resident_arena: *arena_plan.ResidentArena,
    schedule: []const std.json.Value,
    plan: arena_plan.Plan,
    coefficients: []const arena_plan.Binding,
    twiddles: arena_plan.Binding,
    tree_index: u32,
    leaf_seed: [8]u32,
    node_seed: [8]u32,
    mode: BenchmarkMode,
) !CommitmentTelemetry {
    return executeWithMode(
        allocator,
        metal,
        resident_arena,
        schedule,
        plan,
        coefficients,
        twiddles,
        tree_index,
        leaf_seed,
        node_seed,
        mode,
    );
}

fn executeWithMode(
    allocator: std.mem.Allocator,
    metal: *metal_runtime.Runtime,
    resident_arena: *arena_plan.ResidentArena,
    schedule: []const std.json.Value,
    plan: arena_plan.Plan,
    coefficients: []const arena_plan.Binding,
    twiddles: arena_plan.Binding,
    tree_index: u32,
    leaf_seed: [8]u32,
    node_seed: [8]u32,
    mode: BenchmarkMode,
) !CommitmentTelemetry {
    const group_descriptors = try collectTreePurpose(allocator, schedule, plan, "CommitColumnLogSizes", tree_index);
    defer allocator.free(group_descriptors);
    const tile_items = try collectTreePurpose(allocator, schedule, plan, "CommitLdeTile", tree_index);
    defer allocator.free(tile_items);
    const leaf_items = try collectTreePurpose(allocator, schedule, plan, "MerkleLeafState", tree_index);
    defer allocator.free(leaf_items);
    if (tile_items.len != 1 or leaf_items.len != 1) return Error.InvalidCardinality;
    const tile = tile_items[0];
    const leaf_state = leaf_items[0];
    if (std.process.hasEnvVarConstant("STWO_ZIG_SN2_LOG_STAGE_TIMINGS"))
        std.debug.print("commit_prepare tree={d} coefficients={d} twiddle_offset={d} twiddle_size={d} tile_offset={d} tile_size={d} leaf_offset={d} leaf_size={d}\n", .{
            tree_index, coefficients.len, twiddles.offset_bytes, twiddles.size_bytes, tile.offset_bytes, tile.size_bytes, leaf_state.offset_bytes, leaf_state.size_bytes,
        });
    const scratch_items = collectTreePurpose(allocator, schedule, plan, "MerkleLayerScratch", tree_index) catch &[_]arena_plan.Binding{};
    defer if (scratch_items.len != 0) allocator.free(scratch_items);
    const retained = try collectTreePurpose(allocator, schedule, plan, "RetainedMerkleLayers", tree_index);
    defer allocator.free(retained);
    if (leaf_state.size_bytes % 32 != 0 or !std.math.isPowerOfTwo(leaf_state.size_bytes / 32)) return Error.InvalidBindingSize;
    const lifting_log: u32 = std.math.log2_int(u64, leaf_state.size_bytes / 32);
    var coefficient_cursor: usize = 0;
    var gpu_ms: f64 = 0;
    var lde_gpu_ms: f64 = 0;
    var leaf_gpu_ms: f64 = 0;
    var parent_gpu_ms: f64 = 0;
    const use_compact_leaf_state = !std.process.hasEnvVarConstant("STWO_ZIG_SN2_COMMIT_FULL_LOG_LEAVES") and
        !std.process.hasEnvVarConstant("STWO_ZIG_SN2_LOG_COMMIT_STEPS");
    if (use_compact_leaf_state and scratch_items.len != 1) return Error.InvalidCardinality;
    const requires_intermediate_visibility = std.process.hasEnvVarConstant("STWO_ZIG_SN2_LOG_STAGE_TIMINGS") or
        std.process.hasEnvVarConstant("STWO_ZIG_SN2_LOG_COMMIT_LDE_DIGESTS") or
        std.process.hasEnvVarConstant("STWO_ZIG_SN2_LOG_COMMIT_STEPS") or
        std.process.hasEnvVarConstant("STWO_ZIG_SN2_REPEAT_COMMIT_LDE") or
        std.process.hasEnvVarConstant("STWO_ZIG_SN2_REPAIR_COLUMN_613_LDE");
    var command_epoch: ?metal_runtime.CommandEpoch = if (mode == .automatic and use_compact_leaf_state and !requires_intermediate_visibility)
        try metal.beginCommandEpoch(resident_arena.buffer)
    else
        null;
    defer if (command_epoch) |*epoch| epoch.deinit();
    var previous_group_log: ?u32 = null;
    var leaf_state_log: ?u32 = null;
    var command_epoch_stats: ?metal_runtime.CommandEpochStats = null;
    for (group_descriptors, 0..) |descriptor, group_index| {
        const width = std.math.cast(usize, descriptor.size_bytes / 4) orelse return Error.InvalidBindingSize;
        if (std.process.hasEnvVarConstant("STWO_ZIG_SN2_LOG_STAGE_TIMINGS") and group_index % 32 == 0)
            std.debug.print("commit_progress tree={d} group={d} coefficient_cursor={d} gpu_ms={d:.3}\n", .{
                tree_index, group_index, coefficient_cursor, gpu_ms,
            });
        if (width == 0 or width > 16 or coefficient_cursor + width > coefficients.len) {
            std.debug.print("commit_group_invalid tree={d} group={d} width={d} cursor={d} coefficients={d}\n", .{
                tree_index, group_index, width, coefficient_cursor, coefficients.len,
            });
            return Error.InvalidCardinality;
        }
        const group = coefficients[coefficient_cursor .. coefficient_cursor + width];
        var output_offsets: [16]u32 = undefined;
        var output_logs: [16]u32 = undefined;
        var tile_cursor: u64 = 0;
        for (group, 0..) |source, index| {
            if (source.size_bytes < 64 or !std.math.isPowerOfTwo(source.size_bytes / 4)) {
                std.debug.print("commit_source_size_invalid tree={d} group={d} logical_id={d} offset={d} size={d}\n", .{
                    tree_index, group_index, source.logical_id, source.offset_bytes, source.size_bytes,
                });
                return Error.InvalidBindingSize;
            }
            const coefficient_log: u32 = std.math.log2_int(u64, source.size_bytes / 4);
            const evaluation_log = coefficient_log + 1;
            const evaluation_words = @as(u64, 1) << @intCast(evaluation_log);
            if (tile_cursor + evaluation_words > tile.size_bytes / 4) {
                std.debug.print("commit_tile_size_invalid tree={d} group={d} cursor={d} evaluation_words={d} tile_words={d}\n", .{
                    tree_index, group_index, tile_cursor, evaluation_words, tile.size_bytes / 4,
                });
                return Error.InvalidBindingSize;
            }
            output_offsets[index] = std.math.cast(u32, tile.offset_bytes / 4 + tile_cursor) orelse {
                std.debug.print("commit_tile_offset_overflow tree={d} group={d} index={d} offset={d}\n", .{
                    tree_index, group_index, index, tile.offset_bytes + tile_cursor * 4,
                });
                return Error.InvalidBindingSize;
            };
            output_logs[index] = evaluation_log;
            tile_cursor += evaluation_words;
        }
        if (std.process.hasEnvVarConstant("STWO_ZIG_SN2_LOG_COMMIT_SOURCE_DIGESTS"))
            try commitment_telemetry.logCommitSourceDigests(resident_arena, coefficient_cursor, group);
        if (tree_index == 2 and
            std.process.hasEnvVarConstant("STWO_ZIG_SN2_REPAIR_COLUMN_613_LDE") and
            coefficient_cursor <= 2241 and 2241 < coefficient_cursor + width)
        {
            const local_index = 2241 - coefficient_cursor;
            const file = try std.fs.createFileAbsolute("/tmp/sn2-column613-pre-group-source.u32le", .{});
            defer file.close();
            try file.writeAll(try resident_arena.bytes(group[local_index]));
        }
        for (4..lifting_log + 1) |evaluation_log_usize| {
            const evaluation_log: u32 = @intCast(evaluation_log_usize);
            var sources = std.ArrayList(u64).empty;
            defer sources.deinit(allocator);
            var logs = std.ArrayList(u32).empty;
            defer logs.deinit(allocator);
            var outputs = std.ArrayList(u32).empty;
            defer outputs.deinit(allocator);
            for (group, output_offsets[0..width], output_logs[0..width]) |source, output, log_size| {
                if (log_size != evaluation_log) continue;
                try sources.append(allocator, source.offset_bytes / 4);
                try logs.append(allocator, std.math.log2_int(u64, source.size_bytes / 4));
                try outputs.append(allocator, output);
            }
            if (sources.items.len == 0) continue;
            const evaluation_twiddles = twiddleBankBinding(twiddles, evaluation_log);
            const twiddle_offset = twiddleOffsetForLog(evaluation_twiddles, evaluation_log) catch {
                std.debug.print("commit_twiddle_offset_invalid tree={d} group={d} evaluation_log={d} offset={d} size={d}\n", .{
                    tree_index, group_index, evaluation_log, evaluation_twiddles.offset_bytes, evaluation_twiddles.size_bytes,
                });
                return Error.InvalidBindingSize;
            };
            var lde = try metal.prepareCompositionLde(sources.items, logs.items, outputs.items, evaluation_log, twiddle_offset);
            defer lde.deinit();
            const elapsed_gpu_ms = if (command_epoch) |*epoch| epoch_time: {
                try epoch.encodeCompositionLde(lde);
                break :epoch_time 0;
            } else try metal.compositionLdePrepared(resident_arena.buffer, lde);
            gpu_ms += elapsed_gpu_ms;
            lde_gpu_ms += elapsed_gpu_ms;
            if (group_index == 48 and std.process.hasEnvVarConstant("STWO_ZIG_SN2_REPEAT_COMMIT_LDE")) {
                const first_digest = commitment_telemetry.sampleCommitOutputs(resident_arena, outputs.items, evaluation_log);
                const repeated_gpu_ms = try metal.compositionLdePrepared(resident_arena.buffer, lde);
                gpu_ms += repeated_gpu_ms;
                lde_gpu_ms += repeated_gpu_ms;
                const second_digest = commitment_telemetry.sampleCommitOutputs(resident_arena, outputs.items, evaluation_log);
                std.debug.print(
                    "commit_lde_repeat evaluation_log={} first={x:0>16} second={x:0>16}\n",
                    .{ evaluation_log, first_digest, second_digest },
                );
            }
        }
        if (tree_index == 2 and
            std.process.hasEnvVarConstant("STWO_ZIG_SN2_REPAIR_COLUMN_613_LDE") and
            coefficient_cursor <= 2241 and 2241 < coefficient_cursor + width)
        {
            const local_index = 2241 - coefficient_cursor;
            const source = group[local_index];
            const diagnostic_source = group[local_index - 1];
            @memcpy(
                try resident_arena.bytes(diagnostic_source),
                try resident_arena.bytes(source),
            );
            const evaluation_log = output_logs[local_index];
            const evaluation_twiddles = twiddleBankBinding(twiddles, evaluation_log);
            const sources = [_]u64{diagnostic_source.offset_bytes / 4};
            const logs = [_]u32{std.math.log2_int(u64, diagnostic_source.size_bytes / 4)};
            const outputs = [_]u32{output_offsets[local_index]};
            var repair = try metal.prepareCompositionLde(
                &sources,
                &logs,
                &outputs,
                evaluation_log,
                try twiddleOffsetForLog(evaluation_twiddles, evaluation_log),
            );
            defer repair.deinit();
            const repair_gpu_ms = try metal.compositionLdePrepared(resident_arena.buffer, repair);
            gpu_ms += repair_gpu_ms;
            lde_gpu_ms += repair_gpu_ms;
            const lde_words = @as(usize, 1) << @intCast(evaluation_log);
            const arena_bytes: [*]const u8 = @ptrCast(resident_arena.buffer.contents);
            const lde_bytes = arena_bytes[@as(usize, outputs[0]) * 4 ..][0 .. lde_words * 4];
            const file = try std.fs.createFileAbsolute("/tmp/sn2-column613-metal-lde.u32le", .{});
            defer file.close();
            try file.writeAll(lde_bytes);

            const source_bytes = try resident_arena.bytes(source);
            const source_file = try std.fs.createFileAbsolute("/tmp/sn2-column613-commit-source.u32le", .{});
            defer source_file.close();
            try source_file.writeAll(source_bytes);
            const source_words: []align(1) const u32 = std.mem.bytesAsSlice(u32, source_bytes);
            const coefficient_values = try allocator.alloc(M31, source_words.len);
            for (source_words, coefficient_values) |word, *value|
                value.* = M31.fromCanonical(word % 0x7fffffff);
            var cpu_coefficients = try circle_poly_mod.CircleCoefficients.initOwned(coefficient_values);
            defer cpu_coefficients.deinit(allocator);
            const cpu_lde = try cpu_coefficients.evaluate(
                allocator,
                canonic_circle_mod.CanonicCoset.new(evaluation_log).circleDomain(),
            );
            defer allocator.free(@constCast(cpu_lde.values));
            const cpu_file = try std.fs.createFileAbsolute("/tmp/sn2-column613-repair-cpu-lde.u32le", .{});
            defer cpu_file.close();
            try cpu_file.writeAll(std.mem.sliceAsBytes(cpu_lde.values));
            @memcpy(
                @constCast(lde_bytes),
                std.mem.sliceAsBytes(cpu_lde.values),
            );
            const repaired_file = try std.fs.createFileAbsolute("/tmp/sn2-column613-repaired-lde.u32le", .{});
            defer repaired_file.close();
            try repaired_file.writeAll(lde_bytes);
        }
        if (std.process.hasEnvVarConstant("STWO_ZIG_SN2_LOG_COMMIT_LDE_DIGESTS"))
            commitment_telemetry.logCommitLdeDigests(
                resident_arena,
                coefficient_cursor,
                group,
                output_offsets[0..width],
                output_logs[0..width],
            );
        var group_log: u32 = 0;
        for (output_logs[0..width]) |output_log| group_log = @max(group_log, output_log);
        if (group_log > lifting_log or (previous_group_log != null and group_log < previous_group_log.?))
            return Error.InvalidBindingSize;
        const is_final = group_index + 1 == group_descriptors.len;
        const elapsed_leaf_gpu_ms = if (use_compact_leaf_state) compact: {
            const destination_log = if (is_final) lifting_log else group_log;
            var source_state_offset = try wordOffset(leaf_state);
            var source_state_log = leaf_state_log orelse destination_log;
            if (leaf_state_log) |materialized_log| {
                if (destination_log < materialized_log) return Error.InvalidBindingSize;
                if (destination_log > materialized_log) {
                    const scratch = scratch_items[0];
                    const snapshot_words = (@as(u64, 1) << @intCast(materialized_log)) * 8;
                    if (snapshot_words > scratch.size_bytes / 4 or snapshot_words > std.math.maxInt(u32))
                        return Error.InvalidBindingSize;
                    const ranges = [_]metal_runtime.ArenaCopyRange{.{
                        .source_word_offset = leaf_state.offset_bytes / 4,
                        .destination_word_offset = scratch.offset_bytes / 4,
                        .word_count = @intCast(snapshot_words),
                    }};
                    var copy = try metal.prepareArenaCopies(&ranges);
                    defer copy.deinit();
                    const copy_gpu_ms = if (command_epoch) |*epoch| epoch_time: {
                        try epoch.encodeArenaCopy(copy);
                        break :epoch_time 0;
                    } else try metal.arenaCopyPrepared(resident_arena.buffer, copy);
                    gpu_ms += copy_gpu_ms;
                    leaf_gpu_ms += copy_gpu_ms;
                    source_state_offset = try wordOffset(scratch);
                    source_state_log = materialized_log;
                }
            }
            const elapsed = if (command_epoch) |*epoch| epoch_time: {
                try epoch.encodeCompactLeaf(
                    output_offsets[0..width],
                    output_logs[0..width],
                    source_state_offset,
                    source_state_log,
                    try wordOffset(leaf_state),
                    destination_log,
                    @intCast(coefficient_cursor),
                    is_final,
                    0,
                    leaf_seed,
                );
                break :epoch_time 0;
            } else try metal.leafAbsorbCompact(
                resident_arena.buffer,
                output_offsets[0..width],
                output_logs[0..width],
                source_state_offset,
                source_state_log,
                try wordOffset(leaf_state),
                destination_log,
                @intCast(coefficient_cursor),
                is_final,
                0,
                leaf_seed,
            );
            leaf_state_log = destination_log;
            break :compact elapsed;
        } else try metal.leafAbsorb(
            resident_arena.buffer,
            output_offsets[0..width],
            output_logs[0..width],
            try wordOffset(leaf_state),
            lifting_log,
            @intCast(coefficient_cursor),
            is_final,
            0,
            leaf_seed,
        );
        gpu_ms += elapsed_leaf_gpu_ms;
        leaf_gpu_ms += elapsed_leaf_gpu_ms;
        if (std.process.hasEnvVarConstant("STWO_ZIG_SN2_LOG_COMMIT_STEPS"))
            try commitment_telemetry.logCommitStepSamples(
                resident_arena,
                group_index,
                output_offsets[0..width],
                output_logs[0..width],
                leaf_state,
            );
        previous_group_log = group_log;
        coefficient_cursor += width;
    }
    if (std.process.hasEnvVarConstant("STWO_ZIG_SN2_LOG_STAGE_TIMINGS"))
        std.debug.print("commit_progress tree={d} groups_done={d} coefficient_cursor={d} gpu_ms={d:.3}\n", .{
            tree_index, group_descriptors.len, coefficient_cursor, gpu_ms,
        });
    if (coefficient_cursor != coefficients.len) return Error.InvalidCardinality;
    if (use_compact_leaf_state and leaf_state_log != lifting_log) return Error.InvalidBindingSize;
    if (std.process.hasEnvVarConstant("STWO_ZIG_SN2_LOG_COMMIT_DIGESTS"))
        try commitment_telemetry.logBindingDigest(resident_arena, "commit_leaf", 0, leaf_state);
    const bottom_hashes = retained[0].size_bytes / 32;
    if (std.process.hasEnvVarConstant("STWO_ZIG_SN2_LOG_STAGE_TIMINGS")) {
        std.debug.print("commit_merkle tree={d} scratch_count={d} retained_count={d} bottom_hashes={d}\n", .{
            tree_index, scratch_items.len, retained.len, bottom_hashes,
        });
        for (scratch_items, 0..) |scratch, index| std.debug.print(
            "commit_merkle_scratch tree={d} index={d} offset={d} size={d}\n",
            .{ tree_index, index, scratch.offset_bytes, scratch.size_bytes },
        );
        for (retained, 0..) |layer, index| std.debug.print(
            "commit_merkle_retained tree={d} index={d} offset={d} size={d}\n",
            .{ tree_index, index, layer.offset_bytes, layer.size_bytes },
        );
    }
    var child_offsets = std.ArrayList(u32).empty;
    defer child_offsets.deinit(allocator);
    var destination_offsets = std.ArrayList(u32).empty;
    defer destination_offsets.deinit(allocator);
    var parent_counts = std.ArrayList(u32).empty;
    defer parent_counts.deinit(allocator);
    var retained_copy_targets = std.ArrayList(?arena_plan.Binding).empty;
    defer retained_copy_targets.deinit(allocator);
    var current_offset = wordOffset(leaf_state) catch {
        std.debug.print("commit_leaf_offset_overflow tree={d} offset={d}\n", .{ tree_index, leaf_state.offset_bytes });
        return Error.InvalidBindingSize;
    };
    var current_hashes = leaf_state.size_bytes / 32;
    var ping_is_leaf = true;
    while (current_hashes > bottom_hashes) {
        const next_hashes = current_hashes / 2;
        var copy_target: ?arena_plan.Binding = null;
        const destination = if (next_hashes == bottom_hashes) blk: {
            break :blk wordOffset(retained[0]) catch {
                if (scratch_items.len == 0) return Error.MissingBinding;
                ping_is_leaf = !ping_is_leaf;
                const scratch = if (ping_is_leaf) leaf_state else scratch_items[0];
                copy_target = retained[0];
                break :blk wordOffset(scratch) catch return Error.InvalidBindingSize;
            };
        } else blk: {
            if (scratch_items.len == 0) return Error.MissingBinding;
            ping_is_leaf = !ping_is_leaf;
            const scratch = if (ping_is_leaf) leaf_state else scratch_items[0];
            break :blk wordOffset(scratch) catch {
                std.debug.print("commit_scratch_offset_overflow tree={d} offset={d}\n", .{ tree_index, scratch.offset_bytes });
                return Error.InvalidBindingSize;
            };
        };
        try child_offsets.append(allocator, current_offset);
        try destination_offsets.append(allocator, destination);
        try parent_counts.append(allocator, @intCast(next_hashes));
        try retained_copy_targets.append(allocator, copy_target);
        current_offset = destination;
        current_hashes = next_hashes;
    }
    for (retained[1..], 1..) |layer, layer_index| {
        var copy_target: ?arena_plan.Binding = null;
        const destination = wordOffset(layer) catch blk: {
            if (scratch_items.len == 0) return Error.MissingBinding;
            ping_is_leaf = !ping_is_leaf;
            const scratch = if (ping_is_leaf) leaf_state else scratch_items[0];
            if (scratch.size_bytes < layer.size_bytes) {
                std.debug.print("commit_retained_scratch_too_small tree={d} layer={d} scratch_size={d} layer_size={d}\n", .{
                    tree_index, layer_index, scratch.size_bytes, layer.size_bytes,
                });
                return Error.InvalidBindingSize;
            }
            copy_target = layer;
            break :blk wordOffset(scratch) catch return Error.InvalidBindingSize;
        };
        try child_offsets.append(allocator, current_offset);
        try destination_offsets.append(allocator, destination);
        try parent_counts.append(allocator, @intCast(layer.size_bytes / 32));
        try retained_copy_targets.append(allocator, copy_target);
        current_offset = destination;
    }
    var has_retained_copy = false;
    for (retained_copy_targets.items) |copy_target| has_retained_copy = has_retained_copy or copy_target != null;
    if (!has_retained_copy) {
        var parent_chain = try metal.prepareMerkleParentChain(
            child_offsets.items,
            destination_offsets.items,
            parent_counts.items,
            node_seed,
            cairo_domain_prefix_bytes,
        );
        defer parent_chain.deinit();
        const elapsed_parent_gpu_ms = if (command_epoch) |*epoch| epoch_time: {
            try epoch.encodeMerkleParentChain(parent_chain);
            break :epoch_time 0;
        } else try metal.merkleParentChainPrepared(resident_arena.buffer, parent_chain);
        gpu_ms += elapsed_parent_gpu_ms;
        parent_gpu_ms += elapsed_parent_gpu_ms;
    } else {
        for (child_offsets.items, destination_offsets.items, parent_counts.items, retained_copy_targets.items) |child, destination, count, copy_target| {
            var parent_level = try metal.prepareMerkleParentChain(
                &.{child},
                &.{destination},
                &.{count},
                node_seed,
                cairo_domain_prefix_bytes,
            );
            defer parent_level.deinit();
            const elapsed_parent_gpu_ms = if (command_epoch) |*epoch| epoch_time: {
                try epoch.encodeMerkleParentChain(parent_level);
                break :epoch_time 0;
            } else try metal.merkleParentChainPrepared(resident_arena.buffer, parent_level);
            gpu_ms += elapsed_parent_gpu_ms;
            parent_gpu_ms += elapsed_parent_gpu_ms;
            if (copy_target) |target| {
                const ranges = [_]metal_runtime.ArenaCopyRange{.{
                    .source_word_offset = destination,
                    .destination_word_offset = target.offset_bytes / 4,
                    .word_count = @intCast(target.size_bytes / 4),
                }};
                var copy = try metal.prepareArenaCopies(&ranges);
                defer copy.deinit();
                const copy_gpu_ms = if (command_epoch) |*epoch| epoch_time: {
                    try epoch.encodeArenaCopy(copy);
                    break :epoch_time 0;
                } else try metal.arenaCopyPrepared(resident_arena.buffer, copy);
                gpu_ms += copy_gpu_ms;
                parent_gpu_ms += copy_gpu_ms;
            }
        }
    }
    if (command_epoch) |*epoch| {
        try epoch.submit();
        const epoch_stats = try epoch.wait();
        command_epoch_stats = epoch_stats;
        gpu_ms += epoch_stats.gpu_milliseconds;
    }
    if (std.process.hasEnvVarConstant("STWO_ZIG_SN2_LOG_STAGE_TIMINGS"))
        std.debug.print("commit_merkle tree={d} parents_done={d} gpu_ms={d:.3}\n", .{ tree_index, parent_counts.items.len, gpu_ms });
    if (std.process.hasEnvVarConstant("STWO_ZIG_SN2_LOG_COMMIT_DIGESTS")) {
        for (retained, 0..) |layer, layer_index|
            try commitment_telemetry.logBindingDigest(resident_arena, "commit_retained", layer_index, layer);
    }
    const root = retained[retained.len - 1];
    const transcript_ordinals = [_]u32{ 3, 20, 23, 24 };
    const transcript_root = try oneOrdinal(schedule, plan, "TranscriptInput", transcript_ordinals[tree_index]);
    @memcpy((try resident_arena.bytes(transcript_root))[0..32], (try resident_arena.bytes(root))[0..32]);
    return .{
        .gpu_ms = gpu_ms,
        .lde_gpu_ms = lde_gpu_ms,
        .leaf_gpu_ms = leaf_gpu_ms,
        .parent_gpu_ms = parent_gpu_ms,
        .root = root,
        .command_epoch_stats = command_epoch_stats,
    };
}
