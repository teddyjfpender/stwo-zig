const std = @import("std");
const arena_plan = @import("stwo_metal_backend").arena_plan;
const metal_runtime = @import("stwo_metal_backend").runtime;
const protocol_recipes = @import("stwo_metal_backend").protocol_recipes;
const composition_bundle_mod = @import("stwo_cairo_frontend").witness.composition_bundle;
const schedule_bindings = @import("../schedule_bindings.zig");
const commitment_ordering = @import("../resident/commitment/ordering.zig");
const eval_codegen = @import("../eval_codegen.zig");
const composition_config = @import("../resident/composition/config.zig");
const resident_binding = @import("../resident/binding.zig");
const resident_twiddles = @import("../resident/twiddles.zig");
const Error = @import("../resident/errors.zig").Error;
const M31 = @import("stwo_core").fields.m31.M31;
const OrdinalBinding = schedule_bindings.OrdinalBinding;
const canonicalTraceTree = commitment_ordering.canonicalTraceTree;
const twiddleOffsetForLog = resident_twiddles.twiddleOffsetForLog;

pub fn prepare(
    bindings: anytype,
    allocator: std.mem.Allocator,
    metal: *metal_runtime.Runtime,
    resident_arena: *arena_plan.ResidentArena,
    bundle: composition_bundle_mod.Bundle,
    metallib_path: []const u8,
) !protocol_recipes.CompositionRecipe {
    if (std.process.hasEnvVarConstant("STWO_ZIG_SN2_LOG_STAGE_TIMINGS")) std.debug.print(
        "composition_bindings lde_tile_offset={d} lde_tile_size={d} accumulators_offset={d} accumulators_size={d} random_powers_offset={d} random_powers_size={d} descriptors_offset={d} descriptors_size={d} coefficients_first_offset={d} coefficients_count={d}\n",
        .{
            bindings.composition_lde_tile.offset_bytes,
            bindings.composition_lde_tile.size_bytes,
            bindings.composition_accumulators.offset_bytes,
            bindings.composition_accumulators.size_bytes,
            bindings.composition_random_powers.offset_bytes,
            bindings.composition_random_powers.size_bytes,
            bindings.composition_descriptors.offset_bytes,
            bindings.composition_descriptors.size_bytes,
            bindings.composition_coefficients[0].offset_bytes,
            bindings.composition_coefficients.len,
        },
    );
    if (bundle.components.len != bindings.composition_ext_params.len or
        bundle.components.len != bindings.canonical_claimed_sums.len or bundle.total_constraints * 4 != bindings.composition_random_powers.size_bytes / 4)
        return Error.InvalidCardinality;
    const asOffset = struct {
        fn get(binding: arena_plan.Binding) !u32 {
            if (binding.offset_bytes % 4 != 0) return Error.InvalidBindingSize;
            return std.math.cast(u32, binding.offset_bytes / 4) orelse Error.InvalidBindingSize;
        }
    }.get;
    const asWideOffset = struct {
        fn get(binding: arena_plan.Binding) !u64 {
            if (binding.offset_bytes % 4 != 0) return Error.InvalidBindingSize;
            return binding.offset_bytes / 4;
        }
    }.get;
    const bindingLog = struct {
        fn get(binding: arena_plan.Binding) !u32 {
            if (binding.size_bytes < 4 or binding.size_bytes % 4 != 0 or !std.math.isPowerOfTwo(binding.size_bytes / 4))
                return Error.InvalidBindingSize;
            return std.math.log2_int(u64, binding.size_bytes / 4);
        }
    }.get;
    const transcriptOutput = struct {
        fn get(items: []const OrdinalBinding, wanted: u32) !arena_plan.Binding {
            for (items) |item| if (item.ordinal == wanted) return item.binding;
            return Error.MissingBinding;
        }
    }.get;

    var library_config = try composition_config.LibraryConfig.fromProcess(allocator);
    var library_config_live = true;
    defer if (library_config_live) library_config.deinit(allocator);
    const fusion_requested = library_config.fusion_requested;
    const fusion_instruction_cap = library_config.fusion_instruction_cap;
    const fusion_mode = library_config.fusion_mode;
    var library = switch (library_config.library) {
        .source => |source_path| source: {
            const source_bytes = try std.fs.cwd().readFileAlloc(allocator, source_path, 64 * 1024 * 1024);
            defer allocator.free(source_bytes);
            break :source try metal.compileEvalLibrary(source_bytes);
        },
        .metallib => try metal.loadEvalLibrary(metallib_path),
    };
    library_config.deinit(allocator);
    library_config_live = false;
    defer library.deinit();
    const execution_config = try composition_config.ExecutionConfig.fromProcess(
        allocator,
        bundle.components.len,
        fusion_requested,
    );
    const component_limit = execution_config.component_limit;
    const diagnostic_component = execution_config.diagnostic_component;
    const fusion_enabled = execution_config.fusion_enabled;
    const descriptor_bytes = try resident_arena.bytes(bindings.composition_descriptors);
    const descriptor_aligned: []align(4) u8 = @alignCast(descriptor_bytes);
    const descriptor_words = std.mem.bytesAsSlice(u32, descriptor_aligned);
    @memset(descriptor_words, 0);
    var descriptor_cursor: usize = 0;

    var log_present = [_]bool{false} ** 31;
    for (bundle.components) |component| log_present[component.evaluation_log_size] = true;
    var accumulator_logs = std.ArrayList(u32).empty;
    defer accumulator_logs.deinit(allocator);
    var accumulator_offsets = std.ArrayList(u32).empty;
    defer accumulator_offsets.deinit(allocator);
    var accumulator_relative = [_]?u32{null} ** 31;
    var accumulator_words: u64 = 0;
    for (log_present, 0..) |present, log_size| {
        if (!present) continue;
        accumulator_relative[log_size] = @intCast(accumulator_words);
        try accumulator_logs.append(allocator, @intCast(log_size));
        try accumulator_offsets.append(
            allocator,
            std.math.add(u32, try asOffset(bindings.composition_accumulators), @intCast(accumulator_words)) catch return Error.InvalidBindingSize,
        );
        accumulator_words += @as(u64, 4) << @intCast(log_size);
    }
    if (accumulator_words * 4 != bindings.composition_accumulators.size_bytes) return Error.InvalidBindingSize;

    const lde_plans = try allocator.alloc(metal_runtime.CompositionLdePlan, component_limit);
    defer allocator.free(lde_plans);
    var initialized_ldes: usize = 0;
    defer for (lde_plans[0..initialized_ldes]) |*plan| plan.deinit();
    const eval_batches = try allocator.alloc(metal_runtime.EvalBatchPlan, component_limit);
    defer allocator.free(eval_batches);
    var initialized_batches: usize = 0;
    defer for (eval_batches[0..initialized_batches]) |*plan| plan.deinit();
    var ext_descriptors = std.ArrayList(metal_runtime.CompositionExtParamDescriptor).empty;
    defer ext_descriptors.deinit(allocator);

    const canonical_base = try canonicalTraceTree(allocator, bundle, bindings.named_base_coefficients, 1);
    defer allocator.free(canonical_base);
    const canonical_interaction = try canonicalTraceTree(allocator, bundle, bindings.named_interaction_coefficients, 2);
    defer allocator.free(canonical_interaction);
    const trees = [_][]const arena_plan.Binding{
        bindings.preprocessed_coefficients,
        canonical_base,
        canonical_interaction,
    };
    const tile_base = try asOffset(bindings.composition_lde_tile);
    const accumulator_base = try asOffset(bindings.composition_accumulators);
    const random_powers = try asOffset(bindings.composition_random_powers);
    const relation_z = try asOffset(bindings.relation_z);
    const relation_alpha = try asOffset(bindings.relation_alpha_powers);

    var composition_original_parts: usize = 0;
    var composition_dispatch_slices: usize = 0;
    for (bundle.components[0..component_limit], 0..) |component, component_index| {
        if (std.process.hasEnvVarConstant("STWO_ZIG_SN2_LOG_STAGE_TIMINGS"))
            std.debug.print("composition_prepare component={s} instance={d} index={d} eval_log={d}\n", .{
                component.label, component.instance, component_index, component.evaluation_log_size,
            });
        var sources = std.ArrayList(arena_plan.Binding).empty;
        defer sources.deinit(allocator);
        for (component.preprocessed_indices) |column| {
            if (column >= trees[0].len) return Error.InvalidBindingSize;
            try sources.append(allocator, trees[0][column]);
        }
        for ([_]u32{ 1, 2 }) |tree| {
            var found = false;
            for (component.trace_spans) |span| {
                if (span.tree != tree) continue;
                if (found or span.start > span.end or span.end > trees[tree].len) return Error.InvalidBindingSize;
                found = true;
                try sources.appendSlice(allocator, trees[tree][span.start..span.end]);
            }
            if (!found) return Error.InvalidBindingSize;
        }
        const row_count = @as(u32, 1) << @intCast(component.evaluation_log_size);
        const source_offsets = try allocator.alloc(u64, sources.items.len);
        defer allocator.free(source_offsets);
        const source_logs = try allocator.alloc(u32, sources.items.len);
        defer allocator.free(source_logs);
        const destination_offsets = try allocator.alloc(u32, sources.items.len);
        defer allocator.free(destination_offsets);
        for (sources.items, source_offsets, source_logs, destination_offsets, 0..) |source, *source_offset, *source_log, *destination, index| {
            source_offset.* = try asWideOffset(source);
            source_log.* = try bindingLog(source);
            if (source_log.* > component.evaluation_log_size) {
                std.debug.print(
                    "composition source exceeds domain: {s}[{}] local={} source={} log={} evaluation_log={} spans={any}\n",
                    .{ component.label, component.instance, index, source.logical_id, source_log.*, component.evaluation_log_size, component.trace_spans },
                );
                return Error.InvalidBindingSize;
            }
            destination.* = std.math.add(u32, tile_base, @intCast(index * @as(usize, row_count))) catch return Error.InvalidBindingSize;
            if (diagnostic_component == component_index) std.debug.print(
                "composition_source_binding component_index={} local_index={} logical_id={} source_offset={} source_log={} destination_offset={} evaluation_log={}\n",
                .{ component_index, index, source.logical_id, source_offset.*, source_log.*, destination.*, component.evaluation_log_size },
            );
        }
        if (@as(u64, sources.items.len) * row_count * 4 > bindings.composition_lde_tile.size_bytes)
            return Error.InvalidBindingSize;
        lde_plans[component_index] = try metal.prepareCompositionLde(
            source_offsets,
            source_logs,
            destination_offsets,
            component.evaluation_log_size,
            try twiddleOffsetForLog(bindings.forward_twiddles, component.evaluation_log_size),
        );
        initialized_ldes += 1;

        const trace_offsets_at = descriptor_cursor;
        descriptor_cursor += sources.items.len;
        const interaction_offsets_at = descriptor_cursor;
        descriptor_cursor += 3;
        const denominators_at = descriptor_cursor;
        descriptor_cursor += component.denominator_inverses.len;
        if (descriptor_cursor > descriptor_words.len) return Error.InvalidBindingSize;
        @memcpy(descriptor_words[trace_offsets_at .. trace_offsets_at + sources.items.len], destination_offsets);
        const preprocessed_count = component.preprocessed_indices.len;
        var base_count: usize = 0;
        for (component.trace_spans) |span| {
            if (span.tree == 1) base_count = @intCast(span.end - span.start);
        }
        descriptor_words[interaction_offsets_at] = 0;
        descriptor_words[interaction_offsets_at + 1] = @intCast(preprocessed_count);
        descriptor_words[interaction_offsets_at + 2] = @intCast(preprocessed_count + base_count);
        @memcpy(descriptor_words[denominators_at .. denominators_at + component.denominator_inverses.len], component.denominator_inverses);

        const ext_binding = bindings.composition_ext_params[component_index];
        if (ext_binding.size_bytes < @as(u64, component.ext_sources.len) * 16) return Error.InvalidBindingSize;
        for (component.ext_sources, 0..) |source, slot| {
            const destination = std.math.add(u32, try asOffset(ext_binding), @intCast(slot * 4)) catch return Error.InvalidBindingSize;
            const descriptor: metal_runtime.CompositionExtParamDescriptor = switch (source) {
                .constant => |value| .{ .destination = destination, .kind = 0, .source = 0, .scale = 1, .constant = value },
                .lookup_z => .{ .destination = destination, .kind = 1, .source = relation_z, .scale = 1, .constant = .{ 0, 0, 0, 0 } },
                .lookup_alpha_power => |power| .{ .destination = destination, .kind = 1, .source = relation_alpha + power * 4, .scale = 1, .constant = .{ 0, 0, 0, 0 } },
                .lookup_alpha_power_scaled => |scaled| .{ .destination = destination, .kind = 1, .source = relation_alpha + scaled.power * 4, .scale = scaled.scale, .constant = .{ 0, 0, 0, 0 } },
                .claimed_sum_scaled => blk: {
                    const scale = M31.fromCanonical(@as(u32, 1) << @intCast(component.trace_log_size)).inv() catch return Error.InvalidBindingSize;
                    break :blk .{ .destination = destination, .kind = 1, .source = try asOffset(bindings.canonical_claimed_sums[component_index]), .scale = scale.v, .constant = .{ 0, 0, 0, 0 } };
                },
            };
            try ext_descriptors.append(allocator, descriptor);
        }

        composition_original_parts += component.parts.len;
        const plans = try allocator.alloc(metal_runtime.EvalPlan, component.parts.len);
        defer allocator.free(plans);
        var plans_initialized: usize = 0;
        defer for (plans[0..plans_initialized]) |*plan| plan.deinit();
        const accumulator_relative_offset = accumulator_relative[component.evaluation_log_size] orelse return Error.InvalidBindingSize;
        const fused_parts = try allocator.alloc(eval_codegen.FusedPart, component.parts.len);
        defer allocator.free(fused_parts);
        for (component.parts, fused_parts) |part, *fused| fused.* = .{
            .program = part.program,
            .rc_base = part.rc_base,
        };
        var hybrid_partition: ?eval_codegen.FusionPartition = null;
        defer if (hybrid_partition) |*partition| partition.deinit();
        if (fusion_enabled and fusion_mode == .experimental_hybrid_source_diagnostic)
            hybrid_partition = try eval_codegen.hybridFusionPartition(
                allocator,
                fused_parts,
                .{},
            );
        var part_start: usize = 0;
        var hybrid_slice_index: usize = 0;
        while (part_start < component.parts.len) {
            const part_end = if (!fusion_enabled)
                part_start + 1
            else switch (fusion_mode) {
                .capped => try eval_codegen.fusionGroupEnd(
                    fused_parts,
                    part_start,
                    fusion_instruction_cap,
                ),
                .experimental_hybrid_source_diagnostic => end: {
                    const slice = hybrid_partition.?.slices[hybrid_slice_index];
                    if (slice.start != part_start) return Error.InvalidCardinality;
                    hybrid_slice_index += 1;
                    break :end slice.end;
                },
            };
            const part = component.parts[part_start];
            const name = try eval_codegen.fusionSliceKernelName(
                allocator,
                fused_parts,
                .{
                    .start = part_start,
                    .end = part_end,
                    .operations = 0,
                    .source_bytes = 0,
                },
            );
            defer allocator.free(name);
            var slice_operations: usize = 0;
            for (fused_parts[part_start..part_end]) |fused|
                slice_operations += eval_codegen.fusionOperationCount(fused.program);
            var pipeline_timer = try std.time.Timer.start();
            if (std.process.hasEnvVarConstant("STWO_ZIG_SN2_LOG_STAGE_TIMINGS")) std.debug.print(
                "composition_prepare_slice component_index={} slice_index={} first_part={} part_count={} operations={} kernel={s} begin\n",
                .{
                    component_index,
                    plans_initialized,
                    part_start,
                    part_end - part_start,
                    slice_operations,
                    name,
                },
            );
            plans[plans_initialized] = try metal.prepareEvalFromLibrary(library, name, .{
                .trace_offsets = try descriptorWordOffset(bindings.composition_descriptors, trace_offsets_at),
                .interaction_offsets = try descriptorWordOffset(bindings.composition_descriptors, interaction_offsets_at),
                .base_params = 0,
                .ext_params = try asOffset(ext_binding),
                .random_coeffs = random_powers,
                .denom_inv = try descriptorWordOffset(bindings.composition_descriptors, denominators_at),
                .coordinates = .{
                    accumulator_base + accumulator_relative_offset,
                    accumulator_base + accumulator_relative_offset + row_count,
                    accumulator_base + accumulator_relative_offset + row_count * 2,
                    accumulator_base + accumulator_relative_offset + row_count * 3,
                },
                .row_count = row_count,
                .trace_log_size = component.trace_log_size,
                .domain_log_size = component.trace_log_size,
                .rc_base = try randomCoefficientBase(
                    component.random_coefficient_offset,
                    part.rc_base,
                ),
            });
            if (std.process.hasEnvVarConstant("STWO_ZIG_SN2_LOG_STAGE_TIMINGS")) std.debug.print(
                "composition_prepare_slice component_index={} slice_index={} wall_ms={d:.3} done\n",
                .{
                    component_index,
                    plans_initialized,
                    @as(f64, @floatFromInt(pipeline_timer.read())) / std.time.ns_per_ms,
                },
            );
            plans_initialized += 1;
            part_start = part_end;
        }
        if (hybrid_partition) |partition|
            if (hybrid_slice_index != partition.slices.len)
                return Error.InvalidCardinality;
        composition_dispatch_slices += plans_initialized;
        eval_batches[component_index] = try metal.prepareEvalBatch(plans[0..plans_initialized]);
        initialized_batches += 1;
    }

    if (std.process.hasEnvVarConstant("STWO_ZIG_SN2_LOG_STAGE_TIMINGS")) std.debug.print(
        "composition_fusion enabled={} mode={s} instruction_cap={} original_parts={} dispatch_slices={}\n",
        .{
            fusion_enabled,
            @tagName(fusion_mode),
            if (fusion_enabled) fusion_instruction_cap else @as(usize, 0),
            composition_original_parts,
            composition_dispatch_slices,
        },
    );

    // Persist the pipeline states added while resolving either an AOT metallib
    // or a source-compiled library. Without this, every prover process rebuilds
    // every AIR pipeline before composition.
    try library.serialize();

    var inputs = try metal.prepareCompositionInputs(
        ext_descriptors.items,
        try asOffset(try transcriptOutput(bindings.transcript_outputs, 2)),
        random_powers,
        @intCast(bundle.total_constraints),
    );
    defer inputs.deinit();
    var front = try metal.prepareCompositionFront(
        inputs,
        lde_plans,
        eval_batches,
        accumulator_base,
        @intCast(accumulator_words),
    );
    errdefer front.deinit();
    var output_offsets: [8]u32 = undefined;
    var output_bindings: [8]arena_plan.Binding = undefined;
    for (bindings.composition_coefficients, &output_offsets, &output_bindings) |binding, *offset, *output_binding| {
        offset.* = try asOffset(binding);
        output_binding.* = binding;
    }
    const max_rows = @as(u32, 1) << @intCast(bundle.max_evaluation_log_size);
    const scale = M31.fromCanonical(max_rows).inv() catch return Error.InvalidBindingSize;
    var finalize = try metal.prepareCompositionFinalize(
        accumulator_offsets.items,
        accumulator_logs.items,
        try asOffset(bindings.inverse_twiddles),
        output_offsets,
        scale.v,
    );
    errdefer finalize.deinit();
    return protocol_recipes.CompositionRecipe.init(
        allocator,
        metal,
        resident_arena,
        front,
        finalize,
        output_bindings,
        component_limit == bundle.components.len,
    );
}

fn descriptorWordOffset(binding: arena_plan.Binding, relative: usize) !u32 {
    if (binding.offset_bytes % 4 != 0) return Error.InvalidBindingSize;
    return std.math.add(u32, std.math.cast(u32, binding.offset_bytes / 4) orelse return Error.InvalidBindingSize, @intCast(relative)) catch Error.InvalidBindingSize;
}

pub fn randomCoefficientBase(component_offset: u32, part_offset: u32) !u32 {
    return std.math.add(u32, component_offset, part_offset) catch Error.InvalidBindingSize;
}

const wordOffset = resident_binding.wordOffset;
