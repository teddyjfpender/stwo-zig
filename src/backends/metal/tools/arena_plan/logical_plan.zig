const std = @import("std");
const stwo = @import("stwo");
const arena = stwo.backends.metal.arena_plan;
const arena_lifetime = stwo.frontends.cairo.arena_lifetime;
const cairo_proof_plan = stwo.frontends.cairo.proof_plan;
const staged_arena_planner = stwo.frontends.cairo.staged_arena_planner;
const schedule_addressing = @import("schedule_addressing.zig");

const aotNarrowAddressPurpose = schedule_addressing.aotNarrowAddressPurpose;
const compactComponent = schedule_addressing.compactComponent;
const epochIndex = schedule_addressing.epochIndex;
const globalTick = schedule_addressing.globalTick;
const localTick = schedule_addressing.localTick;
const stagedRole = schedule_addressing.stagedRole;
const zeroMultiplicityComponent = schedule_addressing.zeroMultiplicityComponent;

const Prepared = struct {
    ranges: [3]arena.LiveRange = undefined,
    range_count: usize = 0,
};

pub const PurposeStat = struct {
    purpose: []const u8,
    buffers: usize = 0,
    bytes: u64 = 0,
};

pub const LogicalPlan = struct {
    prepared: []Prepared,
    logical: []arena.LogicalBuffer,
    missing_components: std.StringHashMap(void),
    missing_lookup_components: std.StringHashMap(void),
    component_count: usize,
    native_destination_count: usize,
    witness_recipe_buffers: usize,
    witness_recipe_bytes: u64,
    witness_missing_buffers: usize,
    native_recipe_buffers: usize,
    native_recipe_bytes: u64,
    zero_recipe_buffers: usize,
    zero_recipe_bytes: u64,
    bound_recipe_buffers: usize,
    bound_recipe_bytes: u64,
    circle_recipe_buffers: usize,
    circle_recipe_bytes: u64,
    preprocessed_recipe_buffers: usize,
    preprocessed_recipe_bytes: u64,
    peak_tick: u16,
    diagnostic_peak_logical_bytes: u64,
    diagnostic_base_peak_bytes: u64,
    diagnostic_base_peak_tick: u16,
    diagnostic_interaction_peak_bytes: u64,
    diagnostic_interaction_peak_tick: u16,
    peak_purposes: []PurposeStat,
    base_peak_purposes: []PurposeStat,
    interaction_peak_purposes: []PurposeStat,

    pub fn deinit(self: *LogicalPlan, allocator: std.mem.Allocator) void {
        allocator.free(self.interaction_peak_purposes);
        allocator.free(self.base_peak_purposes);
        allocator.free(self.peak_purposes);
        self.missing_lookup_components.deinit();
        self.missing_components.deinit();
        allocator.free(self.logical);
        allocator.free(self.prepared);
        self.* = undefined;
    }
};

pub fn build(ctx: anytype) !LogicalPlan {
    const allocator = ctx.allocator;
    const schedule = ctx.schedule;
    const feed_bundle = ctx.feed_bundle;
    const proof_plan = ctx.proof_plan;
    const staged_planner = ctx.staged_planner;
    const relation_coverage = ctx.relation_coverage;
    const witness_bundle = ctx.witness_bundle;
    const fixed_table_destinations = ctx.fixed_table_destinations;
    const retained_sources = ctx.retained_sources;
    const preprocessed_coverage = ctx.preprocessed_coverage;
    const merkle_parent_coverage = ctx.merkle_parent_coverage;
    const merkle_commit_coverage = ctx.merkle_commit_coverage;
    const composition_coverage = ctx.composition_coverage;

    var native_destinations = std.StringHashMap(void).init(allocator);
    defer native_destinations.deinit();
    var native_producers = std.StringHashMap(void).init(allocator);
    defer native_producers.deinit();
    var missing_components = std.StringHashMap(void).init(allocator);
    errdefer missing_components.deinit();
    var missing_lookup_components = std.StringHashMap(void).init(allocator);
    errdefer missing_lookup_components.deinit();
    if (feed_bundle) |bundle| {
        for (bundle.feeds) |feed| {
            try native_producers.put(feed.producer, {});
            for (feed.destinations) |destination| try native_destinations.put(destination.name, {});
        }
    }

    const prepared = try allocator.alloc(Prepared, schedule.len);
    errdefer allocator.free(prepared);
    @memset(prepared, .{});
    const logical = try allocator.alloc(arena.LogicalBuffer, schedule.len);
    errdefer allocator.free(logical);
    var component_ids = std.StringHashMap(u16).init(allocator);
    defer component_ids.deinit();
    var native_interaction_ids = std.StringHashMap(u16).init(allocator);
    defer native_interaction_ids.deinit();
    if (proof_plan) |value| {
        var next_native = std.math.cast(u16, value.components.len) orelse return error.TooManyComponents;
        for (schedule) |entry| {
            const component_value = entry.object.get("component") orelse continue;
            if (component_value != .string or value.componentIndex(component_value.string) != null or
                std.mem.eql(u8, component_value.string, "ec_op_builtin")) continue;
            const result = try native_interaction_ids.getOrPut(component_value.string);
            if (result.found_existing) continue;
            if (next_native >= 64) return error.TooManyComponents;
            result.value_ptr.* = next_native;
            next_native += 1;
        }
    }
    var next_component: u16 = 0;
    var witness_recipe_buffers: usize = 0;
    var witness_recipe_bytes: u64 = 0;
    var witness_missing_buffers: usize = 0;
    var native_recipe_buffers: usize = 0;
    var native_recipe_bytes: u64 = 0;
    var zero_recipe_buffers: usize = 0;
    var zero_recipe_bytes: u64 = 0;
    var bound_recipe_buffers: usize = 0;
    var bound_recipe_bytes: u64 = 0;
    var circle_recipe_buffers: usize = 0;
    var circle_recipe_bytes: u64 = 0;
    var preprocessed_recipe_buffers: usize = 0;
    var preprocessed_recipe_bytes: u64 = 0;

    for (schedule, 0..) |entry, index| {
        const object = entry.object;
        const purpose = object.get("purpose").?.string;
        const first = epochIndex(object.get("first").?.string) orelse return error.InvalidEpoch;
        const last = epochIndex(object.get("last").?.string) orelse return error.InvalidEpoch;
        var component: ?u16 = null;
        if (object.get("component")) |value| switch (value) {
            .string => |name| {
                const result = try component_ids.getOrPut(name);
                if (!result.found_existing) {
                    if (next_component >= 64) return error.TooManyComponents;
                    result.value_ptr.* = next_component;
                    next_component += 1;
                }
                component = native_interaction_ids.get(name) orelse result.value_ptr.*;
            },
            else => {},
        };
        var staged = false;
        if (staged_planner) |planner| {
            if (std.mem.eql(u8, purpose, "PreprocessedEvaluations")) {
                prepared[index].ranges[0] = .{ .first = 0, .last = globalTick(4) };
                prepared[index].range_count = 1;
                staged = true;
            } else if (std.mem.eql(u8, purpose, "CompositionCoefficients")) {
                prepared[index].ranges[0] = .{ .first = globalTick(5) + 64, .last = globalTick(10) };
                prepared[index].range_count = 1;
                staged = true;
            } else if (std.mem.eql(u8, purpose, "CompositionLdeTile")) {
                prepared[index].ranges[0] = .{ .first = globalTick(5), .last = globalTick(5) + 63 };
                prepared[index].range_count = 1;
                staged = true;
            } else if (std.mem.eql(u8, purpose, "ForwardTwiddles") or
                std.mem.eql(u8, purpose, "EcOpSegmentStart") or
                std.mem.eql(u8, purpose, "WitnessFeedLut"))
            {
                var ranges: [3]arena.LiveRange = undefined;
                const derived = try planner.rangesFor(.protocol_persistent, null, &ranges);
                @memcpy(prepared[index].ranges[0..derived.len], derived);
                prepared[index].range_count = derived.len;
                staged = true;
            } else if (std.mem.eql(u8, purpose, "EcOpPartialIota")) {
                const proof_component = proof_plan.?.componentIndex("partial_ec_mul_generic") orelse
                    return error.MissingProofComponent;
                var ranges: [3]arena.LiveRange = undefined;
                const derived = try planner.rangesFor(.component_scratch, proof_component, &ranges);
                @memcpy(prepared[index].ranges[0..derived.len], derived);
                prepared[index].range_count = derived.len;
                staged = true;
            } else if (std.mem.eql(u8, purpose, "FixedTableSourcePointers") or
                std.mem.eql(u8, purpose, "ExecutionTablePointers") or
                std.mem.eql(u8, purpose, "ExecutionTableStrides") or
                std.mem.eql(u8, purpose, "ExecutionTableRawAddressToId") or
                std.mem.eql(u8, purpose, "ExecutionTableRawF252Words") or
                std.mem.eql(u8, purpose, "ExecutionTableRawSmallWords") or
                std.mem.eql(u8, purpose, "ExecutionTableBigLimb") or
                std.mem.eql(u8, purpose, "ExecutionTableSmallLimb"))
            {
                var ranges: [3]arena.LiveRange = undefined;
                const derived = try planner.rangesFor(.witness_shared, null, &ranges);
                @memcpy(prepared[index].ranges[0..derived.len], derived);
                prepared[index].range_count = derived.len;
                staged = true;
            } else if (std.mem.eql(u8, purpose, "BaseCoefficients") or
                std.mem.eql(u8, purpose, "InteractionCoefficients"))
            {
                const proof_component = if (object.get("component")) |component_value|
                    if (component_value == .string)
                        proof_plan.?.componentIndex(component_value.string) orelse
                            if (std.mem.eql(u8, component_value.string, "ec_op_builtin"))
                                proof_plan.?.componentIndex("partial_ec_mul_generic")
                            else
                                null
                    else
                        null
                else
                    null;
                const role: staged_arena_planner.BufferRole = if (std.mem.eql(u8, purpose, "BaseCoefficients"))
                    .base_coefficients
                else
                    .interaction_coefficients;
                var ranges: [3]arena.LiveRange = undefined;
                const derived = try planner.rangesFor(role, proof_component, &ranges);
                prepared[index].ranges[0] = derived[0];
                prepared[index].ranges[1] = .{ .first = globalTick(5), .last = globalTick(10) };
                prepared[index].range_count = 2;
                staged = true;
            } else if (std.mem.eql(u8, purpose, "FixedMultiplicity") or std.mem.eql(u8, purpose, "RuntimeMultiplicity")) {
                var ranges: [3]arena.LiveRange = undefined;
                const derived = try planner.rangesFor(.multiplicity, null, &ranges);
                @memcpy(prepared[index].ranges[0..derived.len], derived);
                prepared[index].range_count = derived.len;
                staged = true;
            } else if (object.get("component")) |component_value| if (component_value == .string) {
                const proof_component = proof_plan.?.componentIndex(component_value.string) orelse
                    if (std.mem.eql(u8, component_value.string, "ec_op_builtin"))
                        proof_plan.?.componentIndex("partial_ec_mul_generic")
                    else
                        null;
                const role = if (std.mem.eql(u8, purpose, "WitnessInput") and
                    std.mem.eql(u8, component_value.string, "partial_ec_mul_generic") and
                    object.get("ordinal").?.integer < 126)
                    staged_arena_planner.BufferRole.retained_witness_input
                else if (std.mem.eql(u8, purpose, "LookupInputs") and
                    cairo_proof_plan.retainsLookupInputs(component_value.string))
                    staged_arena_planner.BufferRole.retained_lookup_inputs
                else
                    stagedRole(purpose);
                if (proof_component) |component_index| if (role) |staged_role| {
                    var ranges: [3]arena.LiveRange = undefined;
                    const derived = try planner.rangesFor(staged_role, component_index, &ranges);
                    @memcpy(prepared[index].ranges[0..derived.len], derived);
                    prepared[index].range_count = derived.len;
                    staged = true;
                };
            };
        }
        if (!staged) {
            const phases = arena_lifetime.inferredUsePhases(purpose, first, last);
            for (phases.slice()) |phase| {
                const range: arena.LiveRange = if (component) |id|
                    .{ .first = localTick(phase, id), .last = localTick(phase, id) }
                else
                    .{ .first = globalTick(phase), .last = globalTick(phase) + 64 };
                prepared[index].ranges[prepared[index].range_count] = range;
                prepared[index].range_count += 1;
            }
        }
        const words: u64 = @intCast(object.get("len_words").?.integer);
        const bytes = std.math.mul(u64, words, 4) catch return error.SizeOverflow;
        // The fused relation recipe consumes schedule metadata directly and
        // uses RelationScanEvalScratch for its block scan. These captured CUDA
        // workspaces are retained as virtual bindings for schedule validation,
        // but do not need resident Metal storage.
        const planned_bytes: u64 = if (std.mem.eql(u8, purpose, "RelationScanEvalScratch"))
            if (relation_coverage) |coverage| coverage.scan_scratch_bytes else bytes
        else if (std.mem.eql(u8, purpose, "RelationSourcePointers") or
            std.mem.eql(u8, purpose, "RelationOutputPointers") or
            std.mem.eql(u8, purpose, "RelationDenominators"))
            16
        else
            bytes;
        var has_recompute_recipe = false;
        if ((std.mem.eql(u8, purpose, "BaseTrace") or
            std.mem.eql(u8, purpose, "LookupInputs") or
            std.mem.eql(u8, purpose, "SubcomponentInputs")) and witness_bundle != null)
        {
            const component_name = object.get("component").?.string;
            const ordinal: u32 = @intCast(object.get("ordinal").?.integer);
            if (witness_bundle.?.find(component_name)) |program_entry| {
                if ((std.mem.eql(u8, purpose, "BaseTrace") and ordinal >= program_entry.program.n_cols) or
                    (std.mem.eql(u8, purpose, "LookupInputs") and program_entry.program.n_lookup_words == 0) or
                    (std.mem.eql(u8, purpose, "SubcomponentInputs") and program_entry.program.n_sub_words == 0))
                    return error.WitnessShapeMismatch;
                witness_recipe_buffers += 1;
                witness_recipe_bytes += bytes;
                has_recompute_recipe = true;
            } else if (std.mem.eql(u8, purpose, "BaseTrace")) {
                if (std.mem.eql(u8, component_name, "ec_op_builtin")) {
                    native_recipe_buffers += 1;
                    native_recipe_bytes += bytes;
                    has_recompute_recipe = true;
                } else if (native_destinations.contains(component_name)) {
                    native_recipe_buffers += 1;
                    native_recipe_bytes += bytes;
                    has_recompute_recipe = true;
                } else if (zeroMultiplicityComponent(component_name)) {
                    zero_recipe_buffers += 1;
                    zero_recipe_bytes += bytes;
                    has_recompute_recipe = true;
                } else {
                    witness_missing_buffers += 1;
                    try missing_components.put(component_name, {});
                }
            } else if (std.mem.eql(u8, purpose, "LookupInputs")) {
                if (std.mem.eql(u8, component_name, "ec_op_builtin")) {
                    native_recipe_buffers += 1;
                    native_recipe_bytes += bytes;
                    has_recompute_recipe = true;
                } else if (fixed_table_destinations.contains(component_name)) {
                    native_recipe_buffers += 1;
                    native_recipe_bytes += bytes;
                    has_recompute_recipe = true;
                } else {
                    try missing_lookup_components.put(component_name, {});
                }
            }
        }
        if (std.mem.eql(u8, purpose, "WitnessInput") and object.get("component") != null and
            object.get("component").? == .string)
        {
            const component_name = object.get("component").?.string;
            const ec_partial = std.mem.eql(u8, component_name, "partial_ec_mul_generic") and
                object.get("ordinal").?.integer < 126;
            if (ec_partial or compactComponent(component_name)) {
                native_recipe_buffers += 1;
                native_recipe_bytes += bytes;
                has_recompute_recipe = true;
            }
        }
        if (std.mem.eql(u8, purpose, "BaseCoefficients") and witness_bundle != null) {
            const component_name = object.get("component").?.string;
            const ordinal: u32 = @intCast(object.get("ordinal").?.integer);
            if (witness_bundle.?.find(component_name)) |program_entry| {
                if (ordinal >= program_entry.program.n_cols) return error.WitnessShapeMismatch;
            }
            circle_recipe_buffers += 1;
            circle_recipe_bytes += bytes;
            has_recompute_recipe = true;
        } else if (std.mem.eql(u8, purpose, "InteractionCoefficients")) {
            circle_recipe_buffers += 1;
            circle_recipe_bytes += bytes;
            has_recompute_recipe = true;
        } else if (std.mem.eql(u8, purpose, "CommitRetainedEvaluation")) {
            if (retained_sources[index] == null) return error.MissingRetainedSource;
            has_recompute_recipe = true;
        } else if (std.mem.eql(u8, purpose, "PreprocessedCoefficients") and preprocessed_coverage.sources[index] != null) {
            preprocessed_recipe_buffers += 1;
            preprocessed_recipe_bytes += bytes;
            has_recompute_recipe = true;
        } else if ((std.mem.eql(u8, purpose, "RetainedMerkleLayers") or std.mem.eql(u8, purpose, "FriMerkleLayer")) and
            (merkle_parent_coverage.sources[index] != null or merkle_commit_coverage.bottoms[index]))
        {
            has_recompute_recipe = true;
        } else if ((std.mem.eql(u8, purpose, "InteractionTrace") or std.mem.eql(u8, purpose, "RelationClaimedSum")) and relation_coverage != null) {
            has_recompute_recipe = true;
        } else if (std.mem.eql(u8, purpose, "CompositionCoefficients") and composition_coverage != null) {
            has_recompute_recipe = true;
        }
        const recoverable = prepared[index].range_count > 1;
        // These values cross protocol gaps, but the resident prover does not
        // yet execute the planner's spill/recompute actions at their final
        // consumption boundaries. Keep them resident until recovery actions
        // are wired into execution.
        const recovery_executed = !std.mem.eql(u8, purpose, "BaseCoefficients") and
            !std.mem.eql(u8, purpose, "InteractionCoefficients") and
            !std.mem.eql(u8, purpose, "PreprocessedCoefficients") and
            !std.mem.eql(u8, purpose, "RetainedMerkleLayers") and
            !std.mem.eql(u8, purpose, "FriMerkleLayer");
        const can_spill = recoverable and recovery_executed;
        const can_recompute = can_spill and has_recompute_recipe and
            !std.mem.eql(u8, purpose, "BaseCoefficients") and
            !std.mem.eql(u8, purpose, "InteractionCoefficients");
        if (can_recompute) {
            bound_recipe_buffers += 1;
            bound_recipe_bytes += bytes;
        }
        logical[index] = .{
            .id = @intCast(object.get("id").?.integer),
            .size_bytes = planned_bytes,
            // AOT witness kernels use u32 word offsets, including the bindings
            // reached through their arena-resident pointer tables.
            .placement_priority = if (std.mem.eql(u8, purpose, "CompositionLdeTile") or
                std.mem.eql(u8, purpose, "TranscriptState") or
                std.mem.eql(u8, purpose, "TranscriptInput") or
                std.mem.eql(u8, purpose, "TranscriptOutput")) 4 else if (aotNarrowAddressPurpose(purpose)) 3 else if (std.mem.eql(u8, purpose, "ForwardTwiddles") or
                std.mem.eql(u8, purpose, "QuotientInverseTwiddles") or
                std.mem.eql(u8, purpose, "QuotientTile") or
                std.mem.eql(u8, purpose, "InverseTwiddles") or
                std.mem.eql(u8, purpose, "FriRetainedEvaluation") or
                std.mem.eql(u8, purpose, "FriFoldingChallenge") or
                std.mem.eql(u8, purpose, "FriMerkleLayer") or
                std.mem.eql(u8, purpose, "FriPing") or
                std.mem.eql(u8, purpose, "FriPong") or
                std.mem.eql(u8, purpose, "FriFinalCoefficients") or
                std.mem.eql(u8, purpose, "FriFinalDegreeError") or
                std.mem.eql(u8, purpose, "PreprocessedEvaluations")) 2 else if (std.mem.eql(u8, purpose, "InteractionTrace") or
                std.mem.eql(u8, purpose, "RelationClaimedSum") or
                std.mem.eql(u8, purpose, "RelationAlphaPowers") or
                std.mem.eql(u8, purpose, "RelationZ") or
                std.mem.eql(u8, purpose, "RelationScanEvalScratch") or
                std.mem.eql(u8, purpose, "CompositionAccumulators") or
                std.mem.eql(u8, purpose, "CompositionCoefficients") or
                std.mem.eql(u8, purpose, "CompositionExtParams") or
                std.mem.eql(u8, purpose, "CompositionRandomCoefficientPowers") or
                std.mem.eql(u8, purpose, "CompositionDescriptors") or
                std.mem.eql(u8, purpose, "DecommitTraceLdeTile") or
                object.get("component") != null and object.get("component").? == .string and
                    ((std.mem.eql(u8, purpose, "LookupInputs") and
                        (fixed_table_destinations.contains(object.get("component").?.string) or
                            cairo_proof_plan.retainsLookupInputs(object.get("component").?.string))) or
                        (std.mem.eql(u8, purpose, "SubcomponentInputs") and
                            native_producers.contains(object.get("component").?.string)))) 1 else 0,
            .live_ranges = prepared[index].ranges[0..prepared[index].range_count],
            .spill_cost_ns = if (can_spill) @max(1, planned_bytes / 20) else null,
            .recompute_cost_ns = if (can_recompute) @max(1, planned_bytes / 100) else null,
        };
    }

    var peak_tick: u16 = 0;
    var diagnostic_peak_logical_bytes: u64 = 0;
    var diagnostic_base_peak_bytes: u64 = 0;
    var diagnostic_base_peak_tick: u16 = 0;
    var diagnostic_interaction_peak_bytes: u64 = 0;
    var diagnostic_interaction_peak_tick: u16 = 3 * 65;
    for (0..arena.max_ticks) |tick_usize| {
        const tick: u16 = @intCast(tick_usize);
        var live_bytes: u64 = 0;
        for (logical) |buffer| {
            var live = false;
            for (buffer.live_ranges) |range| live = live or (range.first <= tick and tick <= range.last);
            if (live) live_bytes = std.math.add(u64, live_bytes, buffer.size_bytes) catch return error.SizeOverflow;
        }
        if (live_bytes > diagnostic_peak_logical_bytes) {
            diagnostic_peak_logical_bytes = live_bytes;
            peak_tick = tick;
        }
        if (tick <= 2 * 65 and live_bytes > diagnostic_base_peak_bytes) {
            diagnostic_base_peak_bytes = live_bytes;
            diagnostic_base_peak_tick = tick;
        }
        if (tick >= 3 * 65 and tick <= 4 * 65 and live_bytes > diagnostic_interaction_peak_bytes) {
            diagnostic_interaction_peak_bytes = live_bytes;
            diagnostic_interaction_peak_tick = tick;
        }
    }
    var peak_purpose_map = std.StringHashMap(PurposeStat).init(allocator);
    defer peak_purpose_map.deinit();
    for (schedule, logical) |entry, buffer| {
        var live = false;
        for (buffer.live_ranges) |range| live = live or (range.first <= peak_tick and peak_tick <= range.last);
        if (!live) continue;
        const purpose = entry.object.get("purpose").?.string;
        const result = try peak_purpose_map.getOrPut(purpose);
        if (!result.found_existing) result.value_ptr.* = .{ .purpose = purpose };
        result.value_ptr.buffers += 1;
        result.value_ptr.bytes = std.math.add(u64, result.value_ptr.bytes, buffer.size_bytes) catch return error.SizeOverflow;
    }
    const peak_purposes = try allocator.alloc(PurposeStat, peak_purpose_map.count());
    errdefer allocator.free(peak_purposes);
    var peak_purpose_iterator = peak_purpose_map.valueIterator();
    var peak_purpose_index: usize = 0;
    while (peak_purpose_iterator.next()) |stat| : (peak_purpose_index += 1) peak_purposes[peak_purpose_index] = stat.*;
    std.mem.sortUnstable(PurposeStat, peak_purposes, {}, struct {
        fn lessThan(_: void, lhs: PurposeStat, rhs: PurposeStat) bool {
            if (lhs.bytes != rhs.bytes) return lhs.bytes > rhs.bytes;
            return std.mem.lessThan(u8, lhs.purpose, rhs.purpose);
        }
    }.lessThan);
    var base_peak_purpose_map = std.StringHashMap(PurposeStat).init(allocator);
    defer base_peak_purpose_map.deinit();
    for (schedule, logical) |entry, buffer| {
        var live = false;
        for (buffer.live_ranges) |range| live = live or (range.first <= diagnostic_base_peak_tick and diagnostic_base_peak_tick <= range.last);
        if (!live) continue;
        const purpose = entry.object.get("purpose").?.string;
        const result = try base_peak_purpose_map.getOrPut(purpose);
        if (!result.found_existing) result.value_ptr.* = .{ .purpose = purpose };
        result.value_ptr.buffers += 1;
        result.value_ptr.bytes = std.math.add(u64, result.value_ptr.bytes, buffer.size_bytes) catch return error.SizeOverflow;
    }
    const base_peak_purposes = try allocator.alloc(PurposeStat, base_peak_purpose_map.count());
    errdefer allocator.free(base_peak_purposes);
    var base_peak_iterator = base_peak_purpose_map.valueIterator();
    var base_peak_index: usize = 0;
    while (base_peak_iterator.next()) |stat| : (base_peak_index += 1) base_peak_purposes[base_peak_index] = stat.*;
    std.mem.sortUnstable(PurposeStat, base_peak_purposes, {}, struct {
        fn lessThan(_: void, lhs: PurposeStat, rhs: PurposeStat) bool {
            if (lhs.bytes != rhs.bytes) return lhs.bytes > rhs.bytes;
            return std.mem.lessThan(u8, lhs.purpose, rhs.purpose);
        }
    }.lessThan);
    var interaction_peak_purpose_map = std.StringHashMap(PurposeStat).init(allocator);
    defer interaction_peak_purpose_map.deinit();
    for (schedule, logical) |entry, buffer| {
        var live = false;
        for (buffer.live_ranges) |range| live = live or
            (range.first <= diagnostic_interaction_peak_tick and diagnostic_interaction_peak_tick <= range.last);
        if (!live) continue;
        const purpose = entry.object.get("purpose").?.string;
        const result = try interaction_peak_purpose_map.getOrPut(purpose);
        if (!result.found_existing) result.value_ptr.* = .{ .purpose = purpose };
        result.value_ptr.buffers += 1;
        result.value_ptr.bytes = std.math.add(u64, result.value_ptr.bytes, buffer.size_bytes) catch return error.SizeOverflow;
    }
    const interaction_peak_purposes = try allocator.alloc(PurposeStat, interaction_peak_purpose_map.count());
    errdefer allocator.free(interaction_peak_purposes);
    var interaction_peak_iterator = interaction_peak_purpose_map.valueIterator();
    var interaction_peak_index: usize = 0;
    while (interaction_peak_iterator.next()) |stat| : (interaction_peak_index += 1)
        interaction_peak_purposes[interaction_peak_index] = stat.*;
    std.mem.sortUnstable(PurposeStat, interaction_peak_purposes, {}, struct {
        fn lessThan(_: void, lhs: PurposeStat, rhs: PurposeStat) bool {
            if (lhs.bytes != rhs.bytes) return lhs.bytes > rhs.bytes;
            return std.mem.lessThan(u8, lhs.purpose, rhs.purpose);
        }
    }.lessThan);

    return .{
        .prepared = prepared,
        .logical = logical,
        .missing_components = missing_components,
        .missing_lookup_components = missing_lookup_components,
        .component_count = component_ids.count(),
        .native_destination_count = native_destinations.count(),
        .witness_recipe_buffers = witness_recipe_buffers,
        .witness_recipe_bytes = witness_recipe_bytes,
        .witness_missing_buffers = witness_missing_buffers,
        .native_recipe_buffers = native_recipe_buffers,
        .native_recipe_bytes = native_recipe_bytes,
        .zero_recipe_buffers = zero_recipe_buffers,
        .zero_recipe_bytes = zero_recipe_bytes,
        .bound_recipe_buffers = bound_recipe_buffers,
        .bound_recipe_bytes = bound_recipe_bytes,
        .circle_recipe_buffers = circle_recipe_buffers,
        .circle_recipe_bytes = circle_recipe_bytes,
        .preprocessed_recipe_buffers = preprocessed_recipe_buffers,
        .preprocessed_recipe_bytes = preprocessed_recipe_bytes,
        .peak_tick = peak_tick,
        .diagnostic_peak_logical_bytes = diagnostic_peak_logical_bytes,
        .diagnostic_base_peak_bytes = diagnostic_base_peak_bytes,
        .diagnostic_base_peak_tick = diagnostic_base_peak_tick,
        .diagnostic_interaction_peak_bytes = diagnostic_interaction_peak_bytes,
        .diagnostic_interaction_peak_tick = diagnostic_interaction_peak_tick,
        .peak_purposes = peak_purposes,
        .base_peak_purposes = base_peak_purposes,
        .interaction_peak_purposes = interaction_peak_purposes,
    };
}
