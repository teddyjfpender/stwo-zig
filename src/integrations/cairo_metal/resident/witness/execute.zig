//! Deterministic execution of the resident Cairo witness DAG.

const std = @import("std");
const arena_plan = @import("stwo_metal_backend").arena_plan;
const metal_runtime = @import("stwo_metal_backend").runtime;
const protocol_recipes = @import("stwo_metal_backend").protocol_recipes;
const cairo_opcodes = @import("stwo_cairo_frontend").adapter.opcodes;
const cairo_proof_plan = @import("stwo_cairo_frontend").proof_plan;
const witness_bundle_mod = @import("stwo_cairo_frontend").witness.bundle;
const witness_scheduler = @import("stwo_cairo_frontend").witness_scheduler;
const schedule_bindings = @import("../../schedule_bindings.zig");
const multiplicity_feeds = @import("../lookups/multiplicity_feeds.zig");
const resident_binding = @import("../binding.zig");
const trace_diagnostics = @import("../trace/diagnostics.zig");
const trace_interpolation = @import("../trace/interpolation.zig");
const witness_prepare = @import("prepare.zig");
const Error = @import("../errors.zig").Error;

const collectComponent = schedule_bindings.collectComponent;
const oneComponent = schedule_bindings.oneComponent;
const oneComponentOrdinal = schedule_bindings.oneComponentOrdinal;
const oneOrdinal = schedule_bindings.oneOrdinal;
const wordOffset = resident_binding.wordOffset;

const MultiplicityFeedBatch = multiplicity_feeds.MultiplicityFeedBatch;
const RecordedBaseInterpolationBatch = trace_interpolation.RecordedBaseInterpolationBatch;
const WitnessRecipeRequirements = witness_prepare.WitnessRecipeRequirements;
const WitnessRecipes = witness_prepare.WitnessRecipes;
const logComponentBaseEvalDigests = trace_diagnostics.logComponentBaseEvalDigests;

pub const WitnessEdge = cairo_proof_plan.ProducerEdge;

pub fn prepareCompactWitnessInput(
    allocator: std.mem.Allocator,
    metal: *metal_runtime.Runtime,
    resident_arena: *arena_plan.ResidentArena,
    schedule: []const std.json.Value,
    plan: arena_plan.Plan,
    witness_bundle: witness_bundle_mod.Bundle,
    consumer: []const u8,
) !protocol_recipes.CompactRecipe {
    const geometry = cairo_proof_plan.compactGeometry(consumer) orelse return Error.MissingBinding;
    const outputs = try collectComponent(allocator, schedule, plan, "WitnessInput", consumer);
    defer allocator.free(outputs);
    if (outputs.len <= geometry.multiplicity_slot) return Error.InvalidCardinality;
    const consumer_rows = std.math.cast(u32, outputs[0].size_bytes / 4) orelse return Error.InvalidBindingSize;
    var sources = std.ArrayList(arena_plan.Binding).empty;
    defer sources.deinit(allocator);
    var descriptors = std.ArrayList(u32).empty;
    defer descriptors.deinit(allocator);
    var total_rows: u32 = 0;
    for (geometry.edges) |edge| {
        const producer_entry = witness_bundle.find(edge.producer) orelse continue;
        const source = try oneComponent(schedule, plan, "SubcomponentInputs", edge.producer);
        const producer_rows = std.math.cast(u32, source.size_bytes / 4 / producer_entry.program.n_sub_words) orelse return Error.InvalidBindingSize;
        try sources.append(allocator, source);
        try descriptors.appendSlice(allocator, &.{ producer_rows, edge.word_base, edge.words_per_instance, edge.instances, total_rows });
        total_rows = std.math.add(u32, total_rows, std.math.mul(u32, producer_rows, edge.instances) catch return Error.InvalidBindingSize) catch return Error.InvalidBindingSize;
    }
    const descriptor_binding = try oneComponent(schedule, plan, "WitnessInputCompactDescriptors", consumer);
    const descriptor_bytes = std.math.mul(u64, descriptors.items.len, @sizeOf(u32)) catch
        return Error.InvalidCardinality;
    if (descriptor_bytes == 0 or descriptor_binding.size_bytes < descriptor_bytes)
        return Error.InvalidCardinality;
    var descriptor_destination = descriptor_binding;
    descriptor_destination.size_bytes = descriptor_bytes;
    const key_a = try oneComponentOrdinal(schedule, plan, "WitnessInputCompactSortKey", consumer, 0);
    const key_b = try oneComponentOrdinal(schedule, plan, "WitnessInputCompactSortKey", consumer, 1);
    const index_a = try oneComponentOrdinal(schedule, plan, "WitnessInputCompactSortIndex", consumer, 0);
    const index_b = try oneComponentOrdinal(schedule, plan, "WitnessInputCompactSortIndex", consumer, 1);
    const sort_rows = std.math.cast(u32, key_a.size_bytes / 4) orelse return Error.InvalidBindingSize;
    return protocol_recipes.CompactRecipe.init(allocator, metal, resident_arena, .{
        .sources = sources.items,
        .descriptors = descriptors.items,
        .descriptor_destination = descriptor_destination,
        .outputs = outputs,
        .tuple_words = geometry.tuple_words,
        .key_words = geometry.key_words,
        .total_rows = total_rows,
        .sort_rows = sort_rows,
        .consumer_rows = consumer_rows,
        .enabler_slot = geometry.enabler_slot,
        .multiplicity_slot = geometry.multiplicity_slot,
        .iota_slot = geometry.iota_slot,
        .tuples = try oneComponent(schedule, plan, "WitnessInputCompactTupleScratch", consumer),
        .keys_a = key_a,
        .keys_b = key_b,
        .indices_a = index_a,
        .indices_b = index_b,
        .heads = try oneComponent(schedule, plan, "WitnessInputCompactRunHeads", consumer),
        .positions = try oneComponent(schedule, plan, "WitnessInputCompactRunPositions", consumer),
        .unique = try oneComponent(schedule, plan, "WitnessInputCompactUniqueCount", consumer),
        .sort_temp = try oneComponent(schedule, plan, "WitnessInputCompactSortTemp", consumer),
        .scan_temp = try oneComponent(schedule, plan, "WitnessInputCompactScanTemp", consumer),
    });
}

pub const WitnessExecutionTelemetry = struct {
    executed_programs: usize,
    gpu_ms: f64,
    writer_gpu_ms: f64 = 0,
    input_gpu_ms: f64 = 0,
    interpolation_gpu_ms: f64 = 0,
    feed_gpu_ms: f64 = 0,
};

pub fn witnessIndex(bundle: witness_bundle_mod.Bundle, label: []const u8) ?usize {
    for (bundle.entries, 0..) |entry, index| if (std.mem.eql(u8, entry.label, label)) return index;
    return null;
}

fn dependenciesReady(bundle: witness_bundle_mod.Bundle, executed: []const bool, edges: []const WitnessEdge) bool {
    for (edges) |edge| {
        const index = witnessIndex(bundle, edge.producer) orelse continue;
        if (!executed[index]) return false;
    }
    return true;
}

/// Runs every recorded witness program whose inputs are produced by the AOT,
/// gather, seed, or compact routes. The sole native EC-op lane is deliberately
/// left to `EcOpRecipe`, which owns its 126 wide partial-input columns.
pub fn executeRecordedWitnessGraph(
    allocator: std.mem.Allocator,
    metal: *metal_runtime.Runtime,
    resident_arena: *arena_plan.ResidentArena,
    schedule: []const std.json.Value,
    plan: arena_plan.Plan,
    witness_bundle: witness_bundle_mod.Bundle,
    batch: *protocol_recipes.AotWitnessBatchRecipe,
) !WitnessExecutionTelemetry {
    var compact_verify = try prepareCompactWitnessInput(allocator, metal, resident_arena, schedule, plan, witness_bundle, "verify_instruction");
    defer compact_verify.deinit();
    var compact_pedersen = try prepareCompactWitnessInput(allocator, metal, resident_arena, schedule, plan, witness_bundle, "pedersen_aggregator_window_bits_18");
    defer compact_pedersen.deinit();
    var compact_poseidon = try prepareCompactWitnessInput(allocator, metal, resident_arena, schedule, plan, witness_bundle, "poseidon_aggregator");
    defer compact_poseidon.deinit();
    const executed = try allocator.alloc(bool, witness_bundle.entries.len);
    defer allocator.free(executed);
    @memset(executed, false);
    var count: usize = 0;
    const initial_gpu_ms = batch.accumulated_gpu_ms;

    for (witness_bundle.entries, 0..) |entry, index| {
        var direct = false;
        for (cairo_opcodes.direct_witness_lanes) |lane| direct = direct or std.mem.eql(u8, lane.label, entry.label);
        direct = direct or std.mem.eql(u8, entry.label, "bitwise_builtin") or
            std.mem.eql(u8, entry.label, "range_check_builtin") or
            std.mem.eql(u8, entry.label, "pedersen_builtin") or
            std.mem.eql(u8, entry.label, "poseidon_builtin");
        if (!direct) continue;
        try batch.executeIndex(index);
        executed[index] = true;
        count += 1;
    }

    var compact_gpu_ms: f64 = 0;
    var gather_gpu_ms: f64 = 0;
    var progress = true;
    while (progress) {
        progress = false;
        for (witness_bundle.entries, 0..) |entry, index| {
            if (executed[index] or std.mem.eql(u8, entry.label, "partial_ec_mul_generic")) continue;
            if (cairo_proof_plan.compactGeometry(entry.label)) |geometry| {
                if (!dependenciesReady(witness_bundle, executed, geometry.edges)) continue;
                if (std.mem.eql(u8, entry.label, "verify_instruction")) {
                    try compact_verify.execute();
                    compact_gpu_ms += compact_verify.accumulated_gpu_ms;
                    compact_verify.accumulated_gpu_ms = 0;
                } else if (std.mem.eql(u8, entry.label, "pedersen_aggregator_window_bits_18")) {
                    try compact_pedersen.execute();
                    compact_gpu_ms += compact_pedersen.accumulated_gpu_ms;
                    compact_pedersen.accumulated_gpu_ms = 0;
                } else {
                    try compact_poseidon.execute();
                    compact_gpu_ms += compact_poseidon.accumulated_gpu_ms;
                    compact_poseidon.accumulated_gpu_ms = 0;
                }
            } else if (cairo_proof_plan.gatheredProducerEdges(entry.label)) |edges| {
                if (!dependenciesReady(witness_bundle, executed, edges)) continue;
                gather_gpu_ms += try gatherWitnessInput(allocator, metal, resident_arena, schedule, plan, witness_bundle, entry.label);
            } else continue;
            try batch.executeIndex(index);
            executed[index] = true;
            count += 1;
            progress = true;
        }
    }
    if (count + 1 != witness_bundle.entries.len) return Error.InvalidCardinality;
    const native_index = witnessIndex(witness_bundle, "partial_ec_mul_generic") orelse return Error.MissingBinding;
    if (executed[native_index]) return Error.InvalidCardinality;
    return .{ .executed_programs = count, .gpu_ms = batch.accumulated_gpu_ms - initial_gpu_ms + compact_gpu_ms + gather_gpu_ms };
}

pub fn executeNativeEcConsumer(
    witness_bundle: witness_bundle_mod.Bundle,
    batch: *protocol_recipes.AotWitnessBatchRecipe,
    ec_op: *protocol_recipes.EcOpRecipe,
) !WitnessExecutionTelemetry {
    const index = witnessIndex(witness_bundle, "partial_ec_mul_generic") orelse return Error.MissingBinding;
    const initial_batch_ms = batch.accumulated_gpu_ms;
    const initial_ec_ms = ec_op.accumulated_gpu_ms;
    try ec_op.execute();
    try batch.executeIndex(index);
    return .{
        .executed_programs = 1,
        .gpu_ms = batch.accumulated_gpu_ms - initial_batch_ms + ec_op.accumulated_gpu_ms - initial_ec_ms,
    };
}

/// Executes the recorded Cairo witness DAG with the same ownership boundary
/// used by the staged arena: construct one input, refresh its aliased pointer
/// tables, write its trace, interpolate it, then consume its producer feed.
pub fn executeScheduledWitnessGraph(
    allocator: std.mem.Allocator,
    metal: *metal_runtime.Runtime,
    resident_arena: *arena_plan.ResidentArena,
    schedule: []const std.json.Value,
    arena: arena_plan.Plan,
    proof: *const cairo_proof_plan.CairoProofPlan,
    witness_bundle: witness_bundle_mod.Bundle,
    batch: *protocol_recipes.AotWitnessBatchRecipe,
    recipes: WitnessRecipes,
    interpolation: *RecordedBaseInterpolationBatch,
    feeds: *MultiplicityFeedBatch,
) !WitnessExecutionTelemetry {
    if (proof.components.len != witness_bundle.entries.len) return Error.InvalidCardinality;
    try recipes.validate(WitnessRecipeRequirements.fromBundle(witness_bundle));

    const Context = struct {
        allocator: std.mem.Allocator,
        metal: *metal_runtime.Runtime,
        resident_arena: *arena_plan.ResidentArena,
        schedule: []const std.json.Value,
        arena: arena_plan.Plan,
        proof: *const cairo_proof_plan.CairoProofPlan,
        witness_bundle: witness_bundle_mod.Bundle,
        batch: *protocol_recipes.AotWitnessBatchRecipe,
        recipes: WitnessRecipes,
        interpolation: *RecordedBaseInterpolationBatch,
        feeds: *MultiplicityFeedBatch,
        writer_gpu_ms: f64 = 0,
        input_gpu_ms: f64 = 0,
        interpolation_gpu_ms: f64 = 0,
        feed_gpu_ms: f64 = 0,

        fn run(raw: *anyopaque, component_index: u32, stage: witness_scheduler.Stage) !f64 {
            const self: *@This() = @ptrCast(@alignCast(raw));
            if (component_index >= self.proof.components.len) return Error.InvalidCardinality;
            const component = self.proof.components[component_index].name;
            const gpu_ms = switch (stage) {
                .seed => 0,
                .gather => try gatherWitnessInput(
                    self.allocator,
                    self.metal,
                    self.resident_arena,
                    self.schedule,
                    self.arena,
                    self.witness_bundle,
                    component,
                ),
                .compact => try self.executeCompact(component),
                .writer => try self.executeWriter(component_index, component),
                .interpolate => try self.interpolation.executeIndex(component_index),
                .feed => try self.executeFeed(component),
            };
            if (std.process.hasEnvVarConstant("STWO_ZIG_SN2_LOG_RC99_DIGESTS")) {
                try self.logRc99Digest(component, @tagName(stage));
            }
            if (stage == .writer and std.process.hasEnvVarConstant("STWO_ZIG_SN2_LOG_BASE_EVAL_DIGESTS"))
                try logComponentBaseEvalDigests(
                    self.resident_arena,
                    self.schedule,
                    self.arena,
                    component,
                );
            if (std.process.hasEnvVarConstant("STWO_ZIG_SN2_LOG_ADD_OPCODE_COEFF_DIGESTS") and
                ((std.mem.eql(u8, component, "add_opcode") and stage == .interpolate) or
                    std.mem.eql(u8, component, "add_opcode_small") or stage == .feed))
            {
                try self.logAddOpcodeCoefficientDigests(component, @tagName(stage));
            }
            switch (stage) {
                .seed, .gather, .compact => self.input_gpu_ms += gpu_ms,
                .writer => {},
                .interpolate => self.interpolation_gpu_ms += gpu_ms,
                .feed => self.feed_gpu_ms += gpu_ms,
            }
            return gpu_ms;
        }

        fn executeCompact(self: *@This(), component: []const u8) !f64 {
            const recipe = if (std.mem.eql(u8, component, "verify_instruction"))
                self.recipes.compact_verify
            else if (std.mem.eql(u8, component, "pedersen_aggregator_window_bits_18"))
                self.recipes.compact_pedersen
            else if (std.mem.eql(u8, component, "poseidon_aggregator"))
                self.recipes.compact_poseidon
            else
                null;
            const required = recipe orelse return Error.MissingBinding;
            const initial = required.accumulated_gpu_ms;
            try required.execute();
            return required.accumulated_gpu_ms - initial;
        }

        fn executeWriter(self: *@This(), component_index: u32, component: []const u8) !f64 {
            const index = witnessIndex(self.witness_bundle, component) orelse return Error.MissingBinding;
            var writer_gpu_ms: f64 = 0;
            var interpolation_gpu_ms: f64 = 0;
            if (std.mem.eql(u8, component, "partial_ec_mul_generic")) {
                const ec_op = self.recipes.ec_op orelse return Error.MissingBinding;
                const ec_initial = ec_op.accumulated_gpu_ms;
                try ec_op.execute();
                writer_gpu_ms += ec_op.accumulated_gpu_ms - ec_initial;
                if (std.process.hasEnvVarConstant("STWO_ZIG_SN2_LOG_BASE_EVAL_DIGESTS"))
                    try logComponentBaseEvalDigests(
                        self.resident_arena,
                        self.schedule,
                        self.arena,
                        "ec_op_builtin",
                    );
                if (std.process.hasEnvVarConstant("STWO_ZIG_SN2_LOG_RC99_DIGESTS"))
                    try self.logRc99Digest(component, "native_ec");
                interpolation_gpu_ms = try self.interpolation.interpolateEcOp(component_index);
                self.interpolation_gpu_ms += interpolation_gpu_ms;
                if (std.process.hasEnvVarConstant("STWO_ZIG_SN2_LOG_RC99_DIGESTS"))
                    try self.logRc99Digest(component, "native_ec_interpolate");
            }
            const initial = self.batch.accumulated_gpu_ms;
            try self.batch.executeIndex(index);
            writer_gpu_ms += self.batch.accumulated_gpu_ms - initial;
            if (std.mem.eql(u8, component, "blake_g") and
                std.process.hasEnvVarConstant("STWO_ZIG_SN2_LOG_BLAKE_G_EVAL_DIGESTS"))
            {
                const bindings = try collectComponent(
                    self.allocator,
                    self.schedule,
                    self.arena,
                    "BaseTrace",
                    component,
                );
                defer self.allocator.free(bindings);
                const coefficient_bindings = try collectComponent(
                    self.allocator,
                    self.schedule,
                    self.arena,
                    "BaseCoefficients",
                    component,
                );
                defer self.allocator.free(coefficient_bindings);
                if (coefficient_bindings.len != bindings.len) return Error.InvalidCardinality;
                for (bindings, 0..) |binding, column_ordinal| {
                    const bytes = try self.resident_arena.bytes(binding);
                    var digest: u64 = 0xcbf29ce484222325;
                    for (bytes) |byte| {
                        digest ^= byte;
                        digest *%= 0x100000001b3;
                    }
                    std.debug.print(
                        "blake_g_eval_digest ordinal={} source_offset={} destination_offset={} words={} first={x:0>8} last={x:0>8} fnv64={x:0>16}\n",
                        .{
                            column_ordinal,
                            binding.offset_bytes,
                            coefficient_bindings[column_ordinal].offset_bytes,
                            bytes.len / 4,
                            std.mem.readInt(u32, bytes[0..4], .little),
                            std.mem.readInt(u32, bytes[bytes.len - 4 ..][0..4], .little),
                            digest,
                        },
                    );
                }
            }
            if (std.mem.eql(u8, component, "add_opcode") and
                std.process.hasEnvVarConstant("STWO_ZIG_SN2_LOG_ADD_OPCODE_EVAL_DIGESTS"))
            {
                const bindings = try collectComponent(
                    self.allocator,
                    self.schedule,
                    self.arena,
                    "BaseTrace",
                    component,
                );
                defer self.allocator.free(bindings);
                for ([_]usize{ 62, 65, 80 }) |column_ordinal| {
                    if (column_ordinal >= bindings.len) return Error.InvalidCardinality;
                    const bytes = try self.resident_arena.bytes(bindings[column_ordinal]);
                    var digest: u64 = 0xcbf29ce484222325;
                    for (bytes) |byte| {
                        digest ^= byte;
                        digest *%= 0x100000001b3;
                    }
                    std.debug.print(
                        "add_opcode_eval_digest ordinal={} words={} first={x:0>8} last={x:0>8} fnv64={x:0>16}\n",
                        .{
                            column_ordinal,
                            bytes.len / 4,
                            std.mem.readInt(u32, bytes[0..4], .little),
                            std.mem.readInt(u32, bytes[bytes.len - 4 ..][0..4], .little),
                            digest,
                        },
                    );
                }
            }
            self.writer_gpu_ms += writer_gpu_ms;
            return writer_gpu_ms + interpolation_gpu_ms;
        }

        fn logRc99Digest(self: *@This(), component: []const u8, stage: []const u8) !void {
            var digest: u64 = 0xcbf29ce484222325;
            for ([_]u32{ 89, 90 }) |fixed_ordinal| {
                const binding = try oneOrdinal(
                    self.schedule,
                    self.arena,
                    "PreprocessedEvaluations",
                    fixed_ordinal,
                );
                for (try self.resident_arena.bytes(binding)) |byte| {
                    digest ^= byte;
                    digest *%= 0x100000001b3;
                }
            }
            std.debug.print(
                "rc99_digest component={s} stage={s} fnv64={x:0>16}\n",
                .{ component, stage, digest },
            );
        }

        fn logAddOpcodeCoefficientDigests(self: *@This(), component: []const u8, stage: []const u8) !void {
            const bindings = try collectComponent(
                self.allocator,
                self.schedule,
                self.arena,
                "BaseCoefficients",
                "add_opcode",
            );
            defer self.allocator.free(bindings);
            for ([_]usize{ 62, 64, 65, 79, 80 }) |column_ordinal| {
                if (column_ordinal >= bindings.len) return Error.InvalidCardinality;
                const bytes = try self.resident_arena.bytes(bindings[column_ordinal]);
                var digest: u64 = 0xcbf29ce484222325;
                for (bytes) |byte| {
                    digest ^= byte;
                    digest *%= 0x100000001b3;
                }
                std.debug.print(
                    "add_opcode_coeff_digest component={s} stage={s} ordinal={} first={x:0>8} last={x:0>8} fnv64={x:0>16}\n",
                    .{
                        component,
                        stage,
                        column_ordinal,
                        std.mem.readInt(u32, bytes[0..4], .little),
                        std.mem.readInt(u32, bytes[bytes.len - 4 ..][0..4], .little),
                        digest,
                    },
                );
            }
        }

        fn executeFeed(self: *@This(), component: []const u8) !f64 {
            const initial = self.feeds.batch.accumulated_gpu_ms;
            try self.feeds.executeProducer(component);
            return self.feeds.batch.accumulated_gpu_ms - initial;
        }
    };

    var context = Context{
        .allocator = allocator,
        .metal = metal,
        .resident_arena = resident_arena,
        .schedule = schedule,
        .arena = arena,
        .proof = proof,
        .witness_bundle = witness_bundle,
        .batch = batch,
        .recipes = recipes,
        .interpolation = interpolation,
        .feeds = feeds,
    };
    const hook = witness_scheduler.Hook{ .context = &context, .run_fn = Context.run };
    const operations = try allocator.alloc(witness_scheduler.ComponentOperation, proof.components.len);
    defer allocator.free(operations);
    for (proof.components, operations, 0..) |component, *operation, index| {
        operation.* = .{
            .component_index = @intCast(index),
            .gather = if (component.producer_edges.len != 0 and cairo_proof_plan.compactGeometry(component.name) == null) hook else null,
            .compact = if (cairo_proof_plan.compactGeometry(component.name) != null) hook else null,
            .writer = hook,
            .interpolate = hook,
            .feed = hook,
        };
    }
    var scheduler = try witness_scheduler.CairoWitnessScheduler.init(allocator, proof, operations);
    defer scheduler.deinit();
    const initial_feed_gpu_ms = feeds.batch.accumulated_gpu_ms;
    try feeds.begin();
    const feed_clear_gpu_ms = feeds.batch.accumulated_gpu_ms - initial_feed_gpu_ms;
    context.feed_gpu_ms += feed_clear_gpu_ms;
    const result = try scheduler.execute(allocator);
    defer allocator.free(result.components);
    return .{
        .executed_programs = proof.components.len,
        .gpu_ms = result.gpu_ms + feed_clear_gpu_ms,
        .writer_gpu_ms = context.writer_gpu_ms,
        .input_gpu_ms = context.input_gpu_ms,
        .interpolation_gpu_ms = context.interpolation_gpu_ms,
        .feed_gpu_ms = context.feed_gpu_ms,
    };
}

/// Launches one canonical producer-edge gather immediately before its consumer
/// witness program. Producer sub-word slabs and consumer columns never leave
/// the resident arena.
pub fn gatherWitnessInput(
    allocator: std.mem.Allocator,
    metal: *metal_runtime.Runtime,
    resident_arena: *arena_plan.ResidentArena,
    schedule: []const std.json.Value,
    plan: arena_plan.Plan,
    witness_bundle: witness_bundle_mod.Bundle,
    consumer: []const u8,
) !f64 {
    const edges = cairo_proof_plan.gatheredProducerEdges(consumer) orelse return Error.MissingBinding;
    const consumer_entry = witness_bundle.find(consumer) orelse return Error.MissingBinding;
    const input_width = edges[0].words_per_instance;
    const consumer_bindings = try collectComponent(allocator, schedule, plan, "WitnessInput", consumer);
    defer allocator.free(consumer_bindings);
    if (consumer_entry.program.n_inputs != input_width + 1 or consumer_bindings.len != input_width + 1)
        return Error.InvalidCardinality;
    const consumer_rows = std.math.cast(u32, consumer_bindings[0].size_bytes / 4) orelse return Error.InvalidBindingSize;
    const producer_offsets = try allocator.alloc(u32, edges.len);
    defer allocator.free(producer_offsets);
    const descriptors = try allocator.alloc([5]u32, edges.len);
    defer allocator.free(descriptors);
    var real_rows: u32 = 0;
    for (edges, producer_offsets, descriptors) |edge, *producer_offset, *descriptor| {
        if (edge.words_per_instance != input_width) return Error.InvalidCardinality;
        const producer_entry = witness_bundle.find(edge.producer) orelse return Error.MissingBinding;
        const source = try oneComponent(schedule, plan, "SubcomponentInputs", edge.producer);
        const producer_rows = std.math.cast(u32, source.size_bytes / 4 / producer_entry.program.n_sub_words) orelse return Error.InvalidBindingSize;
        if (producer_rows == 0 or source.size_bytes != @as(u64, producer_rows) * producer_entry.program.n_sub_words * 4)
            return Error.InvalidBindingSize;
        producer_offset.* = try wordOffset(source);
        descriptor.* = .{ producer_rows, edge.word_base, edge.words_per_instance, edge.instances, real_rows };
        real_rows = std.math.add(u32, real_rows, std.math.mul(u32, producer_rows, edge.instances) catch return Error.InvalidBindingSize) catch return Error.InvalidBindingSize;
    }
    if (real_rows > consumer_rows) return Error.InvalidBindingSize;
    const consumer_offsets = try allocator.alloc(u32, consumer_bindings.len);
    defer allocator.free(consumer_offsets);
    for (consumer_bindings, consumer_offsets) |binding, *offset| {
        if (binding.size_bytes != @as(u64, consumer_rows) * 4) return Error.InvalidBindingSize;
        offset.* = try wordOffset(binding);
    }
    return metal.witnessInputGather(
        resident_arena.buffer,
        producer_offsets,
        descriptors,
        input_width,
        real_rows,
        consumer_rows,
        consumer_offsets,
        true,
        false,
    );
}
