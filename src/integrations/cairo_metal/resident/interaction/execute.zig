//! Deterministic construction of resident Cairo interaction traces.

const std = @import("std");
const arena_plan = @import("../../../../backends/metal/arena_plan.zig");
const metal_runtime = @import("../../../../backends/metal/runtime.zig");
const protocol_recipes = @import("../../../../backends/metal/protocol_recipes.zig");
const cairo_adapter = @import("stwo_cairo_frontend").adapter;
const cairo_proof_plan = @import("stwo_cairo_frontend").proof_plan;
const witness_bundle_mod = @import("stwo_cairo_frontend").witness.bundle;
const witness_scheduler = @import("stwo_cairo_frontend").witness_scheduler;
const schedule_bindings = @import("../../schedule_bindings.zig");
const interaction_diagnostics = @import("diagnostics.zig");
const preprocessed_coefficients = @import("../preprocessed/coefficients.zig");
const relation_components = @import("../relations/components.zig");
const witness_execute = @import("../witness/execute.zig");
const witness_inputs = @import("../witness/inputs.zig");
const witness_prepare = @import("../witness/prepare.zig");
const Error = @import("../errors.zig").Error;

const collectComponent = schedule_bindings.collectComponent;
const oneComponent = schedule_bindings.oneComponent;
const PreparedRelationComponents = relation_components.PreparedRelationComponents;
const WitnessRecipeRequirements = witness_prepare.WitnessRecipeRequirements;
const WitnessRecipes = witness_prepare.WitnessRecipes;
const gatherWitnessInput = witness_execute.gatherWitnessInput;
const witnessIndex = witness_execute.witnessIndex;
const populateDirectWitnessInput = witness_inputs.populateDirectWitnessInput;
const populateExecutionTables = preprocessed_coefficients.populateExecutionTables;
const logComponentInteractionDigests = interaction_diagnostics.logComponentInteractionDigests;
const logCpuColumnLdeDigest = interaction_diagnostics.logCpuColumnLdeDigest;
const logInteractionWriterCpuSample = interaction_diagnostics.logInteractionWriterCpuSample;
const logLogicalBindingDigest = interaction_diagnostics.logLogicalBindingDigest;
const logLookupRelationCpuClaim = interaction_diagnostics.logLookupRelationCpuClaim;

pub const InteractionExecutionTelemetry = struct {
    executed_programs: usize,
    executed_relations: usize,
    gpu_ms: f64,
    writer_gpu_ms: f64,
    input_gpu_ms: f64,
    relation_gpu_ms: f64,
    interpolation_gpu_ms: f64,
};

/// Replays the recorded witness DAG into lookup/subcomponent slabs and consumes
/// each lookup in its relation before advancing to the next aliased component.
/// Multiplicity feeds are deliberately absent: their base-epoch counts remain
/// resident and are only read by the relation kernels.
pub fn executeScheduledInteractionGraph(
    allocator: std.mem.Allocator,
    metal: *metal_runtime.Runtime,
    resident_arena: *arena_plan.ResidentArena,
    schedule: []const std.json.Value,
    arena: arena_plan.Plan,
    proof: *const cairo_proof_plan.CairoProofPlan,
    witness_bundle: witness_bundle_mod.Bundle,
    input: *const cairo_adapter.ProverInput,
    batch: *protocol_recipes.AotWitnessBatchRecipe,
    recipes: WitnessRecipes,
    relations: *PreparedRelationComponents,
) !InteractionExecutionTelemetry {
    if (proof.components.len != witness_bundle.entries.len) return Error.InvalidCardinality;
    const requirements = WitnessRecipeRequirements.fromBundle(witness_bundle);
    try recipes.validate(requirements);
    for (proof.components) |component| {
        if (try relations.componentIndex(component.name) == null) return Error.MissingBinding;
    }
    if (requirements.ec_op and try relations.componentIndex("ec_op_builtin") == null)
        return Error.MissingBinding;
    const execution_table_gpu_ms = try populateExecutionTables(
        allocator,
        metal,
        resident_arena,
        schedule,
        arena,
        input,
    );

    const Context = struct {
        allocator: std.mem.Allocator,
        metal: *metal_runtime.Runtime,
        resident_arena: *arena_plan.ResidentArena,
        schedule: []const std.json.Value,
        arena: arena_plan.Plan,
        proof: *const cairo_proof_plan.CairoProofPlan,
        witness_bundle: witness_bundle_mod.Bundle,
        input: *const cairo_adapter.ProverInput,
        batch: *protocol_recipes.AotWitnessBatchRecipe,
        recipes: WitnessRecipes,
        relations: *PreparedRelationComponents,
        ec_completed: bool = false,
        executed_writers: usize = 0,
        executed_relations: usize = 0,
        writer_gpu_ms: f64 = 0,
        input_gpu_ms: f64 = 0,
        relation_gpu_ms: f64 = 0,
        interpolation_gpu_ms: f64 = 0,

        fn run(raw: *anyopaque, component_index: u32, stage: witness_scheduler.Stage) !f64 {
            const self: *@This() = @ptrCast(@alignCast(raw));
            if (component_index >= self.proof.components.len) return Error.InvalidCardinality;
            const component = self.proof.components[component_index].name;
            const gpu_ms = switch (stage) {
                .seed => blk: {
                    if (!try populateDirectWitnessInput(
                        self.allocator,
                        self.resident_arena,
                        self.schedule,
                        self.arena,
                        self.witness_bundle,
                        self.input,
                        component,
                    )) return Error.MissingBinding;
                    break :blk 0;
                },
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
                .writer => try self.executeWriter(component),
                .interpolate => try self.executeRelation(component),
                .feed => return Error.InvalidSchedule,
            };
            switch (stage) {
                .seed, .gather, .compact => self.input_gpu_ms += gpu_ms,
                .writer => {},
                .interpolate => {},
                .feed => unreachable,
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

        fn executeWriter(self: *@This(), component: []const u8) !f64 {
            var gpu_ms: f64 = 0;
            if (std.mem.eql(u8, component, "partial_ec_mul_generic")) {
                if (self.ec_completed) return Error.InvalidSchedule;
                const ec_lookup = self.recipes.ec_op orelse return Error.MissingBinding;
                const initial = ec_lookup.accumulated_gpu_ms;
                try ec_lookup.execute();
                const ec_gpu_ms = ec_lookup.accumulated_gpu_ms - initial;
                self.writer_gpu_ms += ec_gpu_ms;
                gpu_ms += ec_gpu_ms;
                const relation_gpu_ms = try self.executeRelation("ec_op_builtin");
                gpu_ms += relation_gpu_ms;
                self.ec_completed = true;
            }
            const index = witnessIndex(self.witness_bundle, component) orelse return Error.MissingBinding;
            const initial = self.batch.accumulated_gpu_ms;
            try self.batch.executeIndex(index);
            const writer_gpu_ms = self.batch.accumulated_gpu_ms - initial;
            if (std.process.hasEnvVarConstant("STWO_ZIG_SN2_DIFF_ADD_OPCODE_INTERACTION") and
                std.mem.eql(u8, component, "add_opcode"))
                try logInteractionWriterCpuSample(
                    self.allocator,
                    self.resident_arena,
                    self.schedule,
                    self.arena,
                    self.witness_bundle,
                    component,
                );
            self.writer_gpu_ms += writer_gpu_ms;
            self.executed_writers += 1;
            return gpu_ms + writer_gpu_ms;
        }

        fn executeRelation(self: *@This(), component: []const u8) !f64 {
            const index = try self.relations.componentIndex(component) orelse return Error.MissingBinding;
            const diff_add_opcode = std.process.hasEnvVarConstant("STWO_ZIG_SN2_DIFF_ADD_OPCODE_INTERACTION") and
                std.mem.eql(u8, component, "add_opcode");
            const log_interaction_evals = std.process.hasEnvVarConstant("STWO_ZIG_SN2_LOG_INTERACTION_EVAL_DIGESTS");
            const trace_column_613 = std.process.hasEnvVarConstant("STWO_ZIG_SN2_TRACE_COLUMN_613");
            if (diff_add_opcode or log_interaction_evals or trace_column_613) {
                const operation = &self.relations.operations[index];
                const relation_before = operation.relation.accumulated_gpu_ms;
                try operation.relation.execute();
                const relation_gpu_ms = operation.relation.accumulated_gpu_ms - relation_before;
                if (log_interaction_evals) try logComponentInteractionDigests(
                    self.allocator,
                    self.resident_arena,
                    self.schedule,
                    self.arena,
                    component,
                );
                if (diff_add_opcode) {
                    const source = try oneComponent(self.schedule, self.arena, "LookupInputs", component);
                    const outputs = try collectComponent(
                        self.allocator,
                        self.schedule,
                        self.arena,
                        "InteractionTrace",
                        component,
                    );
                    defer self.allocator.free(outputs);
                    try logLookupRelationCpuClaim(
                        self.allocator,
                        self.resident_arena,
                        self.schedule,
                        self.arena,
                        component,
                        source,
                        @intCast(source.size_bytes / 4 / self.witness_bundle.find(component).?.program.n_lookup_words),
                        outputs,
                    );
                }
                if (trace_column_613 and std.mem.eql(u8, component, "blake_g"))
                    try logCpuColumnLdeDigest(
                        self.allocator,
                        self.resident_arena,
                        self.arena,
                        1701,
                        23,
                    );
                var interpolation_gpu_ms: f64 = 0;
                for (operation.interpolations) |*interpolation| {
                    const before = interpolation.accumulated_gpu_ms;
                    try interpolation.execute();
                    interpolation_gpu_ms += interpolation.accumulated_gpu_ms - before;
                }
                if (trace_column_613 and std.mem.eql(u8, component, "blake_g")) {
                    try logLogicalBindingDigest(
                        self.resident_arena,
                        self.arena,
                        1737,
                        "after_blake_g_batch_ifft",
                    );
                    {
                        const file = try std.fs.createFileAbsolute("/tmp/sn2-column613-metal-coeff.u32le", .{});
                        defer file.close();
                        try file.writeAll(try self.resident_arena.bytes(self.arena.binding(1737) catch return Error.MissingBinding));
                    }
                    if (operation.interpolations.len != 1) return Error.InvalidCardinality;
                    interpolation_gpu_ms += try operation.interpolations[0].executeColumn(13);
                    try logLogicalBindingDigest(
                        self.resident_arena,
                        self.arena,
                        1737,
                        "after_blake_g_single_ifft",
                    );
                }
                self.relation_gpu_ms += relation_gpu_ms;
                self.interpolation_gpu_ms += interpolation_gpu_ms;
                self.executed_relations += 1;
                return relation_gpu_ms + interpolation_gpu_ms;
            }
            const telemetry = try self.relations.executeIndex(index);
            self.relation_gpu_ms += telemetry.relation_gpu_ms;
            self.interpolation_gpu_ms += telemetry.interpolation_gpu_ms;
            self.executed_relations += 1;
            return telemetry.relation_gpu_ms + telemetry.interpolation_gpu_ms;
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
        .input = input,
        .batch = batch,
        .recipes = recipes,
        .relations = relations,
        .input_gpu_ms = execution_table_gpu_ms,
    };
    const hook = witness_scheduler.Hook{ .context = &context, .run_fn = Context.run };
    const operations = try allocator.alloc(witness_scheduler.ComponentOperation, proof.components.len);
    defer allocator.free(operations);
    for (proof.components, operations, 0..) |component, *operation, index|
        operation.* = interactionOperation(component, @intCast(index), hook);
    var scheduler = try witness_scheduler.CairoWitnessScheduler.init(allocator, proof, operations);
    defer scheduler.deinit();
    const result = try scheduler.execute(allocator);
    defer allocator.free(result.components);
    var expected_writers: usize = 0;
    for (proof.components) |component|
        expected_writers += @intFromBool(!cairo_proof_plan.retainsLookupInputs(component.name) or
            cairo_proof_plan.retainedLookupReplaysSubwords(component.name));
    if (context.ec_completed != requirements.ec_op or
        context.executed_writers != expected_writers or
        context.executed_relations != proof.components.len + @intFromBool(requirements.ec_op))
        return Error.InvalidCardinality;
    return .{
        .executed_programs = context.executed_writers,
        .executed_relations = context.executed_relations,
        .gpu_ms = result.gpu_ms + execution_table_gpu_ms,
        .writer_gpu_ms = context.writer_gpu_ms,
        .input_gpu_ms = context.input_gpu_ms,
        .relation_gpu_ms = context.relation_gpu_ms,
        .interpolation_gpu_ms = context.interpolation_gpu_ms,
    };
}

fn interactionOperation(
    component: cairo_proof_plan.Component,
    component_index: u32,
    hook: witness_scheduler.Hook,
) witness_scheduler.ComponentOperation {
    const compact = cairo_proof_plan.compactGeometry(component.name) != null;
    const retained_ec_input = std.mem.eql(u8, component.name, "partial_ec_mul_generic");
    const retained_lookup = cairo_proof_plan.retainsLookupInputs(component.name);
    const skip_writer = retained_lookup and !cairo_proof_plan.retainedLookupReplaysSubwords(component.name);
    return .{
        .component_index = component_index,
        .seed = if (!skip_writer and !retained_ec_input and !compact and component.producer_edges.len == 0) hook else null,
        .gather = if (!skip_writer and component.producer_edges.len != 0 and !compact) hook else null,
        .compact = if (!skip_writer and compact) hook else null,
        .writer = if (skip_writer) null else hook,
        .interpolate = hook,
    };
}

test "retained interaction lookup runs its relation without rebuilding inputs" {
    const rows = [_]cairo_proof_plan.TracePart{.{ .id = .main, .rows = .{ .real_rows = 16, .padded_rows = 16 } }};
    const edge = [_]cairo_proof_plan.ProducerEdge{.{
        .producer = "producer",
        .word_base = 0,
        .words_per_instance = 1,
        .instances = 1,
    }};
    const Context = struct {
        fn run(_: *anyopaque, _: u32, _: witness_scheduler.Stage) !f64 {
            return 0;
        }
    };
    var context: u8 = 0;
    const hook = witness_scheduler.Hook{ .context = &context, .run_fn = Context.run };
    const retained = interactionOperation(.{
        .name = "cube_252",
        .canonical_ordinal = 0,
        .writer = .recorded_aot,
        .trace_parts = &rows,
        .producer_edges = &edge,
        .capacity_feeds = &.{},
    }, 0, hook);
    try std.testing.expect(retained.seed == null);
    try std.testing.expect(retained.gather == null);
    try std.testing.expect(retained.compact == null);
    try std.testing.expect(retained.writer == null);

    const retained_producer = interactionOperation(.{
        .name = "poseidon_3_partial_rounds_chain",
        .canonical_ordinal = 1,
        .writer = .recorded_aot,
        .trace_parts = &rows,
        .producer_edges = &edge,
        .capacity_feeds = &.{},
    }, 1, hook);
    try std.testing.expect(retained_producer.gather != null);
    try std.testing.expect(retained_producer.writer != null);

    const gathered = interactionOperation(.{
        .name = "blake_g",
        .canonical_ordinal = 2,
        .writer = .recorded_aot,
        .trace_parts = &rows,
        .producer_edges = &edge,
        .capacity_feeds = &.{},
    }, 2, hook);
    try std.testing.expect(gathered.gather != null);
    try std.testing.expect(gathered.writer != null);

    const seeded = interactionOperation(.{
        .name = "add_opcode",
        .canonical_ordinal = 3,
        .writer = .recorded_aot,
        .trace_parts = &rows,
        .producer_edges = &.{},
        .capacity_feeds = &.{},
    }, 3, hook);
    try std.testing.expect(seeded.seed != null);
    try std.testing.expect(seeded.writer != null);
}
