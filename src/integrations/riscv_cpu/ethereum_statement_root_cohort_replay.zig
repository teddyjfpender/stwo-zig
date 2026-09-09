//! Saved native inputs -> complete Tree2 -> independently rebuilt closure.
//! This gate allocates no PCS state and never generates another native proof.
const std = @import("std");
const builtin = @import("builtin");
const recursion = @import("stwo_riscv_frontend").recursion;
const complete_mod = @import("recursive_common_ethereum_incremental_leaf_universal_cohort_v4_complete.zig");
const geometry_mod = @import("recursive_common_ethereum_incremental_leaf_universal_geometry_authority_v4.zig");
const manifest_mod = @import("recursive_common_ethereum_incremental_leaf_universal_manifest_v4.zig");
const runtime = @import("recursive_common_ethereum_incremental_leaf_genuine_runtime_v4.zig");
const process_usage = @import("stwo_prover_engine").measurement.process_usage;
const progress = @import("ethereum_wrapper_resources_v1.zig").progress;
const Relations = recursion.air.universal_challenges.UniversalRelations;
const ProviderRelations = recursion.air.universal_shared_provider.SharedProviderRelations;
const M31 = @import("stwo_core").fields.m31.M31;

pub fn audit(comptime Engine: type, allocator: std.mem.Allocator, materialized: anytype) !void {
    if (materialized.initial_input_admission != null)
        return auditSelected(Engine, recursion.air.ethereum_initial_input_manifest_v1, allocator, materialized);
    return auditSelected(Engine, manifest_mod, allocator, materialized);
}

// Test evidence only: recursively hashes actual contents, including slice
// lengths, without hashing pointer addresses or undefined struct padding.
// Retaining this digest does not retain aliases to the live row arrays.
fn preparedRowsDigest(rows: anytype) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    std.hash.autoHashStrat(&hash, rows, .DeepRecursive);
    return hash.finalResult();
}

fn auditSelected(comptime Engine: type, comptime Contract: type, allocator: std.mem.Allocator, materialized: anytype) !void {
    const Complete = complete_mod.Types(Contract);
    const Cohort = Complete.Cohort(Engine);
    const Geometry = geometry_mod.OwnerV4(Engine);
    const Publication = struct {
        format_version: u16 = 1,
        component_count: u32 = Contract.COMPONENT_COUNT,
        manifest: Contract.Manifest,
        generated: Complete.Generated,
    };
    const initial = Contract == recursion.air.ethereum_initial_input_manifest_v1;
    var producer = runtime.TrackedSmpAllocatorV4{};
    defer producer.requireEmpty() catch @panic("cohort replay producer ownership leak");
    var phase = try Phase.begin("prepare", Contract.COMPONENT_COUNT);
    const serialized = blk: {
        const geometry = try Geometry.init(producer.allocator(), materialized);
        defer geometry.deinit();
        {
            var mutation_timer = try std.time.Timer.start();
            const mutation_work = DeepWork.capture();
            defer {
                const elapsed_ns = mutation_timer.read();
                phase.mutation_regression_ns += elapsed_ns;
                phase.mutation_work.add(DeepWork.capture().difference(mutation_work));
                progress("ETHEREUM_ROOT_COHORT diagnostic=transcript_mutation_regression ns={d}\n", .{elapsed_ns});
            }
            // Mutating a live, admitted source must not mutate already-owned
            // operational rows. The cold auditor must still reject that source.
            const rows = try geometry.transcriptRows();
            const owned_before = DeepWork.capture();
            const before = preparedRowsDigest(try rows.views());
            const execution = &@constCast(materialized).base.transcript.execution;
            const saved = execution.operations[0];
            defer execution.operations[0] = saved;
            execution.operations[0].context_tag = std.math.maxInt(u32);
            try rows.validatePreparedRows();
            const after = preparedRowsDigest(try rows.views());
            try std.testing.expectEqualDeep(before, after);
            try std.testing.expectEqualDeep(DeepWork{}, DeepWork.capture().difference(owned_before));
            const cold_before = DeepWork.capture();
            try std.testing.expectError(error.InvalidRecording, rows.validate());
            const cold_work = DeepWork.capture().difference(cold_before);
            if (builtin.is_test) try std.testing.expect(cold_work.execution_attempts > 0);
            progress("ETHEREUM_ROOT_COHORT transcript_operational_rows_owned=true changed_live_execution_rejected=true\n", .{});
        }
        const cohort = try Cohort.init(producer.allocator(), geometry);
        defer cohort.deinit();
        if (materialized.base.input.fixed_program != null) {
            const mutation_work = DeepWork.capture();
            defer phase.mutation_work.add(DeepWork.capture().difference(mutation_work));
            // A completed constructor cannot grant lasting permission to trust
            // this borrowed source. External entry points must reject changes
            // before touching a destination or starting another preparation.
            const profile = &@constCast(materialized).base.input.stage101.profile;
            const descriptor = profile.fixed_program;
            defer profile.fixed_program = descriptor;
            profile.fixed_program = null;
            const invalid_relations = Relations.dummy();
            const invalid_providers = try ProviderRelations.init(&invalid_relations);
            try std.testing.expectError(error.EthereumFixedProgramAdmissionRequired, Cohort.init(producer.allocator(), geometry));
            try std.testing.expectError(error.EthereumFixedProgramAdmissionRequired, cohort.validate());
            try std.testing.expectError(error.EthereumFixedProgramAdmissionRequired, cohort.fillInteractionInto(&invalid_relations, &invalid_providers, &.{}));
            progress("ETHEREUM_ROOT_COHORT changed_borrowed_source_rejected=true constructor=true validate=true tree2=true\n", .{});
        }
        const manifest = try cohort.manifest();
        const closure = try cohort.tupleClosure();
        try std.testing.expect(closure.isClosed());
        try std.testing.expectEqual(@as(u16, 15), manifest_mod.SCHEMA_VERSION);
        try std.testing.expectEqual(@as(u32, Contract.COMPONENT_COUNT), manifest.roster_count);
        if (!initial) try std.testing.expectEqual(@as(u32, 619), manifest.total_preprocessed_columns);
        try std.testing.expectEqual(@as(u32, 2), materialized.base.composition.program().input_profile.vm_statement_root_count);
        try phase.finish(&producer);
        progress("ETHEREUM_ROOT_COHORT source_tuple_closure=true contributions={d} components={d} tree2_value_bytes={d} pcs=false native_proving=false\n", .{ closure.contribution_count, Contract.COMPONENT_COUNT, try tree2Bytes(manifest) });

        // Deterministic public challenges exercise the real writers/auditors;
        // this is a development closure gate, not Fiat-Shamir proof admission.
        const relations = try deterministicRelations(allocator);
        const providers = try ProviderRelations.init(&relations);
        if (builtin.is_test) {
            phase = try Phase.begin("native_prepared_regression", Contract.COMPONENT_COUNT);
            const allocation_before = producer.snapshot();
            const suffix = (try geometry.geometryView()).suffix;
            const native = (try suffix.geometryView()).native;
            const Native = @import("recursive_common_ethereum_incremental_leaf_native_core_v4.zig").OwnerV4(Engine);
            const receipt = try Native.testing.exercisePreparedRegression(@constCast(native), producer.allocator(), &relations, &providers);
            const allocation_after = producer.snapshot();
            try phase.finish(&producer);
            progress("ETHEREUM_ROOT_COHORT diagnostic=native_prepared_regression legacy_ns={d} native_ns={d} retained_input_bytes={d} allocator_before_bytes={d} allocator_after_bytes={d} tree2_sha256={s}\n", .{ receipt.legacy_ns, receipt.native_ns, receipt.retained_input_bytes, allocation_before.active_bytes, allocation_after.active_bytes, std.fmt.bytesToHex(receipt.tree2_sha256, .lower) });
        }
        phase = try Phase.begin("tree2_generate", Contract.COMPONENT_COUNT);
        const generated = try cohort.rebuildGeneratedInteractions(&relations, &providers);
        try phase.finish(&producer);
        phase = try Phase.begin("producer_closure", Contract.COMPONENT_COUNT);
        try generated.validateStructure();
        try generated.claims.validate(manifest);
        try generated.closure.validate();
        try phase.finish(&producer);
        phase = try Phase.begin("serialize", Contract.COMPONENT_COUNT);
        const bytes = try std.json.Stringify.valueAlloc(allocator, Publication{ .manifest = manifest.*, .generated = generated }, .{});
        errdefer allocator.free(bytes);
        try phase.finish(&producer);
        phase = try Phase.begin("producer_destroy", Contract.COMPONENT_COUNT);
        break :blk bytes;
    };
    defer allocator.free(serialized);
    try producer.requireEmpty();
    try phase.finish(&producer);
    progress("ETHEREUM_ROOT_COHORT producer_destroyed=true serialized_bytes={d}\n", .{serialized.len});

    var verifier = runtime.TrackedSmpAllocatorV4{};
    defer verifier.requireEmpty() catch @panic("cohort replay verifier ownership leak");
    phase = try Phase.begin("cold_prepare", Contract.COMPONENT_COUNT);
    {
        // The materialized source was independently native-verified before this
        // helper. Rebuild the cohort after producer destruction; no producer
        // rows, provider state, or retained Tree2 enters here. The decoded
        // Generated value is untrusted transport checked against these new rows.
        const geometry = try Geometry.init(verifier.allocator(), materialized);
        defer geometry.deinit();
        const cold = try Cohort.init(verifier.allocator(), geometry);
        defer cold.deinit();
        const cold_manifest = try cold.manifest();
        const decoded = try std.json.parseFromSlice(std.json.Value, allocator, serialized, .{ .allocate = .alloc_always });
        defer decoded.deinit();
        const publication = try parseReplayObject(Publication, Complete.Generated, decoded.arena.allocator(), decoded.value);
        const published = &publication;
        if (published.format_version != 1 or published.component_count != Contract.COMPONENT_COUNT)
            return error.InvalidCohortReplayPublication;
        try published.manifest.validate();
        try std.testing.expectEqualDeep(cold_manifest.*, published.manifest);
        try published.generated.claims.validate(cold_manifest);
        const relations = try deterministicRelations(allocator);
        const providers = try ProviderRelations.init(&relations);
        try phase.finish(&verifier);
        // Invalid retained audit bytes cannot bypass the independent cold audit.
        var changed = published.generated;
        changed.identity_sha256[0] ^= 1;
        try std.testing.expectError(error.EthereumIncrementalCompleteCohortMismatchV4, changed.validateStructure());
        phase = try Phase.begin("cold_tree2", Contract.COMPONENT_COUNT);
        // Rebuild every claim and audit from fresh rows. validateGenerated alone
        // accepts the native audit envelope; it does not recompute rows18..34.
        const expected = try cold.rebuildGeneratedInteractions(&relations, &providers);
        try std.testing.expectEqualDeep(expected, published.generated);
        try phase.finish(&verifier);
        phase = try Phase.begin("cold_closure", Contract.COMPONENT_COUNT);
        // Also exercise the independent prefix/suffix row auditor, rather than
        // relying only on agreement between two runs of the fused Tree2 writer.
        // Native audits are authenticated by the complete comparison above.
        try cold.validateGenerated(&published.generated, &relations, &providers);
        try phase.finish(&verifier);
        phase = try Phase.begin("verifier_destroy", Contract.COMPONENT_COUNT);
    }
    try verifier.requireEmpty();
    try phase.finish(&verifier);
    progress("ETHEREUM_ROOT_COHORT complete=true components={d} tree2_generated=true serialized=true producer_destroyed=true independent_cold_closure=true verifier_destroyed=true pcs=false native_proving=false wrapper_proof=false\n", .{Contract.COMPONENT_COUNT});
}

// Replay-only transport: retain the protocol layout by reflection. Zig's JSON
// writer omits void struct fields, but its standard decoder cannot parse void.
// Require every non-void field exactly once and reject any supplied void field.
fn parseReplayObject(comptime T: type, comptime Generated: type, allocator: std.mem.Allocator, value: std.json.Value) !T {
    if (value != .object) return error.InvalidCohortReplayPublication;
    const fields = @typeInfo(T).@"struct".fields;
    const serialized_field_count = comptime blk: {
        var count: usize = 0;
        for (fields) |field| if (field.type != void) {
            count += 1;
        };
        break :blk count;
    };
    if (value.object.count() != serialized_field_count) return error.InvalidCohortReplayPublication;
    var result: T = undefined;
    inline for (fields) |field| {
        if (field.type == void) {
            @field(result, field.name) = {};
            continue;
        }
        const item = value.object.get(field.name) orelse return error.InvalidCohortReplayPublication;
        @field(result, field.name) = if (field.type == Generated)
            try parseReplayObject(Generated, Generated, allocator, item)
        else
            try std.json.parseFromValueLeaky(field.type, allocator, item, .{});
    }
    return result;
}

fn deterministicRelations(allocator: std.mem.Allocator) !Relations {
    var channel = recursion.poseidon2_channel.Channel{};
    channel.mixU32s(&.{ 0x4554_4331, 1 }); // ETC1, development replay version1.
    const relations = try Relations.draw(allocator, &channel);
    try relations.validate();
    return relations;
}

fn tree2Bytes(manifest: anytype) !u64 {
    var count: u64 = 0;
    for (manifest.placements) |placement| {
        const geometry = (placement orelse return error.InvalidCohortReplayPublication).geometry;
        const rows: u64 = @as(u64, 1) << @intCast(geometry.log_size);
        const column_bytes = try std.math.mul(u64, rows, @sizeOf(M31));
        count = try std.math.add(u64, count, try std.math.mul(u64, column_bytes, geometry.interaction_columns));
    }
    return count;
}

// Phase-local differences of process-wide test counters. The retained replay
// runs its admission/read phases synchronously; workers are joined at snapshots.
// These are attempted audit inventories, not timings or proof authority.
const DeepWork = struct {
    replay_attempts: u64 = 0,
    replay_completions: u64 = 0,
    execution_attempts: u64 = 0,
    execution_completions: u64 = 0,
    operations: u64 = 0,
    poseidon_calls: u64 = 0,
    frames: u64 = 0,
    words: u64 = 0,
    evaluation_attempts: u64 = 0,
    evaluation_completions: u64 = 0,
    evaluation_nodes: u64 = 0,
    evaluation_bindings: u64 = 0,
    fri_attempts: u64 = 0,
    fri_completions: u64 = 0,
    fri_nodes: u64 = 0,
    pcs_attempts: u64 = 0,
    pcs_completions: u64 = 0,
    pcs_nodes: u64 = 0,

    fn capture() DeepWork {
        if (!builtin.is_test) return .{};
        const replay = @import("recursive_common_ethereum_incremental_leaf_transcript_v4.zig").testing.snapshot();
        const execution = recursion.recording_poseidon_channel_v4.testing.snapshot();
        const evaluation = @import("recursive_common_ethereum_incremental_leaf_public_sums_v4.zig").testing.snapshot();
        const fri = recursion.air.fri_verifier_circuit.Circuit.testing.snapshot();
        const pcs = recursion.air.pcs_deep_circuit.Circuit.testing.snapshot();
        return .{
            .replay_attempts = replay.attempts,
            .replay_completions = replay.completions,
            .execution_attempts = execution.attempts,
            .execution_completions = execution.completions,
            .operations = execution.operations,
            .poseidon_calls = execution.poseidon_calls,
            .frames = execution.frames,
            .words = execution.words,
            .evaluation_attempts = evaluation.attempts,
            .evaluation_completions = evaluation.completions,
            .evaluation_nodes = evaluation.nodes,
            .evaluation_bindings = evaluation.bindings,
            .fri_attempts = fri.attempts,
            .fri_completions = fri.completions,
            .fri_nodes = fri.nodes,
            .pcs_attempts = pcs.attempts,
            .pcs_completions = pcs.completions,
            .pcs_nodes = pcs.nodes,
        };
    }

    fn difference(self: DeepWork, before: DeepWork) DeepWork {
        var result: DeepWork = .{};
        inline for (@typeInfo(DeepWork).@"struct".fields) |field|
            @field(result, field.name) = @field(self, field.name) - @field(before, field.name);
        return result;
    }

    fn add(self: *DeepWork, value: DeepWork) void {
        inline for (@typeInfo(DeepWork).@"struct".fields) |field|
            @field(self, field.name) += @field(value, field.name);
    }

    fn print(self: DeepWork, phase: []const u8, scope: []const u8) void {
        if (!builtin.is_test) return;
        progress("ETHEREUM_ROOT_COHORT_GRAPH_AUDIT phase={s} scope={s} fri_attempts={d} fri_completions={d} attempted_fri_nodes={d} pcs_attempts={d} pcs_completions={d} attempted_pcs_nodes={d}\n", .{ phase, scope, self.fri_attempts, self.fri_completions, self.fri_nodes, self.pcs_attempts, self.pcs_completions, self.pcs_nodes });
        progress("ETHEREUM_ROOT_COHORT_VALIDATION phase={s} scope={s} replay_attempts={d} replay_completions={d} execution_attempts={d} execution_completions={d} attempted_operations={d} attempted_poseidon_calls={d} attempted_frames={d} attempted_words={d} evaluation_attempts={d} evaluation_completions={d} attempted_evaluation_nodes={d} attempted_evaluation_bindings={d}\n", .{ phase, scope, self.replay_attempts, self.replay_completions, self.execution_attempts, self.execution_completions, self.operations, self.poseidon_calls, self.frames, self.words, self.evaluation_attempts, self.evaluation_completions, self.evaluation_nodes, self.evaluation_bindings });
    }
};

const Phase = struct {
    name: []const u8,
    components: usize,
    timer: std.time.Timer,
    before: process_usage.Snapshot,
    mutation_regression_ns: u64 = 0,
    work_before: DeepWork,
    mutation_work: DeepWork = .{},

    fn begin(name: []const u8, components: usize) !Phase {
        progress("ETHEREUM_ROOT_COHORT phase={s} components={d} begin=true\n", .{ name, components });
        return .{ .name = name, .components = components, .timer = try std.time.Timer.start(), .before = try process_usage.sample(), .work_before = DeepWork.capture() };
    }

    fn finish(self: *Phase, tracked: *runtime.TrackedSmpAllocatorV4) !void {
        const after = try process_usage.sample();
        const delta = try process_usage.difference(self.before, after);
        const memory = tracked.snapshot();
        const inclusive_ns = self.timer.read();
        const work = DeepWork.capture().difference(self.work_before);
        work.print(self.name, "inclusive");
        self.mutation_work.print(self.name, "mutation_regression");
        work.difference(self.mutation_work).print(self.name, "excluding_mutation_regression");
        if (builtin.is_test and std.mem.eql(u8, self.name, "cold_prepare")) {
            try std.testing.expect(work.execution_completions > 0);
            try std.testing.expect(work.poseidon_calls > 0);
            try std.testing.expect(work.evaluation_completions > 0);
            try std.testing.expect(work.evaluation_nodes > 0);
            try std.testing.expect(work.fri_completions > 0);
            try std.testing.expect(work.fri_nodes > 0);
        }
        progress("ETHEREUM_ROOT_COHORT phase={s} components={d} ns={d} process_cpu_ns={?d} current_footprint_bytes={?d} lifetime_peak_footprint_bytes={?d} allocator_live_bytes={d} allocator_peak_bytes={d}\n", .{ self.name, self.components, inclusive_ns, delta.process_cpu_ns, after.current_physical_footprint_bytes, delta.lifetime_peak_physical_footprint_bytes, memory.active_bytes, memory.peak_active_bytes });
        if (self.mutation_regression_ns != 0) {
            progress("ETHEREUM_ROOT_COHORT phase={s} inclusive_ns={d} mutation_regression_ns={d} excluding_mutation_regression_ns={d}\n", .{ self.name, inclusive_ns, self.mutation_regression_ns, inclusive_ns - self.mutation_regression_ns });
        }
    }
};

pub fn exercisePublicationCodec() !void {
    // The view aliases one array across mutation; the retained digest must not.
    var row_values = [_]u32{ 1, 2, 3 };
    const row_view = .{ .rows = @as([]const u32, &row_values) };
    const before_mutation = preparedRowsDigest(row_view);
    row_values[1] = 7;
    try std.testing.expect(!std.meta.eql(before_mutation, preparedRowsDigest(row_view)));

    inline for (.{
        struct { claims: [2]u32 = .{ 17, 29 }, initial_claims: void = {} },
        struct { claims: [2]u32 = .{ 17, 29 }, initial_claims: [2]u32 = .{ 31, 43 } },
    }) |Generated| {
        const Publication = struct { format_version: u16 = 1, generated: Generated = .{} };
        const bytes = try std.json.Stringify.valueAlloc(std.testing.allocator, Publication{}, .{});
        defer std.testing.allocator.free(bytes);
        const parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, bytes, .{});
        defer parsed.deinit();
        const allocator = parsed.arena.allocator();
        const value = try parseReplayObject(Publication, Generated, allocator, parsed.value);
        try std.testing.expectEqualDeep(Publication{}, value);
        const generated = parsed.value.object.getPtr("generated").?;
        if (@TypeOf(value.generated.initial_claims) == void) {
            try std.testing.expect(!generated.object.contains("initial_claims"));
            try generated.object.put("initial_claims", .null);
            try std.testing.expectError(error.InvalidCohortReplayPublication, parseReplayObject(Publication, Generated, allocator, parsed.value));
            generated.object.getPtr("initial_claims").?.* = .{ .integer = 1 };
            try std.testing.expectError(error.InvalidCohortReplayPublication, parseReplayObject(Publication, Generated, allocator, parsed.value));
            try std.testing.expect(generated.object.swapRemove("initial_claims"));
        } else {
            const initial_claims = generated.object.getPtr("initial_claims").?;
            const original = initial_claims.*;
            initial_claims.* = .null;
            try std.testing.expectError(error.UnexpectedToken, parseReplayObject(Publication, Generated, allocator, parsed.value));
            initial_claims.* = original;
        }
        const original = generated.object.get("claims").?;
        try std.testing.expect(generated.object.swapRemove("claims"));
        try std.testing.expectError(error.InvalidCohortReplayPublication, parseReplayObject(Publication, Generated, allocator, parsed.value));
        try generated.object.put("unexpected", original);
        try std.testing.expectError(error.InvalidCohortReplayPublication, parseReplayObject(Publication, Generated, allocator, parsed.value));
    }
}
