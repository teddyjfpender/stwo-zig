//! Cairo proving orchestration over the resident Metal arena.

const std = @import("std");
const arena_plan = @import("stwo_metal_backend").arena_plan;
const schedule_bindings = @import("schedule_bindings.zig");
const metal_runtime = @import("stwo_metal_backend").runtime;
const protocol_recipes = @import("stwo_metal_backend").protocol_recipes;
const transcript_fixture = @import("diagnostics/transcript_fixture.zig");
const composition_bundle_mod = @import("stwo_cairo_frontend").witness.composition_bundle;
const fixed_table_bundle_mod = @import("stwo_cairo_frontend").witness.fixed_table_bundle;
const relation_bundle_mod = @import("stwo_cairo_frontend").witness.relation_bundle;
const witness_bundle_mod = @import("stwo_cairo_frontend").witness.bundle;
const eval_codegen = @import("eval_codegen.zig");
const cairo_proof_plan = @import("stwo_cairo_frontend").proof_plan;
const commitment_ordering = @import("resident/commitment/ordering.zig");
const commitment_telemetry = @import("resident/commitment/telemetry.zig");
const composition_config = @import("resident/composition/config.zig");
const fixed_tables = @import("resident/lookups/fixed_tables.zig");
const multiplicity_feeds = @import("resident/lookups/multiplicity_feeds.zig");
const preprocessed_bindings = @import("resident/preprocessed/bindings.zig");
const preprocessed_coefficients_mod = @import("resident/preprocessed/coefficients.zig");
const preprocessed_storage = @import("resident/preprocessed/storage.zig");
const relation_claims = @import("resident/relations/claims.zig");
const relation_components = @import("resident/relations/components.zig");
const interaction_diagnostics = @import("resident/interaction/diagnostics.zig");
const interaction_execute = @import("resident/interaction/execute.zig");
const resident_binding = @import("resident/binding.zig");
const resident_errors = @import("resident/errors.zig");
const trace_diagnostics = @import("resident/trace/diagnostics.zig");
const trace_interpolation = @import("resident/trace/interpolation.zig");
const transcript_operations = @import("resident/transcript/operations.zig");
const resident_twiddles = @import("resident/twiddles.zig");
const witness_execute = @import("resident/witness/execute.zig");
const witness_inputs = @import("resident/witness/inputs.zig");
const witness_prepare = @import("resident/witness/prepare.zig");
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const circle_poly_mod = @import("stwo_prover_engine").poly.circle.poly;
const canonic_circle_mod = @import("stwo_core").poly.circle.canonic;
const CairoMerkleHasher = @import("stwo_core").vcs_lifted.blake2_merkle.Blake2sPlainMerkleHasher;

const cairo_domain_prefix_bytes = CairoMerkleHasher.domainPrefixBytes();

pub const Error = resident_errors.Error;

pub const Sn2Counts = schedule_bindings.Sn2Counts;
pub const WitnessRecipeRequirements = witness_prepare.WitnessRecipeRequirements;
pub const WitnessRecipes = witness_prepare.WitnessRecipes;

pub const OrdinalBinding = schedule_bindings.OrdinalBinding;
pub const NamedBinding = schedule_bindings.NamedBinding;

pub const DecommitTraceCoefficientBindings = schedule_bindings.DecommitTraceCoefficientBindings;
pub const DecommitTraceGroupBindings = schedule_bindings.DecommitTraceGroupBindings;
pub const DecommitTraceTreeBindings = schedule_bindings.DecommitTraceTreeBindings;
pub const DecommitFriTreeBindings = schedule_bindings.DecommitFriTreeBindings;
pub const TraceTreeRole = schedule_bindings.TraceTreeRole;
pub const TraceTreeGeometry = schedule_bindings.TraceTreeGeometry;
pub const FriTreeGeometry = schedule_bindings.FriTreeGeometry;
pub const ProofDecommitGeometry = schedule_bindings.ProofDecommitGeometry;

const collectDecommitBindings = schedule_bindings.collectDecommitBindings;
const collectSn2DecommitBindings = schedule_bindings.collectSn2DecommitBindings;
const friStartLog = schedule_bindings.friStartLog;

const NamedGroupRange = schedule_bindings.NamedGroupRange;
const purpose = schedule_bindings.purpose;
const logicalId = schedule_bindings.logicalId;
const ordinal = schedule_bindings.ordinal;
const componentName = schedule_bindings.componentName;
const one = schedule_bindings.one;
const oneOrdinal = schedule_bindings.oneOrdinal;
const oneComponent = schedule_bindings.oneComponent;
const oneComponentOrdinal = schedule_bindings.oneComponentOrdinal;
const collect = schedule_bindings.collect;
const collectOrdinals = schedule_bindings.collectOrdinals;
const collectScheduleOrder = schedule_bindings.collectScheduleOrder;
const collectComponent = schedule_bindings.collectComponent;
const collectComponentBindingGroups = schedule_bindings.collectComponentBindingGroups;
const collectNamed = schedule_bindings.collectNamed;
const namedGroupRanges = schedule_bindings.namedGroupRanges;

const canonicalClaimedSumBindings = relation_claims.canonicalClaimedSumBindings;
const collectPreprocessedBindings = preprocessed_bindings.collect;
const canonicalTraceTree = commitment_ordering.canonicalTraceTree;
const collectCommitmentOrder = commitment_ordering.collectCommitmentOrder;
const collectTreePurpose = commitment_ordering.collectTreePurpose;
const commitmentOrderCopy = commitment_ordering.commitmentOrderCopy;
const reorderTraceQueryValues = commitment_ordering.reorderTraceQueryValues;

const prepared_proof = @import("arena_binding/prepared_proof.zig");
const prepared_validation = @import("arena_binding/prepared_validation.zig");
const composition_recipe = @import("arena_binding/composition_recipe.zig");
const proof_assembly = @import("arena_binding/proof_assembly.zig");
const streaming_commitment = @import("arena_binding/streaming_commitment.zig");

pub const PreparedProofBindings = prepared_proof.PreparedProofBindings;
pub const ProofCopy = proof_assembly.ProofCopy;
pub const CommitmentTelemetry = streaming_commitment.CommitmentTelemetry;
pub const StreamingCommitmentBenchmarkMode = streaming_commitment.BenchmarkMode;
pub const executeStreamingCommitmentBenchmark = streaming_commitment.executeBenchmark;

const proofCopyTranscriptOrdinals = proof_assembly.proofCopyTranscriptOrdinals;
const compositionRandomCoefficientBase = composition_recipe.randomCoefficientBase;
const validateDisjointBindings = prepared_validation.validateDisjointBindings;
const validateDisjointActiveBindings = prepared_validation.validateDisjointActiveBindings;
const wordOffset = resident_binding.wordOffset;

pub const RelationComponentTelemetry = relation_components.RelationComponentTelemetry;
pub const RelationComponentOperation = relation_components.RelationComponentOperation;
pub const PreparedRelationComponents = relation_components.PreparedRelationComponents;

pub const populateExecutionTables = preprocessed_coefficients_mod.populateExecutionTables;
pub const populatePreprocessedCoefficients = preprocessed_coefficients_mod.populatePreprocessedCoefficients;
pub const PreprocessedCoefficientLoad = preprocessed_coefficients_mod.PreprocessedCoefficientLoad;
pub const populateUnreconstructedPreprocessedCoefficients = preprocessed_coefficients_mod.populateUnreconstructedPreprocessedCoefficients;
pub const evaluatePreprocessedCoefficients = preprocessed_coefficients_mod.evaluatePreprocessedCoefficients;

pub const spillPreprocessedEvaluations = preprocessed_storage.spillPreprocessedEvaluations;
pub const spillRetainedMerkleLayers = preprocessed_storage.spillRetainedMerkleLayers;
pub const restoreRetainedMerkleLayers = preprocessed_storage.restoreRetainedMerkleLayers;
pub const restorePreprocessedEvaluations = preprocessed_storage.restorePreprocessedEvaluations;
pub const restoreFixedTablePreprocessedEvaluations = preprocessed_storage.restoreFixedTablePreprocessedEvaluations;

pub const populateProtocolTwiddles = resident_twiddles.populateProtocolTwiddles;
pub const populateForwardTwiddles = resident_twiddles.populateForwardTwiddles;
pub const populateNamedInverseTwiddles = resident_twiddles.populateNamedInverseTwiddles;
pub const populateQuotientInverseTwiddles = resident_twiddles.populateQuotientInverseTwiddles;

const populateInverseTwiddles = resident_twiddles.populateInverseTwiddles;
const populateForwardTwiddleBinding = resident_twiddles.populateForwardTwiddleBinding;
const twiddleBankBinding = resident_twiddles.twiddleBankBinding;
const twiddleBindingForLog = resident_twiddles.twiddleBindingForLog;
const twiddleOffsetForLog = resident_twiddles.twiddleOffsetForLog;

pub const TranscriptBootstrapValidationOptions = transcript_fixture.TranscriptBootstrapValidationOptions;
pub const validateTranscriptBootstrap = transcript_fixture.validateTranscriptBootstrap;
pub const restoreTranscriptBootstrap = transcript_fixture.restoreTranscriptBootstrap;

pub const prepareFixedTableBatch = fixed_tables.prepareFixedTableBatch;
pub const fixedLookupIndex = fixed_tables.fixedLookupIndex;

pub const MultiplicityFeedBatch = multiplicity_feeds.MultiplicityFeedBatch;
pub const prepareEcOpWitness = witness_prepare.prepareEcOpWitness;
pub const prepareAotWitnessBatch = witness_prepare.prepareAotWitnessBatch;
pub const prepareAotInteractionBatch = witness_prepare.prepareAotInteractionBatch;
pub const AuthenticatedAotWitnessBatches = witness_prepare.AuthenticatedAotWitnessBatches;
pub const prepareAuthenticatedAotWitnessBatches = witness_prepare.prepareAuthenticatedAotWitnessBatches;

pub const prepareMultiplicityFeedBatch = multiplicity_feeds.prepareMultiplicityFeedBatch;

pub fn clearFixedMultiplicities(
    allocator: std.mem.Allocator,
    metal: *metal_runtime.Runtime,
    resident_arena: *arena_plan.ResidentArena,
    schedule: []const std.json.Value,
    plan: arena_plan.Plan,
) !void {
    const bindings = try collectScheduleOrder(allocator, schedule, plan, "FixedMultiplicity");
    defer allocator.free(bindings);
    const ranges = try allocator.alloc([2]u32, bindings.len);
    defer allocator.free(ranges);
    for (bindings, ranges) |binding, *range| {
        if (binding.size_bytes % 4 != 0) return Error.InvalidBindingSize;
        range.* = .{
            try wordOffset(binding),
            std.math.cast(u32, binding.size_bytes / 4) orelse return Error.InvalidBindingSize,
        };
    }
    try metal.clearArenaRanges(resident_arena.buffer, ranges);
}

pub const RecordedBaseInterpolationBatch = trace_interpolation.RecordedBaseInterpolationBatch;
pub const NativeBaseInterpolationBatch = trace_interpolation.NativeBaseInterpolationBatch;
pub const prepareRecordedBaseInterpolation = trace_interpolation.prepareRecordedBaseInterpolation;
pub const prepareNativeBaseInterpolation = trace_interpolation.prepareNativeBaseInterpolation;
const prepareComponentInterpolationGroupsForPurposes = trace_interpolation.prepareComponentInterpolationGroupsForPurposes;
pub const interpolateTraceColumns = trace_interpolation.interpolateTraceColumns;
pub const interpolateAvailablePreprocessedColumns = trace_interpolation.interpolateAvailablePreprocessedColumns;

pub const populateCasmWitnessInputs = witness_inputs.populateCasmWitnessInputs;
pub const populateBuiltinSeedWitnessInputs = witness_inputs.populateBuiltinSeedWitnessInputs;
pub const populateDirectWitnessInput = witness_inputs.populateDirectWitnessInput;

pub const WitnessEdge = witness_execute.WitnessEdge;
pub const prepareCompactWitnessInput = witness_execute.prepareCompactWitnessInput;
pub const WitnessExecutionTelemetry = witness_execute.WitnessExecutionTelemetry;
pub const executeRecordedWitnessGraph = witness_execute.executeRecordedWitnessGraph;
pub const executeNativeEcConsumer = witness_execute.executeNativeEcConsumer;
pub const executeScheduledWitnessGraph = witness_execute.executeScheduledWitnessGraph;
pub const InteractionExecutionTelemetry = interaction_execute.InteractionExecutionTelemetry;
pub const executeScheduledInteractionGraph = interaction_execute.executeScheduledInteractionGraph;
pub const logComponentInteractionDigests = interaction_diagnostics.logComponentInteractionDigests;
pub const logComponentBaseEvalDigests = trace_diagnostics.logComponentBaseEvalDigests;
pub const logInteractionCoefficientDigests = interaction_diagnostics.logInteractionCoefficientDigests;
pub const logLogicalBindingDigest = interaction_diagnostics.logLogicalBindingDigest;

pub const gatherWitnessInput = witness_execute.gatherWitnessInput;

test "Cairo proof assembly uses seven runtime FRI roots" {
    const ordinals = try proofCopyTranscriptOrdinals(std.testing.allocator, 7);
    defer std.testing.allocator.free(ordinals);
    try std.testing.expectEqualSlices(u32, &.{
        3,     20,    23,    24,    22,    21,    25,
        65536, 65540, 65544, 65548, 65552, 65556, 65560,
        30,    31,
    }, ordinals);
}

test "Cairo proof assembly preserves eight-root SN2 order" {
    const ordinals = try proofCopyTranscriptOrdinals(std.testing.allocator, 8);
    defer std.testing.allocator.free(ordinals);
    try std.testing.expectEqualSlices(u32, &.{
        3,     20,    23,    24,    22,    21,    25,
        65536, 65540, 65544, 65548, 65552, 65556, 65560,
        65564, 30,    31,
    }, ordinals);
}

test "Cairo schedule-order collection accepts component-local ordinals" {
    var plan_bindings = [_]arena_plan.Binding{
        .{
            .logical_id = 40,
            .slot = 0,
            .offset_bytes = 0,
            .size_bytes = 16,
            .materialization = .resident,
            .occupied = [_]u64{0} ** 16,
        },
        .{
            .logical_id = 41,
            .slot = 1,
            .offset_bytes = 16,
            .size_bytes = 16,
            .materialization = .resident,
            .occupied = [_]u64{0} ** 16,
        },
    };
    var empty_slots: [0]arena_plan.Slot = .{};
    var empty_actions: [0]arena_plan.Action = .{};
    var empty_offsets: [0]usize = .{};
    const plan = arena_plan.Plan{
        .allocator = std.testing.allocator,
        .bindings = &plan_bindings,
        .slots = &empty_slots,
        .actions = &empty_actions,
        .action_offsets = &empty_offsets,
        .total_bytes = 32,
        .peak_live_bytes = 32,
        .plan_hash = 0,
    };
    var parsed = try std.json.parseFromSlice(
        std.json.Value,
        std.testing.allocator,
        \\[
        \\  {"purpose":"FixedMultiplicity","component":"range_check_8","ordinal":0,"id":41},
        \\  {"purpose":"FixedMultiplicity","component":"range_check_6","ordinal":0,"id":40}
        \\]
    ,
        .{},
    );
    defer parsed.deinit();
    const collected = try collectScheduleOrder(
        std.testing.allocator,
        parsed.value.array.items,
        plan,
        "FixedMultiplicity",
    );
    defer std.testing.allocator.free(collected);
    try std.testing.expectEqual(@as(usize, 2), collected.len);
    try std.testing.expectEqual(@as(u32, 41), collected[0].logical_id);
    try std.testing.expectEqual(@as(u32, 40), collected[1].logical_id);
}

test "Cairo relation component groups preserve instance boundaries" {
    const bindings = [_]NamedBinding{
        .{ .component = "memory_id_to_big", .ordinal = 0, .binding = undefined },
        .{ .component = "memory_id_to_big", .ordinal = 1, .binding = undefined },
        .{ .component = "memory_id_to_big", .ordinal = 0, .binding = undefined },
        .{ .component = "memory_id_to_big", .ordinal = 1, .binding = undefined },
        .{ .component = "memory_id_to_big", .ordinal = 2, .binding = undefined },
    };
    const ranges = try namedGroupRanges(std.testing.allocator, &bindings);
    defer std.testing.allocator.free(ranges);
    try std.testing.expectEqual(@as(usize, 2), ranges.len);
    try std.testing.expectEqual(NamedGroupRange{ .start = 0, .len = 2 }, ranges[0]);
    try std.testing.expectEqual(NamedGroupRange{ .start = 2, .len = 3 }, ranges[1]);

    const invalid = [_]NamedBinding{
        .{ .component = "memory_id_to_big", .ordinal = 0, .binding = undefined },
        .{ .component = "memory_id_to_big", .ordinal = 2, .binding = undefined },
    };
    try std.testing.expectError(Error.InvalidSchedule, namedGroupRanges(std.testing.allocator, &invalid));
}

test "Cairo composition parts address global random coefficient powers" {
    var composition = try composition_bundle_mod.Bundle.readFile(
        std.testing.allocator,
        "vectors/cairo/sn_pie_2_composition.bin",
    );
    defer composition.deinit();

    var saw_nonzero_component_offset = false;
    for (composition.components) |component| {
        saw_nonzero_component_offset = saw_nonzero_component_offset or component.random_coefficient_offset != 0;
        for (component.parts) |part| {
            const base = try compositionRandomCoefficientBase(
                component.random_coefficient_offset,
                part.rc_base,
            );
            try std.testing.expectEqual(component.random_coefficient_offset + part.rc_base, base);
            try std.testing.expect(base + part.program.header.n_constraints <= composition.total_constraints);
        }
    }
    try std.testing.expect(saw_nonzero_component_offset);
    try std.testing.expectError(
        Error.InvalidBindingSize,
        compositionRandomCoefficientBase(std.math.maxInt(u32), 1),
    );
}

test "Cairo composition workspace rejects inverse twiddle aliases" {
    var inverse_twiddles = arena_plan.Binding{
        .logical_id = 1,
        .slot = 1,
        .offset_bytes = 469_778_432,
        .size_bytes = 33_554_432,
        .materialization = .resident,
        .occupied = [_]u64{0} ** 16,
    };
    const accumulators = arena_plan.Binding{
        .logical_id = 2,
        .slot = 2,
        .offset_bytes = 16_384,
        .size_bytes = 536_852_992,
        .materialization = .resident,
        .occupied = [_]u64{0} ** 16,
    };
    try std.testing.expectError(
        Error.InvalidBindingAlias,
        validateDisjointBindings(inverse_twiddles, accumulators),
    );
    try validateDisjointActiveBindings(inverse_twiddles, accumulators);

    inverse_twiddles.occupied[0] = 1;
    var active_accumulators = accumulators;
    active_accumulators.occupied[0] = 1;
    try std.testing.expectError(
        Error.InvalidBindingAlias,
        validateDisjointActiveBindings(inverse_twiddles, active_accumulators),
    );

    inverse_twiddles.offset_bytes = accumulators.offset_bytes + accumulators.size_bytes;
    try validateDisjointBindings(inverse_twiddles, accumulators);

    inverse_twiddles.offset_bytes = std.math.maxInt(u64) - inverse_twiddles.size_bytes + 1;
    try std.testing.expectError(
        Error.InvalidBindingSize,
        validateDisjointBindings(inverse_twiddles, accumulators),
    );
}

test "Cairo component-local relation preparation rejects an empty claim layout" {
    var bindings: PreparedProofBindings = undefined;
    bindings.relation_claimed_sums = &.{};
    try std.testing.expectError(
        Error.InvalidClaimedSumCount,
        bindings.prepareRelationComponents(
            std.testing.allocator,
            undefined,
            undefined,
            &.{},
            undefined,
            undefined,
            undefined,
            undefined,
        ),
    );
}
