//! Locked SN2 unified-arena assertions for the authenticated input fixture.

const std = @import("std");
const telemetry = @import(
    "../../../backends/cuda/runtime/telemetry.zig",
);
const resident_plan = @import("resident_plan.zig");

pub fn assert(
    resident: resident_plan.Plan,
    ingress: resident_plan.IngressGeometry,
) !void {
    try std.testing.expectEqual(@as(u32, 57), ingress.writer.launch_count);
    try std.testing.expectEqual(@as(u32, 58), ingress.relation.instance_count);
    try std.testing.expectEqual(
        @as(u32, 279),
        ingress.evaluation.placement_count,
    );
    try std.testing.expectEqual(
        @as(u64, 40_525_637),
        ingress.adapted_input_words,
    );
    try std.testing.expectEqual(
        @as(u64, 4_724_225_600),
        ingress.writer.scratch_words,
    );
    try std.testing.expectEqual(
        @as(u64, 1_356_284_992),
        ingress.relation.denominator_words,
    );
    try std.testing.expectEqual(
        @as(u64, 1_356_284_992),
        ingress.relation.output_coordinate_words,
    );
    try std.testing.expectEqual(
        @as(u64, 1_493_172_224),
        ingress.evaluation.lde_tile_words,
    );
    try std.testing.expectEqual(
        @as(u32, 18),
        ingress.evaluation.composition_log_count,
    );
    try std.testing.expectEqual(
        @as(u64, 100_662_912),
        ingress.evaluation.composition_accumulator_words,
    );
    try std.testing.expectEqual(
        @as(u64, 63_984_539_100),
        resident.summary.allocatedResidentBytes(),
    );
    try std.testing.expectEqual(
        resident.ingress_identity,
        try ingress.identity(),
    );

    const interaction_merkle = resident.slot(
        .trace_merkle_hashes,
        2,
    ) orelse return error.MissingInteractionMerkle;
    try std.testing.expectEqual(
        telemetry.Stage.trace_commit,
        interaction_merkle.live_from,
    );
    try std.testing.expectEqual(
        telemetry.Stage.decommit,
        interaction_merkle.live_through,
    );
    try assertPow(resident, 0, .trace_commit);
    try assertPow(resident, 1, .pow);
    const adapted = resident.slot(.adapted_input, 0).?;
    const writer_scratch = resident.slot(.writer_scratch, 0).?;
    const relation_denominators =
        resident.slot(.relation_denominators, 0).?;
    const eval_tile = resident.slot(.eval_lde_tile, 0).?;
    const composition =
        resident.slot(.constraint_composition_accumulator, 0).?;
    const composition_alpha = resident.slot(.composition_alpha, 0).?;
    try std.testing.expectEqual(@as(u32, 1), adapted.id);
    try std.testing.expectEqual(@as(u32, 5), writer_scratch.id);
    try std.testing.expectEqual(@as(u32, 15), relation_denominators.id);
    try std.testing.expectEqual(@as(u32, 23), eval_tile.id);
    try std.testing.expectEqual(@as(u32, 27), composition.id);
    try std.testing.expectEqual(@as(usize, 1_493_172_224), eval_tile.words);
    try std.testing.expectEqual(@as(usize, 100_662_912), composition.words);
    try std.testing.expectEqual(@as(usize, 4), composition_alpha.words);
    try std.testing.expectEqual(
        telemetry.Stage.trace_commit,
        composition_alpha.live_from,
    );
    try std.testing.expectEqual(
        telemetry.Stage.constraint_evaluation,
        composition_alpha.live_through,
    );
    std.debug.print(
        "SN2 unified CUDA arena: slots={} allocated_bytes={} " ++
            "peak_live_bytes={} adapted_words={} writer_scratch={} " ++
            "relation_denom={} eval_lde_tile={} composition_logs={} " ++
            "composition_accumulator={} bootstrap_words={} " ++
            "slot_ids={}/{}/{}/{}/{} " ++
            "pow_ids={}/{}/{}/{}/{}/{}/{}/{}\n",
        .{
            resident.summary.slot_count,
            resident.summary.allocatedResidentBytes(),
            resident.summary.peak_live_words * resident_plan.word_bytes,
            ingress.adapted_input_words,
            ingress.writer.scratch_words,
            ingress.relation.denominator_words,
            ingress.evaluation.lde_tile_words,
            ingress.evaluation.composition_log_count,
            ingress.evaluation.composition_accumulator_words,
            ingress.statement_bootstrap_words,
            adapted.id,
            writer_scratch.id,
            relation_denominators.id,
            eval_tile.id,
            composition.id,
            resident.slot(.pow_prefix, 0).?.id,
            resident.slot(.pow_best_nonce, 0).?.id,
            resident.slot(.pow_completed_blocks, 0).?.id,
            resident.slot(.pow_transcript_nonce, 0).?.id,
            resident.slot(.pow_prefix, 1).?.id,
            resident.slot(.pow_best_nonce, 1).?.id,
            resident.slot(.pow_completed_blocks, 1).?.id,
            resident.slot(.pow_transcript_nonce, 1).?.id,
        },
    );
}

fn assertPow(
    resident: resident_plan.Plan,
    ordinal: u32,
    stage: telemetry.Stage,
) !void {
    const prefix = resident.slot(.pow_prefix, ordinal).?;
    const best = resident.slot(.pow_best_nonce, ordinal).?;
    const completed = resident.slot(.pow_completed_blocks, ordinal).?;
    const transcript = resident.slot(.pow_transcript_nonce, ordinal).?;
    try std.testing.expectEqual(stage, prefix.live_from);
    try std.testing.expectEqual(stage, prefix.live_through);
    try std.testing.expectEqual(stage, best.live_from);
    try std.testing.expectEqual(stage, best.live_through);
    try std.testing.expectEqual(stage, completed.live_from);
    try std.testing.expectEqual(stage, completed.live_through);
    try std.testing.expectEqual(stage, transcript.live_from);
    try std.testing.expectEqual(
        telemetry.Stage.proof_assembly,
        transcript.live_through,
    );
    try std.testing.expect(prefix.id != best.id);
    try std.testing.expect(best.id != completed.id);
    try std.testing.expect(completed.id != transcript.id);
}
