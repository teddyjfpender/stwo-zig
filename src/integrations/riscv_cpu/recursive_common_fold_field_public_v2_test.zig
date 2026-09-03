const std = @import("std");
const stwo_core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");

const subject = @import("recursive_common_fold_field_public_v2.zig");
const artifact = @import("recursive_node_artifact_v1.zig");
const field_public = @import("recursive_field_node_public_v2.zig");
const suffix_boundary =
    @import("recursive_common_fold_suffix_input_boundary_v2.zig");
const suffix_closure =
    @import("recursive_common_fold_suffix_closure_v2.zig");

const recursion = frontend.recursion;
const QM31 = stwo_core.fields.qm31.QM31;

test "common fold derives exact field parent and 116 Poseidon calls" {
    const left = try emptyLeaf(210, "common-fold-left");
    const right = try emptyLeaf(211, "common-fold-right");
    const coordinate = try artifact.TaskCoordinateV1.init(1, 105);
    const schedule = try subject.PoseidonScheduleV2.build(
        &left,
        &right,
        coordinate,
    );
    try schedule.validateAgainst(&left, &right, coordinate);
    try std.testing.expectEqual(
        @as(usize, subject.POSEIDON_CALL_COUNT),
        schedule.callsSlice().len,
    );
    try std.testing.expectEqual(
        @as(u16, subject.STATEMENT_CALL_COUNT),
        schedule.phases[@intFromEnum(subject.PhaseV2.statement)].call_count,
    );
    try std.testing.expectEqual(
        @as(u16, subject.SOURCE_CALL_COUNT),
        schedule.phases[@intFromEnum(subject.PhaseV2.source)].call_count,
    );
    try std.testing.expectEqual(
        @as(u16, subject.SUBTREE_CALL_COUNT),
        schedule.phases[@intFromEnum(subject.PhaseV2.subtree)].call_count,
    );
    try std.testing.expectEqual(
        @as(u16, subject.OUTPUT_CALL_COUNT),
        schedule.phases[@intFromEnum(subject.PhaseV2.output)].call_count,
    );
    const source_preimage = subject.parentSourcePreimage(&left, &right);
    try std.testing.expectEqual(
        recursion.poseidon2_channel.hashCanonicalU32s(
            &source_preimage,
            field_public.PARENT_SOURCE_DOMAIN,
        ),
        schedule.parent.source_digest,
    );
    try schedule.parent.validateParentAgainst(&left, &right);
}

test "common fold schedule rejects call child order and coordinate drift" {
    const left = try emptyLeaf(210, "common-fold-left");
    const right = try emptyLeaf(211, "common-fold-right");
    const coordinate = try artifact.TaskCoordinateV1.init(1, 105);
    const schedule = try subject.PoseidonScheduleV2.build(
        &left,
        &right,
        coordinate,
    );

    var changed_call = schedule;
    changed_call.calls[0].input[0] ^= 1;
    try std.testing.expectError(
        error.CommonFoldFieldScheduleMismatch,
        changed_call.validateAgainst(&left, &right, coordinate),
    );
    try std.testing.expectError(
        error.CommonFoldPublicInputMismatch,
        subject.PoseidonScheduleV2.build(&right, &left, coordinate),
    );
    try std.testing.expectError(
        error.CommonFoldPublicInputMismatch,
        subject.PoseidonScheduleV2.build(
            &left,
            &right,
            try artifact.TaskCoordinateV1.init(2, 52),
        ),
    );

    var domains: [suffix_boundary.DOMAIN_COUNT]suffix_boundary.DomainEvidenceV2 = undefined;
    for (
        &domains,
        suffix_boundary.DOMAINS,
        suffix_boundary.ROW_MASKS,
        0..,
    ) |*domain, relation_domain, source_row_mask, ordinal| {
        domain.* = .{
            .domain = relation_domain,
            .source_row_mask = source_row_mask,
            .tuple_count = 1,
            .claimed_sum = QM31.fromU32Unchecked(
                @intCast(ordinal + 5),
                0,
                0,
                0,
            ),
            .tuple_provenance_sha256 = [_]u8{1} ** 32,
        };
    }
    const verifier_input = QM31.fromU32Unchecked(2, 0, 0, 0);
    const field_public_claim = QM31.fromU32Unchecked(3, 0, 0, 0);
    const framework =
        suffix_closure.frameworkBoundarySumExceptWireAssumeValidated(
            verifier_input,
            field_public_claim,
            &domains,
        );
    var expected = verifier_input.add(field_public_claim);
    for (domains) |domain| {
        if (domain.domain == .recursion_verifier_input_word) continue;
        expected = expected.add(domain.claimed_sum);
    }
    try std.testing.expect(framework.eql(expected));

    var duplicated_verifier = domains;
    for (&duplicated_verifier) |*domain| {
        if (domain.domain == .recursion_verifier_input_word)
            domain.claimed_sum = QM31.fromU32Unchecked(101, 0, 0, 0);
    }
    try std.testing.expect(framework.eql(
        suffix_closure.frameworkBoundarySumExceptWireAssumeValidated(
            verifier_input,
            field_public_claim,
            &duplicated_verifier,
        ),
    ));

    var changed_suffix = domains;
    for (&changed_suffix) |*domain| {
        if (domain.domain == .recursion_step)
            domain.claimed_sum = QM31.fromU32Unchecked(103, 0, 0, 0);
    }
    try std.testing.expect(!framework.eql(
        suffix_closure.frameworkBoundarySumExceptWireAssumeValidated(
            verifier_input,
            field_public_claim,
            &changed_suffix,
        ),
    ));
}

fn emptyLeaf(index: u32, label: []const u8) !field_public.NodePublicV2 {
    const job = try fixtureJob();
    const statement = try recursion.span_statement.SpanStatement.emptyLeaf(
        job,
        index,
    );
    const words = try statement.canonicalWords();
    var canonical: [field_public.STATEMENT_WORD_COUNT]u32 = undefined;
    for (&canonical, words) |*destination, word|
        destination.* = word.toU32();
    return field_public.NodePublicV2.initLeaf(
        try artifact.TaskCoordinateV1.init(0, index),
        canonical,
        recursion.poseidon2_channel.hashBytes(label, 0x464f_4c44),
    );
}

fn fixtureJob() !recursion.span_statement.JobContext {
    const initial = try recursion.span_statement.MachineState.init(
        0,
        [_]u32{0} ** 32,
        [_]u32{1} ** 8,
        [_]u32{2} ** 8,
    );
    const final = try recursion.span_statement.MachineState.init(
        4,
        [_]u32{0} ** 32,
        [_]u32{3} ** 8,
        [_]u32{4} ** 8,
    );
    const complete = try recursion.span_statement.CompleteExecution.init(
        recursion.protocol.PROTOCOL_ID_WORDS,
        [_]u32{5} ** 8,
        initial,
        final,
        [_]u32{6} ** 8,
        [_]u32{7} ** 8,
        8,
    );
    return recursion.span_statement.JobContext.init(complete, 210);
}
