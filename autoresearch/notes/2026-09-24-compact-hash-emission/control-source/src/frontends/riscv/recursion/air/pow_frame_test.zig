//! Exactness, transcript-source, lane, and performance gates for PoW row 7.

const std = @import("std");
const stwo_core = @import("stwo_core");
const M31 = stwo_core.fields.m31.M31;
const QM31 = stwo_core.fields.qm31.QM31;
const degree = @import("../../air/lang/degree.zig");
const relation = @import("../../air/lang/relation.zig");
const static_profile = @import("../../air/lang/static_profile.zig");
const types = @import("../../air/lang/types.zig");
const poseidon2 = @import("../../air/memory_commitment/poseidon2.zig");
const fixed_profile = @import("../fixed_profile.zig");
const protocol = @import("../protocol.zig");
const channel = @import("../poseidon2_channel.zig");
const check_component = @import("pow_check.zig");
const check_relation = @import("pow_check_relation.zig");
const check_witness = @import("pow_check_witness.zig");
const component = @import("pow_frame.zig");
const interaction = @import("pow_frame_relation.zig");
const support = @import("test_support.zig");
const schedule = @import("verifier_schedule.zig");
const witness = @import("pow_frame_witness.zig");

test "R-012 PoW frame pins exact source, AIR, binding, and degree geometry" {
    const authority = component.SourceAuthority.pinned();
    try authority.validate();
    try std.testing.expectEqualStrings(
        component.SOURCE_AUTHORITY_DIGEST_HEX,
        &std.fmt.bytesToHex(authority.identityDigest(), .lower),
    );
    try std.testing.expectEqual(@as(u8, 15), authority.frame_main_columns);
    try std.testing.expectEqual(@as(u8, 2), authority.frame_direct_constraints);
    try std.testing.expectEqual(@as(u8, 3), authority.frame_framework_constraints);
    try std.testing.expectEqual(@as(u8, 14), authority.frame_relation_arity);

    var definition = try component.build(std.testing.allocator);
    defer definition.deinit();
    try std.testing.expectEqual(@as(usize, 15), definition.main.physical().len);
    try std.testing.expectEqual(@as(usize, 2), definition.constraints.len);
    try std.testing.expectEqual(@as(usize, 2), definition.events.len);
    const identity = try component.identity(std.testing.allocator);
    try std.testing.expectEqualStrings(
        component.SEMANTIC_DIGEST_HEX,
        &std.fmt.bytesToHex(identity.bytes, .lower),
    );
    var degrees = try degree.analyze(std.testing.allocator, &definition.arena);
    defer degrees.deinit();
    try std.testing.expectEqual(
        @as(degree.Degree, component.MAXIMUM_CONSTRAINT_DEGREE),
        degrees.maximumConstraintDegree(),
    );
    const plan = try interaction.authenticate(&definition);
    try std.testing.expectEqual(
        relation.Domain.recursion_transcript_pow_frame,
        plan.events[0].domain,
    );
    try std.testing.expectEqual(relation.Role.consume, plan.events[0].role);
    try std.testing.expectEqual(relation.Domain.recursion_pow_check, plan.events[1].domain);
    try std.testing.expectEqual(relation.Role.emit, plan.events[1].role);
    const binding = try witness.Binding.canonical(&definition);
    const executor = try witness.Executor.init(&definition, &binding);
    try executor.validate();
    try std.testing.expectEqualStrings(
        witness.BINDING_DIGEST_HEX,
        &std.fmt.bytesToHex(binding.identityDigest(), .lower),
    );
}

test "R-012 PoW frame profile preserves cubic kind check and one paired recurrence" {
    var definition = try component.build(std.testing.allocator);
    defer definition.deinit();
    const profile = try static_profile.collect(std.testing.allocator, &definition.arena, .{
        .physical_main_columns = component.PHYSICAL_MAIN_COLUMN_COUNT,
        .lookup_layout = .{
            .batch_size = component.LOOKUP_BATCH_SIZE,
            .interaction_coordinates_per_batch = 4,
        },
    });
    try profile.validate();
    try std.testing.expectEqual(@as(u32, 15), profile.logical_input_nodes);
    try std.testing.expectEqual(@as(u32, 2), profile.constraint_roots);
    try std.testing.expectEqual(@as(u32, 2), profile.lookup_events);
    try std.testing.expectEqual(@as(?u32, 1), profile.lookup_batches);
    try std.testing.expectEqual(@as(?u32, 4), profile.interaction_columns);
    try std.testing.expectEqual(@as(u32, 3), profile.maximum_logical_constraint_degree);
    try std.testing.expectEqual(@as(?u32, 3), profile.maximum_modeled_interaction_degree);
    try std.testing.expectEqual(@as(u32, 0), profile.nodes_outside_constraint_effect_closure);
}

test "R-012 PoW frame kind tags are exact and its emitted check cancels row 6" {
    var frame_definition = try component.build(std.testing.allocator);
    defer frame_definition.deinit();
    const frame_plan = try interaction.authenticate(&frame_definition);
    var check_definition = try check_component.build(std.testing.allocator);
    defer check_definition.deinit();
    const predicate_plan = try check_relation.authenticate(&check_definition);

    inline for (.{
        .{ witness.PowKind.interaction, @as(u32, 6) },
        .{ witness.PowKind.pcs, @as(u32, 20) },
    }) |case| {
        const invocation = frameInvocation(case[0], 0);
        const frame_row = try witness.mainRow(invocation);
        try expectAllRootsZero(&frame_definition, frame_row);
        const frame_entries = try frame_plan.entries(
            &frame_definition.arena,
            component.SEMANTIC_DIGEST,
            frame_definition.events,
            frame_row,
        );
        try std.testing.expect(frame_entries[0].numerator.eql(QM31.one().neg()));
        try std.testing.expect(frame_entries[1].numerator.eql(QM31.one()));
        try std.testing.expect(frame_entries[0].values[2].eql(
            QM31.fromBase(M31.fromCanonical(case[1])),
        ));

        const check_invocation = check_witness.Invocation{
            .verifier_id = invocation.verifier_id,
            .kind = invocation.kind,
            .check = invocation.check,
        };
        const check_row = try check_witness.mainRow(check_invocation);
        const predicate_entries = try predicate_plan.entries(
            &check_definition.arena,
            check_component.SEMANTIC_DIGEST,
            check_definition.events,
            check_row,
        );
        try std.testing.expect(predicate_entries[0].numerator.eql(QM31.one().neg()));
        try std.testing.expect(frame_entries[1].numerator
            .add(predicate_entries[0].numerator).isZero());
        for (0..check_component.RELATION_COORDINATE_COUNT) |index|
            try std.testing.expect(frame_entries[1].values[index].eql(
                predicate_entries[0].values[index],
            ));
    }

    var invalid = try witness.mainRow(frameInvocation(.interaction, 0));
    invalid[3] = M31.fromCanonical(3);
    try expectAnyRootNonzero(&frame_definition, invalid);
}

test "R-012 PoW frames derive segment and binary rows only from schedules" {
    var plans = try PlanFixture.init(std.testing.allocator);
    defer plans.deinit();
    const vm_bits = powBits(&plans.vm);
    const recursion_bits = powBits(&plans.recursion);
    var vm_trace: TraceStorage = undefined;
    vm_trace.init(vm_bits, 100);
    var left_trace: TraceStorage = undefined;
    left_trace.init(recursion_bits, 200);
    var right_trace: TraceStorage = undefined;
    right_trace.init(recursion_bits, 300);

    const segment_source = witness.Source{ .segment_leaf = .{
        .plan = &plans.vm,
        .trace = &vm_trace.trace,
    } };
    var segment = try witness.PreparedBatch.init(std.testing.allocator, segment_source);
    defer segment.deinit();
    try segment.validateAgainstSource(segment_source);
    try std.testing.expectEqual(@as(usize, 2), segment.invocations.len);
    try std.testing.expectEqual(@as(u32, 0), segment.invocations[0].verifier_id);
    try std.testing.expectEqual(witness.PowKind.interaction, segment.invocations[0].kind);
    try std.testing.expectEqual(witness.PowKind.pcs, segment.invocations[1].kind);
    try expectInvocationSchedule(segment.invocations, &plans.vm, &vm_trace.trace, 0);

    const binary_source = witness.Source{ .binary_node = .{
        .left = .{ .plan = &plans.recursion, .trace = &left_trace.trace },
        .right = .{ .plan = &plans.recursion, .trace = &right_trace.trace },
    } };
    var binary = try witness.PreparedBatch.init(std.testing.allocator, binary_source);
    defer binary.deinit();
    try binary.validateAgainstSource(binary_source);
    try std.testing.expectEqual(@as(usize, 4), binary.invocations.len);
    try std.testing.expectEqual(@as(u32, 1), binary.invocations[0].verifier_id);
    try std.testing.expectEqual(@as(u32, 2), binary.invocations[2].verifier_id);

    var empty = try witness.PreparedBatch.init(
        std.testing.allocator,
        .{ .empty_leaf = {} },
    );
    defer empty.deinit();
    try std.testing.expectEqual(@as(usize, 0), empty.invocations.len);
}

test "R-012 PoW frame writer has one cold allocation and no hot allocation" {
    var plans = try PlanFixture.init(std.testing.allocator);
    defer plans.deinit();
    var trace: TraceStorage = undefined;
    trace.init(powBits(&plans.vm), 400);
    const source = witness.Source{ .segment_leaf = .{
        .plan = &plans.vm,
        .trace = &trace.trace,
    } };
    var measured = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    var batch = try witness.PreparedBatch.init(measured.allocator(), source);
    defer batch.deinit();
    try std.testing.expectEqual(@as(usize, 1), measured.alloc_index);

    var definition = try component.build(std.testing.allocator);
    defer definition.deinit();
    const binding = try witness.Binding.canonical(&definition);
    const executor = try witness.Executor.init(&definition, &binding);
    const log_size: u32 = 2;
    const size: usize = 1 << log_size;
    var storage: [component.PHYSICAL_MAIN_COLUMN_COUNT * size]M31 =
        .{M31.fromCanonical(91)} ** (component.PHYSICAL_MAIN_COLUMN_COUNT * size);
    var columns: [component.PHYSICAL_MAIN_COLUMN_COUNT][]M31 = undefined;
    splitColumns(component.PHYSICAL_MAIN_COLUMN_COUNT, size, &storage, &columns);
    const before = measured.alloc_index;
    try executor.generateMainInto(&batch, &columns, log_size);
    try std.testing.expectEqual(before, measured.alloc_index);
    for (batch.invocations, 0..) |invocation, row_index| {
        const expected = try witness.mainRow(invocation);
        for (columns, expected) |column, value|
            try std.testing.expect(column[row_index].eql(value));
    }
    for (columns) |column| for (column[batch.invocations.len..]) |padding|
        try std.testing.expect(padding.isZero());

    const snapshot = storage;
    columns[1] = columns[0];
    try std.testing.expectError(
        error.AliasedDestination,
        executor.generateMainInto(&batch, &columns, log_size),
    );
    try std.testing.expectEqualSlices(M31, &snapshot, &storage);
}

test "R-012 PoW frame rejects transcript, schedule, lane, and receipt mutations" {
    var plans = try PlanFixture.init(std.testing.allocator);
    defer plans.deinit();
    var trace: TraceStorage = undefined;
    trace.init(powBits(&plans.vm), 500);
    const source = witness.Source{ .segment_leaf = .{
        .plan = &plans.vm,
        .trace = &trace.trace,
    } };
    var batch = try witness.PreparedBatch.init(std.testing.allocator, source);
    defer batch.deinit();

    trace.calls[0].output[0] = trace.calls[0].output[0].add(M31.one());
    try std.testing.expectError(
        error.InvalidTranscriptTrace,
        batch.validateAgainstSource(source),
    );
    trace.init(powBits(&plans.vm), 500);
    trace.checks[0].bits += 1;
    try std.testing.expectError(error.BitsMismatch, batch.validateAgainstSource(source));
    trace.init(powBits(&plans.vm), 500);
    trace.frames[0].purpose = .mix;
    try std.testing.expectError(error.DrawFrameMissing, batch.validateAgainstSource(source));
    trace.init(powBits(&plans.vm), 500);
    try std.testing.expectError(
        error.SchemaMismatch,
        witness.PreparedBatch.init(std.testing.allocator, .{ .segment_leaf = .{
            .plan = &plans.recursion,
            .trace = &trace.trace,
        } }),
    );

    batch.invocations[0].sequence += 1;
    try std.testing.expectError(error.AuthorityMismatch, batch.validate());
}

test "R-012 PoW frame preparation releases every allocation failure" {
    var plans = try PlanFixture.init(std.testing.allocator);
    defer plans.deinit();
    var trace: TraceStorage = undefined;
    trace.init(powBits(&plans.vm), 600);
    const source = witness.Source{ .segment_leaf = .{
        .plan = &plans.vm,
        .trace = &trace.trace,
    } };
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        frameBatchFailureCase,
        .{source},
    );
}

const TraceStorage = struct {
    words: [2][10]M31,
    calls: [4]witness.PoseidonCall,
    frames: [2]witness.HashFrame,
    checks: [2]check_witness.Check,
    trace: witness.TranscriptTrace,

    fn init(self: *TraceStorage, bits: [2]u32, seed: u32) void {
        var call_at: usize = 0;
        for (0..2) |frame_index| {
            for (0..witness.RATE) |lane|
                self.words[frame_index][lane] = M31.fromCanonical(
                    seed + @as(u32, @intCast(31 * frame_index + lane)),
                );
            self.words[frame_index][witness.RATE] = M31.fromCanonical(
                @intCast(frame_index),
            );
            self.words[frame_index][witness.RATE + 1] = M31.fromCanonical(
                witness.DRAW_TAG,
            );
            var previous: [witness.WIDTH]M31 = .{M31.zero()} ** witness.WIDTH;
            const first_call = call_at;
            for (0..2) |step| {
                var input = previous;
                for (0..witness.RATE) |lane| {
                    const stream_index = step * witness.RATE + lane;
                    const chunk = if (stream_index < self.words[frame_index].len)
                        self.words[frame_index][stream_index]
                    else if (stream_index == self.words[frame_index].len)
                        M31.one()
                    else
                        M31.zero();
                    input[lane] = input[lane].add(chunk);
                }
                var output = input;
                poseidon2.permute(&output);
                self.calls[call_at] = .{
                    .id = .{
                        .call_id = @intCast(call_at),
                        .hash_id = @intCast(frame_index),
                        .step = @intCast(step),
                    },
                    .input = input,
                    .output = output,
                };
                previous = output;
                call_at += 1;
            }
            self.frames[frame_index] = .{
                .hash_id = @intCast(frame_index),
                .first_call_id = @intCast(first_call),
                .call_count = 2,
                .purpose = .draw,
                .words = &self.words[frame_index],
                .output = previous,
            };
            self.checks[frame_index] = .{
                .call_id = @intCast(call_at - 1),
                .nonce = seed + frame_index,
                .bits = bits[frame_index],
                .word = previous[0],
            };
        }
        self.trace = .{
            .poseidon_calls = &self.calls,
            .hash_frames = &self.frames,
            .pow_checks = &self.checks,
        };
    }
};

const PlanFixture = struct {
    vm: schedule.Plan,
    recursion: schedule.Plan,

    fn init(allocator: std.mem.Allocator) !PlanFixture {
        const shape = try testShape();
        var vm = try schedule.Plan.init(
            allocator,
            try schedule.ProgramSpec.init(.vm, 3, 2, 3, 2),
            shape,
        );
        errdefer vm.deinit();
        return .{
            .vm = vm,
            .recursion = try schedule.Plan.init(
                allocator,
                try schedule.ProgramSpec.init(.recursion, 3, 0, 3, 2),
                shape,
            ),
        };
    }

    fn deinit(self: *PlanFixture) void {
        self.recursion.deinit();
        self.vm.deinit();
        self.* = undefined;
    }
};

fn powBits(plan: *const schedule.Plan) [2]u32 {
    var result: [2]u32 = undefined;
    var at: usize = 0;
    for (plan.steps) |step| switch (step) {
        .verify_and_absorb_interaction_pow => |item| {
            result[at] = item.bits;
            at += 1;
        },
        .verify_and_absorb_pcs_pow => |item| {
            result[at] = item.bits;
            at += 1;
        },
        else => {},
    };
    std.debug.assert(at == result.len);
    return result;
}

fn expectInvocationSchedule(
    invocations: []const witness.Invocation,
    plan: *const schedule.Plan,
    trace: *const witness.TranscriptTrace,
    verifier_id: u32,
) !void {
    var at: usize = 0;
    for (plan.steps, 0..) |step, sequence| switch (step) {
        .verify_and_absorb_interaction_pow, .verify_and_absorb_pcs_pow => {
            const check = trace.pow_checks[at];
            const frame = trace.findDrawFrame(check.call_id).?;
            try std.testing.expectEqual(verifier_id, invocations[at].verifier_id);
            try std.testing.expectEqual(@as(u32, @intCast(sequence)), invocations[at].sequence);
            try std.testing.expectEqual(check.call_id, invocations[at].check.call_id);
            try std.testing.expectEqual(frame.hash_id, invocations[at].hash_id);
            at += 1;
        },
        else => {},
    };
    try std.testing.expectEqual(invocations.len, at);
}

fn frameInvocation(kind: witness.PowKind, bits: u32) witness.Invocation {
    var words: [component.WORD_COUNT]M31 = undefined;
    for (&words, 0..) |*word, index| word.* = M31.fromCanonical(@intCast(41 + index));
    words[0] = M31.zero();
    return .{
        .verifier_id = 2,
        .sequence = 19,
        .kind = kind,
        .hash_id = 23,
        .check = .{
            .call_id = 29,
            .nonce = 31,
            .bits = bits,
            .word = words[0],
        },
        .words = words,
    };
}

fn expectAllRootsZero(
    definition: *const component.Definition,
    row: [component.LOGICAL_INPUT_COUNT]M31,
) !void {
    const values = try support.evaluateArena(std.testing.allocator, &definition.arena, &row);
    defer std.testing.allocator.free(values);
    for (definition.roots) |root|
        try std.testing.expect(values[types.idIndex(root)].isZero());
}

fn expectAnyRootNonzero(
    definition: *const component.Definition,
    row: [component.LOGICAL_INPUT_COUNT]M31,
) !void {
    const values = try support.evaluateArena(std.testing.allocator, &definition.arena, &row);
    defer std.testing.allocator.free(values);
    for (definition.roots) |root| {
        if (!values[types.idIndex(root)].isZero()) return;
    }
    return error.TestUnexpectedResult;
}

fn splitColumns(
    comptime count: usize,
    size: usize,
    storage: []M31,
    columns: *[count][]M31,
) void {
    for (columns, 0..) |*column, index|
        column.* = storage[index * size ..][0..size];
}

fn frameBatchFailureCase(allocator: std.mem.Allocator, source: witness.Source) !void {
    var batch = try witness.PreparedBatch.init(allocator, source);
    defer batch.deinit();
}

fn testShape() !fixed_profile.ProofShapeV1 {
    const fri = try fixed_profile.FriSchedule.init(8, protocol.PCS_CONFIG.fri_config);
    return .{
        .air_program_id = channel.hashBytes("pow-air", 0x5450),
        .preprocessing_id = channel.hashBytes("pow-preprocessing", 0x5450),
        .table_layout_id = channel.hashBytes("pow-layout", 0x5450),
        .table_count = 16,
        .claimed_sum_count = 4,
        .sampled_value_count = 8,
        .preprocessed_column_count = 4,
        .tree_column_counts = .{ 4, 4, 4, 4 },
        .tree_heights = .{ 9, 9, 9, 9 },
        .column_log_degree = 8,
        .proof_wire_bytes = 1024,
        .fri = fri,
    };
}
