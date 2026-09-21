const std = @import("std");
const composition_fixture =
    @import("binary_composition_rows_heterogeneous_v2_test.zig");
const fri_fixture =
    @import("air/fri_rows_authority_heterogeneous_v2_test.zig");
const composition_rows = @import("binary_composition_rows_heterogeneous_v2.zig");
const control_v2 = @import("air/control_witness_heterogeneous_v2.zig");
const fri_rows = @import("air/fri_rows_authority_heterogeneous_v2.zig");
const subject = @import("binary_arithmetic_rows_heterogeneous_v2.zig");
const merkle_subject = @import("binary_merkle_path_program_heterogeneous_v2.zig");
const node_descriptor = @import("binary_node_program_descriptor_v1.zig");
const public_rows_subject =
    @import("binary_public_rows_program_heterogeneous_v2.zig");
const provider_subject =
    @import("binary_poseidon_provider_program_heterogeneous_v2.zig");
const transcript_schedule_v2 =
    @import("air/transcript_schedule_rows_heterogeneous_v2.zig");
const transcript_data_v2 =
    @import("air/transcript_data_rows_heterogeneous_v2.zig");
const transcript_execution_v2 =
    @import("air/transcript_execution_program_heterogeneous_v2.zig");
const transcript_state_v2 =
    @import("air/transcript_state_heterogeneous_v2.zig");
const fixed_profile = @import("fixed_profile.zig");
const protocol = @import("protocol.zig");
const channel = @import("poseidon2_channel.zig");
const schedule = @import("air/verifier_schedule.zig");
const vm_claim = @import("vm_public_claim.zig");

test "heterogeneous rows 30 through 32 join independently compiled child programs" {
    const fixture = try Fixture.init();
    defer fixture.deinit();
    const input = try fixture.input();
    var authority = try subject.ArithmeticRowsAuthorityV2.init(
        std.testing.allocator,
        input,
    );
    defer authority.deinit();

    try authority.validateProgramAgainst(try fixture.input());
    try std.testing.expectEqual(subject.LANE_COUNT, authority.rows.lanes.len);
    try std.testing.expect(!std.mem.allEqual(u8, &authority.program_sha256, 0));
    try std.testing.expect(!std.mem.eql(
        u8,
        &authority.rows.lanes[1].circuit_identity,
        &authority.rows.lanes[4].circuit_identity,
    ));
    try std.testing.expect(!std.mem.eql(
        u8,
        &authority.rows.lanes[2].graph.identity_digest,
        &authority.rows.lanes[5].graph.identity_digest,
    ));
}

test "heterogeneous rows 30 through 32 reject cross-authority and row mutation" {
    const fixture = try Fixture.init();
    defer fixture.deinit();
    const input = try fixture.input();
    var authority = try subject.ArithmeticRowsAuthorityV2.init(
        std.testing.allocator,
        input,
    );
    defer authority.deinit();

    var mismatched = try fixture.input();
    mismatched.composition_program = fixture.composition.program();
    try std.testing.expectError(
        error.SampledValueCountMismatch,
        authority.validateProgramAgainst(mismatched),
    );

    try std.testing.expect(authority.rows.plan.linear_rows[0].binary != null);
    authority.rows.plan.linear_rows[0].binary = null;
    try std.testing.expectError(
        error.AuthorityMismatch,
        authority.validateProgramAgainst(try fixture.input()),
    );
}

test "heterogeneous row 33 derives exact ordered child path geometry" {
    const fixture = try Fixture.init();
    defer fixture.deinit();
    const input = try fixture.input();
    var authority = try merkle_subject.MerklePathProgramAuthorityV2.init(
        std.testing.allocator,
        .{
            .fri_authority = input.fri_authority,
            .fri_program = input.fri_program,
        },
    );
    defer authority.deinit();
    try authority.validateProgramAgainst(.{
        .fri_authority = input.fri_authority,
        .fri_program = input.fri_program,
    });
    try std.testing.expect(authority.geometry.leaf_count > 0);
    try std.testing.expect(authority.geometry.invocation_count >
        authority.geometry.leaf_count);

    authority.geometry.invocation_count += 1;
    try std.testing.expectError(
        error.InvalidHeterogeneousMerklePathAuthority,
        authority.validateProgramAgainst(.{
            .fri_authority = input.fri_authority,
            .fri_program = input.fri_program,
        }),
    );
}

test "heterogeneous row 0 retains exact VM left and right schedules" {
    const fixture = try Fixture.init();
    defer fixture.deinit();
    const input = try fixture.input();
    const vm = input.fri_program.lanes[0].plan;
    const left = input.fri_program.lanes[1].plan;
    const right = input.fri_program.lanes[2].plan;
    var authority = try control_v2.PreprocessedV2.init(
        std.testing.allocator,
        vm,
        left,
        right,
    );
    defer authority.deinit();
    try authority.validateAgainst(vm, left, right);
    try std.testing.expectEqual(
        vm.steps.len,
        authority.activeStepCount(.segment_leaf),
    );
    try std.testing.expectEqual(
        left.steps.len + right.steps.len,
        authority.activeStepCount(.binary_node),
    );
    try std.testing.expect(!std.meta.eql(
        authority.lanes[1].schedule_digest,
        authority.lanes[2].schedule_digest,
    ));

    authority.rows[vm.steps.len].tag += 1;
    try std.testing.expectError(
        error.ScheduleAuthorityMismatch,
        authority.validateAgainst(vm, left, right),
    );
}

test "heterogeneous rows 8 and 9 retain lane-specific draw schedules" {
    const fixture = try Fixture.init();
    defer fixture.deinit();
    const input = try fixture.input();
    const vm = input.fri_program.lanes[0].plan;
    const left = input.fri_program.lanes[1].plan;
    const right = input.fri_program.lanes[2].plan;
    var challenges = try transcript_schedule_v2
        .RelationChallengePreprocessedV2.init(
        std.testing.allocator,
        vm,
        left,
        right,
    );
    defer challenges.deinit();
    var randomness = try transcript_schedule_v2
        .VerifierRandomnessPreprocessedV2.init(
        std.testing.allocator,
        vm,
        left,
        right,
    );
    defer randomness.deinit();
    try challenges.validateAgainst(vm, left, right);
    try randomness.validateAgainst(vm, left, right);
    try std.testing.expect(!std.meta.eql(
        challenges.schedule_digests[1],
        challenges.schedule_digests[2],
    ));
    try std.testing.expect(!std.meta.eql(
        randomness.schedule_digests[1],
        randomness.schedule_digests[2],
    ));

    randomness.rows[randomness.counts[0]].item_base += 1;
    try std.testing.expectError(
        error.ScheduleAuthorityMismatch,
        randomness.validateAgainst(vm, left, right),
    );
}

test "heterogeneous transcript rows 2 through 5 reconstruct every lane" {
    const fixture = try Fixture.init();
    defer fixture.deinit();
    const input = try fixture.input();
    const vm = input.fri_program.lanes[0].plan;
    const left = input.fri_program.lanes[1].plan;
    const right = input.fri_program.lanes[2].plan;
    var binding = try transcript_data_v2.TranscriptBindingPreprocessedV2.init(
        std.testing.allocator,
        vm,
        left,
        right,
    );
    defer binding.deinit();
    var state = try transcript_state_v2.PreprocessedV2.init(
        std.testing.allocator,
        &binding,
        vm,
        left,
        right,
    );
    defer state.deinit();
    var words = try transcript_data_v2.TranscriptWordPreprocessedV2.init(
        std.testing.allocator,
        vm,
        left,
        right,
    );
    defer words.deinit();
    var payload = try transcript_data_v2.TranscriptPayloadPreprocessedV2.init(
        std.testing.allocator,
        vm,
        left,
        right,
    );
    defer payload.deinit();

    try binding.validateAgainst(vm, left, right);
    try state.validateAgainst(&binding, vm, left, right);
    try words.validateAgainst(vm, left, right);
    try payload.validateAgainst(vm, left, right);
    try std.testing.expect(!std.meta.eql(
        binding.schedule_digests[1],
        binding.schedule_digests[2],
    ));
    try std.testing.expectEqual(binding.counts, state.call_counts);

    state.rows[state.frame_counts[0]].output_state_key += 1;
    state.authority_sha256 = stateIdentityForMutation(&state);
    try std.testing.expectError(
        error.AuthorityMismatch,
        state.validateAgainst(&binding, vm, left, right),
    );
}

test "heterogeneous transcript rows 1 6 and 7 bind exact execution sites" {
    const fixture = try Fixture.init();
    defer fixture.deinit();
    const input = try fixture.input();
    const vm = input.fri_program.lanes[0].plan;
    const left = input.fri_program.lanes[1].plan;
    const right = input.fri_program.lanes[2].plan;
    var binding = try transcript_data_v2.TranscriptBindingPreprocessedV2.init(
        std.testing.allocator,
        vm,
        left,
        right,
    );
    defer binding.deinit();
    var program = try transcript_execution_v2.ProgramAuthorityV2.init(
        std.testing.allocator,
        &binding,
        vm,
        left,
        right,
    );
    defer program.deinit();
    try program.validateAgainst(&binding, vm, left, right);
    try std.testing.expectEqual(
        binding.counts[1] + binding.counts[2],
        try program.binaryTranscriptProviderCallCount(),
    );
    try std.testing.expectEqual(
        program.pow_counts[0] + program.pow_counts[1] + program.pow_counts[2],
        program.pow_sites.len,
    );

    program.pow_sites[program.pow_counts[0]].call_id += 1;
    try std.testing.expectError(
        error.InvalidTranscriptExecutionProgramAuthority,
        program.validateAgainst(&binding, vm, left, right),
    );
}

test "heterogeneous rows 10 through 17 bind fixed public AIR and two child schedules" {
    const fixture = try Fixture.init();
    defer fixture.deinit();
    const input = try fixture.input();
    const shape = try vm_claim.Shape.init(0, 0);
    const vm_shape = try composition_fixture.testShape(7, 7);
    var vm_plan = try @import("air/verifier_schedule.zig").Plan.init(
        std.testing.allocator,
        try @import("air/verifier_schedule.zig").vmProgramSpec(
            shape.max_input_words,
            shape.max_output_words,
        ),
        vm_shape,
    );
    defer vm_plan.deinit();
    const left = input.fri_program.lanes[1].plan;
    const right = input.fri_program.lanes[2].plan;
    var authority = try public_rows_subject.ProgramAuthorityV2.init(
        std.testing.allocator,
        shape,
        &vm_plan,
        left,
        right,
    );
    defer authority.deinit();
    try authority.validateAgainst(&vm_plan, left, right);
    try std.testing.expectEqual(
        public_rows_subject.ROW_COUNT,
        authority.log_sizes.len,
    );
    try std.testing.expectEqual(
        authority.public_logup_control.lanes[1].public_term_count,
        left.spec.public_logup_term_count,
    );
    try std.testing.expectEqual(
        authority.public_logup_control.lanes[2].public_term_count,
        right.spec.public_logup_term_count,
    );
    try std.testing.expect(!std.meta.eql(
        authority.public_logup_control.lanes[1].schedule_digest,
        authority.public_logup_control.lanes[2].schedule_digest,
    ));
    try std.testing.expect(!std.mem.allEqual(u8, &authority.program_sha256, 0));

    authority.public_logup_control.rows[
        authority.public_logup_control.lanes[0].public_term_count + 1
    ].tag += 1;
    try std.testing.expectError(
        error.ScheduleAuthorityMismatch,
        authority.validateAgainst(&vm_plan, left, right),
    );
}

test "heterogeneous row 34 sums every compiler-owned Poseidon requester" {
    const fixture = try Fixture.init();
    defer fixture.deinit();
    const input = try fixture.input();
    const vm = input.fri_program.lanes[0].plan;
    const left = input.fri_program.lanes[1].plan;
    const right = input.fri_program.lanes[2].plan;
    var calls = try transcript_data_v2.TranscriptBindingPreprocessedV2.init(
        std.testing.allocator,
        vm,
        left,
        right,
    );
    defer calls.deinit();
    var transcript_program = try transcript_execution_v2.ProgramAuthorityV2.init(
        std.testing.allocator,
        &calls,
        vm,
        left,
        right,
    );
    defer transcript_program.deinit();
    var merkle_program = try merkle_subject.MerklePathProgramAuthorityV2.init(
        std.testing.allocator,
        .{
            .fri_authority = input.fri_authority,
            .fri_program = input.fri_program,
        },
    );
    defer merkle_program.deinit();
    const provider_input = provider_subject.ProgramInputV2{
        .transcript_authority = &transcript_program,
        .transcript_calls = &calls,
        .vm_plan = vm,
        .left_plan = left,
        .right_plan = right,
        .fri_authority = input.fri_authority,
        .fri_program = input.fri_program,
        .merkle_path_authority = &merkle_program,
    };
    var authority = try provider_subject.ProgramAuthorityV2.init(provider_input);
    try authority.validateAgainst(provider_input);
    try std.testing.expectEqual(
        authority.counts.total,
        authority.counts.transcript + authority.counts.trace_leaf +
            authority.counts.fri_leaf + authority.counts.fri_node +
            authority.counts.merkle_path,
    );
    try std.testing.expect(authority.counts.transcript > 0);
    try std.testing.expect(authority.counts.trace_leaf > 0);
    try std.testing.expect(authority.counts.fri_leaf > 0);
    try std.testing.expect(authority.counts.fri_node > 0);
    try std.testing.expect(authority.counts.merkle_path > 0);
    try std.testing.expect(!std.mem.allEqual(u8, &authority.program_sha256, 0));

    authority.counts.fri_node += 1;
    try std.testing.expectError(
        error.InvalidHeterogeneousPoseidonProviderAuthority,
        authority.validateAgainst(provider_input),
    );
}

test "complete binary node descriptor cold recompiles rows 0 through 35" {
    const fixture = try FullProgramFixture.init();
    defer fixture.deinit();
    const input = try fixture.input();
    const descriptor = try node_descriptor.NodeProgramDescriptorV1.mint(input);
    try descriptor.validateAgainst(try fixture.input());
    try std.testing.expect(!std.mem.eql(
        u8,
        &descriptor.child_composition_manifest_sha256[0],
        &descriptor.child_composition_manifest_sha256[1],
    ));
    try std.testing.expect(!std.mem.allEqual(
        u8,
        &descriptor.compiler_authority_sha256,
        0,
    ));

    const encoded = try descriptor.encodeCanonical();
    const decoded = try node_descriptor.NodeProgramDescriptorV1
        .decodeCanonical(&encoded);
    try decoded.validateAgainst(try fixture.input());
    try std.testing.expectEqual(node_descriptor.ENCODED_BYTE_COUNT, encoded.len);

    var hostile = encoded;
    hostile[hostile.len - 1] ^= 1;
    try std.testing.expectError(
        error.InvalidNodeProgramDescriptor,
        node_descriptor.NodeProgramDescriptorV1.decodeCanonical(&hostile),
    );

    var selected_compiler = decoded;
    selected_compiler.compiler_authority_sha256[0] ^= 1;
    try std.testing.expectError(
        error.InvalidNodeProgramDescriptor,
        selected_compiler.validate(),
    );

    const retained_composition_instance =
        fixture.composition_authority.instance_sha256;
    const retained_fri_instance = fixture.fri_authority.instance_sha256;
    fixture.composition_authority.instance_sha256[0] ^= 1;
    fixture.fri_authority.instance_sha256[0] ^= 1;
    const same_program = try node_descriptor.NodeProgramDescriptorV1.mint(
        try fixture.input(),
    );
    try std.testing.expectEqualSlices(
        u8,
        &descriptor.program_sha256,
        &same_program.program_sha256,
    );
    fixture.composition_authority.instance_sha256 = retained_composition_instance;
    fixture.fri_authority.instance_sha256 = retained_fri_instance;

    fixture.row0.rows[fixture.vm_plan.steps.len].tag += 1;
    try std.testing.expectError(
        error.ScheduleAuthorityMismatch,
        decoded.validateAgainst(try fixture.input()),
    );
    fixture.row0.rows[fixture.vm_plan.steps.len].tag -= 1;

    try std.testing.expectError(
        error.VerifierProgramAuthorityUnavailable,
        decoded.validateProductionAgainst(try fixture.input()),
    );
}

// Test-only self-sealing attempt. The production validator must still reject
// because it reconstructs every row from the typed row-2 authority.
fn stateIdentityForMutation(
    state: *const transcript_state_v2.PreprocessedV2,
) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo-zig/typed-air/transcript-state-heterogeneous/v2\x00");
    hashInt(&hash, u16, state.format_version);
    hashInt(&hash, u16, state.schema_version);
    hashInt(&hash, u32, state.log_size);
    for (
        state.frame_counts,
        state.call_counts,
        state.schemas,
        state.schedule_digests,
    ) |frames, calls, schema, schedule_digest| {
        hashInt(&hash, u64, frames);
        hashInt(&hash, u64, calls);
        hashInt(&hash, u16, @intFromEnum(schema));
        for (schedule_digest) |word| hashInt(&hash, u32, word);
    }
    hash.update(&state.binding_authority_sha256);
    hashInt(&hash, u64, state.rows.len);
    for (state.rows) |row| for (row.values()) |word|
        hashInt(&hash, u32, word.toU32());
    return hash.finalResult();
}

fn hashInt(hash: anytype, comptime T: type, value: anytype) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, @intCast(value), .little);
    hash.update(&bytes);
}

const Fixture = struct {
    composition: composition_fixture.Fixture,
    fri: fri_fixture.Fixture,
    composition_authority: composition_rows.CompositionRowsAuthorityV2,
    fri_authority: fri_rows.FriRowsAuthorityV2,

    fn init() !*Fixture {
        const self = try std.testing.allocator.create(Fixture);
        errdefer std.testing.allocator.destroy(self);
        self.composition = try composition_fixture.Fixture.initWithSampleCounts(
            std.testing.allocator,
            7,
            7,
        );
        errdefer self.composition.deinit();
        self.fri = try fri_fixture.Fixture.init();
        errdefer self.fri.deinit();
        const fri_program = try self.fri.program();
        var composition_program = self.composition.programWithPlans(
            fri_program.lanes[0].plan,
            fri_program.lanes[1].plan,
            fri_program.lanes[2].plan,
        );
        composition_program.vm_sampled_value_count = 7;
        self.composition_authority = try composition_rows
            .CompositionRowsAuthorityV2.init(
            std.testing.allocator,
            composition_program,
            self.composition.witness(),
        );
        errdefer self.composition_authority.deinit();
        self.fri_authority = try fri_rows.FriRowsAuthorityV2.init(
            std.testing.allocator,
            fri_program,
            self.fri.witness(),
        );
        return self;
    }

    fn deinit(self: *Fixture) void {
        self.fri_authority.deinit();
        self.composition_authority.deinit();
        self.fri.deinit();
        self.composition.deinit();
        std.testing.allocator.destroy(self);
    }

    fn input(self: *const Fixture) !subject.ProgramInputV2 {
        const fri_program = try self.fri.program();
        var composition_program = self.composition.programWithPlans(
            fri_program.lanes[0].plan,
            fri_program.lanes[1].plan,
            fri_program.lanes[2].plan,
        );
        composition_program.vm_sampled_value_count = 7;
        return .{
            .composition_authority = &self.composition_authority,
            .composition_program = composition_program,
            .fri_authority = &self.fri_authority,
            .fri_program = fri_program,
        };
    }
};

const FullProgramFixture = struct {
    base: *Fixture,
    vm_plan: schedule.Plan,
    fri_authority: fri_rows.FriRowsAuthorityV2,
    composition_authority: composition_rows.CompositionRowsAuthorityV2,
    row0: control_v2.PreprocessedV2,
    calls: transcript_data_v2.TranscriptBindingPreprocessedV2,
    row3: transcript_state_v2.PreprocessedV2,
    row4: transcript_data_v2.TranscriptWordPreprocessedV2,
    row5: transcript_data_v2.TranscriptPayloadPreprocessedV2,
    transcript_program: transcript_execution_v2.ProgramAuthorityV2,
    row8: transcript_schedule_v2.RelationChallengePreprocessedV2,
    row9: transcript_schedule_v2.VerifierRandomnessPreprocessedV2,
    public_program: public_rows_subject.ProgramAuthorityV2,
    arithmetic_program: subject.ArithmeticRowsAuthorityV2,
    merkle_program: merkle_subject.MerklePathProgramAuthorityV2,
    provider_program: provider_subject.ProgramAuthorityV2,

    fn init() !*FullProgramFixture {
        const self = try std.testing.allocator.create(FullProgramFixture);
        errdefer std.testing.allocator.destroy(self);
        self.base = try Fixture.init();
        errdefer self.base.deinit();
        self.vm_plan = try candidateVmPlan();
        errdefer self.vm_plan.deinit();

        const fri_input = try self.friInput();
        self.fri_authority = try fri_rows.FriRowsAuthorityV2.init(
            std.testing.allocator,
            fri_input,
            self.base.fri.witness(),
        );
        errdefer self.fri_authority.deinit();
        const composition_input = self.compositionInput(fri_input);
        self.composition_authority = try composition_rows
            .CompositionRowsAuthorityV2.init(
            std.testing.allocator,
            composition_input,
            self.base.composition.witness(),
        );
        errdefer self.composition_authority.deinit();

        self.row0 = try control_v2.PreprocessedV2.init(
            std.testing.allocator,
            &self.vm_plan,
            fri_input.lanes[1].plan,
            fri_input.lanes[2].plan,
        );
        errdefer self.row0.deinit();
        self.calls = try transcript_data_v2.TranscriptBindingPreprocessedV2.init(
            std.testing.allocator,
            &self.vm_plan,
            fri_input.lanes[1].plan,
            fri_input.lanes[2].plan,
        );
        errdefer self.calls.deinit();
        self.row3 = try transcript_state_v2.PreprocessedV2.init(
            std.testing.allocator,
            &self.calls,
            &self.vm_plan,
            fri_input.lanes[1].plan,
            fri_input.lanes[2].plan,
        );
        errdefer self.row3.deinit();
        self.row4 = try transcript_data_v2.TranscriptWordPreprocessedV2.init(
            std.testing.allocator,
            &self.vm_plan,
            fri_input.lanes[1].plan,
            fri_input.lanes[2].plan,
        );
        errdefer self.row4.deinit();
        self.row5 = try transcript_data_v2.TranscriptPayloadPreprocessedV2.init(
            std.testing.allocator,
            &self.vm_plan,
            fri_input.lanes[1].plan,
            fri_input.lanes[2].plan,
        );
        errdefer self.row5.deinit();
        self.transcript_program = try transcript_execution_v2.ProgramAuthorityV2.init(
            std.testing.allocator,
            &self.calls,
            &self.vm_plan,
            fri_input.lanes[1].plan,
            fri_input.lanes[2].plan,
        );
        errdefer self.transcript_program.deinit();
        self.row8 = try transcript_schedule_v2.RelationChallengePreprocessedV2.init(
            std.testing.allocator,
            &self.vm_plan,
            fri_input.lanes[1].plan,
            fri_input.lanes[2].plan,
        );
        errdefer self.row8.deinit();
        self.row9 = try transcript_schedule_v2.VerifierRandomnessPreprocessedV2.init(
            std.testing.allocator,
            &self.vm_plan,
            fri_input.lanes[1].plan,
            fri_input.lanes[2].plan,
        );
        errdefer self.row9.deinit();
        self.public_program = try public_rows_subject.ProgramAuthorityV2.init(
            std.testing.allocator,
            try vm_claim.Shape.init(0, 0),
            &self.vm_plan,
            fri_input.lanes[1].plan,
            fri_input.lanes[2].plan,
        );
        errdefer self.public_program.deinit();
        self.arithmetic_program = try subject.ArithmeticRowsAuthorityV2.init(
            std.testing.allocator,
            self.arithmeticInput(composition_input, fri_input),
        );
        errdefer self.arithmetic_program.deinit();
        self.merkle_program = try merkle_subject.MerklePathProgramAuthorityV2.init(
            std.testing.allocator,
            .{ .fri_authority = &self.fri_authority, .fri_program = fri_input },
        );
        errdefer self.merkle_program.deinit();
        self.provider_program = try provider_subject.ProgramAuthorityV2.init(
            self.providerInput(fri_input),
        );
        return self;
    }

    fn deinit(self: *FullProgramFixture) void {
        self.merkle_program.deinit();
        self.arithmetic_program.deinit();
        self.public_program.deinit();
        self.row9.deinit();
        self.row8.deinit();
        self.transcript_program.deinit();
        self.row5.deinit();
        self.row4.deinit();
        self.row3.deinit();
        self.calls.deinit();
        self.row0.deinit();
        self.composition_authority.deinit();
        self.fri_authority.deinit();
        self.vm_plan.deinit();
        self.base.deinit();
        std.testing.allocator.destroy(self);
    }

    fn friInput(self: *const FullProgramFixture) !fri_rows.ProgramInputV2 {
        var result = try self.base.fri.program();
        result.lanes[0].plan = &self.vm_plan;
        return result;
    }

    fn compositionInput(
        self: *const FullProgramFixture,
        fri_input: fri_rows.ProgramInputV2,
    ) composition_rows.ProgramInputV2 {
        var result = self.base.composition.programWithPlans(
            &self.vm_plan,
            fri_input.lanes[1].plan,
            fri_input.lanes[2].plan,
        );
        result.vm_sampled_value_count = 7;
        return result;
    }

    fn arithmeticInput(
        self: *const FullProgramFixture,
        composition_input: composition_rows.ProgramInputV2,
        fri_input: fri_rows.ProgramInputV2,
    ) subject.ProgramInputV2 {
        return .{
            .composition_authority = &self.composition_authority,
            .composition_program = composition_input,
            .fri_authority = &self.fri_authority,
            .fri_program = fri_input,
        };
    }

    fn providerInput(
        self: *const FullProgramFixture,
        fri_input: fri_rows.ProgramInputV2,
    ) provider_subject.ProgramInputV2 {
        return .{
            .transcript_authority = &self.transcript_program,
            .transcript_calls = &self.calls,
            .vm_plan = &self.vm_plan,
            .left_plan = fri_input.lanes[1].plan,
            .right_plan = fri_input.lanes[2].plan,
            .fri_authority = &self.fri_authority,
            .fri_program = fri_input,
            .merkle_path_authority = &self.merkle_program,
        };
    }

    fn input(self: *const FullProgramFixture) !node_descriptor.CompilerInputV1 {
        const fri_input = try self.friInput();
        return .{
            .vm_plan = &self.vm_plan,
            .left_plan = fri_input.lanes[1].plan,
            .right_plan = fri_input.lanes[2].plan,
            .row0 = &self.row0,
            .transcript_calls = &self.calls,
            .row3 = &self.row3,
            .row4 = &self.row4,
            .row5 = &self.row5,
            .transcript_program = &self.transcript_program,
            .row8 = &self.row8,
            .row9 = &self.row9,
            .public_program = &self.public_program,
            .composition_program = &self.composition_authority,
            .composition_input = self.compositionInput(fri_input),
            .fri_program = &self.fri_authority,
            .fri_input = fri_input,
            .arithmetic_program = &self.arithmetic_program,
            .merkle_program = &self.merkle_program,
            .provider_program = &self.provider_program,
        };
    }
};

fn candidateVmPlan() !schedule.Plan {
    var config = protocol.PCS_CONFIG.fri_config;
    config.log_last_layer_degree_bound = 1;
    config.n_queries = 1;
    config.fold_step = 2;
    return schedule.Plan.initShape(
        std.testing.allocator,
        try schedule.vmProgramSpec(0, 0),
        .{
            .protocol_id = protocol.protocolId(),
            .shape_id = channel.hashBytes("node-descriptor-vm", 0x4e44_5631),
            .interaction_pow_bits = protocol.INTERACTION_POW_BITS,
            .pcs_pow_bits = protocol.PCS_POW_BITS,
            .query_count = 1,
            .table_count = 3,
            .claimed_sum_count = 2,
            .sampled_value_count = 7,
            .tree_heights = [_]u32{8} ** fixed_profile.TREE_COUNT,
            .fri = try fixed_profile.FriSchedule.init(7, config),
        },
    );
}
