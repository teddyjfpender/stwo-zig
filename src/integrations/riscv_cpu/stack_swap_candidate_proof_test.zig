//! CPU instantiation of the nonproduction atomic-U256-swap proof harness.

const std = @import("std");
const CpuBackend = @import("stwo_cpu_backend").CpuBackend;
const frontend = @import("stwo_riscv_frontend");
const stwo_core = @import("stwo_core");

const Engine = frontend.prover_mod.ProverEngineForBackend(CpuBackend);
const harness = frontend.testing.stack_swap_proof_harness_v1;
const contract = frontend.testing.stack_swap_proof_component_v1;
const stark_component = frontend.testing.stack_swap_proof_stark_component_v1;
const trace_mod = frontend.testing.stack_swap_proof_trace_v1;
const abi = frontend.testing.stack_swap_candidate_abi_v1;
const caller = frontend.testing.stack_swap_caller_candidate_v1;
const words = frontend.testing.stack_swap_word_candidate_v1;
const relations_mod = frontend.testing.stack_swap_relations_v1;
const M31 = stwo_core.fields.m31.M31;
const QM31 = stwo_core.fields.qm31.QM31;
const circle = stwo_core.circle;

test "stack swap runner trace proves, postcards, and cold fresh verifies" {
    const receipt = try harness.exerciseTiny(Engine, std.testing.allocator);
    try receipt.validate();
    try std.testing.expect(receipt.call_relation_closed);
    try std.testing.expect(receipt.external_base_tables_required);
    try std.testing.expect(receipt.registry_unallocated);
    try std.testing.expect(!receipt.production_eligible);
}

test "stack swap proof selectors are current-only and power-of-two traces pad" {
    var eight = try trace_mod.WordTrace.init(std.testing.allocator, 8);
    defer eight.deinit();
    try std.testing.expectEqual(@as(u32, 4), eight.log_size);
    try std.testing.expectEqual(@as(usize, 16), eight.domainSize());
    try std.testing.expect(eight.preprocessedAt(
        trace_mod.domain_first_column,
        0,
    ).eql(M31.one()));
    try std.testing.expect(eight.preprocessedAt(
        trace_mod.active_prefix_column,
        7,
    ).eql(M31.one()));
    try std.testing.expect(eight.preprocessedAt(
        trace_mod.active_prefix_column,
        8,
    ).isZero());
    try std.testing.expect(eight.preprocessedAt(
        trace_mod.lane_last_column,
        7,
    ).eql(M31.one()));

    var sixteen = try trace_mod.WordTrace.init(std.testing.allocator, 16);
    defer sixteen.deinit();
    try std.testing.expectEqual(@as(u32, 5), sixteen.log_size);
    var retained = try trace_mod.WordTrace.init(
        std.testing.allocator,
        abi.retained_scope.calls * abi.words_per_value,
    );
    defer retained.deinit();
    try std.testing.expectEqual(@as(u32, 19), retained.log_size);

    const authority = try fixtureAuthority();
    const relations = relations_mod.Relations.dummy();
    const claim = try contract.WordClaim.canonical(
        4,
        8,
        .{QM31.zero()} ** contract.word_batch_count,
    );
    var component = try stark_component.Component(contract.Word).init(
        claim,
        .{ .preprocessed_offset = 0, .main_offset = 0, .interaction_offset = 0 },
        .{ .relations = &relations, .authority = &authority },
    );
    const point = circle.SECURE_FIELD_CIRCLE_GEN.mul(29);
    var masks = try component.maskPoints(std.testing.allocator, point, 6);
    defer masks.deinitDeep(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 3), masks.items[0].len);
    for (masks.items[0]) |column| {
        try std.testing.expectEqual(@as(usize, 1), column.len);
        try std.testing.expect(std.meta.eql(point, column[0]));
    }

    const record = caller.Record{
        .execution_clock = 7,
        .pc = 0x1000,
        .lhs_previous_clock = 0,
        .rhs_previous_clock = 0,
        .lhs_pointer = 0x4000,
        .rhs_pointer = 0x4080,
        .call_index = 0,
    };
    const caller_main = (try caller.materialize(record)).encode();
    var word_main = (try words.materializeRow(record.call(), .at(7), .{
        .lhs_previous_clock = 0,
        .rhs_previous_clock = 0,
        .lhs_before = .{ 1, 2, 3, 4 },
        .rhs_before = .{ 5, 6, 7, 8 },
    })).encode();
    try std.testing.expect(std.meta.eql(
        relations_mod.callerCallTuple(M31, &caller_main),
        contract.wordProofCallTuple(M31, &word_main),
    ));
    word_main[words.Layout.lhs_word_address] =
        word_main[words.Layout.lhs_word_address].add(M31.one());
    try std.testing.expect(!std.meta.eql(
        relations_mod.callerCallTuple(M31, &caller_main),
        contract.wordProofCallTuple(M31, &word_main),
    ));
}

fn fixtureAuthority() !abi.Authority {
    var registry_identity: [32]u8 = undefined;
    for (&registry_identity, 0..) |*byte, index| byte.* = @intCast(0x41 + index);
    return abi.Authority.create(.{
        .funct7 = 5,
        .proof_opcode_id = 49,
        .registry_identity = registry_identity,
    });
}
