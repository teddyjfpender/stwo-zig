const std = @import("std");
const core_air_components = @import("stwo_core").air.components;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const action_lookup = @import("air/joypad_action_lookup.zig");
const cartridge_memory_lookup =
    @import("air/cartridge_memory_lookup.zig");
const cartridge_rom_lookup = @import("air/cartridge_rom_lookup.zig");
const mmio_lookup = @import("air/joypad_mmio_lookup.zig");
const timer_mmio_lookup = @import("air/timer_mmio_lookup.zig");
const cartridge_components = @import("cartridge_proof_components.zig");
const cartridge_statement = @import("cartridge_proof_statement.zig");
const environment_statement = @import("environment_statement.zig");
const subject = @import("environment_proof_components.zig");

test "environment preserves cartridge prefix and pins device tail order" {
    const statement = testStatement();
    var context: subject.Context = undefined;
    subject.init(
        &context,
        statement,
        cartridge_rom_lookup.Relation.dummy(),
        cartridge_memory_lookup.Relation.dummy(),
        action_lookup.Relation.dummy(),
        mmio_lookup.Relations.dummy(),
        timer_mmio_lookup.Relations.dummy(),
    );
    try std.testing.expectEqual(@as(usize, 22), subject.N_CARTRIDGE_COMPONENTS);
    try std.testing.expectEqual(@as(usize, 34), subject.N_COMPONENTS);
    try std.testing.expect(
        context.cartridge.packed_access_component.allow_joypad_mmio,
    );
    try std.testing.expect(
        context.cartridge.packed_access_component.allow_timer_mmio,
    );
    try std.testing.expect(
        !context.cartridge.packed_access_component.allow_ppu_mmio,
    );
    try std.testing.expectEqual(
        statement.action_lookup_claims.events,
        context.action_component.claims.events,
    );
    try std.testing.expectEqual(
        statement.joypad_mmio_lookup_claims.execution[0][0],
        context.mmio_execution_component.claims.execution[0][0],
    );
    try std.testing.expectEqual(
        statement.joypad_if_memory_claim,
        context.if_memory_component.claim,
    );
    try std.testing.expectEqual(
        @intFromPtr(&context.cartridge.memory_relation),
        @intFromPtr(context.if_memory_component.relation),
    );

    var verifier_storage: [subject.N_COMPONENTS]subject.VerifierComponent = undefined;
    const verifier_components = try subject.verifier(
        &context,
        &verifier_storage,
    );
    var cartridge_storage: [cartridge_components.N_COMPONENTS]subject.VerifierComponent = undefined;
    const cartridge = try cartridge_components.verifier(
        &context.cartridge,
        &cartridge_storage,
    );
    for (
        verifier_components[0..subject.N_CARTRIDGE_COMPONENTS],
        cartridge,
    ) |actual, expected| {
        try std.testing.expectEqual(
            @intFromPtr(expected.ctx),
            @intFromPtr(actual.ctx),
        );
        try std.testing.expectEqual(expected.vtable, actual.vtable);
    }
    const tail = [_]*const anyopaque{
        &context.tail_owners[0],
        &context.tail_owners[1],
        &context.tail_owners[2],
        &context.tail_owners[3],
        &context.tail_owners[4],
        &context.tail_owners[5],
        &context.tail_owners[6],
        &context.tail_owners[7],
        &context.tail_owners[8],
        &context.tail_owners[9],
        &context.tail_owners[10],
        &context.tail_owners[11],
    };
    for (context.tail_owners, 0..) |owner, index|
        try std.testing.expectEqual(
            index,
            @intFromEnum(owner.kind),
        );
    for (
        verifier_components[subject.N_CARTRIDGE_COMPONENTS..],
        tail,
    ) |actual, expected|
        try std.testing.expectEqual(
            @intFromPtr(expected),
            @intFromPtr(actual.ctx),
        );

    var prover_storage: [subject.N_COMPONENTS]subject.ProverComponent = undefined;
    const prover_components = try subject.prover(
        &context,
        &prover_storage,
    );
    for (
        prover_components[subject.N_CARTRIDGE_COMPONENTS..],
        tail,
    ) |actual, expected|
        try std.testing.expectEqual(
            @intFromPtr(expected),
            @intFromPtr(actual.ctx),
        );
    try std.testing.expectError(
        error.InvalidProofShape,
        subject.verifier(
            &context,
            verifier_storage[0 .. subject.N_COMPONENTS - 1],
        ),
    );
    try std.testing.expectError(
        error.InvalidProofShape,
        subject.prover(
            &context,
            prover_storage[0 .. subject.N_COMPONENTS - 1],
        ),
    );
}

test "environment components exactly own statement column geometry" {
    var context: subject.Context = undefined;
    subject.init(
        &context,
        testStatement(),
        cartridge_rom_lookup.Relation.dummy(),
        cartridge_memory_lookup.Relation.dummy(),
        action_lookup.Relation.dummy(),
        mmio_lookup.Relations.dummy(),
        timer_mmio_lookup.Relations.dummy(),
    );
    var storage: [subject.N_COMPONENTS]subject.VerifierComponent =
        undefined;
    const collected = try subject.verifier(&context, &storage);
    const components = core_air_components.Components{
        .components = collected,
        .n_preprocessed_columns = environment_statement.N_PREPROCESSED_COLUMNS,
    };
    var logs = try components.columnLogSizes(std.testing.allocator);
    defer logs.deinitDeep(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 3), logs.items.len);
    try std.testing.expectEqualSlices(
        u32,
        &environment_statement.preprocessedLogSizes(4, 4, 4, 4),
        logs.items[0],
    );
    try std.testing.expectEqualSlices(
        u32,
        &environment_statement.mainLogSizes(4, 4, 4, 4),
        logs.items[1],
    );
    try std.testing.expectEqualSlices(
        u32,
        &environment_statement.interactionLogSizes(4, 4, 4, 4),
        logs.items[2],
    );
    var masks = try components.maskPoints(
        std.testing.allocator,
        @import("stwo_core").circle.SECURE_FIELD_CIRCLE_GEN,
        components.compositionLogDegreeBound(),
        false,
    );
    defer masks.deinitDeep(std.testing.allocator);
    try std.testing.expectEqual(
        environment_statement.N_PREPROCESSED_COLUMNS,
        masks.items[0].len,
    );
    try std.testing.expectEqual(
        environment_statement.N_MAIN_COLUMNS,
        masks.items[1].len,
    );
    try std.testing.expectEqual(
        environment_statement.N_INTERACTION_COLUMNS,
        masks.items[2].len,
    );

    const expected_degree_logs = [_]u32{5} ** subject.N_ENVIRONMENT_COMPONENTS;
    const actual_degree_logs = [_]u32{
        context.joypad_component.maxConstraintLogDegreeBound(),
        context.binding_component.maxConstraintLogDegreeBound(),
        context.action_component.maxConstraintLogDegreeBound(),
        context.mmio_execution_component.maxConstraintLogDegreeBound(),
        context.mmio_joypad_component.maxConstraintLogDegreeBound(),
        context.if_memory_component.maxConstraintLogDegreeBound(),
        context.timer_component.maxConstraintLogDegreeBound(),
        context.timer_binding_component.maxConstraintLogDegreeBound(),
        context.timer_mmio_execution_component.maxConstraintLogDegreeBound(),
        context.timer_mmio_timer_component.maxConstraintLogDegreeBound(),
        context.timer_if_memory_component.maxConstraintLogDegreeBound(),
        context.intermediate_observation_component.maxConstraintLogDegreeBound(),
    };
    try std.testing.expectEqualSlices(
        u32,
        &expected_degree_logs,
        &actual_degree_logs,
    );
    try std.testing.expectEqual(
        environment_statement.ACTION_INTERACTION_OFFSET,
        context.action_component.interaction_offset,
    );
    try std.testing.expectEqual(
        environment_statement.MMIO_EXECUTION_INTERACTION_OFFSET,
        context.mmio_execution_component.interaction_offset,
    );
    try std.testing.expectEqual(
        environment_statement.MMIO_JOYPAD_INTERACTION_OFFSET,
        context.mmio_joypad_component.interaction_offset,
    );
    try std.testing.expectEqual(
        environment_statement.JOYPAD_IF_INTERACTION_OFFSET,
        context.if_memory_component.interaction_offset,
    );
    try std.testing.expectEqual(
        environment_statement.TIMER_MMIO_EXECUTION_INTERACTION_OFFSET,
        context.timer_mmio_execution_component.interaction_offset,
    );
    try std.testing.expectEqual(
        environment_statement.TIMER_MMIO_TIMER_INTERACTION_OFFSET,
        context.timer_mmio_timer_component.interaction_offset,
    );
    try std.testing.expectEqual(
        environment_statement.TIMER_IF_INTERACTION_OFFSET,
        context.timer_if_memory_component.interaction_offset,
    );
    try std.testing.expectEqual(
        environment_statement.INTERMEDIATE_OBSERVATION_INTERACTION_OFFSET,
        context.intermediate_observation_component.interaction_offset,
    );
}

test "environment rejects action and IF claim mutations" {
    const statement = testStatement();
    try environment_statement.verifyLookupCancellation(statement);

    var action_mutation = statement;
    action_mutation.action_lookup_claims.events =
        action_mutation.action_lookup_claims.events.add(QM31.one());
    try std.testing.expectError(
        error.JoypadActionLookupSumNonZero,
        environment_statement.verifyLookupCancellation(action_mutation),
    );

    var if_mutation = statement;
    if_mutation.joypad_if_memory_claim =
        if_mutation.joypad_if_memory_claim.add(QM31.one());
    try std.testing.expectError(
        error.CartridgeMemoryLookupSumNonZero,
        environment_statement.verifyLookupCancellation(if_mutation),
    );
}

fn testStatement() environment_statement.ExecutionStatement {
    const rom_claim = q(7);
    const memory_claim = q(11);
    const action_claim = q(13);
    const mmio_claim = q(17);
    var rom_claims = cartridge_rom_lookup.Claims{
        .execution = [_]QM31{QM31.zero()} **
            cartridge_rom_lookup.N_EXECUTION_SUMS,
        .rom = rom_claim.neg(),
    };
    rom_claims.execution[0] = rom_claim;
    var memory_claims = cartridge_memory_lookup.Claims{
        .execution = [_]QM31{QM31.zero()} **
            cartridge_memory_lookup.N_EXECUTION_SUMS,
        .boundary = QM31.zero(),
    };
    memory_claims.execution[0] = memory_claim.neg();
    var mmio_claims = mmio_lookup.Claims{
        .execution = [_][mmio_lookup.N_EXECUTION_SUMS]QM31{
            [_]QM31{QM31.zero()} ** mmio_lookup.N_EXECUTION_SUMS,
        } ** mmio_lookup.N_RELATIONS,
        .joypad = [_]QM31{QM31.zero()} ** mmio_lookup.N_RELATIONS,
    };
    mmio_claims.execution[0][0] = mmio_claim;
    mmio_claims.joypad[0] = mmio_claim.neg();
    return .{
        .version = environment_statement.VERSION,
        .base = cartridge_statement.ExecutionStatement{
            .log_size = 4,
            .initial = .{ .cpu = .{}, .mcycle = 0 },
            .final = .{ .cpu = .{}, .mcycle = 16 },
            .initial_mapper = .{},
            .final_mapper = .{},
            .rom_digest = [_]u8{0} ** 32,
            .initial_system_digest = [_]u8{0} ** 32,
            .final_system_digest = [_]u8{0} ** 32,
            .initial_sram_digest = [_]u8{0} ** 32,
            .final_sram_digest = [_]u8{0} ** 32,
            .rom_lookup_claims = rom_claims,
            .memory_lookup_claims = memory_claims,
        },
        .action_count = 0,
        .action_digest = [_]u8{0} ** 32,
        .initial_joypad = .{},
        .final_joypad = .{},
        .joypad_log_size = 4,
        .initial_timer = .{},
        .final_timer = .{},
        .timer_log_size = 4,
        .observation_region_count = 0,
        .observation_digest = [_]u8{0} ** 32,
        .intermediate_observation_log_size = 4,
        .intermediate_observation_schedule_claim = .{
            .count = 1,
            .digest = [_]u8{0} ** 32,
        },
        .action_lookup_claims = .{
            .events = action_claim,
            .public = action_claim.neg(),
        },
        .joypad_mmio_lookup_claims = mmio_claims,
        .joypad_if_memory_claim = memory_claim,
        .timer_mmio_lookup_claims = .{
            .execution = [_][timer_mmio_lookup.N_EXECUTION_SUMS]QM31{
                [_]QM31{QM31.zero()} **
                    timer_mmio_lookup.N_EXECUTION_SUMS,
            } ** timer_mmio_lookup.N_RELATIONS,
            .timer = [_]QM31{QM31.zero()} **
                timer_mmio_lookup.N_RELATIONS,
        },
        .timer_if_memory_claim = QM31.zero(),
        .intermediate_observation_memory_claim = QM31.zero(),
    };
}

fn q(value: u32) QM31 {
    return QM31.fromU32Unchecked(value, 0, 0, 0);
}
