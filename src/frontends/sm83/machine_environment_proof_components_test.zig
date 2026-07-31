const std = @import("std");
const core_air_components = @import("stwo_core").air.components;
const action_lookup = @import("air/joypad_action_lookup.zig");
const apu_execution = @import("air/apu_execution_lookup.zig");
const dma_execution = @import("air/dma_execution_lookup.zig");
const memory_lookup = @import("air/cartridge_memory_lookup.zig");
const ppu_mmio = @import("air/ppu_mmio_lookup.zig");
const rom_lookup = @import("air/cartridge_rom_lookup.zig");
const joypad_mmio = @import("air/joypad_mmio_lookup.zig");
const timer_mmio = @import("air/timer_mmio_lookup.zig");
const environment_components =
    @import("environment_proof_components.zig");
const geometry = @import("machine_environment_geometry.zig");
const protocol = @import("machine_environment_statement.zig");
const subject = @import("machine_environment_proof_components.zig");

fn testStatement() protocol.ExecutionStatement {
    var result = std.mem.zeroInit(protocol.ExecutionStatement, .{
        .initial_apu = .{},
        .final_apu = .{},
    });
    result.version = protocol.VERSION;
    result.base.version =
        @import("environment_statement.zig").VERSION;
    result.base.base.log_size = 4;
    result.base.base.initial.mcycle = 10;
    result.base.base.final.mcycle = 26;
    result.base.joypad_log_size = 4;
    result.base.timer_log_size = 4;
    result.base.intermediate_observation_log_size = 4;
    result.ppu_log_size = 5;
    result.dma_log_size = 6;
    result.apu_log_size = 4;
    result.initial_dma.clock = 10;
    result.final_dma.clock = 26;
    return result;
}

fn initContext(context: *subject.Context) void {
    subject.init(
        context,
        testStatement(),
        rom_lookup.Relation.dummy(),
        memory_lookup.Relation.dummy(),
        action_lookup.Relation.dummy(),
        joypad_mmio.Relations.dummy(),
        timer_mmio.Relations.dummy(),
        ppu_mmio.Relations.dummy(),
        dma_execution.Relations.dummy(),
        apu_execution.Relation.dummy(),
    );
}

test "machine components preserve v3 prefix and exact tail geometry" {
    var context: subject.Context = undefined;
    initContext(&context);
    try std.testing.expectEqual(
        environment_components.N_COMPONENTS,
        subject.N_ENVIRONMENT_COMPONENTS,
    );
    try std.testing.expectEqual(@as(usize, 53), subject.N_COMPONENTS);
    try std.testing.expect(
        context.environment.cartridge.packed_access_component
            .allow_ppu_mmio,
    );
    try std.testing.expect(
        context.environment.cartridge.packed_access_component
            .allow_apu_mmio,
    );
    const activity = context.environment.cartridge.cpu
        .execution_component.family_activity_columns.?;
    try std.testing.expectEqual(
        geometry.SCHEDULER_PROVENANCE_MAIN_OFFSET,
        activity.instruction,
    );
    try std.testing.expectEqual(
        geometry.SCHEDULER_PROVENANCE_MAIN_OFFSET + 3,
        activity.interrupt_service,
    );
    try std.testing.expectEqual(
        @intFromPtr(&context.environment.cartridge.memory_relation),
        @intFromPtr(context.scheduler_memory_component.relation),
    );
    try std.testing.expectEqual(
        @intFromPtr(&context.environment.cartridge.memory_relation),
        @intFromPtr(context.service_memory_component.relation),
    );
    try std.testing.expectEqual(
        @intFromPtr(&context.environment.cartridge.memory_relation),
        @intFromPtr(context.ppu_if_component.relation),
    );
    try std.testing.expectEqual(
        @intFromPtr(&context.dma_execution_relations),
        @intFromPtr(context.ppu_policy_dma_component.relations),
    );
    try std.testing.expectEqual(
        @intFromPtr(&context.dma_execution_relations),
        @intFromPtr(context.ppu_policy_ppu_component.relations),
    );
    try std.testing.expectEqual(
        @intFromPtr(&context.environment.cartridge.memory_relation),
        @intFromPtr(context.dma_memory_component.relation),
    );
    try std.testing.expectEqual(
        @intFromPtr(&context.apu_execution_relation),
        @intFromPtr(context.apu_execution_execution_component.relation),
    );
    try std.testing.expectEqual(
        @intFromPtr(&context.apu_execution_relation),
        @intFromPtr(context.apu_execution_apu_component.relation),
    );

    var verifier_storage: [subject.N_COMPONENTS]subject.VerifierComponent = undefined;
    const verifier = try subject.verifier(
        &context,
        &verifier_storage,
    );
    var prefix_storage: [environment_components.N_COMPONENTS]subject.VerifierComponent =
        undefined;
    const prefix = try environment_components.verifier(
        &context.environment,
        &prefix_storage,
    );
    try std.testing.expectEqual(
        @intFromPtr(&context.owners[0]),
        @intFromPtr(verifier[0].ctx),
    );
    for (
        verifier[1..subject.N_ENVIRONMENT_COMPONENTS],
        prefix[1..],
    ) |actual, expected| {
        try std.testing.expectEqual(
            @intFromPtr(expected.ctx),
            @intFromPtr(actual.ctx),
        );
        try std.testing.expectEqual(expected.vtable, actual.vtable);
    }

    const components = core_air_components.Components{
        .components = verifier,
        .n_preprocessed_columns = geometry.N_PREPROCESSED_COLUMNS,
    };
    var logs = try components.columnLogSizes(std.testing.allocator);
    defer logs.deinitDeep(std.testing.allocator);
    try std.testing.expectEqualSlices(
        u32,
        &geometry.preprocessedLogSizes(4, 4, 4, 4, 5, 6, 4),
        logs.items[0],
    );
    try std.testing.expectEqualSlices(
        u32,
        &geometry.mainLogSizes(4, 4, 4, 4, 5, 6, 4),
        logs.items[1],
    );
    try std.testing.expectEqualSlices(
        u32,
        &geometry.interactionLogSizes(4, 4, 4, 4, 5, 6, 4),
        logs.items[2],
    );
}

test "machine component collection fails closed on truncated storage" {
    var context: subject.Context = undefined;
    initContext(&context);
    var verifier_storage: [subject.N_COMPONENTS]subject.VerifierComponent = undefined;
    try std.testing.expectError(
        error.InvalidProofShape,
        subject.verifier(
            &context,
            verifier_storage[0 .. subject.N_COMPONENTS - 1],
        ),
    );
    var prover_storage: [subject.N_COMPONENTS]subject.ProverComponent = undefined;
    try std.testing.expectError(
        error.InvalidProofShape,
        subject.prover(
            &context,
            prover_storage[0 .. subject.N_COMPONENTS - 1],
        ),
    );
}
