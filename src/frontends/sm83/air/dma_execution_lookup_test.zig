const std = @import("std");
const subject = @import("dma_execution_lookup.zig");
const binding = @import("dma_binding.zig");
const runner = @import("../runner/mod.zig");
const dma = @import("../runner/dma.zig");
const memory = runner.cartridge_memory;
const mapper = @import("../cartridge/mbc3.zig");

test "DMA execution lookup cancels every positive M-cycle exactly once" {
    const steps = scenarioSteps();
    const source_bytes = [_]u8{0x42} ** 14;
    var trace = try binding.generateTrace(
        std.testing.allocator,
        0,
        16,
        .{},
        &steps,
        &source_bytes,
    );
    defer trace.deinit(std.testing.allocator);
    const relations = subject.Relations.dummy();
    var interaction = try subject.generateInteraction(
        std.testing.allocator,
        &steps,
        0,
        4,
        trace.rows,
        relations,
    );
    defer interaction.deinit();
    try std.testing.expectEqual(@as(usize, 16), interaction.claims.execution_count);
    try std.testing.expectEqual(@as(usize, 16), interaction.claims.dma_count);
    try subject.verifyCancellation(interaction.claims);
    for (interaction.execution_columns) |column|
        try std.testing.expectEqual(@as(usize, 16), column.len);
    for (interaction.dma_columns) |column|
        try std.testing.expectEqual(@as(usize, 16), column.len);
}

test "DMA execution lookup rejects omission clock substitution and claims" {
    const steps = scenarioSteps();
    const source_bytes = [_]u8{0x11} ** 14;
    var trace = try binding.generateTrace(
        std.testing.allocator,
        7,
        23,
        .{ .clock = 7 },
        &steps,
        &source_bytes,
    );
    defer trace.deinit(std.testing.allocator);
    const relations = subject.Relations.dummy();
    try std.testing.expectError(
        error.DmaExecutionCountMismatch,
        subject.generateInteraction(
            std.testing.allocator,
            &steps,
            7,
            4,
            trace.rows[0 .. trace.rows.len - 1],
            relations,
        ),
    );

    trace.rows[3].mcycle += 1;
    try std.testing.expectError(
        error.DmaExecutionLookupSumNonZero,
        subject.generateInteraction(
            std.testing.allocator,
            &steps,
            7,
            4,
            trace.rows,
            relations,
        ),
    );
    trace.rows[3].mcycle -= 1;

    var interaction = try subject.generateInteraction(
        std.testing.allocator,
        &steps,
        7,
        4,
        trace.rows,
        relations,
    );
    defer interaction.deinit();
    interaction.claims.dma = interaction.claims.dma.add(
        @import("stwo_core").fields.qm31.QM31.one(),
    );
    try std.testing.expectError(
        error.DmaExecutionLookupSumNonZero,
        subject.verifyCancellation(interaction.claims),
    );
    interaction.claims.execution_count = 0;
    try std.testing.expectError(
        error.EmptyDmaExecutionLookup,
        subject.verifyCancellation(interaction.claims),
    );
}

fn scenarioSteps() [16]runner.CartridgeStepTrace {
    var result = [_]runner.CartridgeStepTrace{
        accessStep(0xff80, .read, 0),
    } ** 16;
    result[0] = accessStep(dma.DMA_ADDRESS, .write, 0xc0);
    return result;
}

fn accessStep(
    address: u16,
    action: memory.Action,
    value: u8,
) runner.CartridgeStepTrace {
    var result: runner.CartridgeStepTrace = undefined;
    result.instruction.cycle_count = 1;
    result.instruction.cycles[0] = .{
        .address = address,
        .value = value,
        .action = switch (action) {
            .read => .read,
            .write => .write,
        },
    };
    result.accesses = [_]?memory.Access{null} ** 6;
    result.accesses[0] = .{
        .logical_address = address,
        .action = action,
        .region = .system,
        .physical_offset = null,
        .mapper_before = mapper.State{},
        .mapper_after = mapper.State{},
        .value = value,
    };
    return result;
}
