//! Defensive mutation and allocation adversaries for native typed LUI.

const std = @import("std");
const effects = @import("effects.zig");
const instruction_effects = @import("instruction_effects.zig");
const ir = @import("ir.zig");
const relation = @import("relation.zig");
const source = @import("source.zig");
const typed_lui = @import("typed_lui.zig");
const types = @import("types.zig");
const validate = @import("validate.zig");

test "typed LUI rejects substituted state range and destination IR" {
    comptime {
        const info = @typeInfo(@TypeOf(instruction_effects.retireSequential)).@"fn";
        if (info.params.len != 4)
            @compileError("sequential retirement must not accept caller-provided after-values");
    }

    {
        var authored = try typed_lui.build(std.testing.allocator, .generated);
        defer authored.deinit();
        try std.testing.expectError(
            error.InvalidMachineDerivedOperand,
            authored.arena.instructionNextPc(
                authored.columns.clock,
                source.SourceSpan.generated(),
            ),
        );
        const forged_pc = try authored.arena.input(
            "forged_next_pc",
            .pc,
            source.SourceSpan.generated(),
        );
        const produced = authored.arena.effect(
            authored.events.retirement.events.produce,
        ).?;
        authored.arena.effect_values.items[produced.values.start] = forged_pc;
        try std.testing.expectError(error.InvalidEffect, authored.validate());
    }
    {
        var authored = try typed_lui.build(std.testing.allocator, .generated);
        defer authored.deinit();
        const forged_clock = try authored.arena.input(
            "forged_next_clock",
            .clock,
            source.SourceSpan.generated(),
        );
        const produced = authored.arena.effect(
            authored.events.retirement.events.produce,
        ).?;
        authored.arena.effect_values.items[produced.values.start + 1] = forged_clock;
        try std.testing.expectError(error.InvalidEffect, authored.validate());
    }
    {
        var authored = try typed_lui.build(std.testing.allocator, .generated);
        defer authored.deinit();
        authored.arena.effects.items[types.idIndex(authored.events.immediate_range)]
            .binding.?.schema = relation.id(.range_check_20);
        try std.testing.expectError(error.InvalidEffect, authored.validate());
    }
    {
        var authored = try typed_lui.build(std.testing.allocator, .generated);
        defer authored.deinit();
        const emitted = authored.arena.effect(authored.events.destination.emit).?;
        authored.arena.effect_values.items[emitted.values.start + 6] =
            authored.columns.rd_previous[3];
        try validate.validate(&authored.arena);
        try std.testing.expectError(error.InvalidLuiDefinition, authored.validate());
    }
    {
        var authored = try typed_lui.build(std.testing.allocator, .generated);
        defer authored.deinit();
        authored.arena.constraints.items[7].root = authored.zero;
        try validate.validate(&authored.arena);
        try std.testing.expectError(error.InvalidLuiDefinition, authored.validate());
    }
    {
        var authored = try typed_lui.build(std.testing.allocator, .generated);
        defer authored.deinit();
        authored.arena.constraints.items[7].name =
            try authored.arena.internName("forged.lui.constraint");
        try validate.validate(&authored.arena);
        try std.testing.expectError(error.InvalidLuiDefinition, authored.validate());
    }
    {
        var authored = try typed_lui.build(std.testing.allocator, .generated);
        defer authored.deinit();
        const forged_opcode = try authored.arena.constantField(
            1 << 4,
            source.SourceSpan.generated(),
        );
        const fetch = authored.arena.effect(authored.events.program_fetch).?;
        authored.opcode = forged_opcode;
        authored.arena.effect_values.items[fetch.values.start + 1] = forged_opcode;
        try validate.validate(&authored.arena);
        try std.testing.expectError(error.InvalidLuiDefinition, authored.validate());
    }
    {
        var authored = try typed_lui.build(std.testing.allocator, .generated);
        defer authored.deinit();
        const fetch = authored.arena.effect(authored.events.program_fetch).?;
        authored.immediate = authored.zero;
        authored.arena.effect_values.items[fetch.values.start + 3] = authored.zero;
        try validate.validate(&authored.arena);
        try std.testing.expectError(error.InvalidLuiDefinition, authored.validate());
    }
    {
        var authored = try typed_lui.build(std.testing.allocator, .generated);
        defer authored.deinit();
        authored.arena.constraints.items[7].root = authored.zero;
        authored.constraint_roots[7] = authored.zero;
        try validate.validate(&authored.arena);
        try std.testing.expectError(error.InvalidLuiDefinition, authored.validate());
    }
    {
        var authored = try typed_lui.build(std.testing.allocator, .generated);
        defer authored.deinit();
        authored.result[1] = authored.zero;
        try validate.validate(&authored.arena);
        try std.testing.expectError(error.InvalidLuiDefinition, authored.validate());
    }
}

test "typed LUI rejects partial sequential retirement derivations" {
    const span = source.SourceSpan.generated();
    inline for (.{ false, true }) |derive_pc| {
        var arena = ir.Arena.init(std.testing.allocator);
        defer arena.deinit();
        const pc = try arena.input("pc", .pc, span);
        const clock = try arena.input("clock", .clock, span);
        const forged_pc = try arena.input("forged_pc", .pc, span);
        const forged_clock = try arena.input("forged_clock", .clock, span);
        const active = try arena.input("active", .selector, span);
        const next_pc = if (derive_pc)
            try arena.instructionNextPc(pc, span)
        else
            forged_pc;
        const next_clock = if (derive_pc)
            forged_clock
        else
            try arena.instructionNextClock(clock, span);
        _ = try effects.retire(
            &arena,
            .{ .pc = pc, .clock = clock },
            .{ .pc = next_pc, .clock = next_clock },
            active,
            span,
        );
        try std.testing.expectError(error.InvalidEffect, validate.validate(&arena));
    }
}

test "sequential derivations reject orphan generic unrelated and mismatched uses" {
    const span = source.SourceSpan.generated();
    {
        var arena = ir.Arena.init(std.testing.allocator);
        defer arena.deinit();
        const pc = try arena.input("pc", .pc, span);
        _ = try arena.instructionNextPc(pc, span);
        try std.testing.expectError(error.InvalidEffect, validate.validate(&arena));
    }
    {
        var arena = ir.Arena.init(std.testing.allocator);
        defer arena.deinit();
        const pc = try arena.input("pc", .pc, span);
        const one = try arena.constantField(1, span);
        const next_pc = try arena.instructionNextPc(pc, span);
        try std.testing.expectError(
            error.NonFieldOperand,
            arena.add(next_pc, one, span),
        );
        try std.testing.expectError(error.InvalidEffect, validate.validate(&arena));
    }
    {
        var arena = ir.Arena.init(std.testing.allocator);
        defer arena.deinit();
        const pc = try arena.input("pc", .pc, span);
        const clock = try arena.input("clock", .clock, span);
        const active = try arena.input("active", .selector, span);
        const retirement = try instruction_effects.retireSequential(
            &arena,
            .{ .pc = pc, .clock = clock },
            active,
            span,
        );
        _ = try effects.retire(
            &arena,
            .{ .pc = retirement.after.pc, .clock = clock },
            .{ .pc = pc, .clock = clock },
            active,
            span,
        );
        try std.testing.expectError(error.InvalidEffect, validate.validate(&arena));
    }
    {
        var arena = ir.Arena.init(std.testing.allocator);
        defer arena.deinit();
        const pc = try arena.input("pc", .pc, span);
        const forged_pc = try arena.input("forged_pc", .pc, span);
        const clock = try arena.input("clock", .clock, span);
        const active = try arena.input("active", .selector, span);
        const retirement = try instruction_effects.retireSequential(
            &arena,
            .{ .pc = pc, .clock = clock },
            active,
            span,
        );
        const consume = arena.effect(retirement.events.consume).?;
        arena.effect_values.items[consume.values.start] = forged_pc;
        try std.testing.expectError(error.InvalidEffect, validate.validate(&arena));
    }
    {
        var arena = ir.Arena.init(std.testing.allocator);
        defer arena.deinit();
        const pc = try arena.input("pc", .pc, span);
        const clock = try arena.input("clock", .clock, span);
        const active = try arena.input("active", .selector, span);
        const other_active = try arena.input("other_active", .selector, span);
        const retirement = try instruction_effects.retireSequential(
            &arena,
            .{ .pc = pc, .clock = clock },
            active,
            span,
        );
        arena.effects.items[types.idIndex(retirement.events.produce)].liveness =
            other_active;
        try std.testing.expectError(error.InvalidEffect, validate.validate(&arena));
    }
}

test "typed LUI construction releases every allocation failure" {
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        allocationFailureCase,
        .{},
    );
}

test "sequential retirement rollback preserves a nonempty arena" {
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        retirementAllocationFailureCase,
        .{},
    );
}

fn allocationFailureCase(allocator: std.mem.Allocator) !void {
    var authored = try typed_lui.build(allocator, .generated);
    defer authored.deinit();
}

fn retirementAllocationFailureCase(allocator: std.mem.Allocator) !void {
    var arena = ir.Arena.init(allocator);
    defer arena.deinit();
    const span = source.SourceSpan.generated();
    const pc = try arena.input("pc", .pc, span);
    const clock = try arena.input("clock", .clock, span);
    const active = try arena.input("active", .selector, span);
    const nodes_before = arena.nodeCount();
    const effects_before = arena.effectsView().len;
    const values_before = arena.effectValuesView().len;
    _ = instruction_effects.retireSequential(
        &arena,
        .{ .pc = pc, .clock = clock },
        active,
        span,
    ) catch |failure| {
        try std.testing.expectEqual(nodes_before, arena.nodeCount());
        try std.testing.expectEqual(effects_before, arena.effectsView().len);
        try std.testing.expectEqual(values_before, arena.effectValuesView().len);
        try validate.validate(&arena);
        return failure;
    };
}
