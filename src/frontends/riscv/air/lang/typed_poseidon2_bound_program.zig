//! Shared typed permutation, degree cuts, physical binding.
//! Owns no witness executor or backend state.
const std = @import("std");
const compat = @import("typed_poseidon2_compat.zig");
const ir = @import("ir.zig");
const materializer = @import("degree3_materializer.zig");
const poseidon = @import("typed_poseidon2.zig");
const source = @import("source.zig");
const types = @import("types.zig");

pub const Program = struct {
    allocator: std.mem.Allocator,
    arena: ir.Arena,
    gate: types.ValueId,
    spans: poseidon.DefinitionSpans,
    definition: poseidon.Definition,
    plan: materializer.Plan,
    binding: compat.OwnedBinding,

    pub fn init(allocator: std.mem.Allocator) !Program {
        var arena = ir.Arena.init(allocator);
        errdefer arena.deinit();
        const source_id = try arena.addSource(
            "air/components/poseidon2_m31.proof-harness.zig",
        );
        const gate = try arena.input(
            compat.ENABLER_NAME,
            .selector,
            try spanAt(source_id, 1),
        );
        const spans = try distinctSpans(source_id);
        const definition = try poseidon.define(&arena, spans);
        const roots = poseidon.values(definition.outputs);
        var plan = try materializer.plan(allocator, &arena, .{
            .roots = &roots,
            .gate = gate,
        });
        errdefer plan.deinit();
        var schedule = try compat.generate(allocator);
        defer schedule.deinit(allocator);
        var binding = try compat.bindPlan(
            allocator,
            &arena,
            definition,
            spans,
            schedule,
            &plan,
        );
        errdefer binding.deinit(allocator);
        const result = Program{
            .allocator = allocator,
            .arena = arena,
            .gate = gate,
            .spans = spans,
            .definition = definition,
            .plan = plan,
            .binding = binding,
        };
        return result;
    }

    pub fn deinit(self: *Program) void {
        self.binding.deinit(self.allocator);
        self.plan.deinit();
        self.arena.deinit();
        self.* = undefined;
    }
};

fn distinctSpans(source_id: types.SourceId) !poseidon.DefinitionSpans {
    var line: u32 = 2;
    const declaration = try spanAt(source_id, line);
    line += 1;
    var inputs: [poseidon.WIDTH]source.SourceSpan = undefined;
    for (&inputs) |*span| {
        span.* = try spanAt(source_id, line);
        line += 1;
    }
    const initial_linear = try spanAt(source_id, line);
    line += 1;
    var external: [poseidon.N_EXTERNAL_ROUNDS]poseidon.ExternalRoundSpans = undefined;
    for (&external) |*round| {
        round.* = .{
            .constants = try spanAt(source_id, line),
            .sbox = try spanAt(source_id, line + 1),
            .linear = try spanAt(source_id, line + 2),
        };
        line += 3;
    }
    var internal: [poseidon.N_INTERNAL_ROUNDS]poseidon.InternalRoundSpans = undefined;
    for (&internal) |*round| {
        round.* = .{
            .constant = try spanAt(source_id, line),
            .sbox = try spanAt(source_id, line + 1),
            .linear = try spanAt(source_id, line + 2),
        };
        line += 3;
    }
    return .{
        .declaration = declaration,
        .inputs = inputs,
        .body = .{
            .initial_linear = initial_linear,
            .external_rounds = external,
            .internal_rounds = internal,
        },
    };
}

fn spanAt(source_id: types.SourceId, line: u32) !source.SourceSpan {
    return source.SourceSpan.init(
        source_id,
        .{ .byte_offset = line * 8, .line = line, .column = 1 },
        .{ .byte_offset = line * 8 + 1, .line = line, .column = 2 },
    );
}
