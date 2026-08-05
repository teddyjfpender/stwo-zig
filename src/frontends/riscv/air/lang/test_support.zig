const std = @import("std");
const functions = @import("functions.zig");
const ir = @import("ir.zig");
const source = @import("source.zig");
const types = @import("types.zig");

pub const Fixture = struct {
    arena: ir.Arena,
    lhs: types.ValueId,
    rhs: types.ValueId,
    live: types.ValueId,
    word: types.ValueId,
    sum: types.ValueId,
    hint_output: types.ValueId,
    negated: types.ValueId,
    call_output: types.ValueId,

    pub fn init(allocator: std.mem.Allocator) !Fixture {
        return initWithPerturbedInterning(allocator, false);
    }

    pub fn initPerturbed(allocator: std.mem.Allocator) !Fixture {
        return initWithPerturbedInterning(allocator, true);
    }

    fn initWithPerturbedInterning(
        allocator: std.mem.Allocator,
        perturbed: bool,
    ) !Fixture {
        var arena = ir.Arena.init(allocator);
        errdefer arena.deinit();

        if (perturbed) {
            const names = [_][]const u8{
                "fixture/primary.zig",
                "fixture/secondary.zig",
                "lhs",
                "rhs",
                "live",
                "word",
                "fixture.inverse.v1",
                "fixture.sum",
                "fixture.hint",
                "fixture.sum_fn",
                "fixture.hint_fn",
            };
            var index = names.len;
            while (index > 0) {
                index -= 1;
                _ = try arena.internName(names[index]);
            }
            _ = try arena.addSource("fixture/secondary.zig");
        }
        const primary_source = try arena.addSource("fixture/primary.zig");
        _ = try arena.addSource("fixture/secondary.zig");
        const span = try source.SourceSpan.init(
            primary_source,
            .{ .byte_offset = 0, .line = 1, .column = 1 },
            .{ .byte_offset = 4, .line = 1, .column = 5 },
        );
        const lhs = try arena.input("lhs", .felt, span);
        const rhs = try arena.input("rhs", .felt, span);
        const live = try arena.input("live", .bit, span);
        const word = try arena.input("word", .word32, span);
        const sum = try arena.add(lhs, rhs, span);
        const hint_id = try arena.addHint(
            "fixture.inverse.v1",
            &.{lhs},
            &.{.felt},
            span,
        );
        const hint_output = arena.hintOutputs(hint_id).?[0];
        const negated = try arena.neg(sum, span);

        _ = try arena.assertZero(
            "fixture.sum",
            sum,
            live,
            .semantic,
            span,
        );
        _ = try arena.assertZero(
            "fixture.hint",
            hint_output,
            null,
            .hint_binding,
            span,
        );
        _ = try arena.addEffect(
            .register_read,
            &.{ lhs, rhs },
            live,
            0,
            span,
        );
        _ = try arena.addEffect(
            .memory_write,
            &.{hint_output},
            live,
            1,
            span,
        );
        const sum_function = try functions.add(
            &arena,
            "fixture.sum_fn",
            &.{ lhs, rhs, live },
            &.{sum},
            span,
        );
        const hint_function = try functions.begin(
            &arena,
            "fixture.hint_fn",
            &.{ lhs, rhs, live },
            span,
        );
        const call_id = try functions.call(
            &arena,
            sum_function,
            &.{ lhs, rhs, live },
            .inline_expansion,
            span,
        );
        const call_output = functions.callOutputs(&arena, call_id).?[0];
        try functions.finish(
            &arena,
            hint_function,
            &.{ hint_output, negated, call_output },
        );

        return .{
            .arena = arena,
            .lhs = lhs,
            .rhs = rhs,
            .live = live,
            .word = word,
            .sum = sum,
            .hint_output = hint_output,
            .negated = negated,
            .call_output = call_output,
        };
    }

    pub fn deinit(self: *Fixture) void {
        self.arena.deinit();
        self.* = undefined;
    }
};
