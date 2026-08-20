const std = @import("std");
const frames = @import("function_frames.zig");
const functions = @import("functions.zig");
const hints = @import("hints.zig");
const ir = @import("ir.zig");
const source = @import("source.zig");
const types = @import("types.zig");

const generated = source.SourceSpan.generated();

test "function frames compile private SSA writes and exact activation events" {
    var fixture = try ActivationFixture.init(std.testing.allocator);
    defer fixture.deinit();

    var plan = try frames.compile(std.testing.allocator, &fixture.arena);
    defer plan.deinit();
    try plan.validate();
    try plan.validateAgainst(std.testing.allocator, &fixture.arena);

    try std.testing.expectEqual(@as(usize, 2), plan.frames.len);
    try std.testing.expectEqual(@as(usize, 2), plan.calls.len);
    try std.testing.expectEqual(@as(usize, 3), plan.events.len);

    const callee = plan.frame(fixture.callee).?;
    try std.testing.expect(callee.deterministic);
    try std.testing.expect(callee.relation_required);
    try std.testing.expect(plan.ownsWrite(fixture.callee, fixture.sum));
    try std.testing.expect(!plan.ownsWrite(fixture.callee, fixture.x));
    try std.testing.expectEqualSlices(
        types.ValueId,
        &.{fixture.sum},
        plan.writes(callee.*).?,
    );
    try std.testing.expectEqualSlices(
        types.ValueId,
        &.{ fixture.x, fixture.y, fixture.sum },
        plan.tuple(callee.activation_tuple).?,
    );

    const caller = plan.frame(fixture.caller).?;
    try std.testing.expect(caller.deterministic);
    try std.testing.expect(!caller.relation_required);
    try std.testing.expect(plan.ownsWrite(fixture.caller, fixture.internal_output));

    try std.testing.expectEqual(frames.ActivationKind.callee_consume, plan.events[0].kind);
    try std.testing.expectEqual(frames.ActivationRole.consume, plan.events[0].role);
    try std.testing.expectEqual(frames.ActivationKind.caller_emit, plan.events[1].kind);
    try std.testing.expectEqual(fixture.caller, plan.events[1].owner.?);
    try std.testing.expectEqual(frames.ActivationKind.public_emit, plan.events[2].kind);
    try std.testing.expectEqual(@as(?types.FunctionId, null), plan.events[2].owner);

    var hex: [64]u8 = undefined;
    _ = std.fmt.bufPrint(&hex, "{x}", .{plan.plan_digest}) catch unreachable;
    try std.testing.expectEqualStrings(
        "6839b8661426cac5c33bb112eeb4daf0df1fbaf1abfbb68afdd31e5f577743da",
        &hex,
    );
}

test "function frame rejects a transitive undeclared input" {
    var arena = ir.Arena.init(std.testing.allocator);
    defer arena.deinit();
    const x = try arena.input("frame.escape.x", .felt, generated);
    const hidden = try arena.input("frame.escape.hidden", .felt, generated);
    const output = try arena.add(x, hidden, generated);
    _ = try functions.add(
        &arena,
        "frame.escape",
        &.{x},
        &.{output},
        generated,
    );

    try std.testing.expectError(
        error.FrameReadsUndeclaredInput,
        frames.compile(std.testing.allocator, &arena),
    );
}

test "relation activation rejects hint-dependent and non-field ABIs" {
    {
        var arena = ir.Arena.init(std.testing.allocator);
        defer arena.deinit();
        const x = try arena.input("frame.hint.x", .felt, generated);
        const live = try arena.input("frame.hint.live", .bit, generated);
        const output = try boundIdentityHint(&arena, x, live);
        const function = try functions.add(
            &arena,
            "frame.hint",
            &.{ x, live },
            &.{output},
            generated,
        );
        _ = try functions.call(
            &arena,
            function,
            &.{ x, live },
            .relation_backed,
            generated,
        );
        try std.testing.expectError(
            error.NonDeterministicActivation,
            frames.compile(std.testing.allocator, &arena),
        );
    }

    {
        var arena = ir.Arena.init(std.testing.allocator);
        defer arena.deinit();
        const word = try arena.input("frame.word", .word32, generated);
        const function = try functions.add(
            &arena,
            "frame.word_identity",
            &.{word},
            &.{word},
            generated,
        );
        _ = try functions.call(
            &arena,
            function,
            &.{word},
            .relation_backed,
            generated,
        );
        try std.testing.expectError(
            error.NonFieldActivationValue,
            frames.compile(std.testing.allocator, &arena),
        );
    }
}

test "one hint invocation cannot be owned by two function frames" {
    var arena = ir.Arena.init(std.testing.allocator);
    defer arena.deinit();
    const x = try arena.input("frame.shared_hint.x", .felt, generated);
    const live = try arena.input("frame.shared_hint.live", .bit, generated);
    const output = try boundIdentityHint(&arena, x, live);
    _ = try functions.add(
        &arena,
        "frame.shared_hint.first",
        &.{ x, live },
        &.{output},
        generated,
    );
    _ = try functions.add(
        &arena,
        "frame.shared_hint.second",
        &.{ x, live },
        &.{output},
        generated,
    );

    try std.testing.expectError(
        error.CrossFrameHint,
        frames.compile(std.testing.allocator, &arena),
    );
}

test "inline calls retain impurity without creating relation events" {
    var arena = ir.Arena.init(std.testing.allocator);
    defer arena.deinit();
    const x = try arena.input("frame.inline.x", .felt, generated);
    const live = try arena.input("frame.inline.live", .bit, generated);
    const hinted = try boundIdentityHint(&arena, x, live);
    const callee = try functions.add(
        &arena,
        "frame.inline.hinted",
        &.{ x, live },
        &.{hinted},
        generated,
    );
    const caller = try functions.begin(
        &arena,
        "frame.inline.caller",
        &.{ x, live },
        generated,
    );
    const call = try functions.call(
        &arena,
        callee,
        &.{ x, live },
        .inline_expansion,
        generated,
    );
    try functions.finish(&arena, caller, functions.callOutputs(&arena, call).?);

    var plan = try frames.compile(std.testing.allocator, &arena);
    defer plan.deinit();
    try std.testing.expect(!plan.frame(callee).?.deterministic);
    try std.testing.expect(!plan.frame(caller).?.deterministic);
    try std.testing.expectEqual(@as(usize, 0), plan.events.len);
}

test "frame plan rejects event tuple and authority mutations" {
    var fixture = try ActivationFixture.init(std.testing.allocator);
    defer fixture.deinit();
    var plan = try frames.compile(std.testing.allocator, &fixture.arena);
    defer plan.deinit();

    const saved_event = plan.events[1];
    plan.events[1].role = .consume;
    try std.testing.expectError(error.InvalidActivationEvent, plan.validate());
    plan.events[1] = saved_event;

    const saved_tuple = plan.tuple_values[plan.calls[0].tuple.start];
    plan.tuple_values[plan.calls[0].tuple.start] = fixture.sum;
    try std.testing.expectError(error.DigestMismatch, plan.validate());
    plan.tuple_values[plan.calls[0].tuple.start] = saved_tuple;

    const saved_strategy = fixture.arena.calls.items[0].strategy;
    fixture.arena.calls.items[0].strategy = .inline_expansion;
    try std.testing.expectError(
        error.DigestMismatch,
        plan.validateAgainst(std.testing.allocator, &fixture.arena),
    );
    fixture.arena.calls.items[0].strategy = saved_strategy;
    try plan.validateAgainst(std.testing.allocator, &fixture.arena);
}

test "function frame compilation is allocation-failure atomic" {
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        allocationFailureCase,
        .{},
    );
}

fn allocationFailureCase(allocator: std.mem.Allocator) !void {
    var fixture = try ActivationFixture.init(allocator);
    defer fixture.deinit();
    var plan = try frames.compile(allocator, &fixture.arena);
    defer plan.deinit();
    try plan.validate();
}

fn boundIdentityHint(
    arena: *ir.Arena,
    input: types.ValueId,
    active: types.ValueId,
) !types.ValueId {
    const hint_id = try hints.add(
        arena,
        .identity_felt,
        &.{input},
        active,
        generated,
    );
    const output = hints.outputs(arena, hint_id).?[0];
    const binding_root = try arena.sub(output, input, generated);
    const constraint = try arena.assertZero(
        "frame.hint.binding",
        binding_root,
        active,
        .hint_binding,
        generated,
    );
    try hints.bind(arena, hint_id, &.{.{
        .output_index = 0,
        .target = .{ .constraint = constraint },
        .path = &.{ output, binding_root },
    }});
    return output;
}

const ActivationFixture = struct {
    arena: ir.Arena,
    x: types.ValueId,
    y: types.ValueId,
    sum: types.ValueId,
    callee: types.FunctionId,
    caller: types.FunctionId,
    internal_output: types.ValueId,

    fn init(allocator: std.mem.Allocator) !ActivationFixture {
        var arena = ir.Arena.init(allocator);
        errdefer arena.deinit();
        const x = try arena.input("frame.activation.x", .felt, generated);
        const y = try arena.input("frame.activation.y", .felt, generated);
        const sum = try arena.add(x, y, generated);
        const callee = try functions.add(
            &arena,
            "frame.activation.add",
            &.{ x, y },
            &.{sum},
            generated,
        );
        const caller = try functions.begin(
            &arena,
            "frame.activation.caller",
            &.{ x, y },
            generated,
        );
        const internal_call = try functions.call(
            &arena,
            callee,
            &.{ x, y },
            .relation_backed,
            generated,
        );
        const internal_output = functions.callOutputs(&arena, internal_call).?[0];
        try functions.finish(&arena, caller, &.{internal_output});
        _ = try functions.call(
            &arena,
            callee,
            &.{ x, y },
            .relation_backed,
            generated,
        );
        return .{
            .arena = arena,
            .x = x,
            .y = y,
            .sum = sum,
            .callee = callee,
            .caller = caller,
            .internal_output = internal_output,
        };
    }

    fn deinit(self: *ActivationFixture) void {
        self.arena.deinit();
        self.* = undefined;
    }
};
