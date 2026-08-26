const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const digest = @import("digest.zig");
const frames = @import("function_frames.zig");
const functions = @import("functions.zig");
const hints = @import("hints.zig");
const ir = @import("ir.zig");
const lowering = @import("function_body_lowering.zig");
const manifest = @import("manifest.zig");
const source = @import("source.zig");
const types = @import("types.zig");
const validate = @import("validate.zig");

const generated = source.SourceSpan.generated();

test "F-015 owned bodies seal every record and select identity v11 manifest v13" {
    var fixture = try OwnedFixture.init(std.testing.allocator);
    defer fixture.deinit();
    try validate.validate(&fixture.arena);

    const leaf_body = functions.get(&fixture.arena, fixture.leaf).?.body.?;
    try std.testing.expectEqual(@as(u32, 1), leaf_body.constraints.len);
    try std.testing.expectEqual(@as(u32, 0), leaf_body.effects.len);
    try std.testing.expectEqual(@as(u32, 0), leaf_body.hints.len);
    try std.testing.expectEqual(@as(u32, 0), leaf_body.calls.len);
    const wrapper_body = functions.get(&fixture.arena, fixture.wrapper).?.body.?;
    try std.testing.expectEqual(@as(u32, 1), wrapper_body.constraints.len);
    try std.testing.expectEqual(@as(u32, 2), wrapper_body.calls.len);

    const identity = try digest.computeIdentity(&fixture.arena);
    try std.testing.expectEqual(digest.function_body_format_version, identity.format_version);
    try std.testing.expectError(error.InvalidEffect, digest.computeV10(&fixture.arena));

    const bytes = try manifest.serializeAllocCurrent(
        std.testing.allocator,
        &fixture.arena,
    );
    defer std.testing.allocator.free(bytes);
    try std.testing.expectEqual(manifest.function_body_format_version, readU16(bytes, 8));
    try std.testing.expectEqual(
        manifest.function_body_logical_schema_version,
        readU16(bytes, 10),
    );
    try std.testing.expectError(
        error.FunctionBodyOwnershipRequiresManifestV13,
        manifest.serializeAllocV12(std.testing.allocator, &fixture.arena),
    );
}

test "F-015 frame plan binds exact owned ids and executable instantiates dead calls" {
    var fixture = try OwnedFixture.init(std.testing.allocator);
    defer fixture.deinit();
    var plan = try frames.compile(std.testing.allocator, &fixture.arena);
    defer plan.deinit();

    try std.testing.expectEqual(frames.BODY_OWNERSHIP_VERSION, plan.body_ownership_version);
    try std.testing.expectEqual(@as(usize, 2), plan.constraint_ids.len);
    try std.testing.expectEqual(@as(usize, 2), plan.call_ids.len);
    try std.testing.expectEqual(@as(usize, 0), plan.effect_ids.len);
    try std.testing.expectEqual(@as(usize, 0), plan.hint_ids.len);
    try plan.validateAgainst(std.testing.allocator, &fixture.arena);

    const saved_constraint_id = plan.constraint_ids[1];
    plan.constraint_ids[1] = plan.constraint_ids[0];
    try std.testing.expectError(error.InvalidFrame, plan.validate());
    plan.constraint_ids[1] = saved_constraint_id;
    try plan.validate();

    try std.testing.expectError(
        error.FunctionBodyRequiresOwnedLowering,
        lowering.compile(
            std.testing.allocator,
            &fixture.arena,
            &plan,
            fixture.root_call,
            .{},
        ),
    );
    var executable = try lowering.compileOwnedBody(
        std.testing.allocator,
        &fixture.arena,
        &plan,
        fixture.root_call,
        .{},
    );
    defer executable.deinit();
    try executable.validateAgainst(std.testing.allocator, &fixture.arena, &plan);
    try std.testing.expectEqual(lowering.BODY_OWNERSHIP_VERSION, executable.body_ownership_version);
    // Two concrete leaf invocations (one otherwise dead) plus the wrapper.
    try std.testing.expectEqual(@as(u32, 3), executable.expanded_inline_invocations);
    try std.testing.expectEqual(@as(usize, 3), executable.constraint_checks.len);

    const saved_check = executable.constraint_checks[0];
    executable.constraint_checks[0].root_register = executable.register_count;
    try std.testing.expectError(error.InvalidProgramShape, executable.validate());
    executable.constraint_checks[0] = saved_check;
    try executable.validate();

    const prepared = try executable.prepare();
    const scratch = try std.testing.allocator.alloc(M31, prepared.scratchLen());
    defer std.testing.allocator.free(scratch);
    var outputs = [_]M31{M31.fromCanonical(777)};
    try prepared.executeInto(&.{M31.zero()}, scratch, &outputs);
    try std.testing.expectEqual(@as(u32, 1), outputs[0].toU32());

    outputs[0] = M31.fromCanonical(777);
    try std.testing.expectError(
        error.ConstraintViolation,
        prepared.executeInto(&.{M31.fromCanonical(2)}, scratch, &outputs),
    );
    // Direct checks happen before publication even though scratch is work RAM.
    try std.testing.expectEqual(@as(u32, 777), outputs[0].toU32());
}

test "F-015 owner, omission, overlap, and call-range mutations fail closed" {
    var fixture = try OwnedFixture.init(std.testing.allocator);
    defer fixture.deinit();

    const leaf_constraint_index = fixture.arena.functions.items[types.idIndex(fixture.leaf)]
        .body.?.constraints.start;
    const saved_owner = fixture.arena.constraints.items[leaf_constraint_index].owner;
    fixture.arena.constraints.items[leaf_constraint_index].owner = fixture.wrapper;
    try std.testing.expectError(error.InvalidFunctionBody, validate.validate(&fixture.arena));
    fixture.arena.constraints.items[leaf_constraint_index].owner = saved_owner;

    const leaf_index = types.idIndex(fixture.leaf);
    const saved_leaf_body = fixture.arena.functions.items[leaf_index].body.?;
    fixture.arena.functions.items[leaf_index].body.?.constraints.len = 0;
    try std.testing.expectError(error.InvalidFunctionBody, validate.validate(&fixture.arena));
    fixture.arena.functions.items[leaf_index].body = saved_leaf_body;

    const wrapper_index = types.idIndex(fixture.wrapper);
    const saved_wrapper_body = fixture.arena.functions.items[wrapper_index].body.?;
    fixture.arena.functions.items[wrapper_index].body.?.constraints =
        saved_leaf_body.constraints;
    try std.testing.expectError(error.InvalidFunctionBody, validate.validate(&fixture.arena));
    fixture.arena.functions.items[wrapper_index].body = saved_wrapper_body;

    fixture.arena.functions.items[wrapper_index].body.?.calls.len = 0;
    try std.testing.expectError(error.InvalidFunctionBody, validate.validate(&fixture.arena));
    fixture.arena.functions.items[wrapper_index].body = saved_wrapper_body;
    try validate.validate(&fixture.arena);
}

test "F-015 owned cycles and proof-aware bodies are rejected explicitly" {
    {
        var fixture = try OwnedFixture.init(std.testing.allocator);
        defer fixture.deinit();
        var plan = try frames.compile(std.testing.allocator, &fixture.arena);
        defer plan.deinit();
        const call_index = types.idIndex(fixture.wrapper_first_call);
        const saved = fixture.arena.calls.items[call_index].callee;
        fixture.arena.calls.items[call_index].callee = fixture.wrapper;
        try std.testing.expectError(
            error.InlineCycle,
            lowering.compileOwnedBody(
                std.testing.allocator,
                &fixture.arena,
                &plan,
                fixture.root_call,
                .{},
            ),
        );
        fixture.arena.calls.items[call_index].callee = saved;
    }
    {
        var fixture = try HintBodyFixture.init(std.testing.allocator);
        defer fixture.deinit();
        var plan = try frames.compile(std.testing.allocator, &fixture.arena);
        defer plan.deinit();
        try std.testing.expectError(
            error.UnsupportedHint,
            lowering.compileOwnedBody(
                std.testing.allocator,
                &fixture.arena,
                &plan,
                fixture.root_call,
                .{},
            ),
        );
    }
    {
        var fixture = try EffectBodyFixture.init(std.testing.allocator);
        defer fixture.deinit();
        var plan = try frames.compile(std.testing.allocator, &fixture.arena);
        defer plan.deinit();
        try std.testing.expectError(
            error.UnsupportedEffect,
            lowering.compileOwnedBody(
                std.testing.allocator,
                &fixture.arena,
                &plan,
                fixture.root_call,
                .{},
            ),
        );
    }
}

test "F-015 legacy bytes and identities remain on frozen projections" {
    var arena = ir.Arena.init(std.testing.allocator);
    defer arena.deinit();
    const input = try arena.input("legacy.function.input", .felt, generated);
    const output = try arena.neg(input, generated);
    _ = try functions.add(
        &arena,
        "legacy.function",
        &.{input},
        &.{output},
        generated,
    );

    const identity = try digest.computeIdentity(&arena);
    try std.testing.expectEqual(digest.format_version, identity.format_version);
    try std.testing.expectEqualSlices(u8, &try digest.compute(&arena), &identity.bytes);
    const legacy = try manifest.serializeAlloc(std.testing.allocator, &arena);
    defer std.testing.allocator.free(legacy);
    const current = try manifest.serializeAllocCurrent(std.testing.allocator, &arena);
    defer std.testing.allocator.free(current);
    try std.testing.expectEqualSlices(u8, legacy, current);
}

test "F-015 owned authoring and compilation are allocation-failure atomic" {
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        ownedAllocationFailureCase,
        .{},
    );

    comptime {
        const execute_info = @typeInfo(@TypeOf(lowering.PreparedProgram.executeInto)).@"fn";
        for (execute_info.params) |parameter| {
            if (parameter.type.? == std.mem.Allocator)
                @compileError("owned hot execution must not accept an allocator");
        }
    }
}

fn ownedAllocationFailureCase(allocator: std.mem.Allocator) !void {
    var fixture = try OwnedFixture.init(allocator);
    defer fixture.deinit();
    var plan = try frames.compile(allocator, &fixture.arena);
    defer plan.deinit();
    var executable = try lowering.compileOwnedBody(
        allocator,
        &fixture.arena,
        &plan,
        fixture.root_call,
        .{},
    );
    defer executable.deinit();
    try executable.validate();
}

const OwnedFixture = struct {
    arena: ir.Arena,
    leaf: types.FunctionId,
    wrapper: types.FunctionId,
    wrapper_first_call: types.CallId,
    root_call: types.CallId,

    fn init(allocator: std.mem.Allocator) !OwnedFixture {
        var arena = ir.Arena.init(allocator);
        errdefer arena.deinit();

        const leaf_input = try arena.input("owned.leaf.input", .felt, generated);
        const leaf = try functions.beginBody(
            &arena,
            "owned.leaf",
            &.{leaf_input},
            generated,
        );
        const one = try arena.constantField(1, generated);
        const leaf_output = try arena.add(leaf_input, one, generated);
        _ = try arena.assertZero(
            "owned.leaf.input_is_zero",
            leaf_input,
            null,
            .semantic,
            generated,
        );
        try functions.finish(&arena, leaf, &.{leaf_output});

        const wrapper_input = try arena.input("owned.wrapper.input", .felt, generated);
        const wrapper = try functions.beginBody(
            &arena,
            "owned.wrapper",
            &.{wrapper_input},
            generated,
        );
        const first_call = try functions.call(
            &arena,
            leaf,
            &.{wrapper_input},
            .inline_expansion,
            generated,
        );
        // This call is deliberately dead at the output boundary. Owned body
        // lowering must still instantiate its callee constraint.
        _ = try functions.call(
            &arena,
            leaf,
            &.{wrapper_input},
            .inline_expansion,
            generated,
        );
        const first_output = functions.callOutputs(&arena, first_call).?[0];
        const expected = try arena.add(wrapper_input, one, generated);
        const residual = try arena.sub(first_output, expected, generated);
        _ = try arena.assertZero(
            "owned.wrapper.call_is_derived",
            residual,
            null,
            .semantic,
            generated,
        );
        try functions.finish(&arena, wrapper, &.{first_output});

        const root_input = try arena.input("owned.root.input", .felt, generated);
        const root_call = try functions.call(
            &arena,
            wrapper,
            &.{root_input},
            .inline_expansion,
            generated,
        );
        return .{
            .arena = arena,
            .leaf = leaf,
            .wrapper = wrapper,
            .wrapper_first_call = first_call,
            .root_call = root_call,
        };
    }

    fn deinit(self: *OwnedFixture) void {
        self.arena.deinit();
        self.* = undefined;
    }
};

const HintBodyFixture = struct {
    arena: ir.Arena,
    root_call: types.CallId,

    fn init(allocator: std.mem.Allocator) !HintBodyFixture {
        var arena = ir.Arena.init(allocator);
        errdefer arena.deinit();
        const input = try arena.input("owned.hint.input", .felt, generated);
        const active = try arena.input("owned.hint.active", .bit, generated);
        const function = try functions.beginBody(
            &arena,
            "owned.hint",
            &.{ input, active },
            generated,
        );
        const hint_id = try hints.add(
            &arena,
            .identity_felt,
            &.{input},
            active,
            generated,
        );
        const output = hints.outputs(&arena, hint_id).?[0];
        const residual = try arena.sub(output, input, generated);
        const constraint = try arena.assertZero(
            "owned.hint.binding",
            residual,
            active,
            .hint_binding,
            generated,
        );
        try hints.bind(&arena, hint_id, &.{.{
            .output_index = 0,
            .target = .{ .constraint = constraint },
            .path = &.{ output, residual },
        }});
        try functions.finish(&arena, function, &.{output});
        const root_input = try arena.input("owned.hint.root_input", .felt, generated);
        const root_active = try arena.input("owned.hint.root_active", .bit, generated);
        const root_call = try functions.call(
            &arena,
            function,
            &.{ root_input, root_active },
            .inline_expansion,
            generated,
        );
        return .{ .arena = arena, .root_call = root_call };
    }

    fn deinit(self: *HintBodyFixture) void {
        self.arena.deinit();
        self.* = undefined;
    }
};

const EffectBodyFixture = struct {
    arena: ir.Arena,
    root_call: types.CallId,

    fn init(allocator: std.mem.Allocator) !EffectBodyFixture {
        var arena = ir.Arena.init(allocator);
        errdefer arena.deinit();
        const input = try arena.input("owned.effect.input", .felt, generated);
        const active = try arena.input("owned.effect.active", .bit, generated);
        const function = try functions.beginBody(
            &arena,
            "owned.effect",
            &.{ input, active },
            generated,
        );
        _ = try arena.addEffect(
            .public_produce,
            &.{input},
            active,
            null,
            generated,
        );
        try functions.finish(&arena, function, &.{input});
        const root_input = try arena.input("owned.effect.root_input", .felt, generated);
        const root_active = try arena.input("owned.effect.root_active", .bit, generated);
        const root_call = try functions.call(
            &arena,
            function,
            &.{ root_input, root_active },
            .inline_expansion,
            generated,
        );
        return .{ .arena = arena, .root_call = root_call };
    }

    fn deinit(self: *EffectBodyFixture) void {
        self.arena.deinit();
        self.* = undefined;
    }
};

fn readU16(bytes: []const u8, offset: usize) u16 {
    return std.mem.readInt(u16, bytes[offset..][0..2], .little);
}
