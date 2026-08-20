const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const m31 = @import("stwo_core").fields.m31;
const lowering = @import("function_body_lowering.zig");
const frames = @import("function_frames.zig");
const functions = @import("functions.zig");
const hints = @import("hints.zig");
const ir = @import("ir.zig");
const source = @import("source.zig");
const types = @import("types.zig");

const generated = source.SourceSpan.generated();

test "F-015 nested inline calls lower to one canonical executable tape" {
    var fixture = try NestedFixture.init(std.testing.allocator);
    defer fixture.deinit();
    var frame_plan = try frames.compile(std.testing.allocator, &fixture.arena);
    defer frame_plan.deinit();

    var executable = try lowering.compile(
        std.testing.allocator,
        &fixture.arena,
        &frame_plan,
        fixture.root_call,
        .{},
    );
    defer executable.deinit();
    try executable.validate();
    try executable.validateAgainst(
        std.testing.allocator,
        &fixture.arena,
        &frame_plan,
    );

    try std.testing.expectEqual(@as(u16, 4), executable.input_count);
    try std.testing.expectEqual(@as(u16, 4), executable.output_count);
    try std.testing.expectEqual(@as(u32, 5), executable.expanded_inline_invocations);
    try std.testing.expectEqual(
        @as(u32, executable.input_count) + @as(u32, @intCast(executable.instructions.len)),
        executable.register_count,
    );
    try std.testing.expect(executable.instructions.len < 10);
    try std.testing.expectEqual(
        executable.output_registers[2],
        executable.output_registers[3],
    );
    for (executable.instructions) |instruction| {
        try std.testing.expect(@intFromEnum(instruction.opcode) <=
            @intFromEnum(lowering.Opcode.select));
    }

    const payload_bytes = try executable.ownedPayloadBytes();
    try std.testing.expectEqual(
        executable.instructions.len * @sizeOf(lowering.Instruction) +
            executable.output_registers.len * @sizeOf(u32),
        payload_bytes,
    );

    var second = try lowering.compile(
        std.testing.allocator,
        &fixture.arena,
        &frame_plan,
        fixture.root_call,
        .{},
    );
    defer second.deinit();
    try std.testing.expectEqualSlices(
        u8,
        &executable.program_digest,
        &second.program_digest,
    );
    try std.testing.expectEqualSlices(
        u32,
        executable.output_registers,
        second.output_registers,
    );
    try expectInstructionSlicesEqual(executable.instructions, second.instructions);

    var hex: [64]u8 = undefined;
    _ = std.fmt.bufPrint(&hex, "{x}", .{executable.program_digest}) catch unreachable;
    // Pin the executable identity independently of allocator addresses.
    try std.testing.expectEqualStrings(
        "03dc4ca3fbd51246754b26e47fb2176729a7a7d7ab41923710ecd52af6cd5fef",
        &hex,
    );
}

test "F-015 prepared execution is allocation-free and exactly substitutes arguments" {
    var fixture = try NestedFixture.init(std.testing.allocator);
    defer fixture.deinit();
    var frame_plan = try frames.compile(std.testing.allocator, &fixture.arena);
    defer frame_plan.deinit();
    var executable = try lowering.compile(
        std.testing.allocator,
        &fixture.arena,
        &frame_plan,
        fixture.root_call,
        .{},
    );
    defer executable.deinit();

    const prepared = try executable.prepare();
    const scratch = try std.testing.allocator.alloc(M31, prepared.scratchLen());
    defer std.testing.allocator.free(scratch);
    var outputs = [_]M31{M31.fromCanonical(999)} ** 4;

    const selected_true = [_]M31{
        M31.fromCanonical(2),
        M31.fromCanonical(5),
        M31.fromCanonical(7),
        M31.one(),
    };
    try prepared.executeInto(&selected_true, scratch, &outputs);
    try expectCanonical(&outputs, &.{ 42, m31.Modulus - 7, 21, 21 });

    const selected_false = [_]M31{
        M31.fromCanonical(2),
        M31.fromCanonical(5),
        M31.fromCanonical(7),
        M31.zero(),
    };
    try prepared.executeInto(&selected_false, scratch, &outputs);
    try expectCanonical(&outputs, &.{ 57, m31.Modulus - 7, 21, 21 });

    // The one-shot authenticated API has identical semantics; repeated callers
    // use `prepare` above to keep SHA-256 out of the hot loop.
    @memset(&outputs, M31.fromCanonical(999));
    try executable.executeInto(&selected_true, scratch, &outputs);
    try expectCanonical(&outputs, &.{ 42, m31.Modulus - 7, 21, 21 });
}

test "F-015 execution preflight is failure atomic for shapes and aliases" {
    var fixture = try NestedFixture.init(std.testing.allocator);
    defer fixture.deinit();
    var frame_plan = try frames.compile(std.testing.allocator, &fixture.arena);
    defer frame_plan.deinit();
    var executable = try lowering.compile(
        std.testing.allocator,
        &fixture.arena,
        &frame_plan,
        fixture.root_call,
        .{},
    );
    defer executable.deinit();
    const prepared = try executable.prepare();

    var scratch = try std.testing.allocator.alloc(M31, prepared.scratchLen());
    defer std.testing.allocator.free(scratch);
    const sentinel = M31.fromCanonical(123_456);
    @memset(scratch, sentinel);
    var outputs = [_]M31{sentinel} ** 4;
    const inputs = [_]M31{
        M31.fromCanonical(2),
        M31.fromCanonical(5),
        M31.fromCanonical(7),
        M31.one(),
    };

    try std.testing.expectError(
        error.InvalidExecutionShape,
        prepared.executeInto(inputs[0..3], scratch, &outputs),
    );
    try expectAll(scratch, sentinel);
    try expectAll(&outputs, sentinel);

    try std.testing.expectError(
        error.AliasedBuffer,
        prepared.executeInto(&inputs, scratch, scratch[0..outputs.len]),
    );
    try expectAll(scratch, sentinel);
}

test "F-015 program validation rejects tape and identity mutations" {
    var fixture = try NestedFixture.init(std.testing.allocator);
    defer fixture.deinit();
    var frame_plan = try frames.compile(std.testing.allocator, &fixture.arena);
    defer frame_plan.deinit();
    var executable = try lowering.compile(
        std.testing.allocator,
        &fixture.arena,
        &frame_plan,
        fixture.root_call,
        .{},
    );
    defer executable.deinit();

    const saved_instruction = executable.instructions[0];
    executable.instructions[0].operand_c = 1;
    try std.testing.expectError(
        error.NonCanonicalInstruction,
        executable.validate(),
    );
    executable.instructions[0] = saved_instruction;

    const saved_output = executable.output_registers[0];
    executable.output_registers[0] = executable.register_count;
    try std.testing.expectError(error.InvalidProgramShape, executable.validate());
    executable.output_registers[0] = saved_output;

    executable.program_digest[0] ^= 1;
    try std.testing.expectError(error.DigestMismatch, executable.validate());
    executable.program_digest[0] ^= 1;
    try executable.validate();
}

test "F-015 expansion limits and cyclic mutations fail explicitly" {
    var fixture = try NestedFixture.init(std.testing.allocator);
    defer fixture.deinit();
    var frame_plan = try frames.compile(std.testing.allocator, &fixture.arena);
    defer frame_plan.deinit();

    try std.testing.expectError(
        error.InlineDepthExceeded,
        lowering.compile(
            std.testing.allocator,
            &fixture.arena,
            &frame_plan,
            fixture.root_call,
            .{ .max_inline_depth = 2 },
        ),
    );
    try std.testing.expectError(
        error.InlineInvocationLimitExceeded,
        lowering.compile(
            std.testing.allocator,
            &fixture.arena,
            &frame_plan,
            fixture.root_call,
            .{ .max_inline_invocations = 2 },
        ),
    );
    try std.testing.expectError(
        error.InstructionLimitExceeded,
        lowering.compile(
            std.testing.allocator,
            &fixture.arena,
            &frame_plan,
            fixture.root_call,
            .{ .max_instructions = 1 },
        ),
    );
    try std.testing.expectError(
        error.RegisterLimitExceeded,
        lowering.compile(
            std.testing.allocator,
            &fixture.arena,
            &frame_plan,
            fixture.root_call,
            .{ .max_registers = 4 },
        ),
    );

    const call_index = types.idIndex(fixture.wrapper_to_blend);
    const saved_call = fixture.arena.calls.items[call_index];
    fixture.arena.calls.items[call_index].callee = fixture.wrapper;
    try std.testing.expectError(
        error.InlineCycle,
        lowering.compile(
            std.testing.allocator,
            &fixture.arena,
            &frame_plan,
            fixture.root_call,
            .{},
        ),
    );
    fixture.arena.calls.items[call_index] = saved_call;
    try frame_plan.validateAgainst(std.testing.allocator, &fixture.arena);
}

test "F-015 proof-aware leaves fail closed instead of becoming committed inputs" {
    {
        var fixture = try NestedFixture.init(std.testing.allocator);
        defer fixture.deinit();
        fixture.arena.calls.items[types.idIndex(fixture.wrapper_to_blend)].strategy =
            .relation_backed;
        var frame_plan = try frames.compile(std.testing.allocator, &fixture.arena);
        defer frame_plan.deinit();
        try std.testing.expectError(
            error.RelationBackedCall,
            lowering.compile(
                std.testing.allocator,
                &fixture.arena,
                &frame_plan,
                fixture.root_call,
                .{},
            ),
        );
    }

    {
        var fixture = try HintFixture.init(std.testing.allocator);
        defer fixture.deinit();
        var frame_plan = try frames.compile(std.testing.allocator, &fixture.arena);
        defer frame_plan.deinit();
        try std.testing.expectError(
            error.UnsupportedHint,
            lowering.compile(
                std.testing.allocator,
                &fixture.arena,
                &frame_plan,
                fixture.root_call,
                .{},
            ),
        );
    }

    {
        var fixture = try NonFieldFixture.init(std.testing.allocator);
        defer fixture.deinit();
        var frame_plan = try frames.compile(std.testing.allocator, &fixture.arena);
        defer frame_plan.deinit();
        try std.testing.expectError(
            error.NonFieldValue,
            lowering.compile(
                std.testing.allocator,
                &fixture.arena,
                &frame_plan,
                fixture.root_call,
                .{},
            ),
        );
    }
}

test "F-015 compilation is allocation-failure atomic and hot API has no allocator" {
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        allocationFailureCase,
        .{},
    );

    comptime {
        const execute_info = @typeInfo(@TypeOf(lowering.PreparedProgram.executeInto)).@"fn";
        if (execute_info.params.len != 4)
            @compileError("prepared execution API shape drifted");
        for (execute_info.params) |parameter| {
            if (parameter.type.? == std.mem.Allocator)
                @compileError("prepared execution must not accept an allocator");
        }
    }
}

fn allocationFailureCase(allocator: std.mem.Allocator) !void {
    var fixture = try NestedFixture.init(allocator);
    defer fixture.deinit();
    var frame_plan = try frames.compile(allocator, &fixture.arena);
    defer frame_plan.deinit();
    var executable = try lowering.compile(
        allocator,
        &fixture.arena,
        &frame_plan,
        fixture.root_call,
        .{},
    );
    defer executable.deinit();
    try executable.validate();
}

fn expectInstructionSlicesEqual(
    lhs: []const lowering.Instruction,
    rhs: []const lowering.Instruction,
) !void {
    try std.testing.expectEqual(lhs.len, rhs.len);
    for (lhs, rhs) |left, right| try std.testing.expectEqualDeep(left, right);
}

fn expectCanonical(actual: []const M31, expected: []const u32) !void {
    try std.testing.expectEqual(expected.len, actual.len);
    for (actual, expected) |value, canonical|
        try std.testing.expectEqual(canonical, value.toU32());
}

fn expectAll(values: []const M31, expected: M31) !void {
    for (values) |value| try std.testing.expect(value.eql(expected));
}

const NestedFixture = struct {
    arena: ir.Arena,
    root_call: types.CallId,
    wrapper: types.FunctionId,
    wrapper_to_blend: types.CallId,

    fn init(allocator: std.mem.Allocator) !NestedFixture {
        var arena = ir.Arena.init(allocator);
        errdefer arena.deinit();

        const affine_x = try arena.input("inline.affine.x", .felt, generated);
        const affine_y = try arena.input("inline.affine.y", .felt, generated);
        const three = try arena.constantField(3, generated);
        const affine_sum = try arena.add(affine_x, affine_y, generated);
        const affine_scaled = try arena.mul(affine_sum, three, generated);
        const affine = try functions.add(
            &arena,
            "inline.affine",
            &.{ affine_x, affine_y },
            &.{ affine_scaled, affine_sum },
            generated,
        );

        const blend_x = try arena.input("inline.blend.x", .felt, generated);
        const blend_y = try arena.input("inline.blend.y", .felt, generated);
        const blend_z = try arena.input("inline.blend.z", .felt, generated);
        const blend_selector = try arena.input("inline.blend.selector", .bit, generated);
        const blend = try functions.begin(
            &arena,
            "inline.blend",
            &.{ blend_x, blend_y, blend_z, blend_selector },
            generated,
        );
        const first = try functions.call(
            &arena,
            affine,
            &.{ blend_x, blend_y },
            .inline_expansion,
            generated,
        );
        const second = try functions.call(
            &arena,
            affine,
            &.{ blend_y, blend_z },
            .inline_expansion,
            generated,
        );
        const duplicate = try functions.call(
            &arena,
            affine,
            &.{ blend_x, blend_y },
            .inline_expansion,
            generated,
        );
        const first_outputs = functions.callOutputs(&arena, first).?;
        const second_outputs = functions.callOutputs(&arena, second).?;
        const duplicate_outputs = functions.callOutputs(&arena, duplicate).?;
        const selected = try arena.select(
            blend_selector,
            first_outputs[0],
            second_outputs[0],
            generated,
        );
        const combined = try arena.add(selected, duplicate_outputs[0], generated);
        try functions.finish(
            &arena,
            blend,
            &.{ combined, first_outputs[1], duplicate_outputs[0], first_outputs[0] },
        );

        const wrapper_x = try arena.input("inline.wrapper.x", .felt, generated);
        const wrapper_y = try arena.input("inline.wrapper.y", .felt, generated);
        const wrapper_z = try arena.input("inline.wrapper.z", .felt, generated);
        const wrapper_selector = try arena.input("inline.wrapper.selector", .bit, generated);
        const wrapper = try functions.begin(
            &arena,
            "inline.wrapper",
            &.{ wrapper_x, wrapper_y, wrapper_z, wrapper_selector },
            generated,
        );
        const wrapper_to_blend = try functions.call(
            &arena,
            blend,
            &.{ wrapper_x, wrapper_y, wrapper_z, wrapper_selector },
            .inline_expansion,
            generated,
        );
        const wrapped = functions.callOutputs(&arena, wrapper_to_blend).?;
        const negated_sum = try arena.neg(wrapped[1], generated);
        try functions.finish(
            &arena,
            wrapper,
            &.{ wrapped[0], negated_sum, wrapped[2], wrapped[3] },
        );

        const root_x = try arena.input("inline.root.x", .felt, generated);
        const root_y = try arena.input("inline.root.y", .felt, generated);
        const root_z = try arena.input("inline.root.z", .felt, generated);
        const root_selector = try arena.input("inline.root.selector", .bit, generated);
        const root_call = try functions.call(
            &arena,
            wrapper,
            &.{ root_x, root_y, root_z, root_selector },
            .inline_expansion,
            generated,
        );

        return .{
            .arena = arena,
            .root_call = root_call,
            .wrapper = wrapper,
            .wrapper_to_blend = wrapper_to_blend,
        };
    }

    fn deinit(self: *NestedFixture) void {
        self.arena.deinit();
        self.* = undefined;
    }
};

const HintFixture = struct {
    arena: ir.Arena,
    root_call: types.CallId,

    fn init(allocator: std.mem.Allocator) !HintFixture {
        var arena = ir.Arena.init(allocator);
        errdefer arena.deinit();
        const input = try arena.input("inline.hint.input", .felt, generated);
        const active = try arena.input("inline.hint.active", .bit, generated);
        const hint_id = try hints.add(
            &arena,
            .identity_felt,
            &.{input},
            active,
            generated,
        );
        const output = hints.outputs(&arena, hint_id).?[0];
        const binding_root = try arena.sub(output, input, generated);
        const constraint = try arena.assertZero(
            "inline.hint.binding",
            binding_root,
            active,
            .hint_binding,
            generated,
        );
        try hints.bind(&arena, hint_id, &.{.{
            .output_index = 0,
            .target = .{ .constraint = constraint },
            .path = &.{ output, binding_root },
        }});
        const function = try functions.add(
            &arena,
            "inline.hint",
            &.{ input, active },
            &.{output},
            generated,
        );
        const root_input = try arena.input("inline.hint.root_input", .felt, generated);
        const root_active = try arena.input("inline.hint.root_active", .bit, generated);
        const root_call = try functions.call(
            &arena,
            function,
            &.{ root_input, root_active },
            .inline_expansion,
            generated,
        );
        return .{ .arena = arena, .root_call = root_call };
    }

    fn deinit(self: *HintFixture) void {
        self.arena.deinit();
        self.* = undefined;
    }
};

const NonFieldFixture = struct {
    arena: ir.Arena,
    root_call: types.CallId,

    fn init(allocator: std.mem.Allocator) !NonFieldFixture {
        var arena = ir.Arena.init(allocator);
        errdefer arena.deinit();
        const word = try arena.input("inline.word", .word32, generated);
        const function = try functions.add(
            &arena,
            "inline.word.identity",
            &.{word},
            &.{word},
            generated,
        );
        const root_word = try arena.input("inline.word.root", .word32, generated);
        const root_call = try functions.call(
            &arena,
            function,
            &.{root_word},
            .inline_expansion,
            generated,
        );
        return .{ .arena = arena, .root_call = root_call };
    }

    fn deinit(self: *NonFieldFixture) void {
        self.arena.deinit();
        self.* = undefined;
    }
};
