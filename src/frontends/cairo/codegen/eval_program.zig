//! Validated traversal shared by Cairo evaluation-program backends.

const std = @import("std");
const eval = @import("../witness/eval_program.zig");

pub const FusedPart = struct {
    program: eval.Program,
    rc_base: u32,
};

pub const BaseStep = struct {
    instruction: eval.BaseInst,
    declare: bool,
};

pub const ExtStep = struct {
    instruction: eval.ExtInst,
    declare: bool,
};

pub const ConstraintStep = struct {
    root: u32,
    random_coefficient_offset: u32,
};

pub fn instructionCount(program: eval.Program) usize {
    return program.base_insts.len + program.ext_insts.len;
}

pub fn fusionOperationCount(program: eval.Program) usize {
    return instructionCount(program) + program.constraint_roots.len;
}

pub fn fusionGroupEnd(
    parts: []const FusedPart,
    start: usize,
    operation_cap: usize,
    maximum_operation_cap: usize,
) !usize {
    if (start >= parts.len or operation_cap == 0 or
        operation_cap > maximum_operation_cap)
    {
        return error.InvalidFusionGroup;
    }
    var end = start;
    var operations: usize = 0;
    var expected_rc_base = parts[start].rc_base;
    while (end < parts.len) : (end += 1) {
        const part = parts[end];
        if (part.rc_base != expected_rc_base)
            return error.InvalidFusionGroup;
        expected_rc_base = std.math.add(
            u32,
            expected_rc_base,
            part.program.header.n_constraints,
        ) catch return error.InvalidFusionGroup;
        const next = fusionOperationCount(part.program);
        if (next > operation_cap) {
            if (operations == 0) return start + 1;
            break;
        }
        const total = std.math.add(
            usize,
            operations,
            next,
        ) catch return error.InvalidFusionGroup;
        if (operations != 0 and total > operation_cap) break;
        operations = total;
    }
    if (end == start) return error.InvalidFusionGroup;
    return end;
}

pub fn validatePartSequence(parts: []const FusedPart) !void {
    if (parts.len == 0) return error.InvalidFusionGroup;
    const first = parts[0];
    var expected_rc_base = first.rc_base;
    for (parts) |part| {
        try part.program.validate();
        if (part.rc_base != expected_rc_base or
            part.program.header.n_interactions !=
                first.program.header.n_interactions or
            part.program.header.n_base_params !=
                first.program.header.n_base_params or
            part.program.header.n_ext_params !=
                first.program.header.n_ext_params or
            part.program.header.domain_log_size !=
                first.program.header.domain_log_size)
        {
            return error.InvalidFusionGroup;
        }
        expected_rc_base = std.math.add(
            u32,
            expected_rc_base,
            part.program.header.n_constraints,
        ) catch return error.InvalidFusionGroup;
    }
}

pub fn validateFusionGroup(
    parts: []const FusedPart,
    maximum_operation_count: usize,
) !void {
    if (parts.len < 2) return error.InvalidFusionGroup;
    try validatePartSequence(parts);
    var operation_count: usize = 0;
    for (parts) |part| {
        operation_count = std.math.add(
            usize,
            operation_count,
            fusionOperationCount(part.program),
        ) catch return error.InvalidFusionGroup;
    }
    if (operation_count > maximum_operation_count)
        return error.FusionGroupTooLarge;
}

/// Visits a valid program in semantic execution order. Backends receive the
/// first-write state needed to declare registers and the exact relative
/// random-coefficient index for every constraint root.
pub fn walk(
    allocator: std.mem.Allocator,
    program: eval.Program,
    random_coefficient_offset: u32,
    visitor: anytype,
) !void {
    try program.validate();
    const base_declared = try allocator.alloc(
        bool,
        program.header.max_base_regs,
    );
    defer allocator.free(base_declared);
    @memset(base_declared, false);
    for (program.base_insts) |instruction| {
        const declare = !base_declared[instruction.dst];
        base_declared[instruction.dst] = true;
        try visitor.base(.{
            .instruction = instruction,
            .declare = declare,
        });
    }

    const ext_declared = try allocator.alloc(
        bool,
        program.header.max_ext_regs,
    );
    defer allocator.free(ext_declared);
    @memset(ext_declared, false);
    for (program.ext_insts) |instruction| {
        const declare = !ext_declared[instruction.dst];
        ext_declared[instruction.dst] = true;
        try visitor.extended(.{
            .instruction = instruction,
            .declare = declare,
        });
    }

    try visitor.beginConstraints();
    for (program.constraint_roots, 0..) |root, index| {
        const relative = std.math.add(
            u32,
            random_coefficient_offset,
            @intCast(index),
        ) catch return error.InvalidFusionGroup;
        try visitor.constraint(.{
            .root = root,
            .random_coefficient_offset = relative,
        });
    }
}

test "shared traversal preserves semantic and coefficient order" {
    var base = [_]eval.BaseInst{
        .{
            .op = .constant,
            .interaction = 0,
            .dst = 0,
            .a = 3,
            .b = 0,
            .imm = 0,
        },
        .{
            .op = .constant,
            .interaction = 0,
            .dst = 0,
            .a = 5,
            .b = 0,
            .imm = 0,
        },
    };
    var extended = [_]eval.ExtInst{
        .{ .op = .secure_col, .dst = 0, .a = 0, .b = 0, .c = 0, .d = 0 },
    };
    var roots = [_]u32{ 0, 0 };
    const program = eval.Program{
        .allocator = std.testing.allocator,
        .header = .{
            .flags = eval.Flag.prefinalized_logup,
            .semantic_hash = 1,
            .capability_bits = eval.Capability.prefinalized_logup,
            .n_interactions = 1,
            .n_base_params = 0,
            .n_ext_params = 0,
            .n_constraints = 2,
            .max_base_regs = 1,
            .max_ext_regs = 1,
            .domain_log_size = 4,
        },
        .base_consts = &.{},
        .ext_consts = &.{},
        .base_insts = &base,
        .ext_insts = &extended,
        .constraint_roots = &roots,
    };
    var visitor = TestVisitor{};
    try walk(std.testing.allocator, program, 7, &visitor);
    try std.testing.expectEqualSlices(
        bool,
        &.{ true, false },
        visitor.base_declarations[0..visitor.base_count],
    );
    try std.testing.expectEqualSlices(
        u32,
        &.{ 7, 8 },
        visitor.coefficients[0..visitor.constraint_count],
    );
}

const TestVisitor = struct {
    base_declarations: [4]bool = undefined,
    coefficients: [4]u32 = undefined,
    base_count: usize = 0,
    constraint_count: usize = 0,

    fn base(self: *TestVisitor, step: BaseStep) !void {
        self.base_declarations[self.base_count] = step.declare;
        self.base_count += 1;
    }

    fn extended(_: *TestVisitor, _: ExtStep) !void {}

    fn beginConstraints(_: *TestVisitor) !void {}

    fn constraint(self: *TestVisitor, step: ConstraintStep) !void {
        self.coefficients[self.constraint_count] =
            step.random_coefficient_offset;
        self.constraint_count += 1;
    }
};
