const std = @import("std");
const eval = @import("../witness/eval_program.zig");
const M31 = @import("stwo_core").fields.m31.M31;
const Facts = @import("field_shapes.zig").Facts;
test "field shapes remain conservative through aliased register writes" {
    const QM31 = @import("stwo_core").fields.qm31.QM31;
    const allocator = std.testing.allocator;
    var instructions = [_]eval.ExtInst{
        .{ .op = .constant, .dst = 0, .a = 0, .b = 0, .c = 0, .d = 0 },
        .{ .op = .constant, .dst = 1, .a = 1, .b = 0, .c = 0, .d = 0 },
        .{ .op = .secure_col, .dst = 2, .a = 2, .b = 0, .c = 0, .d = 0 },
        .{ .op = .param, .dst = 3, .a = 0, .b = 0, .c = 0, .d = 0 },
        .{ .op = .mul, .dst = 4, .a = 2, .b = 3, .c = 0, .d = 0 },
        .{ .op = .mul, .dst = 4, .a = 4, .b = 0, .c = 0, .d = 0 },
        .{ .op = .add, .dst = 4, .a = 4, .b = 1, .c = 0, .d = 0 },
        .{ .op = .mul, .dst = 4, .a = 4, .b = 3, .c = 0, .d = 0 },
        .{ .op = .sub, .dst = 4, .a = 4, .b = 0, .c = 0, .d = 0 },
        .{ .op = .neg, .dst = 4, .a = 4, .b = 0, .c = 0, .d = 0 },
        .{ .op = .mul, .dst = 2, .a = 2, .b = 2, .c = 0, .d = 0 },
        .{ .op = .neg, .dst = 2, .a = 2, .b = 0, .c = 0, .d = 0 },
        .{ .op = .sub, .dst = 1, .a = 1, .b = 1, .c = 0, .d = 0 },
        .{ .op = .neg, .dst = 0, .a = 0, .b = 0, .c = 0, .d = 0 },
        .{ .op = .add, .dst = 4, .a = 0, .b = 4, .c = 0, .d = 0 },
    };
    var roots = [_]u32{4};
    const program = eval.Program{ .allocator = allocator, .header = .{ .flags = 0, .semantic_hash = 0, .capability_bits = 0, .n_interactions = 1, .n_base_params = 0, .n_ext_params = 1, .n_constraints = 1, .max_base_regs = 3, .max_ext_regs = 5, .domain_log_size = 8 }, .base_consts = &.{}, .ext_consts = &.{}, .base_insts = &.{}, .ext_insts = &instructions, .constraint_roots = &roots };
    var random = std.Random.DefaultPrng.init(42);
    for (0..256) |trial| {
        const facts = try Facts.init(allocator, program);
        defer facts.deinit(allocator);
        facts.base[0] = 0;
        facts.base[1] = 1;
        const value = M31.fromCanonical(if (trial == 0) 2147483646 else random.random().uintLessThan(u32, 2147483647));
        const base = [_]M31{ M31.zero(), M31.one(), value };
        const parameter = QM31.fromM31Array(.{ M31.fromCanonical(random.random().uintLessThan(u32, 2147483647)), M31.fromCanonical(random.random().uintLessThan(u32, 2147483647)), M31.fromCanonical(random.random().uintLessThan(u32, 2147483647)), M31.fromCanonical(random.random().uintLessThan(u32, 2147483647)) });
        var registers: [5]QM31 = @splat(QM31.zero());
        for (instructions) |inst| {
            const kind = facts.extensionKind(inst);
            const result = switch (inst.op) {
                .constant => QM31.fromM31Array(.{ M31.fromCanonical(inst.a), M31.fromCanonical(inst.b), M31.fromCanonical(inst.c), M31.fromCanonical(inst.d) }),
                .secure_col => QM31.fromM31Array(.{ base[inst.a], base[inst.b], base[inst.c], base[inst.d] }),
                .param => parameter,
                .add => registers[inst.a].add(registers[inst.b]),
                .sub => registers[inst.a].sub(registers[inst.b]),
                .mul => registers[inst.a].mul(registers[inst.b]),
                .neg => QM31.zero().sub(registers[inst.a]),
            };
            const coordinates = result.toM31Array();
            switch (kind) {
                .zero => try std.testing.expect(result.eql(QM31.zero())),
                .one => try std.testing.expect(result.eql(QM31.one())),
                .base => for (coordinates[1..]) |coordinate| try std.testing.expect(coordinate.eql(M31.zero())),
                .secure => {},
            }
            registers[inst.dst] = result;
            facts.extended[inst.dst] = kind;
        }
    }
}
