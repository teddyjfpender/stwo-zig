const std = @import("std");
const E = @import("../evaluation.zig");
const R = @import("../rows.zig");
const W = @import("../witness.zig");
const S = @import("../statement.zig");
const machine = @import("../../machine.zig");
const memory = @import("../../memory.zig");
const isa = @import("../../decode.zig");
const a = std.testing.allocator;

fn check(word: u32, lhs: u64, rhs: u64) !void {
    var mem = memory.Memory.init(a, .{});
    defer mem.deinit();
    try mem.map(.{ .start = 0x100001000, .size = 4096, .permissions = .{ .read = true, .execute = true } });
    var bytes: [4]u8 = undefined;
    std.mem.writeInt(u32, &bytes, word, .little);
    try mem.initialize(0x100001000, &bytes);
    var cpu = machine.Cpu.init(0x100001000, 0);
    cpu.regs[1] = lhs;
    cpu.regs[2] = rhs;
    try mem.map(.{ .start = 0x200004000, .size = 8, .permissions = .{ .read = true, .write = true } });
    var initial_bytes: [8]u8 = undefined;
    std.mem.writeInt(u64, &initial_bytes, 0x80ff7f00aabbccdd, .little);
    try mem.initialize(0x200004000, &initial_bytes);
    const initial = cpu.regs;
    const record = try cpu.step(&mem);
    const program = [_]u32{word};
    const cells = [_]S.Cell{.{ .address = 0x200004000, .initial = 0x80ff7f00aabbccdd, .final = mem.backing.load(0x200004000, 8).value }};
    const public = S.Statement{ .program_base = 0x100001000, .program = &program, .initial_pc = 0x100001000, .final_pc = cpu.pc, .initial_registers = initial, .final_registers = cpu.regs, .memory = &cells, .steps = 1 };
    var path = [_]u64{0x100001000};
    var clocks: [1]u16 = .{0};
    const meta = S.Metadata{ .path = &path, .register_clocks = @splat(0), .memory_clocks = &clocks };
    const fixed = try R.fixedRow(public, meta, 0, 32);
    const main = try W.fromRetirement(record, try isa.Instruction.decode(word), @splat(0), .{ .read = true, .write = true });
    const opcode = record.opcode;
    if ((lhs == 1 and (rhs == 0 or rhs == 1)) or record.memory != null or opcode == .JAL or opcode == .JALR or opcode == .FENCE) {
        var projected = try @import("../trace.zig").Trace.init(a, public, meta, &.{main});
        defer projected.deinit();
        // Public-support guards must agree as polynomial identities, including
        // arbitrary extension-field inputs that are not valid execution rows.
        var random = std.Random.DefaultPrng.init(@as(u64, 0x525636345055424c) ^ word);
        var physical_fixed: [E.L.fixed.COUNT]E.Q = undefined;
        var physical_main: [E.L.MAIN]E.Q = undefined;
        for (physical_fixed[0..projected.projection.fixed_count]) |*value| value.* = randomQ(random.random());
        for (physical_main[0..projected.projection.main_count]) |*value| value.* = randomQ(random.random());
        const point_fixed = projected.projection.inflateFixed(physical_fixed[0..projected.projection.fixed_count]);
        const point_main = projected.projection.inflateMain(physical_main[0..projected.projection.main_count]);
        const reference = try a.alloc(E.Q, 8192);
        defer a.free(reference);
        const compact = try a.alloc(E.Q, 8192);
        defer a.free(compact);
        var reference_sink = E.Sink{ .values = reference };
        var compact_sink = E.Sink{ .values = compact };
        const point_view = E.View{ .f = &point_fixed, .m = &point_main };
        E.local(point_view, &reference_sink);
        E.localSupported(point_view, &compact_sink, projected.projection.support);
        try std.testing.expectEqual(reference_sink.count, compact_sink.count);
        for (reference[0..reference_sink.count], compact[0..compact_sink.count]) |expected, actual| try std.testing.expect(expected.eql(actual));
        for (0..projected.domainSize()) |logical| {
            const index = W.physical(logical, projected.log_size);
            const actual_main = projected.mainAt(index);
            for (actual_main, 0..) |value, c| try std.testing.expect(value.eql(if (logical == 0) E.Q.fromBase(main[c]) else E.Q.zero()));
            const expected_fixed = try R.fixedRow(public, meta, logical, projected.domainSize());
            const actual_fixed = projected.fixedAt(index);
            for (actual_fixed, expected_fixed) |value, expected| try std.testing.expect(value.eql(E.Q.fromBase(expected)));
        }
    }
    var fq: E.Fixed = undefined;
    var mq: E.Main = undefined;
    for (&fq, fixed) |*v, x| v.* = E.Q.fromBase(x);
    for (&mq, main) |*v, x| v.* = E.Q.fromBase(x);
    const residuals = try a.alloc(E.Q, 8192);
    defer a.free(residuals);
    var sink = E.Sink{ .values = residuals };
    E.local(.{ .f = &fq, .m = &mq }, &sink);
    for (residuals[0..sink.count], 0..) |r, i| if (!r.isZero()) {
        std.debug.print("RV64 AIR failed op={s} word={x} a={x} b={x} constraint={d}\n", .{ @tagName(record.opcode), word, lhs, rhs, i });
        return error.UnsatisfiedRv64Constraint;
    };
    // Exercise the new byte lookup representation against every existing
    // retirement vector, including all signed division and memory edge cases.
    const Encoding = @import("../encoding.zig");
    const plan = Encoding.Plan.fromOpcodes(&.{record.opcode});
    var physical: [E.L.MAIN]E.Q = undefined;
    for (physical[0..plan.main_count], 0..) |*value, c| value.* = E.Q.fromBase(plan.projectValue(&main, c));
    const byte_main = plan.inflateMain(physical[0..plan.main_count]);
    sink.count = 0;
    @import("../range/constraints.zig").local(.{ .f = &fq, .m = &byte_main }, &sink, &plan, physical[0..plan.main_count]);
    for (residuals[0..sink.count], 0..) |r, i| if (!r.isZero()) {
        std.debug.print("RV64 byte AIR failed op={s} a={x} b={x} constraint={d}\n", .{ @tagName(record.opcode), lhs, rhs, i });
        return error.UnsatisfiedRv64ByteConstraint;
    };
    for ([_]@import("../providers/tables.zig").Kind{ .byte_and, .byte_shift }) |kind| {
        for (0..@import("../range/table_cpu.zig").requests(&plan, kind)) |request| {
            const tuple = @import("../range/table_cpu.zig").tuple(&plan, kind, &byte_main, physical[0..plan.main_count], request);
            var base: [6]u32 = undefined;
            for (tuple, 0..) |v, i| base[i] = (try v.tryIntoM31()).v;
            _ = try kind.rowIndex(base);
        }
    }
}

test "rv64 AIR: concrete byte constraints accept RV64 arithmetic edge cases" {
    const values = [_]u64{ 0, 1, 0x7fffffff, 0x80000000, 0xffffffff, 0x8000000000000000, 0xffffffffffffffff };
    const instructions = [_]u32{ 0x002081b3, 0x402081b3, 0x00108193, 0x002081bb, 0x402081bb, 0x0010819b, 0x0020f1b3, 0x0020e1b3, 0x0020c1b3, 0x0020a1b3, 0x0020b1b3, 0x002091b3, 0x0020d1b3, 0x4020d1b3, 0x002091bb, 0x0020d1bb, 0x4020d1bb, 0x022081b3, 0x022091b3, 0x0220a1b3, 0x0220b1b3, 0x022081bb, 0x0220c1b3, 0x0220d1b3, 0x0220e1b3, 0x0220f1b3, 0x0220c1bb, 0x0220d1bb, 0x0220e1bb, 0x0220f1bb, 0x800001b7, 0x80000197 };
    for (instructions) |word| for (values) |lhs| for (values) |rhs| try check(word, lhs, rhs);
}

test "rv64 AIR: remaining immediate and control instructions cover both branch outcomes" {
    const immediates = [_]u32{ 0xfff0a193, 0xfff0b193, 0xfff0c193, 0xfff0e193, 0xfff0f193, 0x03f09193, 0x03f0d193, 0x43f0d193, 0x01f0919b, 0x01f0d19b, 0x41f0d19b };
    for (immediates) |word| for ([_]u64{ 0, 1, 0x80000000, 0x8000000000000000, 0xffffffffffffffff }) |value| try check(word, value, 0);
    for ([_]u32{ 0x00208463, 0x00209463, 0x0020c463, 0x0020d463, 0x0020e463, 0x0020f463 }) |word| {
        try check(word, 1, 1);
        try check(word, 0xffffffffffffffff, 1);
        try check(word, 1, 0xffffffffffffffff);
    }
    try check(0x0000000f, 0, 0); // FENCE
    try check(0x008001ef, 0, 0); // JAL x3,8
    try check(0x000081e7, 0x100001009, 0); // JALR clears low bit
}

test "rv64 AIR: every load store width and aligned byte offset preserves neighbours" {
    for ([_]u32{ 0x00008183, 0x00009183, 0x0000a183, 0x0000b183, 0x0000c183, 0x0000d183, 0x0000e183, 0x00208023, 0x00209023, 0x0020a023, 0x0020b023 }) |word| {
        const instruction = try isa.Instruction.decode(word);
        const width = isa.effects(instruction.opcode).memory_width;
        var offset: u64 = 0;
        while (offset < 8) : (offset += width) try check(word, 0x200004000 + offset, 0x0102030480ff7f00);
    }
}

test "rv64 AIR: deterministic random full-width arithmetic agrees with retirement" {
    var generator = std.Random.DefaultPrng.init(0x7276363461697232);
    const random = generator.random();
    const instructions = [_]u32{ 0x002081b3, 0x402081b3, 0x002081bb, 0x402081bb, 0x0020f1b3, 0x0020e1b3, 0x0020c1b3, 0x0020a1b3, 0x0020b1b3, 0x002091b3, 0x0020d1b3, 0x4020d1b3, 0x002091bb, 0x0020d1bb, 0x4020d1bb, 0x022081b3, 0x022091b3, 0x0220a1b3, 0x0220b1b3, 0x022081bb, 0x0220c1b3, 0x0220d1b3, 0x0220e1b3, 0x0220f1b3, 0x0220c1bb, 0x0220d1bb, 0x0220e1bb, 0x0220f1bb };
    for (instructions) |word| for (0..64) |_| try check(word, random.int(u64), random.int(u64));
}

fn randomQ(random: std.Random) E.Q {
    return E.Q.fromU32Unchecked(random.int(u32) % 2147483647, random.int(u32) % 2147483647, random.int(u32) % 2147483647, random.int(u32) % 2147483647);
}
