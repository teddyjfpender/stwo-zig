//! Independent native MAIN + lookup ledger oracle for compact GPU formatters.
const std = @import("std");
const C = @import("stwo_core");
const CPU = @import("stwo_riscv_cpu_integration");
const A = @import("stwo_riscv_frontend").rv64_air;
const B = A.word16_v1;
const I = CPU.rv64_family_input;
const IO = @import("rv64/fixture_io.zig");
const a = std.heap.page_allocator;
fn write(dir: std.fs.Dir, id: u32, batch: I.Batch, columns: []const C.fields.m31.M31, c16: []const u64, and_: []const u64, shift: []const u64) !void {
    var data: std.ArrayList(u8) = .empty;
    defer data.deinit(a);
    const w = data.writer(a);
    try IO.words(w, &.{ 0x46574e31, id, @intFromEnum(batch.kind), batch.log, @intCast(batch.facts.len), @intCast(columns.len >> @intCast(batch.log)), @intCast(c16.len), @intCast(and_.len), @intCast(shift.len) });
    try IO.words(w, batch.words());
    for (columns) |v| try IO.words(w, &.{v.v});
    for (c16) |v| try IO.words(w, &.{@intCast(v)});
    for (and_) |v| try IO.words(w, &.{@intCast(v)});
    for (shift) |v| try IO.words(w, &.{@intCast(v)});
    if (batch.kind == .multiplication) {
        var pairs: [65536]u32 = @splat(0);
        const n = @as(usize, 1) << @intCast(batch.log);
        for (0..n) |physical| {
            var row: [A.arithmetic.multiplication.layout.MAIN]C.fields.m31.M31 = undefined;
            for (&row, 0..) |*v, column| v.* = columns[column * n + physical];
            const values = A.arithmetic.multiplication.provider.byteValuesFor(C.fields.m31.M31, &row);
            for (0..48) |i| pairs[values[2 * i].v * 256 + values[2 * i + 1].v] += 1;
        }
        try IO.words(w, &pairs);
    }
    if (batch.kind == .division) {
        for (batch.facts) |fact| {
            const op = A.arithmetic.division.word16_product.layout.OPCODES[fact.op];
            const support = try A.arithmetic.division.word16_product.witness.support(.{ .opcode = op, .a = fact.a, .b = fact.b, .result = fact.c });
            var compact = try I.Batch.multiplication(a, &support, 5);
            defer compact.deinit();
            try IO.words(w, compact.words());
        }
    }
    const name = try std.fmt.allocPrint(a, "case-{}.bin", .{id});
    defer a.free(name);
    try dir.writeFile(.{ .sub_path = name, .data = data.items });
}
fn aluResult(op: usize, x: u64, y: u64) u64 {
    return switch (op) {
        0 => x +% y,
        1 => x -% y,
        2 => @bitCast(@as(i64, @as(i32, @bitCast(@as(u32, @truncate(x +% y)))))),
        3 => @bitCast(@as(i64, @as(i32, @bitCast(@as(u32, @truncate(x -% y)))))),
        4 => @intFromBool(@as(i64, @bitCast(x)) < @as(i64, @bitCast(y))),
        5 => @intFromBool(x < y),
        6 => @intFromBool(x == y),
        7 => @intFromBool(x != y),
        8 => @intFromBool(@as(i64, @bitCast(x)) >= @as(i64, @bitCast(y))),
        else => @intFromBool(x >= y),
    };
}
fn shiftResult(op: usize, x: u64, y: u64) u64 {
    const s: u6 = @intCast(y & if (op < 3) @as(u64, 63) else 31);
    return switch (op) {
        0 => x << s,
        1 => x >> s,
        2 => @bitCast(@as(i64, @bitCast(x)) >> s),
        3 => @bitCast(@as(i64, @as(i32, @bitCast(@as(u32, @truncate(x)) << @as(u5, @intCast(s)))))),
        4 => @bitCast(@as(i64, @as(i32, @bitCast(@as(u32, @truncate(x)) >> @as(u5, @intCast(s)))))),
        else => @bitCast(@as(i64, @as(i32, @bitCast(@as(u32, @truncate(x)))) >> @as(u5, @intCast(s)))),
    };
}
pub fn main() !void {
    const args = try std.process.argsAlloc(a);
    defer std.process.argsFree(a, args);
    if (args.len != 2) return error.ExpectedDirectory;
    try std.fs.cwd().makePath(args[1]);
    var dir = try std.fs.cwd().openDir(args[1], .{});
    defer dir.close();
    const weights = [_]u32{ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24 };
    var facts: [24]B.alu_experiment.source.Fact = undefined;
    for (&facts, 0..) |*f, i| {
        const x: u64 = if (i % 3 == 0) 0xffffffffffffffff else if (i % 3 == 1) 0x800000008000ffff else 0x12340000abcd9876;
        const y: u64 = if (i % 4 == 0) 1 else if (i % 4 == 1) x else 0x98760000ffff1234;
        f.* = .{ .op = @enumFromInt(i % 10), .a = x, .b = y, .c = aluResult(i % 10, x, y) };
    }
    var alu = try B.alu_experiment.source.Source.initWeighted(a, &facts, &weights, 5);
    defer alu.deinit();
    var ba = try I.Batch.alu(a, &facts, &weights, 5);
    defer ba.deinit();
    try write(dir, 0, ba, alu.main, alu.range16_counts, &.{}, &.{});
    var binary: [24]B.binary_source.Fact = undefined;
    for (&binary, 0..) |*f, i| {
        const x = facts[i].a;
        const y = facts[i].b;
        f.* = .{ .op = @enumFromInt(i % 3), .a = x, .b = y, .c = switch (i % 3) {
            0 => x & y,
            1 => x | y,
            else => x ^ y,
        } };
    }
    var bin = try B.binary_source.Source.initWeighted(a, &binary, &weights, 5);
    defer bin.deinit();
    var bb = try I.Batch.binary(a, &binary, &weights, 5);
    defer bb.deinit();
    try write(dir, 1, bb, bin.main, &.{}, bin.and_counts, &.{});
    var shifts: [24]B.shift_word_packed_experiment.source.Fact = undefined;
    for (&shifts, 0..) |*f, i| {
        const x = facts[i].a;
        const y: u64 = if (i % 4 == 0) 0 else if (i % 4 == 1) 63 else if (i % 4 == 2) 0xffffffffffffffff else 32;
        f.* = .{ .op = @enumFromInt(i % 6), .a = x, .b = y, .c = shiftResult(i % 6, x, y) };
    }
    var sh = try B.shift_word_packed_experiment.source.Source.initWeighted(a, &shifts, &weights, 5);
    defer sh.deinit();
    var bs = try I.Batch.shift(a, &shifts, &weights, 5);
    defer bs.deinit();
    try write(dir, 2, bs, sh.main, sh.range16_counts, &.{}, sh.shift_counts);
    var zbb: [24]B.binary_zbb_source.Fact = undefined;
    for (&zbb, 0..) |*f, i| {
        const op: B.binary_zbb.Op = @enumFromInt(i % 6);
        const x = facts[i].a;
        const y = B.binary_zbb.canonicalB(op, facts[i].b);
        f.* = .{ .op = op, .a = x, .b = y, .c = B.binary_zbb.result(op, x, y) };
    }
    var zb = try B.binary_zbb_source.initWeighted(a, &zbb, &weights, 5);
    defer zb.deinit();
    var bz = try I.Batch.zbb(a, &zbb, &weights, 5);
    defer bz.deinit();
    try write(dir, 3, bz, zb.main, &.{}, zb.and_counts, &.{});
    const MUL = A.arithmetic.multiplication;
    const DIV = A.arithmetic.division.word16_product;
    var multiplication: [24]MUL.trace.Request = undefined;
    for (&multiplication, 0..) |*r, i| {
        const x = facts[i].a;
        const y = facts[i].b;
        const product = @as(u128, x) * y;
        const lo: u64 = @truncate(product);
        const hi: u64 = @truncate(product >> 64);
        const result: u64 = switch (i % 5) {
            0 => lo,
            1 => hi -% (if (x >> 63 != 0) y else @as(u64, 0)) -% (if (y >> 63 != 0) x else @as(u64, 0)),
            2 => hi,
            3 => hi -% (if (x >> 63 != 0) y else @as(u64, 0)),
            else => @bitCast(@as(i64, @as(i32, @bitCast(@as(u32, @truncate(lo)))))),
        };
        r.* = .{ .opcode = MUL.layout.OPCODES[i % 5], .a = x, .b = y, .result = result };
    }
    var mt = try MUL.trace.Trace.initWithLog(a, &multiplication, 5);
    defer mt.deinit();
    var bm = try I.Batch.multiplication(a, &multiplication, 5);
    defer bm.deinit();
    try write(dir, 4, bm, mt.main, &.{}, &mt.byte_counts, &.{});
    var division: [24]A.arithmetic.division.trace.Request = undefined;
    for (&division, 0..) |*r, i| {
        const op = i % 8;
        const word = op >= 4;
        const mask: u64 = if (word) 0xffffffff else 0xffffffffffffffff;
        const x: u64 = if (i == 16) 0x8000000000000000 else if (i == 20) 0x80000000 else facts[i].a;
        const y: u64 = if (i == 16 or i == 20) 0xffffffffffffffff else if (i % 3 == 0) 0 else facts[i].b;
        const xx = x & mask;
        const yy = y & mask;
        const signed = op % 2 == 0;
        const negative_a = signed and ((xx >> @as(u6, if (word) 31 else 63)) & 1) != 0;
        const negative_b = signed and ((yy >> @as(u6, if (word) 31 else 63)) & 1) != 0;
        const ax = (if (negative_a) 0 -% xx else xx) & mask;
        const ay = (if (negative_b) 0 -% yy else yy) & mask;
        const rem = op % 4 >= 2;
        const selected = if (ay == 0) (if (rem) ax else @as(u64, 0)) else (if (rem) ax % ay else ax / ay);
        const neg = if (rem) negative_a else negative_a != negative_b;
        const normalized = (if (neg) 0 -% selected else selected) & mask;
        const result: u64 = if (ay == 0 and !rem) 0xffffffffffffffff else if (word) @bitCast(@as(i64, @as(i32, @bitCast(@as(u32, @truncate(normalized)))))) else normalized;
        r.* = .{ .opcode = DIV.layout.OPCODES[op], .a = x, .b = y, .result = result };
    }
    var dt = try DIV.source.Source.initWithLog(a, &division, 5);
    defer dt.deinit();
    var bd = try I.Batch.division(a, &division, 5);
    defer bd.deinit();
    try write(dir, 5, bd, dt.main, dt.counts16, &.{}, &.{});
    const LS = A.memory.load_store_v2;
    const ops = [_]@TypeOf(multiplication[0].opcode){ .LB, .LBU, .LH, .LHU, .LW, .LWU, .LD, .SB, .SH, .SW, .SD };
    var events: [22]LS.native.Event = undefined;
    for (&events, 0..) |*e, i| {
        const op = ops[i % 11];
        const spec = try LS.native.describe(op);
        const address: u64 = 0x1000 + ((i % 8) & ~(@as(usize, spec.width) - 1));
        const immediate: u64 = if (i >= 11) 0xfffffffffffffff8 else 8;
        const rights: u2 = if (i % 3 == 0) 3 else if (spec.write) 2 else 1;
        const before: u64 = 0x80ff1234ab00ff81;
        const b: u64 = if (spec.write) 0x12fe3456abcdef98 else 0;
        const bits: u6 = @intCast(8 * @as(usize, spec.width) - 1);
        const mask: u64 = if (spec.width == 8) 0xffffffffffffffff else (@as(u64, 1) << (bits + 1)) - 1;
        const shift: u6 = @intCast(8 * (address & 7));
        const value = (before >> shift) & mask;
        const after = if (spec.write) (before & ~(mask << shift)) | ((b & mask) << shift) else before;
        const result: u64 = if (spec.write) 0 else if (spec.signed and value & (@as(u64, 1) << bits) != 0) value | ~mask else value;
        e.* = .{ .opcode = op, .a = address -% immediate, .immediate = immediate, .b = b, .c = result, .epoch = if (i % 2 == 0) 1 else 2, .tick = if (i % 2 == 0) 65538 else 7, .before = .{ .value = before, .epoch = 1, .tick = 65535, .rights = rights }, .after = .{ .value = after, .epoch = if (i % 2 == 0) 1 else 2, .tick = if (i % 2 == 0) 65538 else 7, .rights = rights } };
    }
    var ls = try LS.source.Source.init(a, &events, 5);
    defer ls.deinit();
    const packed_events = try CPU.rv64_memory_input.events(a, &events);
    defer a.free(packed_events);
    var data: std.ArrayList(u8) = .empty;
    defer data.deinit(a);
    const w = data.writer(a);
    try IO.words(w, &.{ 0x46574e31, 6, 7, 5, events.len, 70, 65536, 256, 131072 });
    try IO.words(w, std.mem.bytesAsSlice(u32, std.mem.sliceAsBytes(packed_events)));
    for (ls.main) |v| try IO.words(w, &.{v.v});
    for (ls.counts16) |v| try IO.words(w, &.{@intCast(v)});
    for (ls.counts8) |v| try IO.words(w, &.{@intCast(v)});
    for (ls.selection_counts) |v| try IO.words(w, &.{@intCast(v)});
    var pairs: [65536]u32 = @splat(0);
    for (0..32) |i| {
        const row = LS.native.logicalRow(if (i < events.len) events[i] else null);
        pairs[row[13].v * 256 + row[26].v] += 1;
        pairs[row[73].v * 256 + row[74].v] += 1;
    }
    try IO.words(w, &pairs);
    try dir.writeFile(.{ .sub_path = "case-6.bin", .data = data.items });
    const J = @FieldType(CPU.rv64_device_core_headers.Source, "jalr");
    const JFact = std.meta.Child(@typeInfo(@TypeOf(I.Batch.jalr)).@"fn".params[1].type.?);
    var jf: [24]JFact = undefined;
    for (&jf, 0..) |*f, i| f.* = .{ .op = 10, .a = facts[i].a, .b = facts[i].b, .c = (facts[i].a +% facts[i].b) & ~@as(u64, 1) };
    var js = try J.init(a, &jf, 5);
    defer js.deinit();
    var bj = try I.Batch.jalr(a, &jf, 5);
    defer bj.deinit();
    try write(dir, 7, bj, js.main, &.{}, &.{}, &.{});
    const de = [_]LS.native.Event{ events[6], events[10], events[17], events[21] };
    var ds = try A.memory.load_store_dword.source.Source.init(a, &de, 5);
    defer ds.deinit();
    const dp = try CPU.rv64_memory_input.events(a, &de);
    defer a.free(dp);
    data.clearRetainingCapacity();
    try IO.words(w, &.{ 0x46574e31, 8, 8, 5, de.len, 39, 65536, 256, 0 });
    try IO.words(w, std.mem.bytesAsSlice(u32, std.mem.sliceAsBytes(dp)));
    for (ds.main) |v| try IO.words(w, &.{v.v});
    for (ds.counts16) |v| try IO.words(w, &.{@intCast(v)});
    for (ds.counts8) |v| try IO.words(w, &.{@intCast(v)});
    @memset(&pairs, 0);
    for (0..32) |i| {
        const row = LS.native.logicalRow(if (i < de.len) de[i] else null);
        pairs[row[13].v * 256 + row[26].v] += 1;
    }
    try IO.words(w, &pairs);
    try dir.writeFile(.{ .sub_path = "case-8.bin", .data = data.items });
    const cells = [_]A.memory.closed_ram.types.Cell{ .{ .address = 0x1000, .state = .{ .value = 0x1234abcd5678ffff, .epoch = 2, .tick = 0xffffff, .rights = 3 } }, .{ .address = 0x1000000008, .state = .{ .value = 0xffffffffffffffff, .epoch = 65535, .tick = 65536, .rights = 1 } } };
    const cp = try CPU.rv64_memory_input.cells(a, &cells);
    defer a.free(cp);
    data.clearRetainingCapacity();
    try IO.words(w, &.{ 0x46574e31, 9, 9, 5, cells.len, 14, 0, 0, 0 });
    try IO.words(w, std.mem.bytesAsSlice(u32, std.mem.sliceAsBytes(cp)));
    var expected: [14 * 32]C.fields.m31.M31 = undefined;
    for (0..32) |i| {
        const row = LS.native.boundaryRow(&cells, i);
        const physical = A.memory.closed_ram.trace.physical(i, 5);
        for (row, 0..) |v, column| expected[column * 32 + physical] = v;
    }
    for (expected) |v| try IO.words(w, &.{v.v});
    try dir.writeFile(.{ .sub_path = "case-9.bin", .data = data.items });
    std.debug.print("PASS native family witness fixtures=10\n", .{});
}
