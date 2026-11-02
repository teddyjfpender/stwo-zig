//! CPU-proof core components of the Word16 v3 roster: how to record each
//! component kind/layout from any instance (`fromX`), sample instances with
//! random FS draws and claims and valid publics (`all`), and the handler table
//! the honest-trace observer uses to recognise live prover handles.
const std = @import("std");
const core = @import("stwo_core");
const A = @import("stwo_riscv_frontend").rv64_air;
const R = @import("record.zig");
const Lane = R.Lane;
const Sink = R.Sink;
const Q = R.Q;
const X = A.word16_execution;
const W = A.word16_cpu;
const B = A.word16_v1;
const K = @import("case.zig");
const Case = K.Case;
const standardCase = K.standardCase;
const pointCase = K.pointCase;
const caseWith = K.caseWith;

const Cpu = X.component.Component;
const Rom = X.rom_component.Component;
const Jalr = X.jalr_component.Component;
const Word16Cpu = W.component.Component;
const Alu = B.alu_experiment.component.Component;
const Binary = B.binary_component.Component;
const Shift = B.shift_word_packed_experiment.component.Component;
const ShiftTable = B.shift_word_packed_experiment.table_component.Component;
const ShiftTableData = B.shift_word_packed_experiment.table;
const Division = A.arithmetic.division.word16_product.component.Component;
const Multiplication = A.arithmetic.multiplication.degree3_component.Component;
const LoadStore = A.memory.load_store_v2.component.Component;

fn draw(comptime T: type, rng: std.Random) T {
    var out = std.mem.zeroes(T);
    R.randomize(&out, rng);
    return out;
}

// ---- builders from any instance --------------------------------------------

pub fn fromCpu(a: std.mem.Allocator, c: Cpu) !Case {
    const name = if (c.compact) "cpu.compact_decode" else if (c.pairs != null) "cpu.u8_pairs" else if (c.fused) (if (c.public.wide_clock) "cpu.fused_tail.wide_clock" else "cpu.fused_tail") else "cpu.classic";
    return standardCase(a, Cpu, name, "cpu", c);
}
pub fn fromRom(a: std.mem.Allocator, c: Rom) !Case {
    return standardCase(a, Rom, "rom", "rom", c);
}
pub fn fromJalr(a: std.mem.Allocator, c: Jalr) !Case {
    return standardCase(a, Jalr, "jalr", "jalr", c);
}
/// word16_cpu roles: emitFor(fixed, main, interaction, previous_main, previous_interaction).
fn emitWord16Cpu(a: std.mem.Allocator, c: *const Word16Cpu, sink: *Sink) anyerror!void {
    const Needs = struct {
        fn main(cc: *const Word16Cpu, column: usize) bool {
            return cc.needsPrevious(1, column);
        }
        fn inter(cc: *const Word16Cpu, column: usize) bool {
            return cc.needsPrevious(2, column);
        }
    };
    const w = c.widths();
    const f = try R.Masks.init(a, 0, w[0], {}, R.never);
    defer f.deinit(a);
    const m = try R.Masks.init(a, 1, w[1], c, Needs.main);
    defer m.deinit(a);
    const i = try R.Masks.init(a, 2, w[2], c, Needs.inter);
    defer i.deinit(a);
    c.emitFor(Lane, f.current, m.current, i.current, m.previous, i.previous, sink);
}
pub fn fromWord16Cpu(a: std.mem.Allocator, c: Word16Cpu) !Case {
    const name = switch (c.kind) {
        .boundary => "register_boundary",
        .range16 => "range16_table",
        .range8 => "range8_table",
        .rom => "word16_cpu.rom",
        .cpu => "word16_cpu.cpu",
    };
    return caseWith(a, Word16Cpu, name, name, c, c.widths(), emitWord16Cpu);
}
/// ALU / BINARY / SHIFT: emitFor(fixed, main, interaction, previous_interaction).
fn InteractionPrevious(comptime T: type) type {
    return struct {
        fn needs(c: *const T, column: usize) bool {
            return if (@typeInfo(@TypeOf(T.needsPrevious)).@"fn".params.len == 1) T.needsPrevious(column) else c.needsPrevious(column);
        }
        fn emit(a: std.mem.Allocator, c: *const T, sink: *Sink) anyerror!void {
            const w = widthsOf(T, c);
            const f = try R.Masks.init(a, 0, w[0], {}, R.never);
            defer f.deinit(a);
            const m = try R.Masks.init(a, 1, w[1], {}, R.never);
            defer m.deinit(a);
            const i = try R.Masks.init(a, 2, w[2], c, needs);
            defer i.deinit(a);
            c.emitFor(Lane, f.current, m.current, i.current, i.previous, sink);
        }
    };
}
fn widthsOf(comptime T: type, c: *const T) [3]usize {
    if (@hasDecl(T, "widths")) return c.widths();
    return .{ 2, B.shift_word_experiment.lookup.MAIN, B.shift_word_experiment.lookup.INTERACTION };
}
pub fn fromAlu(a: std.mem.Allocator, c: Alu) !Case {
    return caseWith(a, Alu, if (c.fused) "alu.fused_tail" else "alu.classic", "alu", c, c.widths(), InteractionPrevious(Alu).emit);
}
pub fn fromBinary(a: std.mem.Allocator, c: Binary) !Case {
    const name = switch (c.kind) {
        .binary => "binary",
        .and_table => "and_table",
        .and_pair_table => "and_pair_table",
        .expected => "binary.expected",
        .expected_main => "binary.expected_main",
    };
    return caseWith(a, Binary, name, name, c, c.widths(), InteractionPrevious(Binary).emit);
}
pub fn fromShift(a: std.mem.Allocator, c: Shift) !Case {
    return caseWith(a, Shift, "shift", "shift", c, widthsOf(Shift, &c), InteractionPrevious(Shift).emit);
}
fn emitShiftTable(a: std.mem.Allocator, c: *const ShiftTable, sink: *Sink) anyerror!void {
    const Needs = struct {
        fn f(_: void, column: usize) bool {
            return column >= 32;
        }
    };
    const fm = try R.Masks.init(a, 0, ShiftTableData.FIXED, {}, R.never);
    defer fm.deinit(a);
    const m = try R.Masks.init(a, 1, ShiftTableData.MAIN, {}, R.never);
    defer m.deinit(a);
    const i = try R.Masks.init(a, 2, ShiftTableData.INTERACTION, {}, Needs.f);
    defer i.deinit(a);
    c.emitFor(Lane, fm.current, m.current, i.current, i.previous, sink);
}
pub fn fromShiftTable(a: std.mem.Allocator, c: ShiftTable) !Case {
    return caseWith(a, ShiftTable, "shift_table", "shift_table", c, .{ ShiftTableData.FIXED, ShiftTableData.MAIN, ShiftTableData.INTERACTION }, emitShiftTable);
}
pub fn fromDivision(a: std.mem.Allocator, c: Division) !Case {
    return pointCase(a, Division, "division", "division", c);
}
pub fn fromMultiplication(a: std.mem.Allocator, c: Multiplication) !Case {
    return pointCase(a, Multiplication, if (c.pairs != null) "multiplication.u8_pairs" else "multiplication.classic", "multiplication", c);
}
pub fn fromLoadStore(a: std.mem.Allocator, c: LoadStore) !Case {
    const pairs = c.pairs != null;
    const name = switch (c.kind) {
        .ls => if (pairs) "ls32.fused_pairs" else "ls32.classic",
        .initial => if (pairs) "init.fused_pairs" else "init.classic",
        .terminal => if (pairs) "teardown.fused_pairs" else "teardown.classic",
        .selection => "ls.selection_table",
        .range16 => "ls.range16",
        .range8 => "ls.range8",
    };
    return pointCase(a, LoadStore, name, "load_store", c);
}

/// Live prover handles are recognised by the static vtable of these types.
pub const handlers = .{
    .{ Cpu, fromCpu },
    .{ Rom, fromRom },
    .{ Jalr, fromJalr },
    .{ Word16Cpu, fromWord16Cpu },
    .{ Alu, fromAlu },
    .{ Binary, fromBinary },
    .{ Shift, fromShift },
    .{ ShiftTable, fromShiftTable },
    .{ Division, fromDivision },
    .{ Multiplication, fromMultiplication },
    .{ LoadStore, fromLoadStore },
};

// ---- sample instances ------------------------------------------------------

fn cpuPublic(log: u32) X.types.Inputs {
    return .{ .steps = 7, .epoch = 3, .initial_pc = .{ 0x1000, 0, 0, 0 }, .final_pc = .{ 0x1044, 0, 0, 0 }, .wide_clock = X.layout.wideClock(log) };
}
pub fn cpu(a: std.mem.Allocator, rng: std.Random, log: u32, fused: bool, pairs: bool) !Case {
    return cpuWith(a, rng, log, fused, pairs, false);
}
pub fn cpuWith(a: std.mem.Allocator, rng: std.Random, log: u32, fused: bool, pairs: bool, compact: bool) !Case {
    var c = Cpu{ .log_size = log, .offsets = .{ 0, 0, 0 }, .public = cpuPublic(log), .claim = R.randomQ(rng), .challenges = draw(X.types.Challenges, rng), .fused = fused, .compact = compact };
    if (pairs) c.pairs = draw(X.equations.PairChallengesFor(Q), rng);
    return fromCpu(a, c);
}
fn registerPublic() W.public.Public {
    var p = W.public.Public{ .steps = 9, .initial_pc = 0x1000, .final_pc = 0x1040, .initial_registers = @splat(0), .final_registers = @splat(0), .register_clocks = @splat(0) };
    for (1..32) |r| {
        p.initial_registers[r] = 0x0123_4567_89ab_cdef +% r * 0x1111_0000_1111;
        p.final_registers[r] = 0xfedc_ba98_7654_3210 -% r * 0x0101_0101;
        p.register_clocks[r] = @intCast(r % 30);
    }
    return p;
}
fn word16Cpu(rng: std.Random, kind: W.component.Kind) Word16Cpu {
    const log: u32 = switch (kind) {
        .boundary => 5,
        .range16 => 16,
        .range8 => 8,
        else => 6,
    };
    return .{ .kind = kind, .log_size = log, .offsets = .{ 0, 0, 0 }, .public = registerPublic(), .cpu_claims = draw(W.public.Claims, rng), .claim = R.randomQ(rng), .challenges = draw(W.lookup.Challenges, rng) };
}

/// Every CPU-proof core component kind and layout of the Word16 v3 roster.
pub fn all(a: std.mem.Allocator, rng: std.Random, out: *std.ArrayList(Case)) !void {
    for ([_][2]bool{ .{ false, false }, .{ true, false }, .{ true, true } }) |mode| try out.append(a, try cpu(a, rng, 6, mode[0], mode[1]));
    try out.append(a, try cpuWith(a, rng, 6, true, true, true));
    try out.append(a, try fromRom(a, .{ .log_size = 6, .offsets = .{ 0, 0, 0 }, .claim = R.randomQ(rng), .challenges = draw(X.types.RomChallengesFor(Q), rng) }));
    try out.append(a, try fromJalr(a, .{ .log_size = 6, .offsets = .{ 0, 0, 0 }, .claim = R.randomQ(rng), .challenges = draw(X.types.FunctionChallengesFor(Q), rng) }));
    for ([_]W.component.Kind{ .boundary, .range16, .range8 }) |kind| try out.append(a, try fromWord16Cpu(a, word16Cpu(rng, kind)));
    for ([_]bool{ false, true }) |fused| try out.append(a, try fromAlu(a, .{ .log_size = 6, .offsets = .{ 0, 0, 0 }, .challenges = draw(B.alu_experiment.lookup.Challenges, rng), .claims = draw(B.alu_experiment.lookup.Claims, rng), .fused = fused }));
    for ([_]B.binary_component.Kind{ .binary, .and_table, .and_pair_table }) |kind| try out.append(a, try fromBinary(a, .{ .kind = kind, .log_size = if (kind == .binary) 6 else 16, .offsets = .{ 0, 0, 0 }, .challenges = draw(B.binary_lookup.Challenges, rng), .claims = draw(B.binary_lookup.Claims, rng) }));
    try out.append(a, try fromShift(a, .{ .log_size = 6, .offsets = .{ 0, 0, 0 }, .challenges = draw(B.shift_word_packed_experiment.lookup.Challenges, rng), .claims = draw(B.shift_word_packed_experiment.lookup.Claims, rng) }));
    try out.append(a, try fromShiftTable(a, .{ .offsets = .{ 0, 0, 0 }, .prepared = ShiftTableData.Prepared.init(draw(@typeInfo(@TypeOf(ShiftTableData.Prepared.init)).@"fn".params[0].type.?, rng)), .claim = R.randomQ(rng) }));
    {
        var c = std.mem.zeroes(Division);
        c.log_size = 6;
        c.count = 11;
        R.randomize(&c.challenges, rng);
        c.claim = R.randomQ(rng);
        try out.append(a, try fromDivision(a, c));
    }
    for ([_]bool{ false, true }) |pairs| {
        var c = std.mem.zeroes(Multiplication);
        c.log_size = 6;
        c.count = 13;
        R.randomize(&c.challenges, rng);
        c.claim = R.randomQ(rng);
        c.byte_alpha = R.randomQ(rng);
        c.pairs = if (pairs) draw(@TypeOf(c.pairs.?), rng) else null;
        try out.append(a, try fromMultiplication(a, c));
    }
    for ([_]bool{ false, true }) |pairs| for ([_]A.memory.load_store_v2.layout.Kind{ .ls, .initial, .terminal }) |kind| {
        var c = LoadStore{ .kind = kind, .log_size = 6, .rows = 17, .offsets = .{ 0, 0, 0 }, .claims = draw(A.memory.load_store_v2.types.ClaimsFor(Q), rng), .challenges = draw(A.memory.load_store_v2.types.ChallengesFor(Q), rng) };
        if (pairs) c.pairs = draw(@TypeOf(c.pairs.?), rng);
        try out.append(a, try fromLoadStore(a, c));
    };
    try out.append(a, try fromLoadStore(a, .{ .kind = .selection, .log_size = 6, .rows = 17, .offsets = .{ 0, 0, 0 }, .claims = draw(A.memory.load_store_v2.types.ClaimsFor(Q), rng), .challenges = draw(A.memory.load_store_v2.types.ChallengesFor(Q), rng) }));
}
