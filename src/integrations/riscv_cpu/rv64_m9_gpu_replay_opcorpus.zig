//! M9 GPU replay: synthetic per-opcode differential corpus (review 2026-11-07).
//!
//! The real-block parity corpus (24628607 + 26235159) never executes 19 of the 69 fast
//! ops (nop, slt, sra, sraw, sraiw, mulh, mulhsu, rem, divw, divuw, remw, remuw and all 7
//! Zbb ops). This writes a GPU replay input whose expected tape comes from the reference
//! interpreter (`machine.Cpu.stepCached`, Zbb decode set), not from the fast engine or the
//! M9 code, so every GPU op is checked against the architecture on edge-case operands:
//!   case k: one fast step (chunk k, seeded with x1 = a, x2 = b, x3 = c, x10 = 7) followed
//!   by a dummy host step whose `pc_slot` is the case's next pc (exercises the GPU's
//!   end-of-chunk check at host steps on every case), then a second dummy so that no seed
//!   directly follows a host step (no register carry-over between unrelated cases).
//! Output: the standard dump layout (rom.bin, meta.txt, seg0.{seeds,mem,slow,ref}); run it
//! with the `-DM9_STANDALONE` harness exactly like a block dump. Diagnostic only.
const std = @import("std");
const rv = @import("stwo_riscv_frontend").rv64;
const R = @import("rv64_m9_gpu_replay.zig");
const machine = rv.machine;
const mem = rv.memory;
const fast = rv.fast_execution;
const Step = rv.compact_tape.Step;
const Cache = @typeInfo(@typeInfo(@TypeOf(machine.Cpu.stepCached)).@"fn".params[2].type.?).pointer.child;

const CODE: u64 = 0x10000;
const DATA: u64 = 0x40000;
const CODE_WORDS = 4096;

fn r(f7: u32, rs2: u32, rs1: u32, f3: u32, rd: u32, op: u32) u32 {
    return f7 << 25 | rs2 << 20 | rs1 << 15 | f3 << 12 | rd << 7 | op;
}
fn i(imm: i32, rs1: u32, f3: u32, rd: u32, op: u32) u32 {
    return (@as(u32, @bitCast(imm)) & 0xfff) << 20 | rs1 << 15 | f3 << 12 | rd << 7 | op;
}
fn s(imm: i32, rs2: u32, rs1: u32, f3: u32) u32 {
    const u: u32 = @bitCast(imm);
    return ((u >> 5) & 0x7f) << 25 | rs2 << 20 | rs1 << 15 | f3 << 12 | (u & 0x1f) << 7 | 0x23;
}
fn b(imm: i32, rs2: u32, rs1: u32, f3: u32) u32 {
    const u: u32 = @bitCast(imm);
    return ((u >> 12) & 1) << 31 | ((u >> 5) & 0x3f) << 25 | rs2 << 20 | rs1 << 15 | f3 << 12 | ((u >> 1) & 0xf) << 8 | ((u >> 11) & 1) << 7 | 0x63;
}
fn jal(imm: i32, rd: u32) u32 {
    const u: u32 = @bitCast(imm);
    return ((u >> 20) & 1) << 31 | ((u >> 1) & 0x3ff) << 21 | ((u >> 11) & 1) << 20 | ((u >> 12) & 0xff) << 12 | rd << 7 | 0x6f;
}

const Kind = enum { alu, load, store, branch, jump };
const Inst = struct { name: []const u8, word: u32, kind: Kind };

fn program(a: std.mem.Allocator) !std.ArrayList(Inst) {
    var p = std.ArrayList(Inst).empty;
    const R3 = 3;
    const add = struct {
        fn f(list: *std.ArrayList(Inst), al: std.mem.Allocator, name: []const u8, word: u32, kind: Kind) !void {
            try list.append(al, .{ .name = name, .word = word, .kind = kind });
        }
    }.f;
    // OP (0x33): base, M, Zbb
    const op_r = [_]struct { []const u8, u32, u32 }{
        .{ "add", 0, 0 },     .{ "sub", 0x20, 0 },  .{ "sll", 0, 1 },    .{ "slt", 0, 2 },    .{ "sltu", 0, 3 },
        .{ "xor", 0, 4 },     .{ "srl", 0, 5 },     .{ "sra", 0x20, 5 }, .{ "or", 0, 6 },     .{ "and", 0, 7 },
        .{ "mul", 1, 0 },     .{ "mulh", 1, 1 },    .{ "mulhsu", 1, 2 }, .{ "mulhu", 1, 3 },  .{ "div", 1, 4 },
        .{ "divu", 1, 5 },    .{ "rem", 1, 6 },     .{ "remu", 1, 7 },   .{ "andn", 0x20, 7 }, .{ "orn", 0x20, 6 },
        .{ "xnor", 0x20, 4 },
    };
    for (op_r) |o| try add(&p, a, o[0], r(o[1], 2, 1, o[2], R3, 0x33), .alu);
    try add(&p, a, "add_x0", r(0, 2, 1, 0, 0, 0x33), .alu);
    const op_w = [_]struct { []const u8, u32, u32 }{
        .{ "addw", 0, 0 }, .{ "subw", 0x20, 0 }, .{ "sllw", 0, 1 },  .{ "srlw", 0, 5 },  .{ "sraw", 0x20, 5 },
        .{ "mulw", 1, 0 }, .{ "divw", 1, 4 },    .{ "divuw", 1, 5 }, .{ "remw", 1, 6 }, .{ "remuw", 1, 7 },
    };
    for (op_w) |o| try add(&p, a, o[0], r(o[1], 2, 1, o[2], R3, 0x3b), .alu);
    try add(&p, a, "zext_h", r(0x04, 0, 1, 4, R3, 0x3b), .alu);
    for ([_]i32{ 0, 1, -1, 2047, -2048, 0x555 }) |imm| {
        try add(&p, a, "addi", i(imm, 1, 0, R3, 0x13), .alu);
        try add(&p, a, "slti", i(imm, 1, 2, R3, 0x13), .alu);
        try add(&p, a, "sltiu", i(imm, 1, 3, R3, 0x13), .alu);
        try add(&p, a, "xori", i(imm, 1, 4, R3, 0x13), .alu);
        try add(&p, a, "ori", i(imm, 1, 6, R3, 0x13), .alu);
        try add(&p, a, "andi", i(imm, 1, 7, R3, 0x13), .alu);
        try add(&p, a, "addiw", i(imm, 1, 0, R3, 0x1b), .alu);
    }
    try add(&p, a, "addi_x0", i(5, 1, 0, 0, 0x13), .alu);
    for ([_]u32{ 0, 1, 31, 32, 63 }) |sh| {
        try add(&p, a, "slli", i(@intCast(sh), 1, 1, R3, 0x13), .alu);
        try add(&p, a, "srli", i(@intCast(sh), 1, 5, R3, 0x13), .alu);
        try add(&p, a, "srai", i(@intCast(0x400 | sh), 1, 5, R3, 0x13), .alu);
        if (sh < 32) {
            try add(&p, a, "slliw", i(@intCast(sh), 1, 1, R3, 0x1b), .alu);
            try add(&p, a, "srliw", i(@intCast(sh), 1, 5, R3, 0x1b), .alu);
            try add(&p, a, "sraiw", i(@intCast(0x400 | sh), 1, 5, R3, 0x1b), .alu);
        }
    }
    try add(&p, a, "rev8", i(0x6b8, 1, 5, R3, 0x13), .alu);
    try add(&p, a, "sext_b", i(0x604, 1, 1, R3, 0x13), .alu);
    try add(&p, a, "sext_h", i(0x605, 1, 1, R3, 0x13), .alu);
    try add(&p, a, "lui", 0xfedcb000 | R3 << 7 | 0x37, .alu);
    try add(&p, a, "lui_x0", 0x12345000 | 0x37, .alu);
    try add(&p, a, "auipc", 0x80000000 | R3 << 7 | 0x17, .alu);
    try add(&p, a, "fence", 0x0ff0000f, .alu);
    try add(&p, a, "nop", 0x00000013, .alu);
    // loads/stores: x1 holds an address in the data page (set per case), imm 0 or 8
    const lds = [_]struct { []const u8, u32 }{ .{ "lb", 0 }, .{ "lh", 1 }, .{ "lw", 2 }, .{ "ld", 3 }, .{ "lbu", 4 }, .{ "lhu", 5 }, .{ "lwu", 6 } };
    for (lds) |o| for ([_]i32{ 0, 8, -8 }) |imm| try add(&p, a, o[0], i(imm, 1, o[1], R3, 0x03), .load);
    try add(&p, a, "ld_x0", i(0, 1, 3, 0, 0x03), .load);
    const sts = [_]struct { []const u8, u32 }{ .{ "sb", 0 }, .{ "sh", 1 }, .{ "sw", 2 }, .{ "sd", 3 } };
    for (sts) |o| for ([_]i32{ 0, 8, -8 }) |imm| try add(&p, a, o[0], s(imm, 2, 1, o[1]), .store);
    const brs = [_]struct { []const u8, u32 }{ .{ "beq", 0 }, .{ "bne", 1 }, .{ "blt", 4 }, .{ "bge", 5 }, .{ "bltu", 6 }, .{ "bgeu", 7 } };
    for (brs) |o| {
        try add(&p, a, o[0], b(8, 2, 1, o[1]), .branch);
        try add(&p, a, o[0], b(-4, 2, 1, o[1]), .branch);
    }
    try add(&p, a, "jal", jal(16, R3), .jump);
    try add(&p, a, "jal", jal(-8, R3), .jump);
    try add(&p, a, "jal_x0", jal(8, 0), .jump);
    // jalr: x1 is set to a code address per case
    for ([_]i32{ 0, 4, -4, 1 }) |imm| try add(&p, a, "jalr", i(imm, 1, 0, R3, 0x67), .jump);
    try add(&p, a, "jalr_x0", i(0, 1, 0, 0, 0x67), .jump);
    return p;
}

const EDGES = [_]u64{
    0,                  1,                  2,                  3,          0xffff_ffff_ffff_ffff, 0xffff_ffff_ffff_fffe,
    0x7fff_ffff_ffff_ffff, 0x8000_0000_0000_0000, 0x8000_0000_0000_0001, 0x7fff_ffff, 0x8000_0000,            0xffff_ffff,
    0x1_0000_0000,      0xffff_ffff_8000_0000, 0xffff,          0x8000,     0x80,                  0xff,
    31,                 32,                 63,                 64,         0x0123_4567_89ab_cdef, 0xfedc_ba98_7654_3210,
};

pub fn run(a: std.mem.Allocator, out_path: []const u8) !void {
    var prog = try program(a);
    defer prog.deinit(a);
    if (prog.items.len * 2 + 8 > CODE_WORDS) return error.M9CorpusTooLarge;
    var memory = mem.Memory.init(a, .{});
    defer memory.deinit();
    try memory.map(.{ .start = CODE, .size = CODE_WORDS * 4, .permissions = .{ .read = true, .execute = true } });
    try memory.map(.{ .start = DATA, .size = mem.PAGE_SIZE, .permissions = .{ .read = true, .write = true } });
    // Instruction n at word 2n; the odd words are `addi x0, x0, 0` landing pads for jumps.
    var words = [_]u32{0x00000013} ** CODE_WORDS;
    for (prog.items, 0..) |inst, n| words[2 * n + 8] = inst.word;
    try memory.initialize(CODE, std.mem.sliceAsBytes(&words));
    var prng = std.Random.DefaultPrng.init(0x4d39_5265_7669_6577);
    const rand = prng.random();
    {
        var data: [mem.PAGE_SIZE / 8]u64 = undefined;
        for (&data) |*w| w.* = rand.int(u64);
        try memory.initialize(DATA, std.mem.sliceAsBytes(&data));
    }
    var engine = try fast.Engine.init(a, &memory, .{ .isa = .rv64im_zbb_binary });
    defer engine.deinit();
    const rom = try R.exportRom(a, &engine);
    defer a.free(rom);
    var cache = try Cache.initIsa(a, 1024, .rv64im_zbb_binary);
    defer cache.deinit();

    var tape = R.SegmentTape.init(a, 1);
    defer tape.deinit();
    tape.code_lo = engine.code_lo;
    tape.slots = engine.slots.len;
    var ref = std.ArrayList(Step).empty;
    defer ref.deinit(a);
    var per_op: std.StringArrayHashMapUnmanaged(u64) = .empty;
    defer per_op.deinit(a);
    var not_fast: u64 = 0;
    for (prog.items, 0..) |inst, n| {
        const pc = CODE + 4 * (2 * n + 8);
        const slot = tape.slot(pc);
        if (rom[slot].op == 0) {
            std.debug.print("M9 corpus: {s} ({x:0>8}) is not a fast slot\n", .{ inst.name, inst.word });
            not_fast += 1;
            continue;
        }
        const pairs: usize = switch (inst.kind) {
            .alu, .branch => EDGES.len * EDGES.len + 256,
            .load, .store => 192,
            .jump => 16,
        };
        for (0..pairs) |q| {
            var x: u64 = undefined;
            var y: u64 = undefined;
            if (inst.kind == .alu or inst.kind == .branch) {
                if (q < EDGES.len * EDGES.len) {
                    x = EDGES[q / EDGES.len];
                    y = EDGES[q % EDGES.len];
                } else {
                    x = rand.int(u64);
                    y = if (q & 1 == 0) rand.int(u64) else x;
                }
            } else if (inst.kind == .jump) {
                x = CODE + 4 * (2 * rand.uintLessThan(u64, prog.items.len) + 8);
                y = rand.int(u64);
            } else {
                // aligned address for every width, away from the page edges (imm is -8..8)
                x = DATA + 16 + 8 * rand.uintLessThan(u64, mem.PAGE_SIZE / 8 - 4) + (q % 8);
                x &= ~@as(u64, switch ((inst.word >> 12) & 7) {
                    0, 4 => 0,
                    1, 5 => 1,
                    2, 6 => 3,
                    else => 7,
                });
                y = rand.int(u64);
            }
            var cpu = machine.Cpu{ .pc = pc };
            cpu.regs[1] = x;
            cpu.regs[2] = y;
            cpu.regs[3] = rand.int(u64);
            cpu.regs[10] = 7;
            const pos: u32 = @intCast(ref.items.len);
            var seed = R.Seed{ .regs = cpu.regs, .pc = pc, .first_step = pos, .steps = 1, .first_mem = @intCast(tape.memory.items.len), .check_next = 0 };
            seed.regs[0] = 0;
            const rec = try cpu.stepCached(&memory, &cache);
            var memory_index: u32 = rv.compact_tape.NO_MEMORY;
            if (rec.memory) |e| {
                memory_index = @intCast(tape.memory.items.len);
                try tape.memory.append(a, e.before_word.toInt());
            }
            try ref.append(a, .{ .next_pc = rec.next_pc.toInt(), .lhs = rec.lhs.toInt(), .rhs = rec.rhs.toInt(), .previous_rd = rec.previous_rd.toInt(), .result = rec.result.toInt(), .memory_index = memory_index, .flags = @intFromBool(rec.branch_taken) });
            try tape.seeds.append(a, seed);
            // dummy host step right after: its pc_slot is where the case must stop
            const dummy = Step{ .next_pc = 0, .lhs = 0, .rhs = 0, .previous_rd = 0, .result = 0, .memory_index = rv.compact_tape.NO_MEMORY, .flags = 0 };
            try tape.slow.append(a, .{ .pos = pos + 1, .pc_slot = tape.slot(rec.next_pc.toInt()), .rd = R.NO_RD, .step = dummy });
            try ref.append(a, dummy);
            // a second dummy, so the next case's seed never directly follows a host step
            // (the GPU would compare the registers across it, which the corpus does not keep)
            try tape.slow.append(a, .{ .pos = pos + 2, .pc_slot = R.NO_SLOT, .rd = R.NO_RD, .step = dummy });
            try ref.append(a, dummy);
            (try per_op.getOrPutValue(a, inst.name, 0)).value_ptr.* += 1;
        }
    }
    try tape.verifyPartition(tape.start + ref.items.len);

    try std.fs.cwd().makePath(out_path);
    var out = try std.fs.cwd().openDir(out_path, .{});
    defer out.close();
    try out.writeFile(.{ .sub_path = "rom.bin", .data = std.mem.sliceAsBytes(rom) });
    try out.writeFile(.{ .sub_path = "seg0.seeds", .data = std.mem.sliceAsBytes(tape.seeds.items) });
    try out.writeFile(.{ .sub_path = "seg0.mem", .data = std.mem.sliceAsBytes(tape.memory.items) });
    try out.writeFile(.{ .sub_path = "seg0.slow", .data = std.mem.sliceAsBytes(tape.slow.items) });
    try out.writeFile(.{ .sub_path = "seg0.ref", .data = std.mem.sliceAsBytes(ref.items) });
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(std.mem.sliceAsBytes(ref.items), &digest, .{});
    var meta = std.ArrayList(u8).empty;
    defer meta.deinit(a);
    try meta.print(a, "code_lo {d}\nslots {d}\nchunk 1\nsegments 1\nseg 0 {d} {d} {d} {d} {s} {d}\n", .{ engine.code_lo, rom.len, ref.items.len, tape.seeds.items.len, tape.memory.items.len, tape.slow.items.len, &std.fmt.bytesToHex(digest, .lower), R.NO_SLOT });
    try out.writeFile(.{ .sub_path = "meta.txt", .data = meta.items });

    var buf: [1 << 14]u8 = undefined;
    var w = std.fs.File.stdout().writer(&buf);
    const o = &w.interface;
    try o.print("{{\"scope\": \"M9 GPU replay op corpus (reference: machine.Cpu.stepCached, rv64im_zbb_binary)\", \"cases\": {d}, \"steps\": {d}, \"memory_words\": {d}, \"distinct_ops\": {d}, \"not_fast\": {d}, \"sha256\": \"{s}\", \"cases_by_op\": {{", .{ tape.seeds.items.len, ref.items.len, tape.memory.items.len, per_op.count(), not_fast, &std.fmt.bytesToHex(digest, .lower) });
    for (per_op.keys(), per_op.values(), 0..) |k, v, n| try o.print("{s}\"{s}\": {d}", .{ if (n == 0) "" else ", ", k, v });
    try o.print("}}}}\n", .{});
    try o.flush();
    if (not_fast != 0) return error.M9CorpusNotFast;
}
