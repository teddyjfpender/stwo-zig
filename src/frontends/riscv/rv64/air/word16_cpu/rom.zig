//! Independently derived immutable ROM for limited Word16 CPU diagnostics.
//! Binary control uses16 semantic fields. ALU/binary uses23, including signed
//! immediates and both legal branch edges. Every full-u64 PC derives from the
//! complete expected program, never an executed-only instruction selection.
//! Unsupported program words still reject these LIMITED profiles; production
//! full-ELF admission needs per-word validity, not a narrowed expected program.
//! No request PC path, step count or endpoint becomes a fixed column.
const std = @import("std");
const core = @import("stwo_core");
const M = core.fields.m31.M31;
const isa = @import("../../decode.zig");
const Program = @import("../program/setup.zig").Program;
const Operations = @import("../word16_v1/operations.zig");
const P = @import("public.zig");
const L = @import("layout.zig");
const Profile = @import("profile.zig");
pub const FIXED = 18;
pub const Setup = struct {
    allocator: std.mem.Allocator,
    words: []u32,
    addresses: []u64,
    decoded: []isa.Instruction,
    fixed: []M,
    log_size: u32,
    identity: [32]u8,
    profile: Profile.Profile,
    word_rows: []u32,
    row_words: []u32,
    pub fn init(a: std.mem.Allocator, program: Program) !Setup {
        return initWithProfile(a, program, .binary_v1);
    }
    pub fn initWithProfile(a: std.mem.Allocator, program: Program, profile: Profile.Profile) !Setup {
        try program.validate();
        const decoded = try a.alloc(isa.Instruction, program.words.len);
        errdefer a.free(decoded);
        for (program.words, decoded) |raw, *instruction| {
            instruction.* = try isa.Instruction.decode(raw);
            const operation = Operations.classify(instruction.opcode) orelse return error.UnsupportedWord16CpuOpcode;
            if (profile == .binary_v1) {
                switch (instruction.opcode) {
                    .AND, .OR, .XOR => {},
                    else => return error.UnsupportedWord16CpuOpcode,
                }
            } else if (operation.family != .alu and operation.family != .binary) return error.UnsupportedWord16CpuOpcode;
        }
        const words = try a.dupe(u32, program.words);
        errdefer a.free(words);
        const addresses = try a.alloc(u64, words.len);
        errdefer a.free(addresses);
        for (addresses, 0..) |*address, i| address.* = program.pc(i);
        const word_rows = try a.alloc(u32, words.len);
        errdefer a.free(word_rows);
        var rows: usize = 0;
        for (addresses, decoded, word_rows) |pc, instruction, *first_row| {
            first_row.* = @intCast(rows);
            const branch = Operations.classify(instruction.opcode).?.branch_predicate;
            rows += if (branch and ((pc +% @as(u64, @bitCast(instruction.imm))) & 3 == 0)) @as(usize, 2) else 1;
        }
        if (rows > @as(usize, 1) << 22) return error.InvalidWord16RomGeometry;
        const row_words = try a.alloc(u32, rows);
        errdefer a.free(row_words);
        const log_size = @max(L.MIN_LOG, std.math.log2_int_ceil(usize, rows));
        const n = @as(usize, 1) << @intCast(log_size);
        const tuple_count = Profile.romCount(profile);
        const fixed = try a.alloc(M, (tuple_count + 2) * n);
        errdefer a.free(fixed);
        @memset(fixed, M.zero());
        var hash = std.crypto.hash.sha2.Sha256.init(.{});
        hash.update(if (profile == .binary_v1) "stwo-rv64/word16-register-binary-rom/v1\x00" else "stwo-rv64/word16-alu-binary-edges-rom/v2\x00");
        var framed: [12]u8 = undefined;
        for (addresses, words, decoded, 0..) |pc, raw, instruction, i| {
            std.mem.writeInt(u64, framed[0..8], pc, .little);
            std.mem.writeInt(u32, framed[8..12], raw, .little);
            hash.update(&framed);
            const first_row = word_rows[i];
            const end_row = if (i + 1 == words.len) rows else word_rows[i + 1];
            for (first_row..end_row) |row_index| {
                row_words[row_index] = @intCast(i);
                const row = deriveWithProfile(pc, instruction, profile, row_index != first_row);
                const pos = L.physical(row_index, @intCast(log_size));
                for (row[0..tuple_count], 0..) |value, column| fixed[column * n + pos] = value;
            }
        }
        fixed[tuple_count * n + L.physical(0, @intCast(log_size))] = M.one();
        fixed[(tuple_count + 1) * n + L.physical(n - 1, @intCast(log_size))] = M.one();
        return .{ .allocator = a, .words = words, .addresses = addresses, .decoded = decoded, .fixed = fixed, .log_size = @intCast(log_size), .identity = hash.finalResult(), .profile = profile, .word_rows = word_rows, .row_words = row_words };
    }
    pub fn deinit(self: *Setup) void {
        self.allocator.free(self.row_words);
        self.allocator.free(self.word_rows);
        self.allocator.free(self.fixed);
        self.allocator.free(self.decoded);
        self.allocator.free(self.addresses);
        self.allocator.free(self.words);
        self.* = undefined;
    }
    pub fn size(self: *const Setup) usize {
        return @as(usize, 1) << @intCast(self.log_size);
    }
    pub fn fixedCount(self: *const Setup) usize {
        return Profile.romCount(self.profile) + 2;
    }
    pub fn rowPc(self: *const Setup, index: usize) u64 {
        return self.addresses[self.row_words[index]];
    }
    pub fn rowInstruction(self: *const Setup, index: usize) isa.Instruction {
        return self.decoded[self.row_words[index]];
    }
    pub fn rowNext(self: *const Setup, index: usize) u64 {
        const word = self.row_words[index];
        const pc = self.addresses[word];
        return if (index == self.word_rows[word]) pc +% 4 else pc +% @as(u64, @bitCast(self.decoded[word].imm));
    }
    pub fn factIndex(self: *const Setup, word: usize, taken: bool) !usize {
        const first = self.word_rows[word];
        if (!taken) return first;
        const next = first + 1;
        if (next >= self.row_words.len or self.row_words[next] != word) return error.InvalidWord16BranchEdge;
        return next;
    }
    pub fn lookup(self: *const Setup, pc: u64) !usize {
        var lo: usize = 0;
        var hi = self.addresses.len;
        while (lo < hi) {
            const middle = lo + (hi - lo) / 2;
            if (self.addresses[middle] < pc) lo = middle + 1 else hi = middle;
        }
        if (lo == self.addresses.len or self.addresses[lo] != pc) return error.UnknownWord16CpuPc;
        return lo;
    }
};
fn deriveWithProfile(pc: u64, instruction: isa.Instruction, profile: Profile.Profile, taken: bool) [Profile.MAX_ROM]M {
    var row: [Profile.MAX_ROM]M = @splat(M.zero());
    row[0] = M.one();
    @memcpy(row[1..5], &P.word(M, pc));
    const operation = Operations.classify(instruction.opcode).?;
    const next = if (taken) pc +% @as(u64, @bitCast(instruction.imm)) else pc +% 4;
    @memcpy(row[5..9], &P.word(M, next));
    row[9] = M.fromCanonical(operation.busId());
    const ids = effectiveIds(instruction, profile);
    for (ids, 0..) |id, i| {
        row[10 + i] = M.fromCanonical(id);
        row[13 + i] = M.fromCanonical(@intFromBool(id == 0));
    }
    if (profile == .alu_binary_v2) {
        row[16] = M.fromCanonical(@intFromBool(operation.use_immediate));
        row[17] = M.fromCanonical(@intFromBool(operation.branch_predicate));
        if (operation.use_immediate) @memcpy(row[18..22], &P.word(M, @bitCast(instruction.imm)));
        row[22] = M.fromCanonical(@intFromBool(taken));
    }
    return row;
}
pub fn effectiveIds(instruction: isa.Instruction, profile: Profile.Profile) [3]u5 {
    if (profile == .binary_v1) return .{ instruction.rs1, instruction.rs2, instruction.rd };
    const effects = isa.effects(instruction.opcode);
    return .{ if (effects.reads_rs1) instruction.rs1 else 0, if (effects.reads_rs2) instruction.rs2 else 0, if (effects.writes_rd) instruction.rd else 0 };
}
