//! Independently derived immutable ROM for the exact three-opcode profile.
//! Unlike the legacy155-field decode table this has only16 semantic fields.
//! Program bytes/full-u64 PCs authenticate all register IDs/zero flags and the
//! wrapping increment; no request PC path, step count or final state is fixed.
const std = @import("std");
const core = @import("stwo_core");
const M = core.fields.m31.M31;
const isa = @import("../../decode.zig");
const Program = @import("../program/setup.zig").Program;
const Operations = @import("../word16_v1/operations.zig");
const P = @import("public.zig");
const L = @import("layout.zig");
pub const FIXED = 18;
pub const Setup = struct {
    allocator: std.mem.Allocator,
    words: []u32,
    addresses: []u64,
    decoded: []isa.Instruction,
    fixed: []M,
    log_size: u32,
    identity: [32]u8,
    pub fn init(a: std.mem.Allocator, program: Program) !Setup {
        try program.validate();
        const decoded = try a.alloc(isa.Instruction, program.words.len);
        errdefer a.free(decoded);
        for (program.words, decoded) |raw, *instruction| {
            instruction.* = try isa.Instruction.decode(raw);
            switch (instruction.opcode) {
                .AND, .OR, .XOR => {},
                else => return error.UnsupportedWord16CpuOpcode,
            }
        }
        const words = try a.dupe(u32, program.words);
        errdefer a.free(words);
        const addresses = try a.alloc(u64, words.len);
        errdefer a.free(addresses);
        for (addresses, 0..) |*address, i| address.* = program.pc(i);
        const log_size = @max(L.MIN_LOG, std.math.log2_int_ceil(usize, words.len));
        const n = @as(usize, 1) << @intCast(log_size);
        const fixed = try a.alloc(M, FIXED * n);
        errdefer a.free(fixed);
        @memset(fixed, M.zero());
        var hash = std.crypto.hash.sha2.Sha256.init(.{});
        hash.update("stwo-rv64/word16-register-binary-rom/v1\x00");
        var framed: [12]u8 = undefined;
        for (addresses, words, decoded, 0..) |pc, raw, instruction, i| {
            std.mem.writeInt(u64, framed[0..8], pc, .little);
            std.mem.writeInt(u32, framed[8..12], raw, .little);
            hash.update(&framed);
            const row = derive(pc, instruction);
            const pos = L.physical(i, @intCast(log_size));
            for (row, 0..) |value, column| fixed[column * n + pos] = value;
        }
        fixed[16 * n + L.physical(0, @intCast(log_size))] = M.one();
        fixed[17 * n + L.physical(n - 1, @intCast(log_size))] = M.one();
        return .{ .allocator = a, .words = words, .addresses = addresses, .decoded = decoded, .fixed = fixed, .log_size = @intCast(log_size), .identity = hash.finalResult() };
    }
    pub fn deinit(self: *Setup) void {
        self.allocator.free(self.fixed);
        self.allocator.free(self.decoded);
        self.allocator.free(self.addresses);
        self.allocator.free(self.words);
        self.* = undefined;
    }
    pub fn size(self: *const Setup) usize {
        return @as(usize, 1) << @intCast(self.log_size);
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
fn derive(pc: u64, instruction: isa.Instruction) [16]M {
    var row: [16]M = undefined;
    row[0] = M.one();
    @memcpy(row[1..5], &P.word(M, pc));
    @memcpy(row[5..9], &P.word(M, pc +% 4));
    const operation = Operations.classify(instruction.opcode).?;
    row[9] = M.fromCanonical(operation.busId());
    const ids = [_]u5{ instruction.rs1, instruction.rs2, instruction.rd };
    for (ids, 0..) |id, i| {
        row[10 + i] = M.fromCanonical(id);
        row[13 + i] = M.fromCanonical(@intFromBool(id == 0));
    }
    return row;
}
