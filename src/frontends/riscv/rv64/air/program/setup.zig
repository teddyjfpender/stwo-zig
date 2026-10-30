//! Program-only ROM. The receiver constructs this from its expected executable;
//! identity is a cache hint, never authority for a producer-supplied table/root.
//! Owns O(program words) storage; no request, execution path, or final PC enters.
const std = @import("std");
const core = @import("stwo_core");
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const isa = @import("../../decode.zig");
const L = @import("../layout.zig");
const ops = @import("../operations.zig");

pub const MAX_PROGRAM_WORDS = 1 << 22;
pub const Program = struct {
    base: u64,
    words: []const u32,
    addresses: []const u64 = &.{},

    pub fn validate(self: Program) !void {
        if (self.words.len == 0 or self.words.len > MAX_PROGRAM_WORDS) return error.InvalidRv64RomSize;
        if (self.base & 3 != 0) return error.InvalidRv64RomAddress;
        if (self.addresses.len != 0) {
            if (self.addresses.len != self.words.len or self.addresses[0] != self.base) return error.InvalidRv64RomAddress;
            for (self.addresses, 0..) |address, i| if (address & 3 != 0 or (i != 0 and self.addresses[i - 1] >= address)) return error.InvalidRv64RomAddress;
        } else {
            _ = std.math.add(u64, self.base, @as(u64, @intCast(self.words.len)) * 4 - 1) catch return error.InvalidRv64RomAddress;
        }
    }
    pub fn pc(self: Program, index: usize) u64 {
        return if (self.addresses.len == 0) self.base + 4 * index else self.addresses[index];
    }
};

/// All fields consumed as fixed decode authority by the existing arithmetic AIR.
/// Raw bytes and validity also bind undecodable/unreachable executable contents.
pub const field = struct {
    pub const valid = 0;
    pub const pc = 1;
    pub const raw = pc + 8;
    pub const opcode = raw + 4;
    pub const rs1 = opcode + 1;
    pub const rs2 = rs1 + 1;
    pub const rd = rs2 + 1;
    pub const immediate = rd + 1;
    pub const slots = immediate + 8;
    pub const increment = slots + 4;
    pub const target = increment + 8;
    pub const words = target + 8;
    pub const carries = words + L.WORDS;
    pub const COUNT = carries + L.CARRIES;
};
pub const Row = [field.COUNT]M;
pub const Tuple = [field.COUNT]Q;

pub const Setup = struct {
    allocator: std.mem.Allocator,
    addresses: []u64,
    rows: []Row,
    identity: [32]u8,
    log_size: u32,

    /// Copies exact PCs and derives decode rows before publication. Unsupported
    /// words remain in ROM with valid=0 and cannot authenticate an execution.
    pub fn init(a: std.mem.Allocator, program: Program) !Setup {
        try program.validate();
        const addresses = try a.alloc(u64, program.words.len);
        errdefer a.free(addresses);
        const rows = try a.alloc(Row, program.words.len);
        errdefer a.free(rows);
        const Blake2s = if (@hasDecl(std.crypto.hash, "Blake2s256")) std.crypto.hash.Blake2s256 else std.crypto.hash.blake2.Blake2s256;
        var hash = Blake2s.init(.{});
        hash.update("stwo-zig/rv64/program-rom/v1\x00");
        var bytes: [8]u8 = undefined;
        std.mem.writeInt(u64, &bytes, @intCast(program.words.len), .little);
        hash.update(&bytes);
        for (program.words, addresses, rows, 0..) |word, *address, *decoded_row, i| {
            address.* = program.pc(i);
            decoded_row.* = deriveRow(address.*, word);
            std.mem.writeInt(u64, &bytes, address.*, .little);
            hash.update(&bytes);
            var instruction_bytes: [4]u8 = undefined;
            std.mem.writeInt(u32, &instruction_bytes, word, .little);
            hash.update(&instruction_bytes);
        }
        var identity: [32]u8 = undefined;
        hash.final(&identity);
        return .{ .allocator = a, .addresses = addresses, .rows = rows, .identity = identity, .log_size = @max(5, std.math.log2_int_ceil(usize, program.words.len)) };
    }
    pub fn deinit(self: *Setup) void {
        self.allocator.free(self.addresses);
        self.allocator.free(self.rows);
        self.* = undefined;
    }
    pub fn domainSize(self: *const Setup) usize {
        return @as(usize, 1) << @intCast(self.log_size);
    }
    pub fn lookup(self: *const Setup, pc: u64) !usize {
        var low: usize = 0;
        var high = self.addresses.len;
        while (low < high) {
            const mid = low + (high - low) / 2;
            if (self.addresses[mid] < pc) low = mid + 1 else high = mid;
        }
        if (low == self.addresses.len or self.addresses[low] != pc or self.rows[low][field.valid].isZero()) return error.InvalidRv64RomExecution;
        return low;
    }
    pub fn row(self: *const Setup, index: usize) Row {
        return if (index < self.rows.len) self.rows[index] else @splat(M.zero());
    }
    /// Receiver-derived preprocessing, column-major in committed circle order.
    /// First/last occupy the final two columns of this component's fixed slice.
    pub fn fixedColumns(self: *const Setup, a: std.mem.Allocator) ![]M {
        const size = self.domainSize();
        const result = try a.alloc(M, (field.COUNT + 2) * size);
        @memset(result, M.zero());
        for (0..size) |logical| {
            const index = core.utils.bitReverseIndex(core.utils.cosetIndexToCircleDomainIndex(logical, self.log_size), self.log_size);
            const entry = self.row(logical);
            for (entry, 0..) |value, c| result[c * size + index] = value;
            result[field.COUNT * size + index] = scalar(@intFromBool(logical == 0));
            result[(field.COUNT + 1) * size + index] = scalar(@intFromBool(logical + 1 == size));
        }
        return result;
    }
    /// Compact41 profile omits raw encoding and linearly derived enable fields.
    pub fn compactFixedColumns(self: *const Setup, a: std.mem.Allocator) ![]M {
        const compact = @import("compact.zig");
        const size = self.domainSize();
        const result = try a.alloc(M, (compact.COUNT + 2) * size);
        @memset(result, M.zero());
        for (0..size) |logical| {
            const index = core.utils.bitReverseIndex(core.utils.cosetIndexToCircleDomainIndex(logical, self.log_size), self.log_size);
            const entry = self.row(logical);
            for (compact.fields, 0..) |source, c| result[c * size + index] = entry[source];
            result[compact.COUNT * size + index] = scalar(@intFromBool(logical == 0));
            result[(compact.COUNT + 1) * size + index] = scalar(@intFromBool(logical + 1 == size));
        }
        return result;
    }
};

pub fn tuple(row: *const Row) Tuple {
    var result: Tuple = undefined;
    for (&result, row) |*output, value| output.* = Q.fromBase(value);
    return result;
}

pub fn deriveRow(pc: u64, raw: u32) Row {
    var row: Row = @splat(M.zero());
    putBytes(&row, field.pc, pc, 8);
    putBytes(&row, field.raw, raw, 4);
    const instruction = isa.Instruction.decode(raw) catch return row;
    if (instruction.opcode == .ECALL or instruction.opcode == .EBREAK) return row;
    const effects = isa.effects(instruction.opcode);
    const slots = [4]bool{ effects.reads_rs1 and instruction.rs1 != 0, effects.reads_rs2 and instruction.rs2 != 0, effects.writes_rd and instruction.rd != 0, effects.memory_width != 0 };
    row[field.valid] = M.one();
    row[field.opcode] = scalar(@intFromEnum(instruction.opcode));
    row[field.rs1] = scalar(if (slots[0]) instruction.rs1 else 0);
    row[field.rs2] = scalar(if (slots[1]) instruction.rs2 else 0);
    row[field.rd] = scalar(if (slots[2]) instruction.rd else 0);
    putBytes(&row, field.immediate, @bitCast(instruction.imm), 8);
    putBytes(&row, field.increment, pc +% 4, 8);
    putBytes(&row, field.target, pc +% @as(u64, @bitCast(instruction.imm)), 8);
    for (slots, 0..) |enabled, i| row[field.slots + i] = scalar(@intFromBool(enabled));
    for (0..L.WORDS) |i| row[field.words + i] = scalar(@intFromBool(ops.wordActive(@enumFromInt(i), instruction.opcode, slots)));
    for (0..L.CARRIES) |i| row[field.carries + i] = scalar(@intFromBool(ops.carryActive(@enumFromInt(i / 8), i % 8, instruction.opcode)));
    return row;
}
fn scalar(value: u32) M {
    return M.fromCanonical(value);
}
fn putBytes(row: *Row, start: usize, value: u64, count: usize) void {
    for (0..count) |i| row[start + i] = scalar(@intCast((value >> @as(u6, @intCast(i * 8))) & 255));
}
