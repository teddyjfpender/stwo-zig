//! Program-only ROM. The receiver constructs this from its expected executable;
//! identity is a cache hint, never authority for a producer-supplied table/root.
//! Owns O(program words) storage; no request, execution path, or final PC enters.
const std = @import("std");
const core = @import("stwo_core");
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const isa = @import("../../decode.zig");
const execution = @import("../../execution_profile.zig");
pub const SERVICE_DOMAIN = "stwo-zig/rv64/keccak-service-rom/v1\x00";
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
/// Immutable native metadata, derived once with the polynomial decode row.
/// This is a projection cache, not independently supplied proof authority.
pub const Decoded = struct {
    raw: u32,
    instruction: isa.Instruction = .{ .opcode = .FENCE, .rd = 0, .rs1 = 0, .rs2 = 0 },
    enabled: [4]bool = @splat(false),
};

pub const Setup = struct {
    allocator: std.mem.Allocator,
    addresses: []u64,
    rows: []Row,
    decoded: []Decoded,
    contiguous: bool,
    identity: [32]u8,
    log_size: u32,

    /// Copies exact PCs and derives decode rows before publication. Unsupported
    /// words remain in ROM with valid=0 and cannot authenticate an execution.
    pub fn init(a: std.mem.Allocator, program: Program) !Setup {
        return initWithProfile(a, program, .rv64im);
    }
    pub fn initWithProfile(a: std.mem.Allocator, program: Program, profile: execution.Profile) !Setup {
        try program.validate();
        const addresses = try a.alloc(u64, program.words.len);
        errdefer a.free(addresses);
        const rows = try a.alloc(Row, program.words.len);
        errdefer a.free(rows);
        const decoded = try a.alloc(Decoded, program.words.len);
        errdefer a.free(decoded);
        var contiguous = true;
        const Blake2s = if (@hasDecl(std.crypto.hash, "Blake2s256")) std.crypto.hash.Blake2s256 else std.crypto.hash.blake2.Blake2s256;
        var hash = Blake2s.init(.{});
        hash.update("stwo-zig/rv64/program-rom/v1\x00");
        var bytes: [8]u8 = undefined;
        std.mem.writeInt(u64, &bytes, @intCast(program.words.len), .little);
        hash.update(&bytes);
        for (program.words, addresses, rows, decoded, 0..) |word, *address, *decoded_row, *entry, i| {
            address.* = program.pc(i);
            contiguous = contiguous and address.* - program.base == 4 * i;
            decoded_row.* = headerRow(address.*, word);
            entry.* = .{ .raw = word };
            const instruction = execution.decode(profile, word) catch null;
            if (instruction) |inst| if (execution.admitted(profile, inst.opcode)) {
                decoded_row.* = deriveAdmitted(address.*, word, inst, execution.effects(profile, inst.opcode));
                entry.instruction = inst;
                for (&entry.enabled, 0..) |*enabled, slot| enabled.* = !decoded_row[field.slots + slot].isZero();
            };
            std.mem.writeInt(u64, &bytes, address.*, .little);
            hash.update(&bytes);
            var instruction_bytes: [4]u8 = undefined;
            std.mem.writeInt(u32, &instruction_bytes, word, .little);
            hash.update(&instruction_bytes);
        }
        var identity: [32]u8 = undefined;
        hash.final(&identity);
        const service_domain: ?[]const u8 = switch (profile) {
            .rv64im => null,
            .keccak_service_v1 => SERVICE_DOMAIN,
            .ethereum_services_v1 => "stwo-zig/rv64/ethereum-services-rom/v1\x00",
            .ethereum_services_v2 => "stwo-zig/rv64/ethereum-services-rom/v2\x00",
        };
        if (service_domain) |domain| {
            var service_hash = Blake2s.init(.{});
            service_hash.update(domain);
            service_hash.update(&identity);
            service_hash.final(&identity);
        }
        return .{ .allocator = a, .addresses = addresses, .rows = rows, .decoded = decoded, .contiguous = contiguous, .identity = identity, .log_size = @max(5, std.math.log2_int_ceil(usize, program.words.len)) };
    }
    pub fn deinit(self: *Setup) void {
        self.allocator.free(self.addresses);
        self.allocator.free(self.rows);
        self.allocator.free(self.decoded);
        self.* = undefined;
    }
    pub fn domainSize(self: *const Setup) usize {
        return @as(usize, 1) << @intCast(self.log_size);
    }
    pub fn lookup(self: *const Setup, pc: u64) !usize {
        if (self.contiguous) {
            if (pc < self.addresses[0] or pc & 3 != 0) return error.InvalidRv64RomExecution;
            const index = (pc - self.addresses[0]) / 4;
            if (index >= self.rows.len or self.rows[@intCast(index)][field.valid].isZero()) return error.InvalidRv64RomExecution;
            return @intCast(index);
        }
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
    pub fn controlFixedColumns(self: *const Setup, a: std.mem.Allocator, control: @import("../control_policy.zig").Policy) ![]M {
        return self.fixedColumnsWithControl(a, control);
    }
    pub fn fixedColumnsWithControl(self: *const Setup, a: std.mem.Allocator, control: @import("../control_policy.zig").Policy) ![]M {
        return if (control == .bytes_v1) self.compactFixedColumns(a) else self.packedFixedColumns(a);
    }
    /// Packed26 keeps each24/24/16 limb as a separate canonical ROM lane.
    pub fn packedFixedColumns(self: *const Setup, a: std.mem.Allocator) ![]M {
        const packed_control = @import("packed_control.zig");
        const size = self.domainSize();
        const result = try a.alloc(M, (packed_control.COUNT + 2) * size);
        @memset(result, M.zero());
        for (0..size) |logical| {
            const index = core.utils.bitReverseIndex(core.utils.cosetIndexToCircleDomainIndex(logical, self.log_size), self.log_size);
            const entry = self.row(logical);
            const projected = packed_control.fromRowBase(&entry);
            for (projected, 0..) |value, c| result[c * size + index] = value;
            result[packed_control.COUNT * size + index] = scalar(@intFromBool(logical == 0));
            result[(packed_control.COUNT + 1) * size + index] = scalar(@intFromBool(logical + 1 == size));
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
    const instruction = execution.decode(.rv64im, raw) catch return headerRow(pc, raw);
    if (!execution.admitted(.rv64im, instruction.opcode)) return headerRow(pc, raw);
    return deriveAdmitted(pc, raw, instruction, execution.effects(.rv64im, instruction.opcode));
}
fn headerRow(pc: u64, raw: u32) Row {
    var row: Row = @splat(M.zero());
    putBytes(&row, field.pc, pc, 8);
    putBytes(&row, field.raw, raw, 4);
    return row;
}
fn deriveAdmitted(pc: u64, raw: u32, instruction: isa.Instruction, effects: isa.Effects) Row {
    var row = headerRow(pc, raw);
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
