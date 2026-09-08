//! ELF-derived fixed program columns. This preparation helper does not admit
//! a caller-authored table: the verifier must independently derive its source.
const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const infra = @import("../../infra_trace.zig");
const commitment = @import("commitment.zig");
const interaction = @import("interaction.zig");
pub const COLUMN_COUNT = interaction.FIXED_COLUMN_COUNT;
/// Serializable circuit metadata only; independent ELF admission supplies
/// the corresponding fixed columns. No descriptor can authenticate itself.
pub const DescriptorV1 = struct {
    version: u16 = 1,
    circuit_profile: @import("../../prover/ethereum_circuit_profile_v1.zig").CircuitProfileV1 = .fixed_program_narrow_v1,
    elf_sha256: [32]u8,
    decoded_table_sha256: [32]u8,
    row_count: u32,
    compatibility_root: u32,

    pub fn validate(self: @This()) !void {
        if (self.version != 1 or self.circuit_profile != .fixed_program_narrow_v1 or self.row_count == 0 or self.row_count >= @import("stwo_core").fields.m31.Modulus or self.compatibility_root >= @import("stwo_core").fields.m31.Modulus or std.mem.allEqual(u8, &self.elf_sha256, 0) or std.mem.allEqual(u8, &self.decoded_table_sha256, 0)) return error.InvalidFixedProgramDescriptor;
    }
    pub fn fromCanonicalWords(words: [36]u32) !@This() {
        var result: @This() = .{
            .version = std.math.cast(u16, words[0]) orelse return error.InvalidFixedProgramDescriptor,
            .circuit_profile = std.meta.intToEnum(@import("../../prover/ethereum_circuit_profile_v1.zig").CircuitProfileV1, words[1]) catch return error.InvalidFixedProgramDescriptor,
            .row_count = words[2],
            .compatibility_root = words[3],
            .elf_sha256 = undefined,
            .decoded_table_sha256 = undefined,
        };
        for (0..16) |index| {
            const elf_limb = std.math.cast(u16, words[4 + index]) orelse return error.InvalidFixedProgramDescriptor;
            const table_limb = std.math.cast(u16, words[20 + index]) orelse return error.InvalidFixedProgramDescriptor;
            std.mem.writeInt(u16, result.elf_sha256[2 * index ..][0..2], elf_limb, .little);
            std.mem.writeInt(u16, result.decoded_table_sha256[2 * index ..][0..2], table_limb, .little);
        }
        try result.validate();
        return result;
    }
    /// Shared native/recursive field transcript payload. SHA bytes are
    /// represented by exact little-endian u16 limbs, never reduced modulo M31.
    pub fn canonicalWords(self: @This()) ![36]u32 {
        try self.validate();
        var result: [36]u32 = undefined;
        result[0..4].* = .{ self.version, @intFromEnum(self.circuit_profile), self.row_count, self.compatibility_root };
        for (0..16) |index| {
            result[4 + index] = std.mem.readInt(u16, self.elf_sha256[2 * index ..][0..2], .little);
            result[20 + index] = std.mem.readInt(u16, self.decoded_table_sha256[2 * index ..][0..2], .little);
        }
        return result;
    }
};

pub const ColumnsV1 = struct {
    values: [COLUMN_COUNT][]M31,
    log_size: u32,
    pub fn init(allocator: std.mem.Allocator, rows: []const commitment.Row, log_size: u32) !ColumnsV1 {
        if (rows.len == 0 or log_size >= 31 or rows.len > (@as(usize, 1) << @intCast(log_size))) return error.InvalidFixedProgramTable;
        const size = @as(usize, 1) << @intCast(log_size);
        var result: ColumnsV1 = .{ .values = undefined, .log_size = log_size };
        var initialized: usize = 0;
        errdefer for (result.values[0..initialized]) |column| allocator.free(column);
        for (&result.values) |*column| {
            column.* = try allocator.alloc(M31, size);
            @memset(column.*, M31.zero());
            initialized += 1;
        }
        const placement = try infra.BitReversalTable.init(allocator, log_size);
        defer placement.deinit(allocator);
        for (rows, 0..) |row, index| {
            if (row.multiplicity != 0 or (index != 0 and rows[index - 1].addr >= row.addr)) return error.InvalidFixedProgramTable;
            const words = [COLUMN_COUNT]u32{ row.addr, row.values[0], row.values[1], row.values[2], row.values[3], row.root };
            for (words, result.values) |word, column| {
                if (word >= @import("stwo_core").fields.m31.Modulus) return error.InvalidFixedProgramTable;
                column[placement.map(index)] = M31.fromCanonical(word);
            }
        }
        return result;
    }
    pub fn deinit(self: *ColumnsV1, allocator: std.mem.Allocator) void {
        for (self.values) |column| allocator.free(column);
        self.* = undefined;
    }
};
