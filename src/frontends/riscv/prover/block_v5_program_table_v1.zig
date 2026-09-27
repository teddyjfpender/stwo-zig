//! V5 global decoded-ROM provider admission. This is source authority, not a
//! replacement for the existing native program custody proof until the shared
//! program relation is closed against fresh native request receipts.
const std = @import("std");
const core = @import("stwo_core");
const tree = @import("../air/memory_commitment/blake3_state_tree.zig");
const cache = @import("../air/program/blake3_root_cache.zig");
const program = @import("../recursion/air/blake3_public_program.zig");
const M = core.fields.m31.M31;

pub const VERSION: u32 = 1;
pub const DOMAIN = "stwo.riscv.block-v5.global-decoded-rom.v1";
pub const Plan = struct {
    /// Independently pinned by the job's complete ELF image.
    program_root: tree.Digest,
    /// Complete decoded ROM, including inactive words, in leaf order.
    leaves: []const tree.Leaf,
    /// One exact integer count per four decoded words, before M31 reduction.
    multiplicities: []const u64,
    expected_fetches: u64,
    log_size: u32,

    pub fn validate(self: Plan) !void {
        if (self.leaves.len == 0 or self.leaves.len % 4 != 0 or self.multiplicities.len != self.leaves.len / 4)
            return error.InvalidProgramTableRoster;
        if (self.log_size < 7 or self.log_size > 24 or self.multiplicities.len > (@as(usize, 1) << @intCast(self.log_size)))
            return error.InvalidProgramTableGeometry;
        // The entire exact census fits one M31; no field-wrap alias or hot
        // multiplicity overflow is admitted. Larger blocks need exact shards.
        if (self.expected_fetches >= core.fields.m31.Modulus) return error.ProgramFetchCensusOverflow;
        var sum: u64 = 0;
        var previous: ?u32 = null;
        for (self.multiplicities, 0..) |count, i| {
            if (count >= core.fields.m31.Modulus) return error.ProgramFetchCensusOverflow;
            sum = std.math.add(u64, sum, count) catch return error.ProgramFetchCensusOverflow;
            const group = self.leaves[4 * i ..][0..4];
            const address = group[0].index;
            if (address >= (1 << 30) or address & 3 != 0 or (previous != null and address <= previous.?))
                return error.InvalidProgramTableRoster;
            for (group, 0..) |leaf, limb| {
                if (leaf.index != address + @as(u32, @intCast(limb)) or leaf.value >= core.fields.m31.Modulus)
                    return error.InvalidProgramTableRoster;
            }
            previous = address;
        }
        if (sum != self.expected_fetches) return error.ProgramFetchCensusMismatch;
        try cache.validate(self.leaves, self.program_root);
    }

    pub fn digest(self: Plan) ![32]u8 {
        try self.validate();
        var hash = core.vcs.blake3_hash.Blake3Hasher.init();
        hash.update(DOMAIN);
        hash.update(&self.program_root.bytes);
        var word: [8]u8 = undefined;
        std.mem.writeInt(u64, &word, self.leaves.len, .little);
        hash.update(&word);
        std.mem.writeInt(u64, &word, self.expected_fetches, .little);
        hash.update(&word);
        std.mem.writeInt(u64, &word, self.log_size, .little);
        hash.update(&word);
        for (self.leaves) |leaf| {
            std.mem.writeInt(u64, &word, leaf.index, .little);
            hash.update(&word);
            std.mem.writeInt(u64, &word, leaf.value, .little);
            hash.update(&word);
        }
        for (self.multiplicities) |count| {
            std.mem.writeInt(u64, &word, count, .little);
            hash.update(&word);
        }
        return hash.finalize();
    }

    pub fn row(self: Plan, i: usize) !program.Row {
        if (i >= self.multiplicities.len) return error.InvalidProgramTableRoster;
        var values: [4]u32 = undefined;
        for (&values, self.leaves[4 * i ..][0..4]) |*value, leaf| value.* = leaf.value;
        return program.fixedRow(self.leaves[4 * i].index, @intCast(self.multiplicities[i]), values);
    }

    pub fn fixedColumns(self: Plan, a: std.mem.Allocator) ![program.PREPROCESSED_COLUMN_COUNT][]M {
        try self.validate();
        var columns: [program.PREPROCESSED_COLUMN_COUNT][]M = undefined;
        var initialized: usize = 0;
        errdefer for (columns[0..initialized]) |column| a.free(column);
        for (&columns) |*column| {
            column.* = try a.alloc(M, @as(usize, 1) << @intCast(self.log_size));
            @memset(column.*, M.zero());
            initialized += 1;
        }
        const layout = @import("../recursion/air/framework_interaction.zig");
        for (0..self.multiplicities.len) |i| {
            const row_value = try self.row(i);
            for (&columns, row_value) |*column, value| column.*[layout.committedRow(i, self.log_size)] = value;
        }
        return columns;
    }
};
