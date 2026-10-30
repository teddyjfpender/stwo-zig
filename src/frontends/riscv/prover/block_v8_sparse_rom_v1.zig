//! Sparse ROM preprocessing under a distinct source identity. Support/counts
//! are public proposals; tuple authority comes ONLY from independently pinned
//! complete ELF decoding. The complete decoded-ROM root is never recomputed
//! from the subset, and the legacy complete Plan is never relabeled.
const std = @import("std");
const core = @import("stwo_core");
const Image = @import("block_v8_endpoint_local_program_v1.zig");
const Air = @import("../recursion/air/blake3_public_program.zig");
const M = core.fields.m31.M31;
const Column = @import("stwo_prover_engine").pcs.ColumnEvaluation;
const Tree = @import("../air/memory_commitment/blake3_state_tree.zig");
pub const production_active = false;
pub const VERSION: u32 = 1;
pub const TAG: u32 = 0x42385352;
pub const Entry = struct { pc: u32, count: u64 };
pub const Trusted = struct {
    elf: []const u8,
    elf_sha256: [32]u8,
    profile: @import("../runner/elf_loader.zig").ExecutionProfile,
    program_root: Tree.Digest,
    expected_fetches: u64,
};
pub const Limits = struct { initial: @import("block_v7_initial_intervals_v1.zig").Limits = .{}, max_selected_pcs: usize = 1 << 20 };
pub const Owned = struct {
    allocator: std.mem.Allocator,
    trusted: Trusted,
    entries: []Entry,
    rows: []Air.Row,
    log_size: u32,
    digest: [32]u8,
    full_instruction_rows: usize,
    halt_address: u32,
    pub fn derive(a: std.mem.Allocator, trusted: Trusted, entries: []const Entry, limits: Limits) !Owned {
        var image = try Image.Owned.init(a, trusted.elf, trusted.elf_sha256, trusted.profile, limits.initial);
        defer image.deinit();
        return fromImage(a, trusted, entries, &image, limits);
    }
    /// Prover-local reuse only: a fresh receiver always derives from its own ELF.
    pub fn fromImage(a: std.mem.Allocator, trusted: Trusted, entries: []const Entry, image: *const Image.Owned, limits: Limits) !Owned {
        if (!std.meta.eql(image.elf_sha256, trusted.elf_sha256) or image.info.execution_profile != trusted.profile or !std.meta.eql(image.root, trusted.program_root)) return error.UntrustedSparseRomImage;
        if (entries.len == 0 or entries.len > limits.max_selected_pcs or entries.len > 1 << 24 or trusted.expected_fetches == 0 or trusted.expected_fetches >= core.fields.m31.Modulus) return error.InvalidSparseRomInventory;
        const rows = try a.alloc(Air.Row, entries.len);
        errdefer a.free(rows);
        var sum: u64 = 0;
        var previous: ?u32 = null;
        const lower = image.info.memory_layout.program_base;
        for (entries, rows) |entry, *row| {
            if (entry.pc & 3 != 0 or entry.pc < lower or entry.pc >= image.info.memory_layout.program_end or (previous != null and entry.pc <= previous.?) or entry.count == 0 or entry.count >= core.fields.m31.Modulus) return error.InvalidSparseRomInventory;
            sum = std.math.add(u64, sum, entry.count) catch return error.SparseRomFetchOverflow;
            const index: usize = entry.pc - lower;
            if (index + 4 > image.leaves.len) return error.UntrustedSparseRomImage;
            var decoded: [4]u32 = undefined;
            for (image.leaves[index..][0..4], &decoded, 0..) |leaf, *value, limb| {
                if (leaf.index != entry.pc + limb or leaf.value >= core.fields.m31.Modulus) return error.UntrustedSparseRomImage;
                value.* = leaf.value;
            }
            row.* = try Air.fixedRow(entry.pc, @intCast(entry.count), decoded);
            previous = entry.pc;
        }
        if (sum != trusted.expected_fetches) return error.SparseRomFetchCountMismatch;
        const copied = try a.dupe(Entry, entries);
        errdefer a.free(copied);
        const log_size = @max(@as(u32, 4), std.math.log2_int_ceil(usize, entries.len));
        var channel = core.proof_suites.Blake3.Channel{};
        channel.mixU32s(&.{ TAG, VERSION, @intFromEnum(trusted.profile), log_size, @intCast(entries.len) });
        channel.mixRoot(trusted.elf_sha256);
        channel.mixRoot(trusted.program_root.bytes);
        channel.mixRoot(Air.SEMANTIC_DIGEST);
        channel.mixU64(trusted.expected_fetches);
        for (entries, rows) |entry, row| {
            channel.mixU32s(&.{entry.pc});
            channel.mixU64(entry.count);
            for (row) |v| channel.mixU32s(&.{v.v});
        }
        return .{ .allocator = a, .trusted = trusted, .entries = copied, .rows = rows, .log_size = log_size, .digest = channel.digestBytes(), .full_instruction_rows = image.leaves.len / 4, .halt_address = image.info.halt_flag };
    }
    pub fn fixedColumns(self: *const Owned, a: std.mem.Allocator) ![Air.PREPROCESSED_COLUMN_COUNT]Column {
        var columns: [Air.PREPROCESSED_COLUMN_COUNT]Column = undefined;
        var ready: usize = 0;
        errdefer for (columns[0..ready]) |c| a.free(c.values);
        for (&columns) |*c| {
            const values = try a.alloc(M, @as(usize, 1) << @intCast(self.log_size));
            @memset(values, M.zero());
            c.* = .{ .log_size = self.log_size, .values = values };
            ready += 1;
        }
        for (self.rows, 0..) |row, i| {
            for (row, &columns) |v, *c| @constCast(c.values)[@import("../recursion/air/framework_interaction.zig").committedRow(i, self.log_size)] = v;
        }
        return columns;
    }
    pub fn deinit(self: *Owned) void {
        self.allocator.free(self.rows);
        self.allocator.free(self.entries);
        self.* = undefined;
    }
};
