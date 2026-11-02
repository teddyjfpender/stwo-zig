//! Immutable raw-program owner/cache and the concrete full Word16 ROM.
//! Execution metadata never comes from a producer key or observed PC subset.
const std = @import("std");
const front = @import("stwo_riscv_frontend");
const core = @import("stwo_core");
const X = front.rv64_air.word16_execution;
const Raw = front.rv64_air.program.setup;
const Full = @import("../rv64_full.zig");
const Execution = front.rv64.execution_profile;
const M = core.fields.m31.M31;
pub const Entry = X.features.Entry;
pub const Metadata = @import("program_metadata.zig");
pub const MAX_LOG = 22;
pub const Program = struct {
    allocator: std.mem.Allocator,
    words: []const u32,
    addresses: []const u64,
    entries: []const Entry,
    word_rows: []const u32,
    row_to_entry: []const u32,
    row_taken: []const bool,
    metadata_lease: ?Metadata.Lease = null,
    fixed: []M,
    fixed_retired: bool = false,
    log_size: u32,
    identity: [32]u8,
    opcodes: [65]bool,
    profile: Execution.Profile,
    contiguous: bool,
    owns_raw: bool,
    /// Compact decode ROM (Geometry.cpu_compact_decode): the fixed matrix and
    /// every reconstructed tuple use Entry.romTupleCompact. The row layout
    /// (one or two rows per word) and the program identity are unchanged;
    /// the layout is bound by the geometry flag, its transcript identity and
    /// the fixed root.
    compact: bool = false,
    pub fn init(a: std.mem.Allocator, expected: Raw.Program) !Program {
        return initWithProfile(a, expected, X.features.PROFILE);
    }
    pub fn initWithProfile(a: std.mem.Allocator, expected: Raw.Program, profile: Execution.Profile) !Program {
        try expected.validate();
        const words = try a.dupe(u32, expected.words);
        errdefer a.free(words);
        const addresses = try a.alloc(u64, words.len);
        errdefer a.free(addresses);
        for (addresses, 0..) |*address, i| address.* = expected.pc(i);
        return build(a, words, addresses, true, profile, null);
    }
    /// The independently derived authority must outlive this borrowed view.
    /// Only the new feature cache/ROM is owned here; raw arrays are not copied.
    pub fn initWithAuthority(a: std.mem.Allocator, expected: *const Full.ProgramAuthority) !Program {
        return build(a, expected.words, expected.program.addresses, false, expected.profile, expected);
    }
    /// Reuse only owned decoded metadata. Raw views ALWAYS come from this
    /// independently derived authority and retain the existing image lifetime.
    pub fn initWithAuthorityAndMetadataCache(a: std.mem.Allocator, expected: *const Full.ProgramAuthority, metadata_cache: *const Metadata.Cache) !Program {
        if (expected.words.len == 0 or expected.words.len != expected.program.addresses.len) return error.InvalidExecutionProgram;
        const input = Metadata.Input{ .words = expected.words, .addresses = expected.program.addresses, .profile = expected.profile };
        if (try metadata_cache.lookup(input)) |found| {
            var lease = found;
            errdefer lease.deinit();
            const data = lease.view();
            const fixed = try fixedFromEntries(a, data.entries, data.word_rows, data.log_size, null, false);
            return .{ .allocator = a, .words = expected.words, .addresses = expected.program.addresses, .entries = data.entries, .word_rows = data.word_rows, .row_to_entry = data.row_to_entry, .row_taken = data.row_taken, .metadata_lease = lease, .fixed = fixed, .log_size = data.log_size, .identity = lease.identity(), .opcodes = data.opcodes, .profile = expected.profile, .contiguous = data.contiguous, .owns_raw = false };
        }
        var program = try initWithAuthority(a, expected);
        errdefer program.deinit();
        var owned_input = input;
        owned_input.identity = program.identity;
        if (try metadata_cache.adopt(owned_input, program.metadataView(), a)) |lease| {
            const data = lease.view();
            program.entries = data.entries;
            program.word_rows = data.word_rows;
            program.row_to_entry = data.row_to_entry;
            program.row_taken = data.row_taken;
            program.metadata_lease = lease;
        }
        return program;
    }
    pub fn metadataView(self: *const Program) Metadata.Data {
        return .{ .entries = self.entries, .word_rows = self.word_rows, .row_to_entry = self.row_to_entry, .row_taken = self.row_taken, .log_size = self.log_size, .opcodes = self.opcodes, .contiguous = self.contiguous };
    }
    fn build(a: std.mem.Allocator, words: []const u32, addresses: []const u64, owns_raw: bool, profile: Execution.Profile, cache: ?*const Full.ProgramAuthority) !Program {
        if (words.len == 0 or words.len != addresses.len) return error.InvalidExecutionProgram;
        const entries = try a.alloc(Entry, words.len);
        errdefer a.free(entries);
        const word_rows = try a.alloc(u32, words.len);
        errdefer a.free(word_rows);
        var count: usize = 0;
        var opcodes: [65]bool = @splat(false);
        var hash = std.crypto.hash.sha2.Sha256.init(.{});
        hash.update("stwo-rv64/full-word16/program-rom/v1\x00");
        const feature_identity = X.features.identity();
        hash.update(&feature_identity);
        var framed: [12]u8 = undefined;
        std.mem.writeInt(u32, framed[0..4], @intFromEnum(profile), .little);
        std.mem.writeInt(u64, framed[4..12], words.len, .little);
        hash.update(&framed);
        for (words, addresses, entries, word_rows, 0..) |raw, pc, *entry, *first, i| {
            entry.* = .{ .raw = raw, .pc = pc, .instruction = .{ .opcode = .FENCE, .rd = 0, .rs1 = 0, .rs2 = 0 } };
            if (cache) |authority| {
                // Undefined/default invalid decode cache contents are NEVER read.
                if (authority.program.rows[i][Raw.field.valid].v == 1) {
                    std.debug.assert(authority.program.decoded[i].raw == raw);
                    entry.* = Entry.fromInstruction(raw, pc, authority.program.decoded[i].instruction);
                }
            } else if (Execution.decode(profile, raw)) |instruction| {
                if (Execution.admitted(profile, instruction.opcode)) entry.* = Entry.fromInstruction(raw, pc, instruction);
            } else |_| {}
            first.* = @intCast(count);
            count = std.math.add(usize, count, if (entry.hasTakenEdge()) 2 else 1) catch return error.ExecutionRomGeometryLimit;
            if (count > @as(usize, 1) << MAX_LOG) return error.ExecutionRomGeometryLimit;
            if (entry.valid) opcodes[@intFromEnum(entry.instruction.opcode)] = true;
            std.mem.writeInt(u64, framed[0..8], pc, .little);
            std.mem.writeInt(u32, framed[8..12], raw, .little);
            hash.update(&framed);
        }
        const row_to_entry = try a.alloc(u32, count);
        errdefer a.free(row_to_entry);
        const row_taken = try a.alloc(bool, count);
        errdefer a.free(row_taken);
        const log_size: u32 = @intCast(@max(X.layout.MIN_LOG, std.math.log2_int_ceil(usize, count)));
        const fixed = try fixedFromEntries(a, entries, word_rows, log_size, .{ .row_to_entry = row_to_entry, .row_taken = row_taken }, false);
        return .{ .allocator = a, .words = words, .addresses = addresses, .entries = entries, .word_rows = word_rows, .row_to_entry = row_to_entry, .row_taken = row_taken, .fixed = fixed, .log_size = log_size, .identity = hash.finalResult(), .opcodes = opcodes, .profile = profile, .contiguous = front.rv64_air.word16_cpu.rom.contiguousAddresses(addresses), .owns_raw = owns_raw };
    }
    const MutableMaps = struct { row_to_entry: []u32, row_taken: []bool };
    /// Switches this owner to the compact decode ROM. Rebuilds the fixed
    /// matrix unless it was already retired (tuples are then reconstructed
    /// from the immutable entries). One-way and idempotent.
    pub fn makeCompact(self: *Program) !void {
        if (self.compact) return;
        if (!self.fixed_retired) {
            const fixed = try fixedFromEntries(self.allocator, self.entries, self.word_rows, self.log_size, null, true);
            self.allocator.free(self.fixed);
            self.fixed = fixed;
        }
        self.compact = true;
    }
    fn fixedFromEntries(a: std.mem.Allocator, entries: []const Entry, word_rows: []const u32, log_size: u32, maps: ?MutableMaps, compact: bool) ![]M {
        const n: usize = @as(usize, 1) << @intCast(log_size);
        const fixed = try a.alloc(M, X.layout.rom.FIXED * n);
        @memset(fixed, M.zero());
        for (entries, word_rows, 0..) |entry, first, i| {
            const rows: usize = if (entry.hasTakenEdge()) 2 else 1;
            for (0..rows) |edge| {
                const logical = first + edge;
                if (maps) |out| {
                    out.row_to_entry[logical] = @intCast(i);
                    out.row_taken[logical] = edge != 0;
                }
                const tuple = if (compact) entry.romTupleCompact(edge != 0) else entry.romTuple(edge != 0);
                const position = X.layout.physical(logical, log_size);
                for (tuple, 0..) |value, column| fixed[column * n + position] = value;
            }
        }
        fixed[X.layout.rom.FIRST * n + X.layout.physical(0, log_size)] = M.one();
        fixed[X.layout.rom.LAST * n + X.layout.physical(n - 1, log_size)] = M.one();
        return fixed;
    }
    pub fn size(self: *const Program) usize {
        return @as(usize, 1) << @intCast(self.log_size);
    }
    pub fn expectedProgram(self: *const Program) Raw.Program {
        return .{ .base = self.addresses[0], .words = self.words, .addresses = if (self.contiguous) &.{} else self.addresses };
    }
    pub fn lookup(self: *const Program, pc: u64) !usize {
        const index = if (self.contiguous) dense: {
            if (pc & 3 != 0 or pc < self.addresses[0]) return error.UnknownExecutionPc;
            const word = (pc - self.addresses[0]) / 4;
            if (word >= self.words.len) return error.UnknownExecutionPc;
            break :dense @as(usize, @intCast(word));
        } else sparse: {
            var lo: usize = 0;
            var hi = self.addresses.len;
            while (lo < hi) {
                const mid = lo + (hi - lo) / 2;
                if (self.addresses[mid] < pc) lo = mid + 1 else hi = mid;
            }
            if (lo == self.addresses.len or self.addresses[lo] != pc) return error.UnknownExecutionPc;
            break :sparse lo;
        };
        if (!self.entries[index].valid) return error.InvalidExecutionProgramWord;
        return index;
    }
    pub fn factIndex(self: *const Program, entry_index: usize, taken: bool) !usize {
        if (entry_index >= self.entries.len or !self.entries[entry_index].valid) return error.InvalidExecutionProgramWord;
        if (taken and !self.entries[entry_index].hasTakenEdge()) return error.InvalidExecutionBranchEdge;
        return self.word_rows[entry_index] + @as(usize, @intFromBool(taken));
    }
    /// Reconstructs one ROM fact from the immutable decoded entry authority.
    /// Padding is the same zero tuple used when constructing the fixed matrix.
    pub fn tupleAt(self: *const Program, logical: usize) ![X.layout.rom.COUNT]M {
        if (logical >= self.size()) return error.InvalidExecutionRomShape;
        if (logical >= self.row_to_entry.len) return @splat(M.zero());
        const entry = self.row_to_entry[logical];
        if (entry >= self.entries.len or self.row_taken.len != self.row_to_entry.len) return error.InvalidExecutionRomShape;
        return if (self.compact) self.entries[entry].romTupleCompact(self.row_taken[logical]) else self.entries[entry].romTuple(self.row_taken[logical]);
    }
    pub fn validateFixedWitness(self: *const Program) !void {
        if (self.fixed_retired) return error.ExecutionFixedWitnessRetired;
        if (self.fixed.len != X.layout.rom.FIXED * self.size()) return error.InvalidExecutionRomShape;
    }
    /// Sealed PCS coefficients own their data independently of this matrix.
    pub fn releaseFixedWitness(self: *Program) !void {
        try self.validateFixedWitness();
        self.allocator.free(self.fixed);
        self.fixed = &.{};
        self.fixed_retired = true;
    }
    pub fn deinit(self: *Program) void {
        self.allocator.free(self.fixed);
        if (self.metadata_lease) |*lease| {
            if (self.owns_raw) {
                self.allocator.free(self.addresses);
                self.allocator.free(self.words);
            }
            lease.deinit();
        } else {
            self.allocator.free(self.row_taken);
            self.allocator.free(self.row_to_entry);
            self.allocator.free(self.word_rows);
            self.allocator.free(self.entries);
            if (self.owns_raw) {
                self.allocator.free(self.addresses);
                self.allocator.free(self.words);
            }
        }
        self.* = undefined;
    }
};
