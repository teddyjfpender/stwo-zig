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
pub const MAX_LOG = 22;
pub const Program = struct {
    allocator: std.mem.Allocator,
    words: []const u32,
    addresses: []const u64,
    entries: []Entry,
    word_rows: []u32,
    row_to_entry: []u32,
    row_taken: []bool,
    fixed: []M,
    log_size: u32,
    identity: [32]u8,
    opcodes: [65]bool,
    profile: Execution.Profile,
    contiguous: bool,
    owns_raw: bool,
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
        const n: usize = @as(usize, 1) << @intCast(log_size);
        const fixed = try a.alloc(M, X.layout.rom.FIXED * n);
        errdefer a.free(fixed);
        @memset(fixed, M.zero());
        for (entries, word_rows, 0..) |entry, first, i| {
            const rows: usize = if (entry.hasTakenEdge()) 2 else 1;
            for (0..rows) |edge| {
                const logical = first + edge;
                row_to_entry[logical] = @intCast(i);
                row_taken[logical] = edge != 0;
                const tuple = entry.romTuple(edge != 0);
                const position = X.layout.physical(logical, log_size);
                for (tuple, 0..) |value, column| fixed[column * n + position] = value;
            }
        }
        fixed[X.layout.rom.FIRST * n + X.layout.physical(0, log_size)] = M.one();
        fixed[X.layout.rom.LAST * n + X.layout.physical(n - 1, log_size)] = M.one();
        return .{ .allocator = a, .words = words, .addresses = addresses, .entries = entries, .word_rows = word_rows, .row_to_entry = row_to_entry, .row_taken = row_taken, .fixed = fixed, .log_size = log_size, .identity = hash.finalResult(), .opcodes = opcodes, .profile = profile, .contiguous = front.rv64_air.word16_cpu.rom.contiguousAddresses(addresses), .owns_raw = owns_raw };
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
    pub fn deinit(self: *Program) void {
        self.allocator.free(self.fixed);
        self.allocator.free(self.row_taken);
        self.allocator.free(self.row_to_entry);
        self.allocator.free(self.word_rows);
        self.allocator.free(self.entries);
        if (self.owns_raw) {
            self.allocator.free(self.addresses);
            self.allocator.free(self.words);
        }
        self.* = undefined;
    }
};
