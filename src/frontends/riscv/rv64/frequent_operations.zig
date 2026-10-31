//! Bounded diagnostic census, never arithmetic or lookup authority. Retains the
//! first N distinct ordered (opcode,a,b,c) tuples and counts later exact hits.
//! Saturation makes coverage a lower bound, not an estimate of unseen repeats.
const std = @import("std");
const isa = @import("decode.zig");
const Retirement = @import("retirement.zig").Retirement;
pub const MAX_ENTRIES = 1 << 20;
pub const Tuple = struct { opcode: isa.Opcode, lhs: u64, rhs: u64, result: u64 };
pub const Entry = struct { tuple: Tuple, occurrences: u64 };
pub const Summary = struct {
    eligible_operations: u64,
    retained_unique: usize,
    tracked_occurrences: u64,
    untracked_occurrences: u64,
    repeated_retained_operations: u64,
    top: []Entry,
};
pub const Census = struct {
    allocator: std.mem.Allocator,
    limit: usize,
    counts: std.AutoHashMapUnmanaged(Tuple, u64) = .empty,
    eligible: u64 = 0,
    tracked: u64 = 0,
    untracked: u64 = 0,

    pub fn init(a: std.mem.Allocator, limit: usize) !Census {
        if (limit == 0 or limit > MAX_ENTRIES) return error.InvalidFrequentOperationLimit;
        return .{ .allocator = a, .limit = limit };
    }
    pub fn deinit(self: *Census) void {
        self.counts.deinit(self.allocator);
        self.* = undefined;
    }
    pub fn observe(self: *Census, tuple: Tuple) !void {
        if (self.eligible == std.math.maxInt(u64)) return error.FrequentOperationCountOverflow;
        if (self.counts.getPtr(tuple)) |count| {
            count.* += 1;
            self.tracked += 1;
        } else if (self.counts.count() < self.limit) {
            // Failed insertion does not change accounting or existing entries.
            try self.counts.put(self.allocator, tuple, 1);
            self.tracked += 1;
        } else self.untracked += 1;
        self.eligible += 1;
    }
    pub fn retire(self: *Census, row: Retirement) !void {
        if (operation(row)) |tuple| try self.observe(tuple);
    }
    /// Caller owns top. Deterministic ordering also makes independently
    /// collected census reports directly comparable. No witness is retained.
    pub fn summary(self: *const Census, a: std.mem.Allocator, top_limit: usize) !Summary {
        if (top_limit > 4096) return error.InvalidFrequentOperationReportLimit;
        const all = try a.alloc(Entry, self.counts.count());
        defer a.free(all);
        var iterator = self.counts.iterator();
        var i: usize = 0;
        while (iterator.next()) |entry| : (i += 1) all[i] = .{ .tuple = entry.key_ptr.*, .occurrences = entry.value_ptr.* };
        std.mem.sort(Entry, all, {}, less);
        return .{ .eligible_operations = self.eligible, .retained_unique = self.counts.count(), .tracked_occurrences = self.tracked, .untracked_occurrences = self.untracked, .repeated_retained_operations = self.tracked - self.counts.count(), .top = try a.dupe(Entry, all[0..@min(top_limit, all.len)]) };
    }
};
fn less(_: void, a: Entry, b: Entry) bool {
    if (a.occurrences != b.occurrences) return a.occurrences > b.occurrences;
    const x = a.tuple;
    const y = b.tuple;
    if (x.opcode != y.opcode) return @intFromEnum(x.opcode) < @intFromEnum(y.opcode);
    if (x.lhs != y.lhs) return x.lhs < y.lhs;
    if (x.rhs != y.rhs) return x.rhs < y.rhs;
    return x.result < y.result;
}
/// Preserve full operands and opcode (including W/sign modes). Immediate
/// operations use the decoded sign-extended immediate, never the unused rs2.
/// Addresses, branches, AUIPC, services and traps are deliberately excluded.
pub fn operation(row: Retirement) ?Tuple {
    const immediate = switch (row.opcode) {
        .ADDI, .SLTI, .SLTIU, .XORI, .ORI, .ANDI, .SLLI, .SRLI, .SRAI, .ADDIW, .SLLIW, .SRLIW, .SRAIW, .LUI => true,
        .ADD, .SUB, .SLL, .SLT, .SLTU, .XOR, .SRL, .SRA, .OR, .AND, .ADDW, .SUBW, .SLLW, .SRLW, .SRAW, .MUL, .MULH, .MULHSU, .MULHU, .DIV, .DIVU, .REM, .REMU, .MULW, .DIVW, .DIVUW, .REMW, .REMUW => false,
        else => return null,
    };
    return .{ .opcode = row.opcode, .lhs = row.lhs.toInt(), .rhs = if (immediate) row.immediate.toInt() else row.rhs.toInt(), .result = row.result.toInt() };
}
