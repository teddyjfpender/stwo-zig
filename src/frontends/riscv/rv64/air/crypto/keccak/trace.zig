//! One final column-major witness; pure paired semantics reuse the old authority.
const std = @import("std");
const Storage = @import("../main_storage.zig");
const core = @import("stwo_core");
const M = core.fields.m31.M31;
const L = @import("layout.zig");
const witness = @import("../../../../air/guest_precompile/keccakf_witness.zig");
const authority = @import("../../../../air/guest_precompile/keccakf_authority.zig");
const physical = @import("../../witness.zig").physical;
pub const State = authority.State;
pub const PackedRow = @import("packed_row.zig").PackedRow;
pub const Trace = struct {
    allocator: std.mem.Allocator,
    log_size: u32,
    calls: u32,
    first_call_id: u32,
    fixed: []M,
    main: []M,
    main_allocator: ?std.mem.Allocator = null,
    owns_main: bool = true,
    metadata: []PackedRow = &.{},
    interaction: []M = &.{},
    pub fn init(a: std.mem.Allocator, inputs: []const State, first_call_id: u32) !Trace {
        return initWithLog(a, inputs, first_call_id, try L.logSize(inputs.len));
    }
    pub fn initWithLog(a: std.mem.Allocator, inputs: []const State, first_call_id: u32, log: u32) !Trace {
        return initWithLogAndMainAllocator(a, a, inputs, first_call_id, log);
    }
    pub fn initWithLogAndMainAllocator(a: std.mem.Allocator, main_allocator: std.mem.Allocator, inputs: []const State, first_call_id: u32, log: u32) !Trace {
        return build(a, .{ .owned = main_allocator }, inputs, first_call_id, log);
    }
    pub fn initWithMainBuffer(a: std.mem.Allocator, inputs: []const State, first_call_id: u32, log: u32, main: []M) !Trace {
        return build(a, .{ .borrowed = main }, inputs, first_call_id, log);
    }
    fn build(a: std.mem.Allocator, storage: Storage.Buffer, inputs: []const State, first_call_id: u32, log: u32) !Trace {
        try L.validateGeometry(inputs.len, first_call_id, log);
        const n = @as(usize, 1) << @intCast(log);
        try storage.validate(L.MAIN * n);
        if (storage == .borrowed) try Storage.exclude(&.{.{ .values = storage.borrowed, .cells = L.MAIN * n }}, std.mem.sliceAsBytes(inputs));
        const fixed = try fixedColumnsForLog(a, log);
        errdefer a.free(fixed);
        const metadata = try a.alloc(PackedRow, try std.math.mul(usize, try std.math.divCeil(usize, inputs.len, 2), L.ROWS_PER_PAIR));
        errdefer a.free(metadata);
        const main = try storage.acquire(L.MAIN * n);
        errdefer storage.release(main);
        @memset(main, M.zero());
        var i: usize = 0;
        while (i < inputs.len) : (i += 2) {
            const slot = try witness.buildSlot(inputs[i], if (i + 1 < inputs.len) inputs[i + 1] else null);
            for (slot.rows, 0..) |row, group| {
                const logical = i / 2 * L.ROWS_PER_PAIR + group;
                metadata[logical] = PackedRow.fromNative(&row, @intCast(@as(u64, first_call_id) + i));
                const r = physical(logical, log);
                for (row.state, 0..) |v, c| main[c * n + r] = M.fromCanonical(v);
                for (row.parity, 0..) |v, c| main[(L.STATE + c) * n + r] = M.fromCanonical(v);
                main[L.ACTIVE_A * n + r] = M.one();
                main[L.ACTIVE_B * n + r] = M.fromCanonical(@intFromBool(i + 1 < inputs.len));
                main[L.BASE_ID * n + r] = M.fromCanonical(@intCast(@as(u64, first_call_id) + i));
            }
        }
        return .{ .allocator = a, .log_size = log, .calls = @intCast(inputs.len), .first_call_id = first_call_id, .fixed = fixed, .main = main, .main_allocator = storage.allocator(), .owns_main = storage == .owned, .metadata = metadata };
    }
    pub fn deinit(self: *Trace) void {
        self.allocator.free(self.fixed);
        if (self.owns_main and self.main.len != 0) (self.main_allocator orelse self.allocator).free(self.main);
        self.allocator.free(self.metadata);
        self.allocator.free(self.interaction);
        self.* = undefined;
    }
    pub fn size(self: *const Trace) usize {
        return @as(usize, 1) << @intCast(self.log_size);
    }
    pub fn validateMetadata(self: *const Trace) !void {
        try L.validateGeometry(self.calls, self.first_call_id, self.log_size);
        if (self.metadata.len != try std.math.mul(usize, try std.math.divCeil(usize, self.calls, 2), L.ROWS_PER_PAIR)) return error.InvalidKeccakMetadata;
    }
    pub fn metadataRow(self: *const Trace, logical: usize) ![L.MAIN]M {
        const index = logical % self.size();
        return if (index < self.metadata.len) self.metadata[index].expand() else @splat(M.zero());
    }
    pub fn takeMain(self: *Trace) ![]M {
        if (!self.owns_main) return error.BorrowedCryptoMain;
        try self.validateMetadata();
        if (self.main.len != L.MAIN * self.size()) return error.InvalidKeccakMainPhase;
        const result = self.main;
        self.main = &.{};
        return result;
    }
    pub fn releaseMain(self: *Trace) !void {
        try self.validateMetadata();
        if (self.main.len != L.MAIN * self.size()) return error.InvalidCryptoMainPhase;
        if (self.owns_main) (self.main_allocator orelse self.allocator).free(self.main);
        self.main = &.{};
    }
    pub fn mainRow(self: *const Trace, logical: usize) [L.MAIN]M {
        var row: [L.MAIN]M = undefined;
        const r = physical(logical % self.size(), self.log_size);
        for (&row, 0..) |*v, c| v.* = self.main[c * self.size() + r];
        return row;
    }
};
pub fn fixedColumns(a: std.mem.Allocator, calls: u32, first_call_id: u32) ![]M {
    const log = try L.logSize(calls);
    try L.validateGeometry(calls, first_call_id, log);
    return fixedColumnsForLog(a, log);
}
/// One domain-only row. Incomplete tail slots retain phase0 so the header
/// transitions to inactive, but cannot recombine output across the domain wrap.
pub fn fixedAt(log: u32, logical: usize) ![L.FIXED]M {
    if (log < 5 or log > 26) return error.InvalidKeccakComponentGeometry;
    const n = @as(usize, 1) << @intCast(log);
    if (logical >= n) return error.InvalidKeccakComponentGeometry;
    const complete = logical < n / L.ROWS_PER_PAIR * L.ROWS_PER_PAIR;
    const phase = logical % L.ROWS_PER_PAIR;
    var row: [L.FIXED]M = @splat(M.zero());
    if (phaseEnabled(phase, complete)) row[phase] = M.one();
    row[L.FIRST] = M.fromCanonical(@intFromBool(logical == 0));
    row[L.SLOT_INDEX] = M.fromCanonical(@intCast(logical / L.ROWS_PER_PAIR));
    row[L.COMPLETE_SLOT] = M.fromCanonical(@intFromBool(complete));
    return row;
}
fn phaseEnabled(phase: usize, complete: bool) bool {
    // Phase26 reads +1/+2. A final partial slot may have no such output rows;
    // wrapping them to the first active input would impose a false equation.
    return phase != 26 or complete;
}
/// Immutable for one geometry. Request counts and call IDs occur only in main.
pub fn fixedColumnsForLog(a: std.mem.Allocator, log: u32) ![]M {
    if (log < 5 or log > 26) return error.InvalidKeccakComponentGeometry;
    const n = @as(usize, 1) << @intCast(log);
    const data = try a.alloc(M, L.FIXED * n);
    @memset(data, M.zero());
    data[L.FIRST * n + physical(0, log)] = M.one();
    const complete_rows = n / L.ROWS_PER_PAIR * L.ROWS_PER_PAIR;
    for (0..n) |logical| {
        const r = physical(logical, log);
        data[(logical % L.ROWS_PER_PAIR) * n + r] = M.fromCanonical(@intFromBool(phaseEnabled(logical % L.ROWS_PER_PAIR, logical < complete_rows)));
        data[L.SLOT_INDEX * n + r] = M.fromCanonical(@intCast(logical / L.ROWS_PER_PAIR));
        data[L.COMPLETE_SLOT * n + r] = M.fromCanonical(@intFromBool(logical < complete_rows));
    }
    return data;
}
