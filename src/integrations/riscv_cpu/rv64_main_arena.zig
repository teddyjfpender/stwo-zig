//! One owned ragged main allocation. Physical native-height order differs from
//! canonical proof-column order; component offsets and domains never change.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const M = core.fields.m31.M31;
const ownership = @import("stwo_riscv_frontend").rv64_air.memory.ownership;
pub const Column = engine.pcs.ColumnEvaluation;
pub const Role = enum(u8) {
    cpu,
    rom,
    bytes,
    byte_and,
    byte_shift,
    division,
    multiplication,
    keccak,
    chi,
    xor5,
    keccak_bridge,
    secp_add_product,
    secp_add_linear,
    secp_add_bridge,
    secp_double_product,
    secp_double_linear,
    secp_double_bridge,
    ram_chunk,
    ram_common_cells,
    ram_edge_cells,
    ram_leaf,
    ram_node,
    ram_side,
    ram_common_permits,
    ram_edge_permits,
    ram_poseidon,
    ram_policy,
};
pub const ROLE_COUNT = @typeInfo(Role).@"enum".fields.len;
pub const MIN_LOG: u32 = 4;
pub const MAX_LOG: u32 = 30;
pub const ALIGNMENT_BYTES = 64;
const ALIGNMENT_WORDS = ALIGNMENT_BYTES / @sizeOf(M);
pub const Spec = struct { role: Role, log_size: u32, width: usize };
pub const Span = struct { log_size: u32, width: usize, offset: usize, cells: usize, column_offset: usize, initialized: bool = false };
pub const Matrix = struct { log_size: u32, width: usize, values: []M, column_offset: usize };
pub const Phase = enum { building, ready, taken, dead };
pub const Commit = struct {
    columns: []Column,
    backing: [][]M,
    /// Before passing to PCS, this is the sole owner. PCS consumes both fields on
    /// success AND failure; never call deinit after that ownership handoff.
    pub fn deinit(self: *Commit, a: std.mem.Allocator) void {
        a.free(self.columns);
        for (self.backing) |allocation| a.free(allocation);
        a.free(self.backing);
        self.* = undefined;
    }
};
pub const Arena = struct {
    allocator: std.mem.Allocator,
    raw: []M,
    payload_offset: usize,
    payload_cells: usize,
    column_count: usize,
    spans: [ROLE_COUNT]?Span,
    remaining: usize,
    phase: Phase = .building,
    pub fn init(a: std.mem.Allocator, specs: []const Spec) !Arena {
        if (specs.len == 0) return error.EmptyMainArena;
        var spans: [ROLE_COUNT]?Span = @splat(null);
        var columns: usize = 0;
        for (specs) |spec| {
            const index = @intFromEnum(spec.role);
            if (index >= ROLE_COUNT or spec.width == 0 or spec.log_size < MIN_LOG or spec.log_size > MAX_LOG) return error.InvalidMainSpec;
            if (spans[index] != null) return error.DuplicateMainRole;
            const cells = try std.math.mul(usize, spec.width, @as(usize, 1) << @intCast(spec.log_size));
            columns = try std.math.add(usize, columns, spec.width);
            spans[index] = .{ .log_size = spec.log_size, .width = spec.width, .cells = cells, .offset = 0, .column_offset = 0 };
        }
        var cursor: usize = 0;
        var log = MAX_LOG;
        while (true) : (log -= 1) {
            cursor = try alignWords(cursor);
            // Enum order is the canonical protocol order, hence native-height groups
            // remain contiguous in the PCS group's own original column ordering.
            for (&spans) |*entry| if (entry.*) |*entry_span| {
                if (entry_span.log_size == log) {
                    entry_span.offset = cursor;
                    cursor = try std.math.add(usize, cursor, entry_span.cells);
                }
            };
            if (log == MIN_LOG) break;
        }
        var column_offset: usize = 0;
        for (&spans) |*entry| if (entry.*) |*entry_span| {
            entry_span.column_offset = column_offset;
            column_offset = try std.math.add(usize, column_offset, entry_span.width);
        };
        const raw_cells = try std.math.add(usize, cursor, ALIGNMENT_WORDS - 1);
        _ = try std.math.mul(usize, raw_cells, @sizeOf(M));
        const raw = try a.alloc(M, raw_cells);
        errdefer a.free(raw);
        const address = @intFromPtr(raw.ptr);
        const aligned = (try std.math.add(usize, address, ALIGNMENT_BYTES - 1)) & ~@as(usize, ALIGNMENT_BYTES - 1);
        const start = (aligned - address) / @sizeOf(M);
        // Initialize only unused allocation margins. Each builder initializes its
        // role matrix once, including its padding, before markInitialized.
        @memset(raw[0..start], M.zero());
        @memset(raw[start + cursor ..], M.zero());
        return .{ .allocator = a, .raw = raw, .payload_offset = start, .payload_cells = cursor, .column_count = columns, .spans = spans, .remaining = specs.len };
    }
    pub fn deinit(self: *Arena) void {
        if (self.phase == .dead) return;
        if (self.raw.len != 0) self.allocator.free(self.raw);
        self.raw = &.{};
        self.phase = .dead;
    }
    pub fn span(self: *const Arena, role: Role) !Span {
        try self.requireLive();
        return self.spans[@intFromEnum(role)] orelse error.MissingMainRole;
    }
    /// Mutable borrowing is restricted to the role's initialization phase. The
    /// returned view must not be mutated after markInitialized, or accessed after
    /// takeForCommit.
    pub fn matrix(self: *Arena, role: Role) !Matrix {
        if (self.phase != .building) return error.InvalidMainPhase;
        const entry = try self.span(role);
        if (entry.initialized) return error.MainRoleAlreadyInitialized;
        return .{ .log_size = entry.log_size, .width = entry.width, .values = self.raw[self.payload_offset + entry.offset ..][0..entry.cells], .column_offset = entry.column_offset };
    }
    pub fn markInitialized(self: *Arena, role: Role) !void {
        if (self.phase != .building) return error.InvalidMainPhase;
        const index = @intFromEnum(role);
        var entry = self.spans[index] orelse return error.MissingMainRole;
        if (entry.initialized) return error.MainRoleAlreadyInitialized;
        entry.initialized = true;
        self.spans[index] = entry;
        self.remaining -= 1;
        if (self.remaining == 0) self.phase = .ready;
    }
    pub fn canonicalColumns(self: *const Arena, a: std.mem.Allocator) ![]Column {
        try self.requireReady();
        const columns = try a.alloc(Column, self.column_count);
        errdefer a.free(columns);
        var at: usize = 0;
        for (self.spans) |entry| if (entry) |value| {
            const n = @as(usize, 1) << @intCast(value.log_size);
            const start = self.payload_offset + value.offset;
            for (0..value.width) |c| {
                columns[at] = .{ .log_size = value.log_size, .values = self.raw[start + c * n ..][0..n] };
                at += 1;
            }
        };
        std.debug.assert(at == columns.len);
        return columns;
    }
    /// The descriptor and one ORIGINAL allocation travel together. Allocation
    /// failure leaves this arena live/ready and does not move any matrix.
    pub fn takeForCommit(self: *Arena, a: std.mem.Allocator) !Commit {
        try self.requireReady();
        if (!ownership.same(a, self.allocator)) return error.InvalidMainAllocator;
        const columns = try self.canonicalColumns(a);
        errdefer a.free(columns);
        const backing = try a.alloc([]M, 1);
        backing[0] = self.raw;
        self.raw = &.{};
        self.phase = .taken;
        return .{ .columns = columns, .backing = backing };
    }
    fn requireLive(self: *const Arena) !void {
        if (self.phase == .taken or self.phase == .dead) return error.InvalidMainPhase;
    }
    fn requireReady(self: *const Arena) !void {
        if (self.phase == .building) return error.MainRoleNotInitialized;
        if (self.phase != .ready) return error.InvalidMainPhase;
    }
};
fn alignWords(value: usize) !usize {
    return (try std.math.add(usize, value, ALIGNMENT_WORDS - 1)) & ~@as(usize, ALIGNMENT_WORDS - 1);
}
