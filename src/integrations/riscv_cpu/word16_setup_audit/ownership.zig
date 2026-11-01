//! Measurement only: owned allocation payloads, not allocator rounding or RSS.
//! Polynomial/column views and retained tree leases do not acquire a second
//! payload charge. No verification or setup identity uses these counters.
const std = @import("std");
const core = @import("stwo_core");
const M = core.fields.m31.M31;
pub const Categories = struct {
    original_fixed: u64 = 0,
    program_metadata: u64 = 0,
    coefficients: u64 = 0,
    retained_evaluations: u64 = 0,
    merkle: u64 = 0,
    auxiliary: u64 = 0,
    headers: u64 = 0,
    pub fn total(self: @This()) u64 {
        return self.original_fixed + self.program_metadata + self.coefficients + self.retained_evaluations + self.merkle + self.auxiliary + self.headers;
    }
};
pub const Record = struct {
    kind: []const u8,
    index: usize,
    payload: Categories = .{},
    logical_fixed_bytes: u64 = 0,
    coefficient_view_bytes: u64 = 0,
    retained_evaluation_bytes: u64 = 0,
    uncovered_coefficient_bytes: u64 = 0,
    source_columns: usize = 0,
    merkle_nonempty_layers: usize = 0,
    merkle_log: u32 = 0,
    program_words: usize = 0,
    program_rows: usize = 0,
};
const Range = struct { start: usize, end: usize };
pub const Accountant = struct {
    allocator: std.mem.Allocator,
    ranges: std.ArrayList(Range) = .{},
    totals: Categories = .{},
    pub fn deinit(self: *@This()) void {
        self.ranges.deinit(self.allocator);
    }
    pub fn add(self: *@This(), record: *Record, comptime name: []const u8, values: anytype) !void {
        if (values.len == 0) return;
        const bytes = try std.math.mul(usize, values.len, @sizeOf(@TypeOf(values[0])));
        return self.addAddress(record, name, @intFromPtr(values.ptr), bytes);
    }
    /// Numeric allocation snapshots avoid dereferencing shared cache state.
    pub fn addAddress(self: *@This(), record: *Record, comptime name: []const u8, start: usize, bytes: usize) !void {
        if (bytes == 0) return;
        const end = try std.math.add(usize, start, bytes);
        for (self.ranges.items) |prior| {
            if (start == prior.start and end == prior.end) return;
            if (start < prior.end and prior.start < end) return error.OverlappingOwnedAuditRanges;
        }
        try self.ranges.append(self.allocator, .{ .start = start, .end = end });
        @field(record.payload, name) += bytes;
        @field(self.totals, name) += bytes;
    }
    pub fn object(self: *@This(), record: *Record, pointer: anytype) !void {
        try self.add(record, "headers", @as([*]const @TypeOf(pointer.*), @ptrCast(pointer))[0..1]);
    }
    fn covered(self: *const @This(), values: []const M) bool {
        if (values.len == 0) return true;
        const start = @intFromPtr(values.ptr);
        const end = start + values.len * @sizeOf(M);
        for (self.ranges.items) |r| if (start >= r.start and end <= r.end) return true;
        return false;
    }
    pub fn tree(self: *@This(), record: *Record, value: anytype) !void {
        // One unique setup key is visited once. shared_owner.tree is a move
        // snapshot with identical slices, not another set of allocations.
        record.source_columns = value.columns.len;
        try self.add(record, "headers", value.columns);
        if (value.shared_owner) |owner| try self.object(record, owner);
        if (value.coefficient_backing_buffers) |buffers| {
            try self.add(record, "headers", buffers);
            for (buffers) |buffer| try self.add(record, "coefficients", buffer);
        }
        if (value.column_backing_buffers) |buffers| {
            try self.add(record, "headers", buffers);
            for (buffers) |buffer| try self.add(record, "retained_evaluations", buffer);
        }
        if (value.streaming_column_backings) |buffers| {
            try self.add(record, "headers", buffers);
            for (buffers) |buffer| try self.add(record, "retained_evaluations", buffer.values);
        }
        if (value.coefficients) |polys| {
            try self.add(record, "headers", polys);
            for (polys) |poly| if (poly.owns_coeffs) try self.add(record, "coefficients", poly.coefficients());
            for (polys) |poly| {
                record.coefficient_view_bytes += poly.coefficients().len * @sizeOf(M);
                if (!self.covered(poly.coefficients())) record.uncovered_coefficient_bytes += poly.coefficients().len * @sizeOf(M);
            }
        }
        for (value.columns) |column| record.retained_evaluation_bytes += column.values.len * @sizeOf(M);
        try self.add(record, "headers", value.commitment.layers);
        record.merkle_log = @intCast(value.commitment.layers.len - 1);
        for (value.commitment.layers) |layer| {
            if (layer.len != 0) record.merkle_nonempty_layers += 1;
            try self.add(record, "merkle", layer);
        }
    }
    pub fn cpu(self: *@This(), index: usize, setup: anytype) !Record {
        var r = Record{ .kind = "cpu", .index = index };
        try self.object(&r, setup);
        const m = &setup.materials;
        inline for (.{ "cpu_fixed", "boundary_fixed", "alu_fixed", "alu_tail_fixed", "binary_fixed", "binary_tail_fixed", "shift_fixed", "shift_tail_fixed", "jalr_fixed", "division_fixed", "multiplication_fixed", "range16_fixed", "range8_fixed", "ls_fixed", "ls_tail_fixed", "memory_boundary_fixed", "selection_fixed" }) |name| try self.add(&r, "original_fixed", @field(m, name));
        if (m.memory_terminal_fixed) |v| try self.add(&r, "original_fixed", v);
        try self.add(&r, "original_fixed", m.and_table.fixed);
        try self.add(&r, "original_fixed", m.shift_table.fixed);
        try self.add(&r, "original_fixed", m.program.fixed);
        try self.add(&r, "program_metadata", m.program.entries);
        try self.add(&r, "program_metadata", m.program.word_rows);
        try self.add(&r, "program_metadata", m.program.row_to_entry);
        try self.add(&r, "program_metadata", m.program.row_taken);
        if (m.program.owns_raw) {
            try self.add(&r, "program_metadata", m.program.words);
            try self.add(&r, "program_metadata", m.program.addresses);
        }
        r.program_words = m.program.words.len;
        r.program_rows = m.program.row_to_entry.len;
        for (setup.fixed) |v| try self.add(&r, "original_fixed", v);
        for (setup.key.tree.columns) |c| r.logical_fixed_bytes += (@as(u64, 1) << @intCast(c.log_size - 1)) * @sizeOf(M);
        try self.tree(&r, setup.key.tree);
        return r;
    }
    pub fn keccak(self: *@This(), index: usize, setup: anytype) !Record {
        var r = Record{ .kind = "keccak", .index = index };
        try self.object(&r, setup);
        try self.add(&r, "original_fixed", setup.fixed);
        try self.add(&r, "original_fixed", setup.chi.fixed);
        try self.add(&r, "original_fixed", setup.xor5.fixed);
        try self.add(&r, "auxiliary", setup.chi.main);
        try self.add(&r, "auxiliary", setup.xor5.main);
        try self.tree(&r, setup.key.tree);
        return r;
    }
    pub fn secp(self: *@This(), index: usize, setup: anytype) !Record {
        var r = Record{ .kind = "secp", .index = index };
        try self.object(&r, setup);
        try self.add(&r, "original_fixed", setup.product_fixed);
        try self.add(&r, "original_fixed", setup.linear_fixed);
        try self.add(&r, "original_fixed", setup.bytes.fixed);
        try self.add(&r, "auxiliary", setup.bytes.main);
        try self.tree(&r, setup.key.tree);
        return r;
    }
};
