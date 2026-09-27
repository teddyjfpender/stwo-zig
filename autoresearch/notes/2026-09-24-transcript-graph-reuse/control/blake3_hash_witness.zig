//! Full-hash witness and fixed-column projection share one canonical DAG.
//! A witness is not an admission token: verifier preprocessing is rebuilt from
//! the public length/message/digest, without evaluating compression rounds.
const std = @import("std");
const core = @import("stwo_core");
const M31 = core.fields.m31.M31;
const graph = @import("blake3_hash_plan.zig");
const g = @import("blake3_g_call.zig");
const xor = @import("blake3_xor_call.zig");
const boundary = @import("blake3_boundary.zig");
pub const Rows = struct {
    allocator: std.mem.Allocator,
    g_rows: []g.Row,
    xor_rows: []xor.Row,
    boundary_rows: []boundary.Row,
    pub fn deinit(self: *Rows) void {
        self.allocator.free(self.g_rows);
        self.allocator.free(self.xor_rows);
        self.allocator.free(self.boundary_rows);
        self.* = undefined;
    }
    pub fn logs(self: *const Rows) [3]u32 {
        return .{ log(self.g_rows.len), log(self.xor_rows.len), log(self.boundary_rows.len) };
    }
    fn log(len: usize) u32 {
        return @max(1, std.math.log2_int_ceil(usize, len));
    }
};
pub const Prepared = struct { rows: Rows, digest: [32]u8 };
pub const Destination = struct {
    g_rows: []g.Row,
    xor_rows: []xor.Row,
    boundary_rows: []boundary.Row,
};

pub fn prepare(a: std.mem.Allocator, circuit: u32, input: []const u8, claimed_digest: [32]u8) !Prepared {
    var plan = try graph.build(a, input.len);
    defer plan.deinit();
    return prepareWithPlan(a, circuit, input, claimed_digest, &plan);
}
/// Borrow a canonical length-owned graph; witness values never mutate it.
pub fn prepareWithPlan(a: std.mem.Allocator, circuit: u32, input: []const u8, claimed_digest: [32]u8, plan: *const graph.Plan) !Prepared {
    if (plan.input_len != input.len) return error.InvalidBlake3Input;
    var rows = try allocateRows(a, plan);
    errdefer rows.deinit();
    const digest = try writePlan(a, circuit, input, claimed_digest, plan, .{ .g_rows = rows.g_rows, .xor_rows = rows.xor_rows, .boundary_rows = rows.boundary_rows });
    return .{ .rows = rows, .digest = digest };
}
/// Exact shape is checked before mutation. Later errors may leave partial rows;
/// the caller retains ownership and must not publish them on failure.
pub fn prepareInto(a: std.mem.Allocator, circuit: u32, input: []const u8, claimed_digest: [32]u8, destination: Destination) ![32]u8 {
    var plan = try graph.build(a, input.len);
    defer plan.deinit();
    return prepareIntoWithPlan(a, circuit, input, claimed_digest, &plan, destination);
}
pub fn prepareIntoWithPlan(a: std.mem.Allocator, circuit: u32, input: []const u8, claim: [32]u8, plan: *const graph.Plan, destination: Destination) ![32]u8 {
    return writePlan(a, circuit, input, claim, plan, destination);
}
const RowSink = struct {
    destination: Destination,
    fn write(self: *@This(), comptime kind: usize, index: usize, row: anytype) void {
        const rows = switch (kind) {
            0 => self.destination.g_rows,
            1 => self.destination.xor_rows,
            2 => self.destination.boundary_rows,
            else => unreachable,
        };
        rows[index] = row;
    }
};
pub fn ColumnBuffer(comptime Air: type) type {
    return struct {
        columns: [Air.LOGICAL_INPUT_COUNT][]M31,
        log_size: u32,
        first: usize = 0,
        fn validate(self: @This(), count: usize) !void {
            if (self.log_size == 0 or self.log_size > 24) return error.InvalidBlake3WitnessDestination;
            const size = @as(usize, 1) << @intCast(self.log_size);
            if (self.first > size or count > size - self.first) return error.InvalidBlake3WitnessDestination;
            for (self.columns) |column| if (column.len != size) return error.InvalidBlake3WitnessDestination;
        }
        fn write(self: @This(), index: usize, row: Air.Row) void {
            const target = @import("framework_interaction.zig").committedRow(self.first + index, self.log_size);
            for (self.columns, row) |column, value| column[target] = value;
        }
    };
}
pub const ColumnDestination = struct {
    g_rows: ColumnBuffer(g),
    xor_rows: ColumnBuffer(xor),
    boundary_rows: ColumnBuffer(boundary),
    fn write(self: *@This(), comptime kind: usize, index: usize, row: anytype) void {
        switch (kind) {
            0 => self.g_rows.write(index, row),
            1 => self.xor_rows.write(index, row),
            2 => self.boundary_rows.write(index, row),
            else => unreachable,
        }
    }
};
/// Writes only the selected logical ranges. Caller initializes padding and owns
/// nonoverlapping columns; later errors may leave partial output.
pub fn prepareColumns(a: std.mem.Allocator, circuit: u32, input: []const u8, claim: [32]u8, destination: ColumnDestination) ![32]u8 {
    var plan = try graph.build(a, input.len);
    defer plan.deinit();
    try destination.g_rows.validate(plan.g.len);
    try destination.xor_rows.validate(plan.xor.len);
    try destination.boundary_rows.validate(plan.sources.len + 8);
    var sink = destination;
    return emitPlan(a, circuit, input, claim, &plan, &sink);
}
/// Native physical main columns plus generated witness metadata. This metadata
/// must still be checked against independently constructed fixed preprocessing.
pub fn MainColumnBuffer(comptime Air: type) type {
    return struct {
        columns: [Air.PHYSICAL_MAIN_COLUMN_COUNT][]M31,
        metadata: []@import("blake3_hash_metadata.zig").Row(Air),
        log_size: u32,
        first: usize = 0,
        pub fn validate(self: @This(), count: usize) !void {
            if (self.log_size == 0 or self.log_size > 24 or self.metadata.len != count) return error.InvalidBlake3WitnessDestination;
            const size = @as(usize, 1) << @intCast(self.log_size);
            if (self.first > size or count > size - self.first) return error.InvalidBlake3WitnessDestination;
            for (self.columns) |column| if (column.len != size) return error.InvalidBlake3WitnessDestination;
        }
        fn writeBatch(self: @This(), first: usize, comptime count: usize, rows: *const [count]Air.Row) void {
            var targets: [count]usize = undefined;
            for (&targets, rows, 0..) |*target, row, offset| {
                target.* = @import("framework_interaction.zig").committedRow(self.first + first + offset, self.log_size);
                self.metadata[first + offset] = row[Air.PHYSICAL_MAIN_COLUMN_COUNT..].*;
            }
            // Keep one destination column hot across a compression call instead
            // of switching between every large column for each generated row.
            for (self.columns, 0..) |column, field| {
                for (targets, rows) |target, row| column[target] = row[field];
            }
        }
    };
}
pub const MainColumnDestination = struct {
    g_rows: MainColumnBuffer(g),
    xor_rows: MainColumnBuffer(xor),
    boundary_rows: []boundary.Row,
};
/// Bounded stack staging: exactly one compression call, never a full witness.
/// emitPlan emits complete groups of 56 G and 16 XOR rows per call.
const MainColumnSink = struct {
    destination: MainColumnDestination,
    g_batch: [56]g.Row = undefined,
    xor_batch: [16]xor.Row = undefined,
    fn write(self: *@This(), comptime kind: usize, index: usize, row: anytype) void {
        switch (kind) {
            0 => {
                self.g_batch[index % 56] = row;
                if (index % 56 == 55) self.destination.g_rows.writeBatch(index - 55, 56, &self.g_batch);
            },
            1 => {
                self.xor_batch[index % 16] = row;
                if (index % 16 == 15) self.destination.xor_rows.writeBatch(index - 15, 16, &self.xor_batch);
            },
            2 => self.destination.boundary_rows[index] = row,
            else => unreachable,
        }
    }
};
/// Caller owns nonoverlapping main columns, metadata and boundaries and initializes
/// padding. All shapes are checked before mutation; later errors may leave partial
/// unpublished output. No full G/XOR logical-row arrays are materialized.
pub fn prepareMainColumns(a: std.mem.Allocator, circuit: u32, input: []const u8, claim: [32]u8, destination: MainColumnDestination) ![32]u8 {
    var plan = try graph.build(a, input.len);
    defer plan.deinit();
    return prepareMainColumnsWithPlan(a, circuit, input, claim, &plan, destination);
}
pub fn prepareMainColumnsWithPlan(a: std.mem.Allocator, circuit: u32, input: []const u8, claim: [32]u8, plan: *const graph.Plan, destination: MainColumnDestination) ![32]u8 {
    if (plan.input_len != input.len) return error.InvalidBlake3Input;
    try destination.g_rows.validate(plan.g.len);
    try destination.xor_rows.validate(plan.xor.len);
    if (destination.boundary_rows.len != plan.sources.len + 8) return error.InvalidBlake3WitnessDestination;
    var sink = MainColumnSink{ .destination = destination };
    return emitPlan(a, circuit, input, claim, plan, &sink);
}
fn writePlan(a: std.mem.Allocator, circuit: u32, input: []const u8, claimed_digest: [32]u8, plan: *const graph.Plan, rows: Destination) ![32]u8 {
    if (rows.g_rows.len != plan.g.len or rows.xor_rows.len != plan.xor.len or rows.boundary_rows.len != plan.sources.len + 8) return error.InvalidBlake3WitnessDestination;
    var sink = RowSink{ .destination = rows };
    return emitPlan(a, circuit, input, claimed_digest, plan, &sink);
}
fn emitPlan(a: std.mem.Allocator, circuit: u32, input: []const u8, claimed_digest: [32]u8, plan: *const graph.Plan, sink: anytype) ![32]u8 {
    if (plan.input_len != input.len) return error.InvalidBlake3Input;
    const wires = try a.alloc(u32, plan.uses.len);
    defer a.free(wires);
    for (plan.sources) |source| wires[source.wire] = try source.read(input);
    var native = core.crypto.blake3_compression.Native{};
    for (0..plan.calls.len) |call| {
        const first_g = call * 56;
        for (plan.g[first_g..][0..56], first_g..) |scheduled, index| {
            var words: [6]u32 = undefined;
            for (&words, scheduled.input) |*word, wire| word.* = wires[wire];
            const output = try core.crypto.blake3_compression.g(core.crypto.blake3_compression.Native, &native, words);
            for (scheduled.output, output) |wire, word| wires[wire] = word;
            sink.write(0, index, try g.logicalRow(gSchedule(circuit, scheduled, plan.uses), words));
        }
        const first_xor = call * 16;
        for (plan.xor[first_xor..][0..16], first_xor..) |scheduled, index| {
            const words = [2]u32{ wires[scheduled.input[0]], wires[scheduled.input[1]] };
            wires[scheduled.output] = words[0] ^ words[1];
            sink.write(1, index, try xor.logicalRow(xorSchedule(circuit, scheduled, plan.uses), words));
        }
    }
    var digest: [32]u8 = undefined;
    for (plan.output, 0..) |wire, i| std.mem.writeInt(u32, digest[i * 4 ..][0..4], wires[wire], .little);
    try emitBoundaries(sink, circuit, input, claimed_digest, plan);
    return digest;
}

/// Main words are placeholders except the public boundary. Only fixed columns
/// from this result are authoritative. No intermediate CV or G output is read.
pub fn trustedRows(a: std.mem.Allocator, circuit: u32, input: []const u8, digest: [32]u8) !Rows {
    var plan = try graph.build(a, input.len);
    defer plan.deinit();
    return trustedRowsWithPlan(a, circuit, input, digest, &plan);
}
pub fn trustedRowsWithPlan(a: std.mem.Allocator, circuit: u32, input: []const u8, digest: [32]u8, plan: *const graph.Plan) !Rows {
    if (plan.input_len != input.len) return error.InvalidBlake3Input;
    return fixedRows(a, circuit, input, digest, plan);
}
/// Length-only fixed projection for caller-bound messages. Input boundary
/// placeholders must be removed and replaced by authenticated bridge rows.
pub fn trustedShapeRows(a: std.mem.Allocator, circuit: u32, input_len: usize, digest: [32]u8) !Rows {
    var plan = try graph.build(a, input_len);
    defer plan.deinit();
    return fixedRows(a, circuit, null, digest, &plan);
}
/// Fixed preprocessing binds public input bytes and claim, without compression.
pub fn trustedInto(a: std.mem.Allocator, circuit: u32, input: []const u8, digest: [32]u8, destination: Destination) !void {
    var plan = try graph.build(a, input.len);
    defer plan.deinit();
    try fixedRowsInto(circuit, input, digest, &plan, destination);
}
/// Length-only fixed preprocessing for externally authenticated input bytes.
pub fn trustedShapeInto(a: std.mem.Allocator, circuit: u32, input_len: usize, digest: [32]u8, destination: Destination) !void {
    var plan = try graph.build(a, input_len);
    defer plan.deinit();
    try trustedShapeIntoWithPlan(circuit, input_len, digest, &plan, destination);
}
pub fn trustedShapeIntoWithPlan(circuit: u32, input_len: usize, digest: [32]u8, plan: *const graph.Plan, destination: Destination) !void {
    if (plan.input_len != input_len) return error.InvalidBlake3Input;
    try fixedRowsInto(circuit, null, digest, plan, destination);
}
/// Independently derive fixed tails from canonical topology, without evaluating
/// compression or allocating full logical hash rows. Shapes precede any writes.
pub fn trustedShapeMetadataWithPlan(circuit: u32, input_len: usize, digest: [32]u8, plan: *const graph.Plan, metadata: @import("blake3_hash_metadata.zig").Rows, boundaries: []boundary.Row) !void {
    if (plan.input_len != input_len) return error.InvalidBlake3Input;
    try metadata.validate(plan.g.len, plan.xor.len);
    if (boundaries.len != plan.sources.len + 8) return error.InvalidBlake3WitnessDestination;
    for (metadata.g_rows, plan.g) |*row, call| row.* = (try g.fixedRow(gSchedule(circuit, call, plan.uses)))[g.PHYSICAL_MAIN_COLUMN_COUNT..].*;
    for (metadata.xor_rows, plan.xor) |*row, call| row.* = (try xor.fixedRow(xorSchedule(circuit, call, plan.uses)))[xor.PHYSICAL_MAIN_COLUMN_COUNT..].*;
    try writeBoundaries(boundaries, circuit, null, digest, plan);
}
fn allocateRows(a: std.mem.Allocator, plan: *const graph.Plan) !Rows {
    const gs = try a.alloc(g.Row, plan.g.len);
    errdefer a.free(gs);
    const xs = try a.alloc(xor.Row, plan.xor.len);
    errdefer a.free(xs);
    const bs = try a.alloc(boundary.Row, plan.sources.len + 8);
    errdefer a.free(bs);
    return .{ .allocator = a, .g_rows = gs, .xor_rows = xs, .boundary_rows = bs };
}
fn fixedRows(a: std.mem.Allocator, circuit: u32, input: ?[]const u8, digest: [32]u8, plan: *const graph.Plan) !Rows {
    var rows = try allocateRows(a, plan);
    errdefer rows.deinit();
    try fixedRowsInto(circuit, input, digest, plan, .{ .g_rows = rows.g_rows, .xor_rows = rows.xor_rows, .boundary_rows = rows.boundary_rows });
    return rows;
}
fn fixedRowsInto(circuit: u32, input: ?[]const u8, digest: [32]u8, plan: *const graph.Plan, rows: Destination) !void {
    if (rows.g_rows.len != plan.g.len or rows.xor_rows.len != plan.xor.len or rows.boundary_rows.len != plan.sources.len + 8) return error.InvalidBlake3WitnessDestination;
    for (rows.g_rows, plan.g) |*row, call| row.* = try g.fixedRow(gSchedule(circuit, call, plan.uses));
    for (rows.xor_rows, plan.xor) |*row, call| row.* = try xor.fixedRow(xorSchedule(circuit, call, plan.uses));
    try writeBoundaries(rows.boundary_rows, circuit, input, digest, plan);
}

fn writeBoundaries(bs: []boundary.Row, circuit: u32, input: ?[]const u8, digest: [32]u8, plan: *const graph.Plan) !void {
    var sink = RowSink{ .destination = .{ .g_rows = &.{}, .xor_rows = &.{}, .boundary_rows = bs } };
    try emitBoundaries(&sink, circuit, input, digest, plan);
}
fn emitBoundaries(sink: anytype, circuit: u32, input: ?[]const u8, digest: [32]u8, plan: *const graph.Plan) !void {
    for (plan.sources, 0..) |source, i| sink.write(2, i, try boundary.logicalRow(circuit, source.wire, M31.fromCanonical(plan.uses[source.wire]), if (input) |bytes| try source.read(bytes) else switch (source.value) {
        .constant => |word| word,
        .input => 0,
    }));
    for (plan.output, 0..) |wire, i| sink.write(2, plan.sources.len + i, try boundary.logicalRow(circuit, wire, M31.one().neg(), std.mem.readInt(u32, digest[i * 4 ..][0..4], .little)));
}

fn gSchedule(circuit: u32, call: @import("blake3_compression_plan.zig").GCall, uses: []const u32) g.Schedule {
    var result = g.Schedule{ .circuit = circuit, .input = call.input, .output = call.output, .uses = undefined };
    for (&result.uses, call.output) |*count, wire| count.* = uses[wire];
    return result;
}
fn xorSchedule(circuit: u32, call: @import("blake3_compression_plan.zig").XorCall, uses: []const u32) xor.Schedule {
    return .{ .circuit = circuit, .input = call.input, .output = call.output, .uses = uses[call.output] };
}
