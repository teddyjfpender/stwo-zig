//! Hash a canonical frame whose digest roles come from authenticated producers.
//! Callers must supply producers with source_uses and remove their public sinks.
const std = @import("std");
const core = @import("stwo_core");
const framing = core.channel.blake3.framing;
const hash = @import("blake3_hash_witness.zig");
const graph = @import("blake3_hash_plan.zig");
const routing = @import("blake3_frame_route.zig");
const boundary = @import("blake3_boundary.zig");
pub const route = @import("blake3_byte_route.zig");
pub const Binding = routing.Binding;
pub const PayloadBinding = routing.PayloadBinding;
pub const Prepared = struct {
    arena: std.heap.ArenaAllocator,
    /// Borrowed fixed tails when main values live in caller columns; full hash rows are empty.
    hash_metadata: ?@import("blake3_hash_metadata.zig").Rows = null,
    rows: struct {
        g_rows: []@import("blake3_g_call.zig").Row,
        xor_rows: []@import("blake3_xor_call.zig").Row,
        boundary_rows: []boundary.Row,
    },
    route_rows: []route.Row,
    source_uses: [2][8]u32,
    payload_uses: []u32,
    digest: ?[32]u8,
    pub fn deinit(self: *Prepared) void {
        self.arena.deinit();
        self.* = undefined;
    }
};
/// Domain-specific digest-only frames share the canonical byte router.
/// Payload admission remains restricted to the core transcript Frame type.
pub fn prepareDigestFrame(a: std.mem.Allocator, circuit: u32, frame: anytype, bindings: []const Binding, claim: [32]u8) !Prepared {
    return build(a, circuit, frame, bindings, claim, true, null, null, null, null);
}
pub fn trustedDigestFrame(a: std.mem.Allocator, circuit: u32, frame: anytype, bindings: []const Binding, claim: [32]u8) !Prepared {
    return build(a, circuit, frame, bindings, claim, false, null, null, null, null);
}
pub fn prepare(a: std.mem.Allocator, circuit: u32, frame: framing.Frame, bindings: []const Binding, claim: [32]u8) !Prepared {
    return build(a, circuit, frame, bindings, claim, true, null, null, null, null);
}
pub fn trusted(a: std.mem.Allocator, circuit: u32, frame: framing.Frame, bindings: []const Binding, claim: [32]u8) !Prepared {
    return build(a, circuit, frame, bindings, claim, false, null, null, null, null);
}
pub fn preparePayload(a: std.mem.Allocator, circuit: u32, frame: framing.Frame, bindings: []const Binding, payload: PayloadBinding, claim: [32]u8) !Prepared {
    return build(a, circuit, frame, bindings, claim, true, payload, null, null, null);
}
pub fn trustedPayload(a: std.mem.Allocator, circuit: u32, frame: framing.Frame, bindings: []const Binding, payload: PayloadBinding, claim: [32]u8) !Prepared {
    return build(a, circuit, frame, bindings, claim, false, payload, null, null, null);
}
/// Borrowed exact hash-row ranges; Prepared.deinit does not free these.
pub const HashDestination = struct {
    g_rows: []@import("blake3_g_call.zig").Row = &.{},
    xor_rows: []@import("blake3_xor_call.zig").Row = &.{},
    /// Trusted preprocessing may target compact tails instead of full rows.
    fixed: ?Metadata = null,
    pub fn slice(self: @This(), gf: usize, gs: usize, xf: usize, xs: usize) !@This() {
        if (self.fixed) |m| {
            if (self.g_rows.len != 0 or self.xor_rows.len != 0) return error.InvalidBlake3WitnessDestination;
            return .{ .fixed = try m.slice(gf, gs, xf, xs) };
        }
        if (gf > self.g_rows.len or gs > self.g_rows.len - gf or xf > self.xor_rows.len or xs > self.xor_rows.len - xf) return error.InvalidBlake3WitnessDestination;
        return .{ .g_rows = self.g_rows[gf..][0..gs], .xor_rows = self.xor_rows[xf..][0..xs] };
    }
    pub fn validate(self: @This(), gs: usize, xs: usize) !void {
        if (self.fixed) |m| {
            if (self.g_rows.len != 0 or self.xor_rows.len != 0) return error.InvalidBlake3WitnessDestination;
            try m.validate(gs, xs);
        } else if (self.g_rows.len != gs or self.xor_rows.len != xs) return error.InvalidBlake3WitnessDestination;
    }
};
pub fn prepareInto(a: std.mem.Allocator, circuit: u32, frame: framing.Frame, bindings: []const Binding, payload: ?PayloadBinding, claim: [32]u8, destination: HashDestination) !Prepared {
    return build(a, circuit, frame, bindings, claim, true, payload, destination, null, null);
}
pub fn trustedInto(a: std.mem.Allocator, circuit: u32, frame: framing.Frame, bindings: []const Binding, payload: ?PayloadBinding, claim: [32]u8, destination: HashDestination) !Prepared {
    return build(a, circuit, frame, bindings, claim, false, payload, destination, null, null);
}
pub const Metadata = @import("blake3_hash_metadata.zig").Rows;
pub const MainColumns = struct {
    pub fn metadata(self: @This()) Metadata {
        return .{ .g_rows = self.g_rows.metadata, .xor_rows = self.xor_rows.metadata };
    }
    g_rows: hash.MainColumnBuffer(@import("blake3_g_call.zig")),
    xor_rows: hash.MainColumnBuffer(@import("blake3_xor_call.zig")),
    pub fn validate(self: @This(), g_count: usize, xor_count: usize) !void {
        try self.g_rows.validate(g_count);
        try self.xor_rows.validate(xor_count);
    }
    /// Validate the whole view before deriving a non-owning logical subrange.
    pub fn slice(self: @This(), g_first: usize, g_count: usize, xor_first: usize, xor_count: usize) !@This() {
        try self.validate(self.g_rows.metadata.len, self.xor_rows.metadata.len);
        if (g_first > self.g_rows.metadata.len or g_count > self.g_rows.metadata.len - g_first or
            xor_first > self.xor_rows.metadata.len or xor_count > self.xor_rows.metadata.len - xor_first) return error.InvalidBlake3WitnessDestination;
        var out = self;
        out.g_rows.first += g_first;
        out.g_rows.metadata = self.g_rows.metadata[g_first..][0..g_count];
        out.xor_rows.first += xor_first;
        out.xor_rows.metadata = self.xor_rows.metadata[xor_first..][0..xor_count];
        return out;
    }
};
/// Borrowed columns/metadata outlive this call and are never freed by Prepared.
/// Generated metadata still requires independent fixed-preprocessing admission.
pub fn prepareMainColumns(a: std.mem.Allocator, circuit: u32, frame: framing.Frame, bindings: []const Binding, payload: ?PayloadBinding, claim: [32]u8, columns: MainColumns) !Prepared {
    return build(a, circuit, frame, bindings, claim, true, payload, null, columns, null);
}
/// Emit into caller-owned rows/columns using canonical immutable topology.
pub fn destinationWithPlan(a: std.mem.Allocator, circuit: u32, value: framing.Frame, bindings: []const Binding, payload: ?PayloadBinding, claim: [32]u8, live: bool, destination: ?HashDestination, columns: ?MainColumns, shape: *const graph.Plan) !Prepared {
    if (columns != null) {
        if (!live) return error.InvalidBlake3Frame;
        if (destination != null) return error.InvalidBlake3WitnessDestination;
    }
    return build(a, circuit, value, bindings, claim, live, payload, destination, columns, shape);
}
/// Reuse a canonical graph across frames of the same encoded length.
pub fn digestFrameWithPlan(a: std.mem.Allocator, circuit: u32, frame: anytype, bindings: []const Binding, claim: [32]u8, live: bool, shape: *const graph.Plan) !Prepared {
    return build(a, circuit, frame, bindings, claim, live, null, null, null, shape);
}
const Digests = struct {
    bindings: []const Binding,
    values: [2][32]u8 = undefined,
    payload: ?PayloadBinding,
    payload_values: []u32,
    pub fn protocolWord(self: *Digests, role: framing.PayloadRole, index: usize, value: u32) void {
        if (self.payload) |item| if (role == item.role) {
            self.payload_values[index] = value;
        };
    }
    pub fn update(_: *Digests, _: []const u8) void {}
    pub fn protocolDigest(self: *Digests, role: framing.DigestRole, value: [32]u8) void {
        for (self.bindings, 0..) |binding, i| if (binding.role == role) {
            self.values[i] = value;
        };
    }
};
fn build(backing: std.mem.Allocator, circuit: u32, frame: anytype, bindings: []const Binding, claim: [32]u8, live: bool, payload: ?PayloadBinding, destination: ?HashDestination, columns: ?MainColumns, borrowed: ?*const graph.Plan) !Prepared {
    var arena = std.heap.ArenaAllocator.init(backing);
    errdefer arena.deinit();
    const a = arena.allocator();
    const len = try frame.encodedSize();
    var owned: ?graph.Plan = if (borrowed == null) try graph.build(backing, len) else null;
    defer if (owned) |*value| value.deinit();
    const shape = borrowed orelse &owned.?;
    if (shape.input_len != len) return error.InvalidBlake3Frame;
    var plan = try routing.buildWithPayloadPlan(a, circuit, frame, bindings, payload, shape);
    const fixed_metadata = if (destination) |out| out.fixed else null;
    if (live and fixed_metadata != null) return error.InvalidBlake3WitnessDestination;
    if (destination) |out| try out.validate(shape.g.len, shape.xor.len);
    var rows = hash.Rows{
        .allocator = a,
        .g_rows = if (columns != null) &.{} else if (destination) |out| out.g_rows else try a.alloc(@import("blake3_g_call.zig").Row, shape.g.len),
        .xor_rows = if (columns != null) &.{} else if (destination) |out| out.xor_rows else try a.alloc(@import("blake3_xor_call.zig").Row, shape.xor.len),
        .boundary_rows = try a.alloc(boundary.Row, shape.sources.len + 8),
    };
    const hash_destination = hash.Destination{ .g_rows = rows.g_rows, .xor_rows = rows.xor_rows, .boundary_rows = rows.boundary_rows };
    var digest: ?[32]u8 = null;
    if (live) {
        const bytes = try frame.encode(a);
        defer a.free(bytes);
        digest = if (columns) |out|
            try hash.prepareMainColumnsWithPlan(backing, circuit, bytes, claim, shape, .{ .g_rows = out.g_rows, .xor_rows = out.xor_rows, .boundary_rows = rows.boundary_rows })
        else
            try hash.prepareIntoWithPlan(backing, circuit, bytes, claim, shape, hash_destination);
    } else if (fixed_metadata) |out| {
        try hash.trustedShapeMetadataWithPlan(circuit, len, claim, shape, out, rows.boundary_rows);
    } else try hash.trustedShapeIntoWithPlan(circuit, len, claim, shape, hash_destination);

    var boundaries: std.ArrayList(boundary.Row) = .empty;
    for (shape.sources, rows.boundary_rows[0..shape.sources.len]) |source, row| if (source.value == .constant) try boundaries.append(a, row);
    try boundaries.appendSlice(a, rows.boundary_rows[shape.sources.len..]);
    const retained = try boundaries.toOwnedSlice(a);
    a.free(rows.boundary_rows);
    rows.boundary_rows = retained;
    const routed = try a.alloc(route.Row, plan.schedules.len);
    var callers: [2]routing.Caller = undefined;
    for (bindings, 0..) |binding, i| callers[i] = binding.caller;
    const payload_values = try a.alloc(u32, if (live and payload != null) payload.?.word_count else 0);
    var digests = Digests{ .bindings = bindings, .payload = payload, .payload_values = payload_values };
    if (live) frame.write(&digests);
    for (routed, plan.schedules) |*row, schedule| row.* = if (live)
        try routing.witnessRowWithPayload(schedule, callers[0..bindings.len], digests.values[0..bindings.len], payload, payload_values)
    else
        try route.fixedRow(schedule);
    const uses = plan.child_uses;
    const payload_uses = try a.dupe(u32, plan.payload_uses);
    plan.deinit();
    return .{ .arena = arena, .hash_metadata = if (columns) |out| out.metadata() else fixed_metadata, .rows = .{ .g_rows = rows.g_rows, .xor_rows = rows.xor_rows, .boundary_rows = rows.boundary_rows }, .route_rows = routed, .source_uses = uses, .payload_uses = payload_uses, .digest = digest };
}
