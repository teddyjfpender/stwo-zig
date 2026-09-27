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
    /// When true, G/XOR rows contain only generated metadata; main values live in caller columns.
    hash_rows_are_metadata: bool = false,
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
    return build(a, circuit, frame, bindings, claim, true, null, null, null);
}
pub fn trustedDigestFrame(a: std.mem.Allocator, circuit: u32, frame: anytype, bindings: []const Binding, claim: [32]u8) !Prepared {
    return build(a, circuit, frame, bindings, claim, false, null, null, null);
}
pub fn prepare(a: std.mem.Allocator, circuit: u32, frame: framing.Frame, bindings: []const Binding, claim: [32]u8) !Prepared {
    return build(a, circuit, frame, bindings, claim, true, null, null, null);
}
pub fn trusted(a: std.mem.Allocator, circuit: u32, frame: framing.Frame, bindings: []const Binding, claim: [32]u8) !Prepared {
    return build(a, circuit, frame, bindings, claim, false, null, null, null);
}
pub fn preparePayload(a: std.mem.Allocator, circuit: u32, frame: framing.Frame, bindings: []const Binding, payload: PayloadBinding, claim: [32]u8) !Prepared {
    return build(a, circuit, frame, bindings, claim, true, payload, null, null);
}
pub fn trustedPayload(a: std.mem.Allocator, circuit: u32, frame: framing.Frame, bindings: []const Binding, payload: PayloadBinding, claim: [32]u8) !Prepared {
    return build(a, circuit, frame, bindings, claim, false, payload, null, null);
}
/// Borrowed exact hash-row ranges; Prepared.deinit does not free these.
pub const HashDestination = struct {
    g_rows: []@import("blake3_g_call.zig").Row,
    xor_rows: []@import("blake3_xor_call.zig").Row,
};
pub fn prepareInto(a: std.mem.Allocator, circuit: u32, frame: framing.Frame, bindings: []const Binding, payload: ?PayloadBinding, claim: [32]u8, destination: HashDestination) !Prepared {
    return build(a, circuit, frame, bindings, claim, true, payload, destination, null);
}
pub fn trustedInto(a: std.mem.Allocator, circuit: u32, frame: framing.Frame, bindings: []const Binding, payload: ?PayloadBinding, claim: [32]u8, destination: HashDestination) !Prepared {
    return build(a, circuit, frame, bindings, claim, false, payload, destination, null);
}
pub const MainColumns = struct {
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
    return build(a, circuit, frame, bindings, claim, true, payload, .{ .g_rows = columns.g_rows.metadata, .xor_rows = columns.xor_rows.metadata }, columns);
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
fn build(backing: std.mem.Allocator, circuit: u32, frame: anytype, bindings: []const Binding, claim: [32]u8, live: bool, payload: ?PayloadBinding, destination: ?HashDestination, columns: ?MainColumns) !Prepared {
    var arena = std.heap.ArenaAllocator.init(backing);
    errdefer arena.deinit();
    const a = arena.allocator();
    var plan = try routing.buildWithPayload(a, circuit, frame, bindings, payload);

    const len = try frame.encodedSize();
    var shape = try graph.build(backing, len);
    defer shape.deinit();
    if (destination) |out| if (out.g_rows.len != shape.g.len or out.xor_rows.len != shape.xor.len) return error.InvalidBlake3WitnessDestination;
    var rows = hash.Rows{
        .allocator = a,
        .g_rows = if (destination) |out| out.g_rows else try a.alloc(@import("blake3_g_call.zig").Row, shape.g.len),
        .xor_rows = if (destination) |out| out.xor_rows else try a.alloc(@import("blake3_xor_call.zig").Row, shape.xor.len),
        .boundary_rows = try a.alloc(boundary.Row, shape.sources.len + 8),
    };
    const hash_destination = hash.Destination{ .g_rows = rows.g_rows, .xor_rows = rows.xor_rows, .boundary_rows = rows.boundary_rows };
    var digest: ?[32]u8 = null;
    if (live) {
        const bytes = try frame.encode(a);
        defer a.free(bytes);
        digest = if (columns) |out|
            try hash.prepareMainColumns(backing, circuit, bytes, claim, .{ .g_rows = out.g_rows, .xor_rows = out.xor_rows, .boundary_rows = rows.boundary_rows })
        else
            try hash.prepareInto(backing, circuit, bytes, claim, hash_destination);
    } else try hash.trustedShapeInto(backing, circuit, len, claim, hash_destination);

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
    return .{ .arena = arena, .hash_rows_are_metadata = columns != null, .rows = .{ .g_rows = rows.g_rows, .xor_rows = rows.xor_rows, .boundary_rows = rows.boundary_rows }, .route_rows = routed, .source_uses = uses, .payload_uses = payload_uses, .digest = digest };
}
