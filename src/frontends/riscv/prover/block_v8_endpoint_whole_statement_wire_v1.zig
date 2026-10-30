//! Bounded public metadata transport for the new endpoint original protocol.
//! ROM leaves are reconstructed from the independently pinned ELF. Complete
//! snapshots, security and ELF remain receiver policy, never wire authority.
const std = @import("std");
const Receiver = @import("block_v7_execution_receiver_v1.zig");
const Statement = @import("block_v8_endpoint_whole_statement_v1.zig");
const Scope = @import("block_v8_endpoint_whole_scope_v1.zig");
const Budget = @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget;
const ShapeWire = @import("guest_precompile/proof_artifact_wire.zig");
const Writer = @import("bounded_artifact_writer_v1.zig").Writer;
pub const Limits = struct { bytes: usize = 16 << 20, decode_bytes: usize = 128 << 20, reconstruction_bytes: usize = 512 << 20 };
const SCHEMA = "stwo-v8-native-endpoint-window-metadata-v1";
const Data = struct {
    schema: []const u8,
    shape: []const u8,
    frame: @FieldType(Scope.Input, "frame"),
    endpoint_count: u32,
    native_roots: [4][32]u8,
    program_plan: @FieldType(Scope.Input, "program_plan"),
    program_roots: [2][32]u8,
    lookup_plan: @FieldType(Scope.Input, "lookup_plan"),
    lookup_layout: @FieldType(Scope.Input, "lookup_layout"),
    lookup_roots: [2][32]u8,
    memory_geometry: @FieldType(Scope.Input, "memory_geometry"),
    memory_roots: [2][32]u8,
    memory_interval_log: u32,
    selected_initial_addresses: []const u32,
};
pub fn encode(a: std.mem.Allocator, trusted: Receiver.Trusted, input: Scope.Input, limits: Limits) ![]u8 {
    const window = trusted.window orelse return error.InvalidEndpointMetadataMode;
    if (limits.bytes == 0 or input.endpoint_count == 0 or input.memory_geometry.len == 0 or input.memory_geometry.len > 4096)
        return error.InvalidEndpointMetadata;
    var shape = Writer.init(a, limits.bytes);
    defer shape.deinit();
    try ShapeWire.encodeBlake3Statement(&shape, input.shape, .{});
    const hex = try a.alloc(u8, try std.math.mul(usize, shape.bytes.items.len, 2));
    defer a.free(hex);
    const alphabet = "0123456789abcdef";
    for (shape.bytes.items, 0..) |byte, index| {
        hex[2 * index] = alphabet[byte >> 4];
        hex[2 * index + 1] = alphabet[byte & 15];
    }
    var plan = input.program_plan;
    plan.leaves = &.{};
    const data = Data{ .schema = SCHEMA, .shape = hex, .frame = input.frame, .endpoint_count = input.endpoint_count, .native_roots = input.native_roots, .program_plan = plan, .program_roots = input.program_roots, .lookup_plan = input.lookup_plan, .lookup_layout = input.lookup_layout, .lookup_roots = input.lookup_roots, .memory_geometry = input.memory_geometry, .memory_roots = input.memory_roots, .memory_interval_log = input.memory_interval_log, .selected_initial_addresses = if (window.selection) |selected| selected.addresses else &.{} };
    const bytes = try std.json.Stringify.valueAlloc(a, data, .{});
    errdefer a.free(bytes);
    if (bytes.len > limits.bytes) return error.EndpointMetadataSizeLimit;
    return bytes;
}
/// One bounded parse can serve address admission and owned metadata decode.
/// The parsed object authenticates no proof and nominates no verifier key.
pub const Parsed = struct {
    allocator: std.mem.Allocator,
    budget: *Budget,
    arena: std.heap.ArenaAllocator,
    data: Data,
    pub fn init(a: std.mem.Allocator, bytes: []const u8, limits: Limits) !*Parsed {
        if (limits.bytes == 0 or limits.decode_bytes == 0 or bytes.len > limits.bytes) return error.EndpointMetadataSizeLimit;
        const budget = try Budget.createRetainingParent(a, limits.decode_bytes);
        errdefer budget.destroy();
        const self = try a.create(Parsed);
        errdefer a.destroy(self);
        self.allocator = a;
        self.budget = budget;
        self.arena = std.heap.ArenaAllocator.init(budget.allocator());
        errdefer self.arena.deinit();
        self.data = try std.json.parseFromSliceLeaky(Data, self.arena.allocator(), bytes, .{ .allocate = .alloc_always, .max_value_len = limits.bytes });
        try validateData(self.data);
        return self;
    }
    pub fn deinit(self: *Parsed) void {
        const a = self.allocator;
        const budget = self.budget;
        self.arena.deinit();
        a.destroy(self);
        budget.destroy();
    }
    pub fn selection(self: *const Parsed) []const u32 {
        return self.data.selected_initial_addresses;
    }
    pub fn decodeTrusted(self: *Parsed, a: std.mem.Allocator, trusted: Receiver.Trusted, limits: Limits) !*Statement.Owned {
        if (trusted.window == null or limits.reconstruction_bytes == 0) return error.InvalidEndpointMetadataMode;
        const data = self.data;
        const t = self.arena.allocator();
        const selected: []const u32 = if (trusted.window.?.selection) |value| value.addresses else &.{};
        if (!std.mem.eql(u32, selected, data.selected_initial_addresses)) return error.UntrustedEndpointInitializationSelection;
        if (data.shape.len % 2 != 0) return error.InvalidEndpointShapeWire;
        const raw = try t.alloc(u8, data.shape.len / 2);
        _ = try std.fmt.hexToBytes(raw, data.shape);
        var shape = try ShapeWire.decodeBlake3Statement(t, raw, .{});
        defer shape.deinit(t);
        if (data.program_plan.leaves.len != 0) return error.UnexpectedEndpointSerializedRom;
        const reconstruction = try Budget.createRetainingParent(a, limits.reconstruction_bytes);
        defer reconstruction.destroy();
        var image = try @import("block_v7_program_image_v1.zig").Owned.init(reconstruction.allocator(), trusted.elf, &trusted.window.?.initial, .{});
        defer image.deinit();
        if (!std.meta.eql(image.root, data.program_plan.program_root)) return error.UntrustedEndpointProgramImage;
        var plan = data.program_plan;
        plan.leaves = image.leaves;
        return Statement.Owned.init(a, trusted, .{ .shape = &shape.value, .frame = data.frame, .endpoint_count = data.endpoint_count, .native_roots = data.native_roots, .program_plan = plan, .program_roots = data.program_roots, .lookup_plan = data.lookup_plan, .lookup_layout = data.lookup_layout, .lookup_roots = data.lookup_roots, .memory_geometry = data.memory_geometry, .memory_roots = data.memory_roots, .memory_interval_log = data.memory_interval_log });
    }
};
pub fn selectionAddresses(a: std.mem.Allocator, bytes: []const u8, limits: Limits) ![]u32 {
    const parsed = try Parsed.init(a, bytes, limits);
    defer parsed.deinit();
    return a.dupe(u32, parsed.selection());
}
pub fn decode(a: std.mem.Allocator, bytes: []const u8, trusted: Receiver.Trusted, limits: Limits) !*Statement.Owned {
    const parsed = try Parsed.init(a, bytes, limits);
    defer parsed.deinit();
    return parsed.decodeTrusted(a, trusted, limits);
}
fn validateData(data: Data) !void {
    if (!std.mem.eql(u8, data.schema, SCHEMA) or data.endpoint_count == 0 or data.endpoint_count > 1 << 24 or
        data.memory_geometry.len == 0 or data.memory_geometry.len > 4096)
        return error.InvalidEndpointMetadata;
}
