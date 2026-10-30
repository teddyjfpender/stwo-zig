//! Explicit mixed native/caller metadata, with NO complete RAM snapshot or initialization
//! table in the wire. ELF, security, and total cohorts are external policy.
//! Decoding metadata authenticates no local original and no global memory.
const std = @import("std");
const Scope = @import("block_v8_endpoint_mixed_scope_v1.zig");
const Statement = @import("block_v8_endpoint_mixed_statement_v1.zig");
const Budget = @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget;
const ShapeWire = @import("guest_precompile/proof_artifact_wire.zig");
const Writer = @import("bounded_artifact_writer_v1.zig").Writer;
pub const Limits = struct { bytes: usize = 16 << 20, decode_bytes: usize = 128 << 20, reconstruction_bytes: usize = 512 << 20 };
pub const SCHEMA = "stwo-v8-mixed-native-caller-endpoint-metadata-v1";
pub const SPARSE_SCHEMA = "stwo-v8-mixed-native-caller-endpoint-sparse-rom-metadata-v1";
const CallerWire = @import("guest_precompile/ethereum_sha_statement_wire.zig");
const Data = struct {
    caller_statement: []const u8,
    caller_roots: [2][32]u8,
    schema: []const u8,
    shape: []const u8,
    frame: @FieldType(Scope.Input, "frame"),
    cohort_ordinal: u32,
    endpoint_count: u32,
    native_roots: [4][32]u8,
    program_plan: @FieldType(Scope.Input, "program_plan"),
    program_roots: [2][32]u8,
    lookup_plan: @FieldType(Scope.Input, "lookup_plan"),
    lookup_layout: @FieldType(Scope.Input, "lookup_layout"),
    lookup_roots: [2][32]u8,
};
const SparseData = struct {
    caller_statement: []const u8,
    caller_roots: [2][32]u8,
    sparse_support: []const @import("block_v8_sparse_rom_v1.zig").Entry,
    schema: []const u8,
    shape: []const u8,
    frame: @FieldType(Scope.Input, "frame"),
    cohort_ordinal: u32,
    endpoint_count: u32,
    native_roots: [4][32]u8,
    program_plan: @FieldType(Scope.Input, "program_plan"),
    program_roots: [2][32]u8,
    lookup_plan: @FieldType(Scope.Input, "lookup_plan"),
    lookup_layout: @FieldType(Scope.Input, "lookup_layout"),
    lookup_roots: [2][32]u8,
};
pub fn encode(a: std.mem.Allocator, trusted: Scope.Trusted, input: Scope.Input, limits: Limits) ![]u8 {
    if (limits.bytes == 0 or input.endpoint_count == 0 or input.endpoint_count > 1 << 24 or input.cohort_ordinal >= trusted.cohort_count) return error.InvalidEndpointLocalMetadata;
    var shape = Writer.init(a, limits.bytes);
    defer shape.deinit();
    try ShapeWire.encodeBlake3Statement(&shape, input.shape, .{});
    const hex = try a.alloc(u8, try std.math.mul(usize, shape.bytes.items.len, 2));
    defer a.free(hex);
    const alphabet = "0123456789abcdef";
    for (shape.bytes.items, 0..) |byte, i| {
        hex[2 * i] = alphabet[byte >> 4];
        hex[2 * i + 1] = alphabet[byte & 15];
    }
    var plan = input.program_plan;
    plan.leaves = &.{}; // reconstructed from the independently pinned ELF
    var caller = Writer.init(a, CallerWire.extension_encoded_size);
    defer caller.deinit();
    try CallerWire.encodeExtension(&caller, input.caller_statement);
    const caller_hex = try a.alloc(u8, 2 * caller.bytes.items.len);
    defer a.free(caller_hex);
    for (caller.bytes.items, 0..) |byte, i| {
        caller_hex[2 * i] = alphabet[byte >> 4];
        caller_hex[2 * i + 1] = alphabet[byte & 15];
    }
    const data = Data{ .caller_statement = caller_hex, .caller_roots = input.caller_roots, .schema = SCHEMA, .shape = hex, .frame = input.frame, .cohort_ordinal = input.cohort_ordinal, .endpoint_count = input.endpoint_count, .native_roots = input.native_roots, .program_plan = plan, .program_roots = input.program_roots, .lookup_plan = input.lookup_plan, .lookup_layout = input.lookup_layout, .lookup_roots = input.lookup_roots };
    const bytes = if (input.rom_flavor == .legacy_complete) try std.json.Stringify.valueAlloc(a, data, .{}) else blk: {
        var sparse: SparseData = undefined;
        inline for (std.meta.fields(Data)) |field| @field(sparse, field.name) = @field(data, field.name);
        sparse.schema = SPARSE_SCHEMA;
        sparse.sparse_support = input.sparse_support;
        break :blk try std.json.Stringify.valueAlloc(a, sparse, .{});
    };
    errdefer a.free(bytes);
    if (bytes.len > limits.bytes) return error.EndpointLocalMetadataSizeLimit;
    return bytes;
}
pub fn decode(a: std.mem.Allocator, bytes: []const u8, trusted: Scope.Trusted, limits: Limits) !*Statement.Owned {
    if (limits.bytes == 0 or limits.decode_bytes == 0 or limits.reconstruction_bytes == 0 or bytes.len > limits.bytes) return error.EndpointLocalMetadataSizeLimit;
    const budget = try Budget.createRetainingParent(a, limits.decode_bytes);
    defer budget.destroy();
    var arena = std.heap.ArenaAllocator.init(budget.allocator());
    defer arena.deinit();
    const t = arena.allocator();
    const probe = try std.json.parseFromSliceLeaky(struct { schema: []const u8 }, t, bytes, .{ .ignore_unknown_fields = true, .max_value_len = limits.bytes });
    const flavor: Scope.RomFlavor = if (std.mem.eql(u8, probe.schema, SCHEMA)) .legacy_complete else if (std.mem.eql(u8, probe.schema, SPARSE_SCHEMA)) .sparse_elf else return error.InvalidEndpointLocalMetadata;
    var support: []const @import("block_v8_sparse_rom_v1.zig").Entry = &.{};
    const data: Data = if (flavor == .legacy_complete) try std.json.parseFromSliceLeaky(Data, t, bytes, .{ .allocate = .alloc_always, .max_value_len = limits.bytes }) else blk: {
        const sparse = try std.json.parseFromSliceLeaky(SparseData, t, bytes, .{ .allocate = .alloc_always, .max_value_len = limits.bytes });
        support = sparse.sparse_support;
        var common: Data = undefined;
        inline for (std.meta.fields(Data)) |field| @field(common, field.name) = @field(sparse, field.name);
        break :blk common;
    };
    if (data.cohort_ordinal >= trusted.cohort_count or data.endpoint_count == 0 or data.endpoint_count > 1 << 24 or data.program_plan.leaves.len != 0 or data.shape.len % 2 != 0 or (flavor == .sparse_elf and data.program_plan.multiplicities.len != 0)) return error.InvalidEndpointLocalMetadata;
    if (data.caller_statement.len != 2 * CallerWire.extension_encoded_size) return error.InvalidMixedCallerStatementLength;
    for (data.caller_statement) |byte| if (!((byte >= '0' and byte <= '9') or (byte >= 'a' and byte <= 'f'))) return error.InvalidMixedCallerStatementEncoding;
    const caller_bytes = try t.alloc(u8, CallerWire.extension_encoded_size);
    _ = try std.fmt.hexToBytes(caller_bytes, data.caller_statement);
    const caller_statement = try CallerWire.decodeExtension(caller_bytes);
    for (data.shape) |byte| if (!((byte >= '0' and byte <= '9') or (byte >= 'a' and byte <= 'f'))) return error.InvalidEndpointLocalShapeEncoding;
    const raw = try t.alloc(u8, data.shape.len / 2);
    _ = try std.fmt.hexToBytes(raw, data.shape);
    var shape = try ShapeWire.decodeBlake3Statement(t, raw, .{});
    defer shape.deinit(t);
    const reconstruction = try Budget.createRetainingParent(a, limits.reconstruction_bytes);
    defer reconstruction.destroy();
    const r = reconstruction.allocator();
    var image = try @import("block_v8_endpoint_local_program_v1.zig").Owned.init(r, trusted.elf, trusted.elf_sha256, trusted.profile, .{});
    defer image.deinit();
    if (!std.meta.eql(image.root, data.program_plan.program_root)) return error.UntrustedEndpointLocalProgram;
    var plan = data.program_plan;
    plan.leaves = if (flavor == .legacy_complete) image.leaves else &.{};
    return Statement.Owned.init(a, trusted, .{ .rom_flavor = flavor, .sparse_support = support, .caller_statement = &caller_statement, .caller_roots = data.caller_roots, .shape = &shape.value, .frame = data.frame, .cohort_ordinal = data.cohort_ordinal, .endpoint_count = data.endpoint_count, .native_roots = data.native_roots, .program_plan = plan, .program_roots = data.program_roots, .lookup_plan = data.lookup_plan, .lookup_layout = data.lookup_layout, .lookup_roots = data.lookup_roots });
}
