//! Bounded Group public metadata. ELF/security/total cohorts stay external;
//! metadata decoding is never a substitute for ONE genuine Group verification.
const std = @import("std");
const Scope = @import("block_v8_endpoint_group_scope_v1.zig");
const Statement = @import("block_v8_endpoint_group_statement_v1.zig");
const Budget = @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget;
const ShapeWire = @import("guest_precompile/proof_artifact_wire.zig");
const CallerWire = @import("guest_precompile/ethereum_sha_statement_wire.zig");
const Writer = @import("bounded_artifact_writer_v1.zig").Writer;
pub const Limits = struct { bytes: usize = 16 << 20, decode_bytes: usize = 128 << 20, reconstruction_bytes: usize = 512 << 20 };
pub const SCHEMA = "stwo-v8-group-native-caller-endpoint-metadata-v1";
pub const WIDE_SCHEMA = "stwo-v8-native-wide-group-endpoint-metadata-v2";
const Member = struct {
    shape: []const u8,
    frame: @FieldType(Scope.MemberInput, "frame"),
    cohort_ordinal: u32,
    endpoint_count: u32,
    native_main_root: [32]u8,
    endpoint_main_root: [32]u8,
    caller_statement: ?[]const u8 = null,
    caller_main_root: [32]u8 = @splat(0),
};
const Data = struct {
    schema: []const u8,
    members: []const Member,
    fixed_root: [32]u8,
    range_main_root: [32]u8,
    rom_flavor: @import("block_v8_endpoint_local_scope_v1.zig").RomFlavor,
    sparse_support: []const @import("block_v8_sparse_rom_v1.zig").Entry,
    program_plan: @FieldType(Scope.Input, "program_plan"),
    program_roots: [2][32]u8,
    lookup_plan: @FieldType(Scope.Input, "lookup_plan"),
    lookup_layout: @FieldType(Scope.Input, "lookup_layout"),
    lookup_roots: [2][32]u8,
};
fn hex(a: std.mem.Allocator, bytes: []const u8) ![]u8 {
    const out = try a.alloc(u8, try std.math.mul(usize, 2, bytes.len));
    const alphabet = "0123456789abcdef";
    for (bytes, 0..) |b, i| {
        out[2 * i] = alphabet[b >> 4];
        out[2 * i + 1] = alphabet[b & 15];
    }
    return out;
}
fn unhex(a: std.mem.Allocator, text: []const u8) ![]u8 {
    if (text.len % 2 != 0) return error.InvalidGroupMetadataHex;
    for (text) |b| if (!((b >= '0' and b <= '9') or (b >= 'a' and b <= 'f'))) return error.InvalidGroupMetadataHex;
    const out = try a.alloc(u8, text.len / 2);
    errdefer a.free(out);
    _ = try std.fmt.hexToBytes(out, text);
    return out;
}
pub fn encode(a: std.mem.Allocator, trusted: Scope.Trusted, input: Scope.Input, limits: Limits) ![]u8 {
    if (limits.bytes == 0 or input.members.len == 0 or input.members.len > @import("block_v8_endpoint_group_layout_v1.zig").maxMembers(input.profile) or input.members.len > trusted.cohort_count) return error.InvalidGroupMetadata;
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const t = arena.allocator();
    const members = try t.alloc(Member, input.members.len);
    for (input.members, members) |member, *out| {
        var shape = Writer.init(t, limits.bytes);
        try ShapeWire.encodeBlake3Statement(&shape, member.shape, .{});
        out.* = .{ .shape = try hex(t, shape.bytes.items), .frame = member.frame, .cohort_ordinal = member.cohort_ordinal, .endpoint_count = member.endpoint_count, .native_main_root = member.native_main_root, .endpoint_main_root = member.endpoint_main_root };
        if (member.caller) |caller| {
            var raw = Writer.init(t, CallerWire.extension_encoded_size);
            try CallerWire.encodeExtension(&raw, caller.statement);
            out.caller_statement = try hex(t, raw.bytes.items);
            out.caller_main_root = caller.main_root;
        }
    }
    var plan = input.program_plan;
    plan.leaves = &.{};
    const bytes = try std.json.Stringify.valueAlloc(a, Data{ .schema = if (input.profile == .compact_v1) SCHEMA else WIDE_SCHEMA, .members = members, .fixed_root = input.fixed_root, .range_main_root = input.range_main_root, .rom_flavor = input.rom_flavor, .sparse_support = input.sparse_support, .program_plan = plan, .program_roots = input.program_roots, .lookup_plan = input.lookup_plan, .lookup_layout = input.lookup_layout, .lookup_roots = input.lookup_roots }, .{});
    errdefer a.free(bytes);
    if (bytes.len > limits.bytes) return error.GroupMetadataSizeLimit;
    return bytes;
}
pub fn decode(a: std.mem.Allocator, bytes: []const u8, trusted: Scope.Trusted, limits: Limits) !*Statement.Owned {
    if (limits.bytes == 0 or limits.decode_bytes == 0 or limits.reconstruction_bytes == 0 or bytes.len > limits.bytes) return error.GroupMetadataSizeLimit;
    const budget = try Budget.createRetainingParent(a, limits.decode_bytes);
    defer budget.destroy();
    var arena = std.heap.ArenaAllocator.init(budget.allocator());
    defer arena.deinit();
    const t = arena.allocator();
    const data = try std.json.parseFromSliceLeaky(Data, t, bytes, .{ .allocate = .alloc_always, .max_value_len = limits.bytes });
    const profile: Scope.Profile = if (std.mem.eql(u8, data.schema, SCHEMA)) .compact_v1 else if (std.mem.eql(u8, data.schema, WIDE_SCHEMA)) .native_wide_v2 else return error.InvalidGroupMetadata;
    if (data.members.len == 0 or data.members.len > @import("block_v8_endpoint_group_layout_v1.zig").maxMembers(profile) or data.members.len > trusted.cohort_count or data.program_plan.leaves.len != 0 or (data.rom_flavor == .sparse_elf and data.program_plan.multiplicities.len != 0) or (data.rom_flavor == .legacy_complete and data.sparse_support.len != 0)) return error.InvalidGroupMetadata;
    const members = try t.alloc(Scope.MemberInput, data.members.len);
    for (data.members, members) |member, *out| {
        if (member.cohort_ordinal >= trusted.cohort_count or member.endpoint_count == 0 or member.endpoint_count > 1 << 24) return error.InvalidGroupMetadata;
        const raw = try unhex(t, member.shape);
        const shape = try ShapeWire.decodeBlake3Statement(t, raw, .{});
        const value = try t.create(@TypeOf(shape.value));
        value.* = shape.value;
        out.* = .{ .shape = value, .frame = member.frame, .cohort_ordinal = member.cohort_ordinal, .endpoint_count = member.endpoint_count, .native_main_root = member.native_main_root, .endpoint_main_root = member.endpoint_main_root };
        if (member.caller_statement) |encoded| {
            if (encoded.len != 2 * CallerWire.extension_encoded_size) return error.InvalidGroupCallerEncoding;
            const caller_bytes = try unhex(t, encoded);
            const decoded = try CallerWire.decodeExtension(caller_bytes);
            const caller = try t.create(@TypeOf(decoded));
            caller.* = decoded;
            out.caller = .{ .statement = caller, .main_root = member.caller_main_root };
        } else if (!std.mem.allEqual(u8, &member.caller_main_root, 0)) return error.InvalidGroupCallerEncoding;
    }
    const reconstruction = try Budget.createRetainingParent(a, limits.reconstruction_bytes);
    defer reconstruction.destroy();
    var image = try @import("block_v8_endpoint_local_program_v1.zig").Owned.init(reconstruction.allocator(), trusted.elf, trusted.elf_sha256, trusted.profile, .{});
    defer image.deinit();
    if (!std.meta.eql(image.root, data.program_plan.program_root)) return error.UntrustedGroupMetadataProgram;
    var plan = data.program_plan;
    plan.leaves = if (data.rom_flavor == .legacy_complete) image.leaves else &.{};
    return Statement.Owned.init(a, trusted, .{ .profile = profile, .members = members, .fixed_root = data.fixed_root, .range_main_root = data.range_main_root, .rom_flavor = data.rom_flavor, .sparse_support = data.sparse_support, .program_plan = plan, .program_roots = data.program_roots, .lookup_plan = data.lookup_plan, .lookup_layout = data.lookup_layout, .lookup_roots = data.lookup_roots });
}
