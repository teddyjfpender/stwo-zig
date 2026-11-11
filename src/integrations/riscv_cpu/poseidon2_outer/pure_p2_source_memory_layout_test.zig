//! Witness-free ABI sizes used by the retained-source lifetime inventory.
const std = @import("std");
const A = @import("stwo_riscv_frontend").rv64_air;
const Core = @import("../word16_execution/sources.zig").Source;
const Native = @import("../word16_execution/prepared.zig").Prepared;
fn elem(comptime T: type, comptime field: []const u8) usize {
    return @sizeOf(@typeInfo(@FieldType(T, field)).pointer.child);
}
test "OP retained source layout manifest uses compiled owner ABI sizes only" {
    const path = std.posix.getenv("STWO_OP_SOURCE_LAYOUT_OUTPUT") orelse return error.SkipZigTest;
    const V = A.memory.load_store_v2.source.Source;
    const D = A.memory.load_store_dword.source.Source;
    const Bulk = A.crypto.bulk_memory.source.Source;
    const Secp = A.crypto.secp256k1.word16_bridge.source;
    const Sponge = A.crypto.keccak_sponge.source;
    const sizes = .{
        .cpu_metadata = elem(@FieldType(Core, "cpu"), "metadata"),
        .alu_metadata = elem(@FieldType(Core, "alu"), "metadata"),
        .binary_metadata = elem(@FieldType(Core, "binary"), "metadata"),
        .shift_metadata = elem(@FieldType(Core, "shift"), "metadata"),
        .division_metadata = elem(@FieldType(Core, "division"), "metadata"),
        .multiplication_metadata = elem(@FieldType(Core, "multiplication"), "request_metadata"),
        .ls32_metadata = elem(V, "metadata"),
        .ls64_metadata = elem(D, "metadata"),
        .boundary_metadata = elem(@FieldType(@FieldType(Core, "memory"), "initial"), "metadata"),
        .alu_native_fact = elem(@FieldType(Native, "alu"), "facts"),
        .binary_native_fact = elem(@FieldType(Native, "binary"), "facts"),
        .shift_native_fact = elem(Native, "shift"),
        .division_native_fact = elem(Native, "division"),
        .multiplication_native_fact = elem(Native, "multiplication"),
        .jalr_fact = elem(@FieldType(Core, "jalr"), "facts"),
        .bridge_call = elem(Secp.Source, "calls"),
        .tower_call = elem(Secp.TowerSource, "calls"),
        .bulk_call = elem(Bulk, "calls"),
        .bulk_word = elem(Bulk, "words"),
        .sponge_call = elem(Sponge.Plan, "calls"),
        .sponge_word = elem(Sponge.Plan, "words"),
        .sponge_permutation = elem(Sponge.Plan, "perms"),
        .ordinary_event = @sizeOf(A.memory.load_store_v2.native.Event),
        .cell = @sizeOf(@import("../word16_execution/memory/statement.zig").Cell),
        .m31 = @sizeOf(@import("stwo_core").fields.m31.M31),
        .miller_advice_per_call = @sizeOf(A.crypto.bn254_tower.narrow.trace.Input) + @sizeOf(A.crypto.bn254_tower.narrow.micro.Advice),
        .miller_advice_per_worker = 2 * 256 * @sizeOf(u32) + A.crypto.bn254_tower.narrow.micro.CARRY_LIMIT * @sizeOf(u32),
        .miller_frontier_main = A.crypto.bn254_tower.narrow.ForField(@import("stwo_core").fields.om31.OM31).Component(.frontier).L.MAIN,
        .miller_arithmetic_main = A.crypto.bn254_tower.narrow.ForField(@import("stwo_core").fields.om31.OM31).Component(.arithmetic).L.MAIN,
        .miller_frontier_inter = A.crypto.bn254_tower.narrow.ForField(@import("stwo_core").fields.om31.OM31).Component(.frontier).L.INTERACTION,
        .miller_arithmetic_inter = A.crypto.bn254_tower.narrow.ForField(@import("stwo_core").fields.om31.OM31).Component(.arithmetic).L.INTERACTION,
    };
    var file = try std.fs.cwd().createFile(path, .{});
    defer file.close();
    const bytes = try std.json.Stringify.valueAlloc(std.testing.allocator, sizes, .{ .whitespace = .indent_2 });
    defer std.testing.allocator.free(bytes);
    try file.writeAll(bytes);
}

fn catalogBound(comptime T: type, calls: u32) !usize {
    const bytes = if (T == @import("../word16_global_execution/services/gkr_local/truth_catalog.zig").Sha() or T == @import("../word16_global_execution/services/gkr_local/truth_catalog.zig").Arith()) @sizeOf(T.N.Input) else @sizeOf(T.N.Packet);
    return try std.math.add(usize, try std.math.mul(usize, calls, bytes), @sizeOf(@import("../word16_global_execution/services/roster.zig").TruthSource) + (if (T.bytes == 0) @as(usize, 0) else 256 * @sizeOf(u64)));
}
fn catalogDeclarationBound(d: @import("../word16_global_execution/services/wire.zig").TruthDeclaration) !usize {
    const C = @import("../word16_global_execution/services/gkr_local/truth_catalog.zig");
    _ = try C.descriptorForDeclaration(d);
    return switch (d.family) {
        .sha256 => catalogBound(C.Sha(), d.calls),
        .arith256_mod => catalogBound(C.Arith(), d.calls),
        .add => catalogBound(C.Curve(A.crypto.curves.spec.SecpKind.add), d.calls),
        .double => catalogBound(C.Curve(A.crypto.curves.spec.SecpKind.double), d.calls),
        .keccak => error.NotV3Truth,
        inline else => |family| catalogBound(C.Curve(@as(A.crypto.curves.Op, @enumFromInt(@intFromEnum(family)))), d.calls),
    };
}
test "OP retained truth planner manifest needs no setup witness or execution" {
    const input = std.posix.getenv("STWO_OP_SOURCE_FROZEN_PLAN") orelse return error.SkipZigTest;
    const output = std.posix.getenv("STWO_OP_SOURCE_TRUTH_OUTPUT") orelse return error.SkipZigTest;
    const a = std.testing.allocator;
    const Runtime = @import("pure_p2_op_runtime.zig");
    const Resource = @import("truth_local_gkr/resource.zig");
    const Wire = @import("../word16_global_execution/services/wire.zig");
    const raw = try std.fs.cwd().readFileAlloc(a, input, 8 << 20);
    defer a.free(raw);
    const parsed = try std.json.parseFromSlice(struct { metadata: Runtime.Metadata }, a, raw, .{ .ignore_unknown_fields = true });
    defer parsed.deinit();
    const m = parsed.value.metadata;
    var total: [@import("../word16_global_execution/services/types.zig").FAMILIES]u32 = @splat(0);
    for (m.truths) |truth| total[@intFromEnum(truth.family)] += truth.calls;
    const resources = Runtime.Resources{};
    const declarations = try @import("pure_p2_truth_local_plan.zig").declarations(a, total, m.profile.config(), .{ .live_bytes = resources.truth_live_bytes, .main_bytes = resources.truth_main_bytes, .interaction_bytes = resources.truth_interaction_bytes, .gkr_bytes = resources.gkr_bytes }, 256 - m.cpus.len - m.miller.len);
    defer a.free(declarations);
    const Row = struct { declaration: Wire.TruthDeclaration, local_gkr: ?Resource.Plan, retained_metadata_bound: usize };
    const rows = try a.alloc(Row, declarations.len);
    defer a.free(rows);
    for (declarations, rows) |d, *row| {
        const local = d.family == .keccak or ((d.family == .add or d.family == .double) and d.logs[1] != 0);
        const plan = if (local) try Resource.derive(d, m.profile.config()) else null;
        row.* = .{ .declaration = d, .local_gkr = plan, .retained_metadata_bound = if (plan) |p| p.durable_metadata_bytes else try catalogDeclarationBound(d) };
    }
    const bytes = try std.json.Stringify.valueAlloc(a, rows, .{ .whitespace = .indent_2 });
    defer a.free(bytes);
    var file = try std.fs.cwd().createFile(output, .{});
    defer file.close();
    try file.writeAll(bytes);
}
