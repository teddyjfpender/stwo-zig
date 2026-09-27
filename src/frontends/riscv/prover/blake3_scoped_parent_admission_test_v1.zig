//! Metadata/lifetime fixtures only. No Plan/Worker/capture is fabricated or
//! constructed, no proof admission/commitment is attempted, and no proof runs.
const std = @import("std");
const core = @import("stwo_core");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const Borrow = @import("../recursion/blake3_parent_admission_borrow_v1.zig");
const Guard = @import("../recursion/blake3_parent_fixed_row_guard_v1.zig");
const Storage = @import("../recursion/air/blake3_parent_row_storage.zig");
// Deliberately noncryptographic metadata: this type cannot satisfy any original
// producer/protocol API. The generic slot supplies custody, never authority.
const PublicMetadata = struct { ordinal: u32, words: []const u32, felts: []const Q };
const Slot = Borrow.For(PublicMetadata);
fn metadataLifetime(a: std.mem.Allocator) !void {
    var slot = Slot{};
    try std.testing.expectError(error.ParentDynamicAdmissionNotBound, slot.require());
    const first_words = try a.dupe(u32, &.{ 11, 13 });
    var owns_first_words = true;
    defer if (owns_first_words) a.free(first_words);
    const first_felts = try a.dupe(Q, &.{Q.one()});
    var owns_first_felts = true;
    defer if (owns_first_felts) a.free(first_felts);
    slot.bind(.{ .ordinal = 0, .words = first_words, .felts = first_felts });
    // Original constructor/lease release removes all public pointers before
    // the source allocation can end. require cannot read those freed arrays.
    try std.testing.expect((try slot.require()).words.ptr == first_words.ptr);
    slot.release();
    a.free(first_felts);
    owns_first_felts = false;
    a.free(first_words);
    owns_first_words = false;
    try std.testing.expect(slot.current == null);
    try std.testing.expectError(error.ParentDynamicAdmissionNotBound, slot.require());
    const current_words = try a.dupe(u32, &.{ 17, 19, 23 });
    defer a.free(current_words);
    const current_felts = try a.dupe(Q, &.{ Q.one(), Q.zero() });
    defer a.free(current_felts);
    slot.bind(.{ .ordinal = 1, .words = current_words, .felts = current_felts });
    defer slot.release();
    try std.testing.expectEqual(@as(u32, 1), (try slot.require()).ordinal);
    try std.testing.expectEqualSlices(u32, &.{ 17, 19, 23 }, (try slot.require()).words);
    try std.testing.expect((try slot.require()).felts.ptr == current_felts.ptr);
    current_words[1] += 1;
    current_felts[0] = Q.zero();
    // Every read addresses this request's actual data, not retained old tuples.
    try std.testing.expectEqual(@as(u32, 20), (try slot.require()).words[1]);
    try std.testing.expect((try slot.require()).felts[0].isZero());
}
test "scoped producer lifetime: previous public borrow clears before source teardown and current tuple replaces it" {
    try metadataLifetime(std.testing.allocator);
}
test "scoped producer lifetime: public borrow metadata allocation failures unwind" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, metadataLifetime, .{});
}
fn fixedMetadata(a: std.mem.Allocator) !void {
    var fixed: std.meta.Tuple(&blk: {
        var types: [Storage.Airs.len]type = undefined;
        for (Storage.Airs, &types) |Air, *T| T.* = [1]Storage.FixedRow(Air);
        break :blk types;
    }) = undefined;
    var main_values = [_]M{ M.zero(), M.one() };
    var rows = Storage.Prepared{ .allocator = a, .main = @splat(&.{}), .fixed = undefined, .input_count = 0 };
    // Main values and fixed rows are synchronous stack-backed metadata probes;
    // only descriptor arrays allocate. Never pass these probes to a producer.
    defer inline for (rows.main) |columns| a.free(columns);
    inline for (Storage.Airs, 0..) |Air, i| {
        fixed[i][0] = @splat(M.zero());
        rows.fixed[i] = &fixed[i];
        rows.main[i] = try a.alloc(@import("stwo_prover_engine").pcs.ColumnEvaluation, Air.PHYSICAL_MAIN_COLUMN_COUNT);
        for (rows.main[i]) |*column| column.* = .{ .log_size = 1, .values = &main_values };
    }
    const logs: [Storage.Airs.len]u32 = @splat(1);
    const counts: [Storage.Airs.len]usize = @splat(1);
    var digests: [Storage.Airs.len][32]u8 = undefined;
    inline for (0..Storage.Airs.len) |i| digests[i] = Guard.fixedDigest(rows.fixed[i]);
    const G = Guard.ForAirs(Storage.Airs);
    try G.require(&rows, &logs, &counts, &digests);
    // Exact original guards: fixed row length, physical main count, per-column
    // log and value extent, fixed content hash, and independently supplied logs.
    const original_fixed = rows.fixed[0];
    rows.fixed[0] = original_fixed[0..0];
    try std.testing.expectError(error.InvalidBlake3ParentRows, G.require(&rows, &logs, &counts, &digests));
    rows.fixed[0] = original_fixed;
    {
        const original_main = rows.main[0];
        rows.main[0] = original_main[0 .. original_main.len - 1];
        defer rows.main[0] = original_main;
        try std.testing.expectError(error.InvalidBlake3ParentRows, G.require(&rows, &logs, &counts, &digests));
    }
    rows.main[0][0].log_size = 2;
    try std.testing.expectError(error.InvalidBlake3ParentRows, G.require(&rows, &logs, &counts, &digests));
    rows.main[0][0].log_size = 1;
    rows.main[0][0].values = main_values[0..1];
    try std.testing.expectError(error.InvalidBlake3ParentRows, G.require(&rows, &logs, &counts, &digests));
    rows.main[0][0].values = &main_values;
    fixed[0][0][0] = M.one();
    try std.testing.expectError(error.InvalidBlake3ParentRows, G.require(&rows, &logs, &counts, &digests));
    fixed[0][0][0] = M.zero();
    var changed_logs = logs;
    changed_logs[0] = 2;
    try std.testing.expectError(error.InvalidBlake3ParentRows, G.require(&rows, &changed_logs, &counts, &digests));
    try G.require(&rows, &logs, &counts, &digests);
}
test "scoped producer lifetime: shared original fixed guards reject all row log column extent and content faults" {
    try fixedMetadata(std.testing.allocator);
}
test "scoped producer lifetime: bounded original fixed metadata descriptor allocation failures unwind" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, fixedMetadata, .{});
}
fn containsPointer(comptime T: type) bool {
    return switch (@typeInfo(T)) {
        .pointer => true,
        .array => |value| containsPointer(value.child),
        .optional => |value| containsPointer(value.child),
        .@"struct" => |value| blk: {
            inline for (value.fields) |field| if (comptime containsPointer(field.type)) break :blk true;
            break :blk false;
        },
        else => false,
    };
}
test "scoped producer lifetime: default API preserved and scoped persistent key contains no source pointers" {
    @setEvalBranchQuota(20_000);
    const P = @import("../recursion/blake3_native_parent_producer.zig");
    const protocols = .{
        @import("../recursion/block_v5_reusable_native_parent_protocol_v1.zig"),
        @import("../recursion/block_v5_reusable_caller_fused_parent_protocol_v1.zig"),
        @import("../recursion/block_v5_reusable_native_capacity_fused_parent_protocol_v1.zig"),
    };
    inline for (protocols) |Protocol| {
        const Default = P.PlanForProtocol(Cpu, Protocol);
        const Scoped = P.PlanForProtocolScopedAdmission(Cpu, Protocol);
        try std.testing.expect(@FieldType(Default, "admission") == Protocol.Admission);
        try std.testing.expect(@FieldType(Scoped, "admission") == Borrow.For(Protocol.Admission));
        try std.testing.expect(@FieldType(Borrow.For(Protocol.Admission), "current") == ?Protocol.Admission);
        try std.testing.expect(!containsPointer(@FieldType(Scoped, "template_key")));
    }
}
