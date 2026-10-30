//! Genuine Mixed14 typed verifier: no surviving original witness or producer key.
const std = @import("std");
const E = @import("stwo_prover_engine");
const Fixture = @import("../../prover/tests/block_v8_endpoint_mixed_fixture.zig");
const Family = @import("../block_v8_endpoint_mixed_recursive_v1.zig");
const Codec = @import("../../prover/block_v8_endpoint_mixed_codec_v1.zig");
const Statement = Family.Statement;
fn qualify(kind: Fixture.Kind, comptime prove_parent: bool) !void {
    const budget = try E.host_budget_allocator.SharedHostBudget.create(std.testing.allocator, 32 << 30);
    defer budget.destroy();
    const a = budget.allocator();
    var pool: E.work_pool.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{ .worker_count = 4, .backing_allocator = a });
    defer pool.deinit();
    var binding = try E.work_pool.ScopedPoolBinding.init(&pool);
    defer binding.deinit();
    const selected = @import("../blake3_execution_parent_protocol.zig").Profile.csp_q70_pow26;
    const fixture = try Fixture.Owned.init(a, kind, selected.config());
    var fixture_live = true;
    defer if (fixture_live) fixture.deinit();
    const original = try Family.Original.produce(a, fixture.trusted, fixture.input(), fixture.current.?.owner.preprocessed.items, fixture.stages(), .{});
    var original_live = true;
    defer if (original_live) original.deinit();
    var input = fixture.input();
    input.native_roots = original.native_roots;
    input.caller_roots = original.caller_roots;
    const metadata = try Statement.Owned.init(a, fixture.trusted, input);
    defer metadata.deinit();
    const body = try Codec.encode(a, original, metadata.trusted, metadata.input, .{});
    defer a.free(body);
    original.deinit();
    original_live = false;
    fixture.deinit();
    fixture_live = false;
    var parent = blk: {
        var decoded = try Codec.decode(a, body, metadata.trusted, metadata.input, .{});
        defer decoded.deinit();
        var capture = try Family.Original.verifyAndCapture(a, metadata.trusted, metadata.input, &decoded.stark, decoded.claims, .{});
        defer capture.deinit();
        const profile = try Family.Profile.Owned.derive(a, metadata, decoded.claims, .{});
        defer profile.deinit();
        try std.testing.expectEqual(@as(usize, 15), profile.shape.columns.len);
        var composition = try Family.Composition.prepare(a, profile, &capture);
        defer composition.deinit();
        // Equal/opposite physical caller RAM claims preserve the total caller,
        // endpoint and global buses. Only replaying the actual per-descriptor
        // AIR recurrences rejects this forgery; a host aggregate receipt cannot.
        const values = try Family.Composition.publicValues(a, profile);
        defer a.free(values);
        const ram_start = values.len - 416 - profile.claims.caller_ram.len;
        try std.testing.expect(profile.claims.caller_ram.len >= 2);
        for (composition.sources, composition.inputs) |source, *value| if (source == .public_input) {
            if (source.public_input == ram_start) value.* = value.add(@import("stwo_core").fields.qm31.QM31.one());
            if (source.public_input == ram_start + 1) value.* = value.sub(@import("stwo_core").fields.qm31.QM31.one());
        };
        try std.testing.expectError(error.UnsatisfiedCircuit, composition.circuit.evaluateInto(composition.inputs, composition.values));
        for (composition.sources, composition.inputs) |source, *value| if (source == .public_input) {
            if (source.public_input == ram_start) value.* = value.sub(@import("stwo_core").fields.qm31.QM31.one());
            if (source.public_input == ram_start + 1) value.* = value.add(@import("stwo_core").fields.qm31.QM31.one());
        };
        try composition.circuit.evaluateInto(composition.inputs, composition.values);
        var replay = try Family.Transcript.replay(a, profile, &capture, 4);
        defer replay.deinit();
        if (!prove_parent) return;
        break :blk try Family.Pipeline.produce(a, profile, &capture, .{ .profile = selected });
    };
    defer parent.deinit();
    var fresh = try Family.Pipeline.verify(a, parent.bytes, parent.claims, metadata, .{}, .{ .profile = selected });
    defer fresh.deinit();
    try std.testing.expectEqual(.mixed_execution_global_ram_open, fresh.summary.scope);
    try std.testing.expect(fresh.summary.external_retirements > 0);
    try std.testing.expectEqualDeep(input.native_roots[2], fresh.summary.source.endpoint_root);
    std.debug.print("B8_MIXED_RECURSION kind={s} bytes={d} proof_ns={d} original_destroyed=true global_ram=open\n", .{ @tagName(kind), parent.bytes.len, parent.stats.proof_ns });
}
test "mixed typed recursion genuine SHA Keccak original canonical root" {
    try qualify(.sha_keccak, true);
}
test "mixed typed recursion genuine recovery original canonical root" {
    try qualify(.recovery, true);
}

test "hostile mixed typed opposite caller RAM claims preserve aggregate but fail equations" {
    try qualify(.sha_keccak, false);
    try qualify(.recovery, false);
}
