//! Optional actual-block schema2 gate. Every native proof is regenerated against
//! the new common manifest; classic bytes are used only as negative controls.
const std = @import("std");
const engine = @import("stwo_prover_engine");
const Runtime = @import("pure_p2_op_runtime.zig");
const B = @import("pure_p2_op_bundle.zig");
const Local = @import("truth_local_gkr/worker.zig");
const Request = @import("../rv64_ethereum_request.zig");
const Profile = @import("pure_p2_worker_protocol.zig").Profile;
const O = @import("pure_p2_worker_protocol.zig").W.O;
const a = std.testing.allocator;
const Audit = struct {
    next: usize = 0,
    cpus: usize = 0,
    classic: usize = 0,
    local: usize = 0,
    finished: bool = false,
    fn self(raw: ?*anyopaque) *Audit {
        return @ptrCast(@alignCast(raw.?));
    }
    fn cpu(raw: ?*anyopaque, _: std.mem.Allocator, v: B.CpuVerified) !void {
        const state = self(raw);
        try std.testing.expectEqual(state.next, v.ordinal);
        try std.testing.expect(v.stage_one.local != null);
        state.cpus += 1;
        state.next += 1;
    }
    fn classicTruth(raw: ?*anyopaque, _: std.mem.Allocator, v: B.TruthVerified) !void {
        const state = self(raw);
        try std.testing.expectEqual(state.next, v.ordinal);
        try std.testing.expect(v.truth == .sha256 and v.stage_one.local == null);
        state.classic += 1;
        state.next += 1;
    }
    fn localTruth(raw: ?*anyopaque, _: std.mem.Allocator, v: B.LocalTruthVerified) !void {
        const state = self(raw);
        try std.testing.expectEqual(state.next, v.ordinal);
        try std.testing.expect(v.truth == .keccak and v.stage_one.local == null);
        try std.testing.expect(v.encoded.local.len > 0);
        try std.testing.expectEqualSlices(u8, &v.key.identity, &v.expected.fixed_identity);
        try std.testing.expect(!std.mem.eql(u8, &v.key.base.identity, &v.expected.fixed_identity));
        state.local += 1;
        state.next += 1;
    }
    fn complete(raw: ?*anyopaque, _: std.mem.Allocator, v: Runtime.CompleteVerified) !void {
        const state = self(raw);
        try std.testing.expectEqual(@as(u32, 2), v.metadata.schema);
        try std.testing.expectEqual(@as(usize, 3), state.next);
        try std.testing.expectEqual(@as(usize, 2), v.truth_local_keys.len);
        try std.testing.expect(v.truth_local_keys[0] != null and v.truth_local_keys[1] == null);
        state.finished = true;
    }
    fn hooks(state: *Audit) Runtime.ReceptionHooks {
        return .{ .context = state, .complete = complete, .fragments = .{ .context = state, .cpu = cpu, .truth = classicTruth, .truth_local = localTruth } };
    }
};
const Attack = struct {
    bundle: *B.Bundle,
    accepted: bool = false,
    fn run(raw: ?*anyopaque, alloc: std.mem.Allocator, source: Runtime.SourceDirectory) !void {
        const state: *Attack = @ptrCast(@alignCast(raw.?));
        var closed = try state.bundle.verifyWithHooksForTruthLocal(alloc, source.inventory, source.setups, source.requests, source.metadata.spans, source.cpu_keys, source.truths, source.truth_keys, source.miller, .{});
        defer closed.deinit(alloc);
        state.accepted = true;
    }
};

test "OP schema2 actual Keccak338 CPU and SHA join with fresh closure and strict policy" {
    const request_path = std.posix.getenv("STWO_OP_NATIVE_HOOK_REQUEST") orelse return error.SkipZigTest;
    const classic_path = std.posix.getenv("STWO_OP_NATIVE_HOOK_BUNDLE") orelse return error.SkipZigTest;
    const output = std.posix.getenv("STWO_OP_NATIVE_TRUTH_LOCAL_OUTPUT") orelse return error.SkipZigTest;
    const config_bytes = try std.fs.cwd().readFileAlloc(a, request_path, 16384);
    defer a.free(config_bytes);
    const parsed = try std.json.parseFromSlice(Request.Config, a, config_bytes, .{});
    defer parsed.deinit();
    const budget = try engine.host_budget_allocator.SharedHostBudget.create(a, 32 << 30);
    defer budget.destroy();
    const alloc = budget.allocator();
    var pool: engine.work_pool.WorkPool = .{};
    try pool.initInPlaceWithOptions(.{ .worker_count = 8 });
    defer pool.deinit();
    var binding = try engine.work_pool.ScopedPoolBinding.init(&pool);
    defer binding.deinit();
    const profile = Profile.op_target_b4_q72_p0_fold4_v1;
    const resources = Runtime.Resources{ .park_cpu_metadata = std.posix.getenv("STWO_OP_NATIVE_METADATA_PARKING") != null, .retire_source_auxiliaries = std.posix.getenv("STWO_OP_NATIVE_SOURCE_RETIREMENT") != null };
    const options = Runtime.Options{ .truth_local_gkr = true };
    try Runtime.produceDirectoryWithOptions(alloc, parsed.value, output, profile, resources, options);
    try std.testing.expectEqual(@as(usize, 0), budget.snapshot().live_bytes);
    var audit: Audit = .{};
    try Runtime.verifyDirectoryWithOptions(alloc, parsed.value, output, profile, resources, options, audit.hooks());
    try std.testing.expect(audit.finished and audit.cpus == 1 and audit.classic == 1 and audit.local == 1);
    try std.testing.expectEqual(@as(usize, 0), budget.snapshot().live_bytes);
    try std.testing.expectError(error.OpNativeSchemaPolicy, Runtime.verifyDirectory(alloc, parsed.value, output, profile, resources));
    try std.testing.expectError(error.OpNativeSchemaPolicy, Runtime.verifyDirectoryWithOptions(alloc, parsed.value, classic_path, profile, resources, options, .{}));
    {
        var dir = try std.fs.cwd().openDir(output, .{});
        defer dir.close();
        const bytes = try dir.readFileAlloc(alloc, "native-op.bin", resources.bundle_bytes);
        defer alloc.free(bytes);
        var bundle = try B.decode(alloc, bytes, 3, .{ .bytes = resources.bundle_bytes, .proof_bytes = resources.proof_bytes });
        defer bundle.deinit(alloc);
        const saved_claim = bundle.proofs[1].claims[0];
        bundle.proofs[1].claims[0] = saved_claim.add(O.one());
        var duplicate = Attack{ .bundle = &bundle };
        try std.testing.expectError(error.OpTruthLocalClaimEnvelope, Runtime.withSourceDirectoryWithOptions(alloc, parsed.value, output, profile, resources, options, &duplicate, Attack.run));
        try std.testing.expect(!duplicate.accepted);
        bundle.proofs[1].claims[0] = saved_claim;
        {
            var local = try Local.decode(alloc, bundle.proofs[1].bytes, resources.proof_bytes);
            defer local.deinit(alloc);
            local.receipt[35] ^= 1;
            const altered = try Local.encode(alloc, &local);
            defer alloc.free(altered);
            const original = bundle.proofs[1].bytes;
            bundle.proofs[1].bytes = altered;
            defer bundle.proofs[1].bytes = original;
            var receipt = Attack{ .bundle = &bundle };
            try std.testing.expectError(error.LocalGkrReceiptMismatch, Runtime.withSourceDirectoryWithOptions(alloc, parsed.value, output, profile, resources, options, &receipt, Attack.run));
            try std.testing.expect(!receipt.accepted);
        }
        {
            var classic_dir = try std.fs.cwd().openDir(classic_path, .{});
            defer classic_dir.close();
            const old_bytes = try classic_dir.readFileAlloc(alloc, "native-op.bin", resources.bundle_bytes);
            defer alloc.free(old_bytes);
            var old = try B.decode(alloc, old_bytes, 3, .{ .bytes = resources.bundle_bytes, .proof_bytes = resources.proof_bytes });
            defer old.deinit(alloc);
            const regenerated = bundle.proofs[0];
            bundle.proofs[0] = old.proofs[0];
            defer bundle.proofs[0] = regenerated;
            var swap = Attack{ .bundle = &bundle };
            try std.testing.expect(std.meta.isError(Runtime.withSourceDirectoryWithOptions(alloc, parsed.value, output, profile, resources, options, &swap, Attack.run)));
            try std.testing.expect(!swap.accepted);
        }
    }
    try std.testing.expectEqual(@as(usize, 0), budget.snapshot().live_bytes);
    try std.testing.expectEqual(@as(usize, 0), budget.snapshot().external_live_bytes);
    std.debug.print("OP_SCHEMA2_ACTUAL steps=796406 CPU=1 local_Keccak=338 classic_SHA=34 fresh=true closure=RAM_KIO_Wire strict_schema=true tamper=claims_receipt_old_CPU final_heap=0\n", .{});
}
