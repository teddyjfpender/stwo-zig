//! Actual retained native fragments supply untrusted root metadata. Preparation
//! is an obligation, never acceptance: changed expected frames must still be
//! rejected by the physical grouped root receiver.
const std = @import("std");
const E = @import("stwo_prover_engine");
const core = @import("stwo_core");
const Runtime = @import("runtime.zig");
const Receiver = @import("receiver.zig");
const Root = @import("root_admission.zig");
const Leaf = @import("../pure_p2_op_root_receiver.zig").Leaf;
const Fold = @import("../native_omul/fold.zig");
const N = @import("../pure_p2_native.zig");
const O = core.fields.om31.OM31;
const State = struct {
    leaves: ?[]Leaf = null,
    frames: ?[]Fold.Digest = null,
    made: usize = 0,
    controls: u32 = 0,
    completed: bool = false,
    fn deinit(self: *State, a: std.mem.Allocator) void {
        if (self.leaves) |leaves| {
            for (leaves[0..self.made]) |leaf| a.free(leaf.claims);
            a.free(leaves);
        }
        if (self.frames) |frames| a.free(frames);
        self.* = .{};
    }
    fn digest(a: std.mem.Allocator, words: []u32) !Fold.Digest {
        defer a.free(words);
        var out: Fold.Digest = undefined;
        for (&out, try core.crypto.poseidon2_m31_sponge.decode(N.hashWords(words))) |*v, value| v.* = core.fields.qm31.QM31.fromBase(value);
        return out;
    }
    fn fragment(raw: ?*anyopaque, a: std.mem.Allocator, value: Receiver.Verified) !void {
        const self: *State = @ptrCast(@alignCast(raw.?));
        if (self.leaves == null) {
            self.leaves = try a.alloc(Leaf, value.manifest.entries.len);
            self.frames = try a.alloc(Fold.Digest, value.manifest.entries.len);
        }
        try std.testing.expectEqual(self.made, value.ordinal);
        const ordinal: u32 = @intCast(value.ordinal);
        const manifest = value.manifest.digest;
        const words, const claims, const receipt = switch (value.source) {
            .cpu => |source| .{ try @import("statement.zig").expectedWords(a, source.value.setup, source.value.request, source.value.span, source.first, source.value.key, .{ .ordinal = ordinal, .statement = try source.value.key.statement(source.value.setup, source.value.request, source.first, source.value.span, ordinal) }, manifest, value.main, source.encoded.receipt, source.encoded.claims), source.encoded.claims, @as(?[36]u8, source.encoded.receipt) },
            .detached => |source| .{ try @import("../sponge_local_gkr/statement.zig").expectedWords(a, source.value.key, source.value.geometry, ordinal, manifest, value.main, source.encoded.receipt, source.encoded.claims), @as(*const [24]O, @ptrCast(&source.encoded.claims))[0..], @as(?[36]u8, source.encoded.receipt) },
            .catalog => |source| .{ try @import("../pure_p2_truth_statement.zig").expectedWords(a, source.value.key, source.value.truth, try source.value.key.expected(source.value.truth, ordinal), manifest, value.main, source.encoded.claims), source.encoded.claims, @as(?[36]u8, null) },
            .local_catalog => |source| .{ try @import("../truth_local_gkr/statement.zig").expectedWords(a, source.value.local_key.?, source.value.truth, try source.value.local_key.?.expected(source.value.truth, ordinal), manifest, value.main, source.encoded.receipt, source.encoded.claims), source.encoded.claims[0..], @as(?[36]u8, source.encoded.receipt) },
            .miller => |source| .{ try @import("../pure_p2_tower_statement.zig").expectedWords(a, source.value.key, source.value.span, try source.value.key.expected(source.value.span, ordinal), manifest, value.main, source.encoded.claims), source.encoded.claims[0..], @as(?[36]u8, null) },
            .local_miller => |source| .{ try @import("../miller_local_gkr/statement.zig").expectedWords(a, source.value.local_key.?, source.value.span, try source.value.local_key.?.expected(source.value.span, ordinal), manifest, value.main, source.encoded.receipt, source.encoded.claims), source.encoded.claims[0..], @as(?[36]u8, source.encoded.receipt) },
        };
        self.frames.?[value.ordinal] = try digest(a, words);
        self.leaves.?[value.ordinal] = .{ .ordinal = ordinal, .main = value.main, .receipt = receipt, .claims = try a.dupe(O, claims) };
        self.made += 1;
    }
    fn rejectsOrChanges(a: std.mem.Allocator, authority: Root.Authority, metadata: Root.Metadata, expected: Fold.Digest) !void {
        var result = Root.prepare(a, authority, metadata);
        if (result) |*prepared| {
            defer prepared.deinit();
            if (std.meta.eql(try prepared.expectedRoot(), expected)) return error.UnchangedRootAfterMetadataMutation;
        } else |_| {}
    }
    fn complete(raw: ?*anyopaque, a: std.mem.Allocator, source: Runtime.SourceDirectory, closed: *const Receiver.Closed) !void {
        const self: *State = @ptrCast(@alignCast(raw.?));
        const authority = Root.Authority{ .inventory = source.inventory, .cpus = source.authority.cpu, .detached = source.authority.detached, .catalog = source.authority.catalogs, .towers = source.authority.catalog.miller, .image = source.image };
        const leaves = self.leaves.?;
        var metadata = Root.Metadata{ .execution = source.inventory.execution, .manifest = closed.pending.digest, .leaves = leaves };
        var prepared = try Root.prepare(a, authority, metadata);
        defer prepared.deinit();
        try std.testing.expectEqual(self.made, prepared.outputs.len);
        for (prepared.outputs, self.frames.?) |actual, expected| try std.testing.expectEqualDeep(expected, actual);
        const expected_root = try Fold.treeDigest(a, self.frames.?);
        try std.testing.expectEqualDeep(expected_root, try prepared.expectedRoot());
        const control = metadata;
        metadata.execution[0] ^= 1;
        try rejectsOrChanges(a, authority, metadata, expected_root);
        self.controls += 1;
        metadata = control;
        metadata.manifest = N.hashWords(&.{987});
        try rejectsOrChanges(a, authority, metadata, expected_root);
        self.controls += 1;
        metadata = control;
        metadata.leaves = leaves[0 .. leaves.len - 1];
        try rejectsOrChanges(a, authority, metadata, expected_root);
        self.controls += 1;
        metadata = control;
        leaves[0].ordinal += 1;
        try rejectsOrChanges(a, authority, metadata, expected_root);
        self.controls += 1;
        leaves[0].ordinal -= 1;
        std.mem.swap(Leaf, &leaves[0], &leaves[1]);
        try rejectsOrChanges(a, authority, metadata, expected_root);
        self.controls += 1;
        std.mem.swap(Leaf, &leaves[0], &leaves[1]);
        const saved = leaves[0].receipt;
        leaves[0].receipt = null;
        try rejectsOrChanges(a, authority, metadata, expected_root);
        self.controls += 1;
        leaves[0].receipt = saved;
        const d = source.authority.cpu.len;
        if (source.authority.detached.len != 0) {
            const original = leaves[d].receipt;
            leaves[d].receipt = N.hashWords(&.{989});
            try rejectsOrChanges(a, authority, metadata, expected_root);
            self.controls += 1;
            leaves[d].receipt = original;
            // These two Wire debts cancel globally, but their authenticated
            // physical frame digests must change even if preparation succeeds.
            const cpu_claims = @constCast(leaves[0].claims);
            const d_claims = @constCast(leaves[d].claims);
            const c = cpu_claims.len - 1;
            const before = cpu_claims[c];
            const other = d_claims[2];
            cpu_claims[c] = before.add(O.one());
            d_claims[2] = other.sub(O.one());
            try rejectsOrChanges(a, authority, metadata, expected_root);
            self.controls += 1;
            cpu_claims[c] = before;
            d_claims[2] = other;
        }
        var image = source.image.*;
        image.expected_output[0] ^= 1;
        var wrong = authority;
        wrong.image = &image;
        try std.testing.expectError(error.EthereumOutputMismatch, Root.prepare(a, wrong, metadata));
        self.controls += 1;
        var final = try Root.prepare(a, authority, metadata);
        defer final.deinit();
        try std.testing.expectEqualDeep(expected_root, try final.expectedRoot());
        self.completed = true;
    }
};
test "detached actual retained native root obligations independent frames and balanced debt" {
    const path = std.posix.getenv("STWO_OP_DETACHED_CONFIG") orelse return error.SkipZigTest;
    const out = std.posix.getenv("STWO_OP_DETACHED_OUT") orelse return error.MissingOpNativeDirectory;
    const raw = try std.fs.cwd().readFileAlloc(std.testing.allocator, path, 16384);
    defer std.testing.allocator.free(raw);
    const parsed = try std.json.parseFromSlice(@import("../../rv64_ethereum_request.zig").Config, std.testing.allocator, raw, .{});
    defer parsed.deinit();
    if (parsed.value.max_steps > 10_000_000) return error.SmallCapturePlanControlRequired;
    const budget = try E.host_budget_allocator.SharedHostBudget.create(std.heap.smp_allocator, 32 << 30);
    defer budget.destroy();
    var pool: E.work_pool.WorkPool = .{};
    try pool.initInPlaceWithOptions(.{ .worker_count = 8 });
    defer pool.deinit();
    var binding = try E.work_pool.ScopedPoolBinding.init(&pool);
    defer binding.deinit();
    var state = State{};
    {
        defer state.deinit(budget.allocator());
        try Runtime.verifyDirectoryWithHooks(budget.allocator(), parsed.value, out, .op_target_b4_q72_p0_fold4_v1, .{}, .{ .context = &state, .complete = State.complete, .fragments = .{ .context = &state, .fragment = State.fragment } });
        try std.testing.expect(state.completed);
        try std.testing.expectEqual(@as(u32, 9), state.controls);
    }
    try std.testing.expectEqual(@as(usize, 0), budget.snapshot().live_bytes);
    try std.testing.expectEqual(@as(usize, 0), budget.snapshot().external_live_bytes);
    std.debug.print("OP_DETACHED_ROOT_OBLIGATIONS all_frames=true controls=9 live=0 external=0 peak={} root_acceptance=false\n", .{budget.snapshot().peak_live_bytes});
}
