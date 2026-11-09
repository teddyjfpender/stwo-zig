//! Closed synthetic two-child recursion. Never authenticates an OP execution.
const std = @import("std");
const Core = @import("stwo_core");
const Engine = @import("stwo_prover_engine");
const Common = @import("../../rv64_recursion/om31_poseidon/common.zig");
const C = @import("../context.zig");
const K = @import("outer_authority.zig").Key;
const P = @import("outer_proof.zig");
const Fold = @import("fold.zig");
const Q = Core.fields.qm31.QM31;
const M = Core.fields.m31.M31;
const O = Core.fields.om31.OM31;
const profile = @import("../op_profile.zig").Profile.op_target_b4_q72_p0_fold4_v1;
pub fn source(a: std.mem.Allocator, seed: u32, terms: usize, trace_only: bool) !C.Context {
    var owner = if (trace_only) try C.Context.initTraceOnly(a, 9) else try C.Context.init(a, 9);
    errdefer owner.deinit();
    var structural = Common.lane.StructuralScope.init();
    defer structural.deinit();
    var mul = @import("../native_omul/scope.zig").begin();
    defer mul.deinit();
    var dot = @import("scope.zig").Scope.begin(&owner);
    defer dot.deinit();
    Common.begin(&owner);
    var active = true;
    defer if (active) Common.finish() catch {};
    const weight = try Common.F.guess(owner.algebra(), O.fromBase(M.fromCanonical(seed)));
    const scalar = try owner.base.guessM31(Q.fromBase(M.fromCanonical(3)));
    const weights = try a.alloc(Common.F, terms);
    defer a.free(weights);
    const scalars = try a.alloc(Common.Var, terms);
    defer a.free(scalars);
    @memset(weights, weight);
    @memset(scalars, scalar);
    const result = try @import("../../rv64_recursion/om31_native/deep_dot.zig").current().?(owner.algebra(), weights, scalars);
    var sponge = try @import("../sponge.zig").ForContext(C.Context).init(&owner, .words);
    try sponge.absorbConstU32(seed);
    try sponge.absorbMany(&.{ result.c0.v, result.c1.v });
    const output = try sponge.finish();
    try Common.finish();
    active = false;
    try owner.setOutputs(&output);
    try owner.finalizeForNativeDot();
    return owner;
}
pub fn outputs(owner: *C.Context) Fold.Digest {
    var out: Fold.Digest = undefined;
    for (&out, owner.base.circuit.output.items[1..]) |*v, id| v.* = owner.base.get(.{ .idx = id });
    return out;
}
fn rejectParent(a: std.mem.Allocator, pair: Fold.Source, key: *const K, name: []const u8) !void {
    var witness = try pair.buildForProving(a);
    defer witness.deinit();
    try std.testing.expect(!try witness.isCircuitValid());
    const expected = try pair.expectedOutput();
    try std.testing.expectError(error.PoseidonGlobalLookupSum, P.prove(a, &witness, key, &expected));
    std.debug.print("OP_R7_PARENT_MUTATION {s}=PoseidonGlobalLookupSum\n", .{name});
}
test "OP R7 recursive eight claim statement numerical two children and lifted new role" {
    const budget = try Engine.host_budget_allocator.SharedHostBudget.create(std.heap.smp_allocator, 24 << 30);
    defer budget.destroy();
    {
        const a = budget.allocator();
        var pool: Engine.work_pool.WorkPool = .{};
        try pool.initInPlaceWithOptions(.{ .worker_count = 8 });
        defer pool.deinit();
        var binding = try Engine.work_pool.ScopedPoolBinding.init(&pool);
        defer binding.deinit();
        var c0 = try source(a, 7, 3, false);
        defer c0.deinit();
        var c1 = try source(a, 19, 65537, false);
        defer c1.deinit();
        try std.testing.expect(try c0.isCircuitValid());
        try std.testing.expect(try c1.isCircuitValid());
        const out0 = outputs(&c0);
        const out1 = outputs(&c1);
        var k0 = try K.init(a, &c0, profile);
        defer k0.deinit();
        var k1 = try K.init(a, &c1, profile);
        defer k1.deinit();
        try std.testing.expect(k1.dot_log > k1.core.maxLog());
        const b0 = try P.prove(a, &c0, &k0, &out0);
        defer a.free(b0);
        const b1 = try P.prove(a, &c1, &k1, &out1);
        defer a.free(b1);
        // Independent source construction, not the producer keys.
        var f0 = try source(a, 7, 3, true);
        defer f0.deinit();
        var f1 = try source(a, 19, 65537, true);
        defer f1.deinit();
        var r0 = try K.init(a, &f0, profile);
        defer r0.deinit();
        var r1 = try K.init(a, &f1, profile);
        defer r1.deinit();
        var p0 = try P.verifyCaptured(a, &r0, &out0, b0);
        defer p0.deinit(a);
        var p1 = try P.verifyCaptured(a, &r1, &out1, b1);
        defer p1.deinit(a);
        const pair = Fold.Source{ .children = .{ .{ .key = &r0, .verified = &p0, .output = out0 }, .{ .key = &r1, .verified = &p1, .output = out1 } } };
        var parent = try pair.build(a, false);
        defer parent.deinit();
        try std.testing.expect(try parent.isCircuitValid());
        const counts = try @import("cpu_source_test.zig").Counts.derive(&parent);
        std.debug.print("OP_R7_PARENT_SOURCE raw={any} cells={}\n", .{ try parent.rawCountsForNativeDot(), counts.total_native_cells });
        // Full physical parent is explicit: routine source tests remain fast.
        if (std.posix.getenv("STWO_OP_R7_RECURSIVE_ARTIFACTS") == null) return;
        // Independent source-only composition: no claimed roots or child proof
        // bytes participate in the fresh key's construction.
        var fresh = try (Fold.TraceSource{ .keys = .{ &r0, &r1 } }).build(a);
        defer fresh.deinit();
        var receiver = try K.init(a, &fresh, profile);
        defer receiver.deinit();
        var producer = try K.init(a, &parent, profile);
        var owns_producer = true;
        defer if (owns_producer) producer.deinit();
        const identity = producer.core.base.identity;
        try std.testing.expectEqualSlices(u8, &identity, &receiver.core.base.identity);
        const root = try pair.expectedOutput();
        var timer = try std.time.Timer.start();
        const bytes = try P.prove(a, &parent, &producer, &root);
        defer a.free(bytes);
        const prove_ns = timer.lap();
        producer.deinit();
        owns_producer = false;
        try P.verify(a, &receiver, &root, bytes);
        const verify_ns = timer.lap();
        // Ordered source keys and all9 digest limbs remain independent authority.
        const swapped = try Fold.digest(out1, out0);
        try std.testing.expect(std.meta.isError(P.verify(a, &receiver, &swapped, bytes)));
        var missing = try (Fold.TraceSource{ .keys = .{ &r0, &r0 } }).build(a);
        defer missing.deinit();
        var missing_key = try K.init(a, &missing, profile);
        defer missing_key.deinit();
        try std.testing.expectError(error.InvalidNativeDotR7Authority, P.verify(a, &missing_key, &root, bytes));
        try std.testing.expectError(error.InvalidNativeDotR7Authority, P.verify(a, &r1, &out0, b0));
        // Coherent claim balancing preserves the global sum, but must still
        // fail each component's authenticated local AIR/PCS equation.
        var altered = p0;
        altered.claims[5] = altered.claims[5].add(O.one());
        altered.claims[6] = altered.claims[6].sub(O.one());
        const bad_pair = Fold.Source{ .children = .{ .{ .key = &r0, .verified = &altered, .output = out0 }, pair.children[1] } };
        try rejectParent(a, bad_pair, &receiver, "balanced_claims");
        const bad_frames = Fold.Source{ .children = .{ .{ .key = &r0, .verified = &p0, .output = out1 }, .{ .key = &r1, .verified = &p1, .output = out0 } } };
        try rejectParent(a, bad_frames, &receiver, "swapped_frames");
        const missing_frame = Fold.Source{ .children = .{ pair.children[0], .{ .key = &r1, .verified = &p1, .output = @splat(Q.zero()) } } };
        try rejectParent(a, missing_frame, &receiver, "missing_second_frame");
        p0.proof.commitment_scheme_proof.commitments.items[1][0] ^= 1;
        {
            defer p0.proof.commitment_scheme_proof.commitments.items[1][0] ^= 1;
            try rejectParent(a, pair, &receiver, "child_main_root_transcript");
        }
        var sha: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(bytes, &sha, .{});
        if (std.posix.getenv("STWO_OP_R7_RECURSIVE_ARTIFACTS")) |path| {
            try std.fs.cwd().makeDir(path);
            var dir = try std.fs.cwd().openDir(path, .{});
            defer dir.close();
            const write = @import("../../rv64_ethereum_batch_receipt.zig").writeExclusive;
            try write(dir, "child0.bin", b0);
            try write(dir, "child1.bin", b1);
            try write(dir, "parent.bin", bytes);
            const receipt = try std.json.Stringify.valueAlloc(a, .{ .schema = "op-r7-eight-role-recursive-parent-v2", .bytes = bytes.len, .sha256 = std.fmt.bytesToHex(sha, .lower), .source_identity = std.fmt.bytesToHex(identity, .lower), .cells = counts, .prove_ns = prove_ns, .fresh_verify_ns = verify_ns, .extra_role_exceeds_core = true, .physical_mutations = [_][]const u8{ "balanced_claims", "swapped_frames", "missing_second_frame", "child_main_root_transcript" }, .physical_error = "PoseidonGlobalLookupSum", .peak_live_bytes = budget.snapshot().peak_live_bytes, .cap_bytes = 24 << 30, .execution_root_admitted = false }, .{ .whitespace = .indent_2 });
            defer a.free(receipt);
            try write(dir, "receipt.json", receipt);
        }
        std.debug.print("OP_R7_PARENT_PHYSICAL bytes={} sha={s} prove_ns={} verify_ns={} peak={} cells={} identity={s}\n", .{ bytes.len, std.fmt.bytesToHex(sha, .lower), prove_ns, verify_ns, budget.snapshot().peak_live_bytes, counts.total_native_cells, std.fmt.bytesToHex(identity, .lower) });
    }
    try std.testing.expectEqual(@as(usize, 0), budget.snapshot().live_bytes);
}
