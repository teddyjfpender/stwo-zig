const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const tables = @import("../air/lookups/tables/mod.zig");
const proof_mod = @import("block_v5_native_lookup_proof_v1.zig");
const batch = @import("block_v5_native_lookup_batch_v1.zig");
const codec = @import("block_v5_native_lookup_codec_v1.zig");
const seal = @import("block_v5_source_seal_v1.zig");
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const Transport = struct {
    raw: []const u8,
    plan: proof_mod.Plan,
    config: core.pcs.PcsConfig,
    receipt: ?proof_mod.OpenReceipt = null,
    fn load(context: *anyopaque, index: u32) !proof_mod.Proof {
        const self: *Transport = @ptrCast(@alignCast(context));
        if (index != self.plan.index) return error.ForeignLookupGroup;
        return codec.decode(std.testing.allocator, self.raw, self.plan, self.config, .{});
    }
    fn accept(context: *anyopaque, plan: proof_mod.Plan, receipt: proof_mod.OpenReceipt) !void {
        const self: *Transport = @ptrCast(@alignCast(context));
        if (!std.meta.eql(plan, self.plan) or self.receipt != null) return error.ForeignLookupGroup;
        self.receipt = receipt;
    }
};

test "block-v5 global native lookup providers freshly verify all six typed tables" {
    const a = std.testing.allocator;
    var pool: engine.work_pool.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{ .worker_count = 4, .backing_allocator = a });
    defer pool.deinit();
    var bound = try engine.work_pool.ScopedPoolBinding.init(&pool);
    defer bound.deinit();
    var counters = try tables.counter.Set.init(a);
    defer counters.deinit(a);
    for (&counters.counters, 0..) |*counter, index|
        try counter.registerBase(if (index == 1) M.one().neg() else M.one(), (try tables.schema.tupleAt(counter.kind, index)).slice());
    const plan = proof_mod.Plan{ .index = 0, .first_execution = 0, .execution_count = 1, .max_requests = @splat(1) };
    var unsafe = plan;
    unsafe.max_requests[0] = core.fields.m31.Modulus;
    try std.testing.expectError(error.BlockV5LookupGroupExceedsField, unsafe.validate());
    const config = core.pcs.PcsConfig{ .pow_bits = 0, .fri_config = try core.fri.FriConfig.init(0, 1, 8) };
    const Api = proof_mod.ForBackend(Cpu);
    var too_small = plan;
    too_small.max_requests[0] = 0;
    try std.testing.expectError(error.BlockV5NativeLookupDemandExceeded, Api.commitFirstRound(a, &counters, too_small, config));
    var basis = try Api.FixedBasis.init(a, config);
    defer basis.deinit(a);
    var first = try Api.commitFirstRoundWithBasis(a, &counters, plan, &basis);
    defer first.deinit(a);
    {
        var repeated = try Api.commitFirstRoundWithBasis(a, &counters, plan, &basis);
        defer repeated.deinit(a);
        try std.testing.expectEqualDeep(first.roots, repeated.roots);
        try std.testing.expect(first.scheme.trees.items[0].shared_owner != null);
        try std.testing.expect(first.scheme.trees.items[0].shared_owner == repeated.scheme.trees.items[0].shared_owner);
        try std.testing.expect(first.scheme.trees.items[0].shared_owner == basis.scheme.trees.items[0].shared_owner);
    }
    var counts: [seal.family_count]u32 = @splat(0);
    inline for ([_]seal.Family{ .program, .execution, .execution_sidecar, .program_request, .memory, .native_lookup }) |kind| counts[@intFromEnum(kind) - 1] = 1;
    const pins = seal.Pins{ .job_id = @splat(1), .source_image_digest = @splat(2), .native_template_id = @splat(3), .program_root = @splat(4), .program_plan_digest = @splat(5), .memory_plan_digest = @splat(6), .initial_source_plan_digest = @splat(7), .config = config, .counts = counts };
    const entries = [_]seal.Entry{
        .{ .family = .program, .index = 0, .instance_id = @splat(10), .roots = .{ @splat(11), @splat(12) } },
        .{ .family = .execution, .index = 0, .instance_id = @splat(13), .roots = .{ @splat(14), @splat(15) } },
        .{ .family = .execution_sidecar, .index = 0, .instance_id = @splat(16), .roots = .{ @splat(17), @splat(18) } },
        .{ .family = .program_request, .index = 0, .instance_id = @splat(19), .roots = .{ @splat(20), @splat(21) } },
        .{ .family = .memory, .index = 0, .instance_id = @splat(22), .roots = .{ @splat(23), @splat(24) } },
        try first.entry(plan),
    };
    const sealed = try seal.seal(pins, &entries);
    const old = counters.counters[0].values[0];
    counters.counters[0].values[0] = old.add(M.one());
    try std.testing.expectError(error.BlockV5NativeLookupReplayMismatch, Api.prove(a, &first, &counters, plan, sealed, pins, &entries));
    counters.counters[0].values[0] = old;
    const roots = first.roots;
    var proved = try Api.prove(a, &first, &counters, plan, sealed, pins, &entries);
    const raw = try codec.encode(a, &proved, plan, .{});
    defer a.free(raw);
    proved.deinit(a);
    const trailing = try a.alloc(u8, raw.len + 1);
    defer a.free(trailing);
    @memcpy(trailing[0..raw.len], raw);
    trailing[raw.len] = 0;
    try std.testing.expectError(error.TrailingSectionBytes, codec.decode(a, trailing, plan, config, .{}));
    var foreign = plan;
    foreign.max_requests[0] += 1;
    try std.testing.expectError(error.UntrustedBlockV5LookupWirePlan, codec.decode(a, raw, foreign, config, .{}));
    var transport = Transport{ .raw = raw, .plan = plan, .config = config };
    try batch.receive(Cpu, a, .{ .context = &transport, .load = Transport.load }, .{ .context = &transport, .accept = Transport.accept }, &.{.{ .plan = plan, .roots = roots }}, sealed, pins, &entries);
    const receipt = transport.receipt.?;
    var channel = sealed.sharedChannel();
    const vm = try @import("../recursion/air/universal_challenges.zig").UniversalRelations.draw(a, &channel);
    const relations = try @import("../recursion/air/universal_provider_relations.zig").SharedProviderRelations.init(&vm);
    var oracle = Q.zero();
    for (&counters.counters, receipt.claims, 0..) |*counter, claim, index| {
        const entry = tables.interaction.tableEntry(counter.kind, try tables.schema.tupleAt(counter.kind, index), counter.values[index]);
        const expected = entry.numerator.mul(try (try entry.denominator(&relations.native)).inv());
        try std.testing.expectEqualDeep(expected, claim);
        oracle = oracle.add(expected);
    }
    try std.testing.expectEqualDeep(oracle, receipt.total);
    try std.testing.expectEqualDeep(sealed.digest, receipt.sealed_digest);
}
