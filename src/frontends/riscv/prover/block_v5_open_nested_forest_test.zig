//! Five actual lightweight native leaves, genuine quartet then exact outer
//! recursion. The production receive seam reconstructs the DAG independently.
const std = @import("std");
const core = @import("stwo_core");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const runner = @import("../runner/mod.zig");
const Fixture = @import("block_v5_lightweight_native_proof_test.zig").Fixture;
const native = @import("block_v5_native_execution_proof_v3.zig");
const admission = @import("block_v5_native_recursive_admission_v3.zig");
const seals = @import("block_v5_source_seal_v1.zig");
const catalog_mod = @import("block_v5_native_template_catalog_v1.zig");
const parent = @import("../recursion/blake3_execution_parent_proof.zig");
const leaf_bus = @import("../recursion/block_v5_recursive_public_bus_v1.zig");
const leaf_protocol = @import("../recursion/block_v5_reusable_native_parent_protocol_v1.zig");
const leaf_receiver = @import("../recursion/block_v5_reusable_native_leaf_v1.zig");
const normalized = @import("../recursion/block_v5_open_child_frames_v2.zig");
const bus = @import("../recursion/block_v5_open_parent_public_bus_v2.zig");
const protocol = @import("../recursion/block_v5_reusable_open_parent_protocol_v2.zig");
const preparation = @import("../recursion/block_v5_open_parent_preparation_v2.zig");
const exact = @import("../recursion/block_v5_open_exact_forest_receiver_v1.zig");
const parent_verifier = @import("../recursion/blake3_native_parent_verifier.zig");
const Api = native.ForBackend(Cpu);
const Fold = struct {
    prepared: preparation.Prepared,
    key: protocol.Key,
    policy: protocol.Admission,
    equation: parent_verifier.Verified,
    bytes: []u8,
    a: std.mem.Allocator,
    fn deinit(self: *Fold) void {
        self.equation.deinit();
        self.a.free(self.bytes);
        self.prepared.deinit();
    }
};
fn proveFold(a: std.mem.Allocator, purpose: bus.Purpose, children: []const normalized.Child, captures: []const *const parent_verifier.Verified) !Fold {
    var prepared = try preparation.prepare(a, purpose, children, captures, 2);
    errdefer prepared.deinit();
    const key = try protocol.Key.fromGeometry(try parent.ForBackend(Cpu).deriveKey(a, &prepared.recursive), prepared.wires);
    const policy = try protocol.Admission.init(key, try key.identity(), prepared.wires, prepared.values);
    const Plan = @import("../recursion/blake3_native_parent_producer.zig").PlanForProtocol(Cpu, protocol);
    const plan = try Plan.init(a, &prepared.recursive.rows, policy);
    defer plan.deinit();
    var artifact = try plan.prove(a, &prepared.recursive.rows);
    defer artifact.deinit();
    const bytes = try parent.codec.encode(a, &artifact, &policy);
    errdefer a.free(bytes);
    var owned = try parent.codec.decode(a, bytes, &policy);
    var equation = try parent.verify(&owned, &policy);
    errdefer equation.deinit();
    try equation.validate(&policy, policy.expected_id);
    return .{ .prepared = prepared, .key = key, .policy = policy, .equation = equation, .bytes = bytes, .a = a };
}
const Loader = struct {
    bytes: []const u8,
    pub fn load(self: Loader, a: std.mem.Allocator) ![]u8 {
        return a.dupe(u8, self.bytes);
    }
};

fn qualify(comptime staged_files: bool, comptime incremental: bool) !void {
    const COUNT = if (incremental) 8 else 5;
    const a = std.testing.allocator;
    const file_stage = @import("block_v5_open_forest_stage_v1.zig");
    const manifest = @import("block_v5_open_forest_manifest_v1.zig");
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var leaf_files: [COUNT]file_stage.LeafFile = undefined;
    var instructions: [COUNT + 1]u32 = undefined;
    for (0..COUNT) |i| instructions[i] = (@as(u32, @intCast(i + 1)) << 20) | 0x0093;
    instructions[COUNT] = 0x0000006f;
    const elf = @import("../runner/guest_precompile/test_elf.zig").buildProgram(instructions.len, &instructions, 0, .rv32im_zkvm_v1);
    var session = try runner.BaseExecutionSession.init(a, &elf, .{ .trace_retention = .segment_owned, .clock_frame = .leaf_local });
    defer session.deinit();
    var segments: [COUNT]@import("../runner/result.zig").SegmentResult = undefined;
    var segment_count: usize = 0;
    defer for (segments[0..segment_count]) |*segment| segment.deinit();
    for (0..COUNT) |i| {
        segments[i] = if (i == 0) try session.startSegment(1) else try session.resumeSegment(segments[i - 1].continuation.?, 1);
        segment_count += 1;
    }
    var counts: [seals.family_count]u32 = @splat(0);
    counts[@intFromEnum(seals.Family.program) - 1] = 1;
    counts[@intFromEnum(seals.Family.execution) - 1] = COUNT;
    counts[@intFromEnum(seals.Family.execution_sidecar) - 1] = COUNT;
    counts[@intFromEnum(seals.Family.program_request) - 1] = COUNT;
    counts[@intFromEnum(seals.Family.memory) - 1] = 1;
    var pins = seals.Pins{ .job_id = @splat(1), .source_image_digest = @splat(2), .program_root = @splat(3), .program_plan_digest = @splat(4), .memory_plan_digest = @splat(5), .initial_source_plan_digest = @splat(6), .rw_endpoint_plan_digest = @splat(25), .native_template_catalog_digest = @splat(26), .config = parent.protocol.PCS_CONFIG, .counts = counts };
    var fixtures: [COUNT]Fixture = undefined;
    var fixture_count: usize = 0;
    defer for (fixtures[0..fixture_count]) |*fixture| fixture.deinit();
    var rounds: [COUNT]Api.FirstRound = undefined;
    var round_count: usize = 0;
    defer for (rounds[0..round_count]) |*round| round.deinit(a);
    var records: [COUNT]catalog_mod.Record = undefined;
    for (0..COUNT) |i| {
        fixtures[i] = try Fixture.init(a, &segments[i], pins);
        fixture_count += 1;
        rounds[i] = try Api.commitFirstRound(a, fixtures[i].owner, fixtures[i].pin, pins.config, .rv32im_zkvm_v1, @intCast(i));
        round_count += 1;
        records[i] = .{ .index = @intCast(i), .template_id = rounds[i].template_id, .geometry_digest = rounds[i].template.geometry_digest, .fixed_root = rounds[i].roots[0] };
        try std.testing.expectEqualDeep(rounds[0].template_id, rounds[i].template_id);
    }
    const catalog = catalog_mod.Admission{ .records = &records };
    pins.native_template_catalog_digest = try catalog.digest();
    var entries: std.ArrayList(seals.Entry) = .empty;
    defer entries.deinit(a);
    try entries.append(a, .{ .family = .program, .index = 0, .instance_id = @splat(7), .roots = .{ @splat(8), @splat(9) } });
    for (&rounds) |*round| try entries.append(a, round.entry());
    for (0..COUNT) |i| try entries.append(a, .{ .family = .execution_sidecar, .index = @intCast(i), .instance_id = @splat(@as(u8, @intCast(10 + i))), .roots = .{ @splat(@as(u8, @intCast(20 + i))), @splat(@as(u8, @intCast(30 + i))) } });
    for (0..COUNT) |i| try entries.append(a, .{ .family = .program_request, .index = @intCast(i), .instance_id = @splat(@as(u8, @intCast(40 + i))), .roots = .{ @splat(@as(u8, @intCast(50 + i))), @splat(@as(u8, @intCast(60 + i))) } });
    try entries.append(a, .{ .family = .memory, .index = 0, .instance_id = @splat(70), .roots = .{ @splat(71), @splat(72) } });
    const sealed = try seals.seal(pins, entries.items);
    var native_policies: [COUNT]admission.Prepared = undefined;
    var policy_count: usize = 0;
    defer for (native_policies[0..policy_count]) |*policy| policy.deinit();
    var native_captures: [COUNT]native.VerifiedCapture = undefined;
    var native_count: usize = 0;
    defer for (native_captures[0..native_count]) |*capture| capture.deinit();
    var leaf_equations: [COUNT]leaf_receiver.OpenEquation = undefined;
    var leaf_count: usize = 0;
    defer for (leaf_equations[0..leaf_count]) |*equation| equation.deinit();
    var children: [COUNT]normalized.Child = undefined;
    var child_count: usize = 0;
    defer for (children[0..child_count]) |*child| child.deinit();
    var expected: [COUNT]exact.LeafPolicy = undefined;
    var leaf_schedule: ?[]leaf_bus.Wire = null;
    defer if (leaf_schedule) |owned| a.free(owned);
    const LeafPlan = @import("../recursion/blake3_native_parent_producer.zig").PlanForProtocol(Cpu, leaf_protocol);
    var leaf_plan: ?*LeafPlan = null;
    defer if (leaf_plan) |owned| owned.deinit();
    var key_id: ?[32]u8 = null;
    var leaf_bytes: usize = 0;
    var open_sum = core.fields.qm31.QM31.zero();
    const pins_public = exact.OuterPins{ .job_id = pins.job_id, .source_image_digest = pins.source_image_digest, .sealed_digest = sealed.digest, .segment_count = COUNT, .first_cycle = segments[0].global_first_cycle, .last_cycle = segments[COUNT - 1].global_first_cycle + segments[COUNT - 1].cycle_count - 1, .initial_pc = fixtures[0].owner.statement.initial_pc, .final_pc = fixtures[COUNT - 1].owner.statement.final_pc };
    const stage_options = file_stage.Options{ .profile = .diagnostic_q8_pow0, .lane_count = if (incremental) 1 else 2, .total_host_limit = 12 * 1024 * 1024 * 1024, .max_execution_count = COUNT, .max_proof_bytes = 64 * 1024 * 1024, .pool_workers_per_lane = 2 };
    var stream: ?*file_stage.Stream = if (incremental) try file_stage.Stream.start(a, tmp.dir, pins_public, stage_options) else null;
    defer if (stream) |active| active.abort();
    for (0..COUNT) |i| {
        const native_proof = try Api.proveWithCatalog(a, &rounds[i], sealed, pins, entries.items, catalog);
        native_captures[i] = try Api.verifyCaptureOwnedWithCatalog(a, native_proof, &fixtures[i].owner.statement, fixtures[i].pin, rounds[i].template, rounds[i].template_id, .rv32im_zkvm_v1, @intCast(i), sealed, pins, entries.items, catalog);
        native_count += 1;
        native_policies[i] = try admission.Prepared.init(a, &fixtures[i].owner.statement, fixtures[i].pin, rounds[i].template, rounds[i].template_id, @intCast(i), sealed, pins, entries.items, catalog);
        policy_count += 1;
        var prepared = try leaf_bus.prepare(a, &native_policies[i], &native_captures[i], 2);
        defer prepared.deinit();
        const key = try leaf_protocol.Key.fromGeometry(try parent.ForBackend(Cpu).deriveKey(a, &prepared.recursive), prepared.wires);
        const id = try key.identity();
        if (leaf_schedule == null) leaf_schedule = try a.dupe(leaf_bus.Wire, prepared.wires);
        const policy = try leaf_protocol.Admission.init(key, id, leaf_schedule.?, prepared.values);
        if (key_id) |previous| {
            try std.testing.expectEqualDeep(previous, id);
            try std.testing.expect(try leaf_plan.?.tryRebindAdmission(&prepared.recursive.rows, policy));
        } else {
            key_id = id;
            leaf_plan = try LeafPlan.init(a, &prepared.recursive.rows, policy);
        }
        var artifact = try leaf_plan.?.prove(a, &prepared.recursive.rows);
        defer artifact.deinit();
        const bytes = try parent.codec.encode(a, &artifact, &policy);
        defer a.free(bytes);
        leaf_bytes += bytes.len;
        if (!staged_files) {
            leaf_equations[i] = try leaf_receiver.verify(a, bytes, key, id, leaf_schedule.?, &native_policies[i], native_captures[i].receipt);
            leaf_count += 1;
        }
        expected[i] = .{ .native = &native_policies[i], .exported = native_captures[i].receipt, .recursive_key = key, .recursive_key_id = id, .recursive_schedule = leaf_schedule.? };
        if (staged_files) {
            var name_buffer: [80]u8 = undefined;
            leaf_files[i] = .{ .policy = expected[i], .file = try file_stage.writeProof(tmp.dir, try file_stage.leafPath(@intCast(i), &name_buffer), bytes, 1024 * 1024) };
            if (incremental) {
                const active = stream.?;
                if (i == 0) {
                    var wrong_file = leaf_files[i];
                    wrong_file.file.sha256[0] ^= 1;
                    try std.testing.expectError(error.TamperedV5OpenProofFile, active.submit(@intCast(i), wrong_file));
                    try std.testing.expectEqual(@as(usize, 0), active.progress().submitted);
                    var wrong_key = leaf_files[i];
                    wrong_key.policy.recursive_key_id[0] ^= 1;
                    try std.testing.expectError(error.UntrustedReusableNativeParentKey, active.submit(@intCast(i), wrong_key));
                }
                try active.submit(@intCast(i), leaf_files[i]);
                try std.testing.expectError(error.InvalidMixedForestLeafPublication, active.submit(@intCast(i), leaf_files[i]));
                if (i == 3) {
                    // The first genuine fold publishes before the remaining
                    // native/base leaves even start their second-pass proof.
                    try active.waitForParents(1);
                    try std.testing.expectEqual(@as(usize, 4), active.progress().submitted);
                    try std.testing.expectEqual(@as(usize, 1), active.progress().completed);
                }
            }
        }
        if (!staged_files) {
            children[i] = try normalized.fromNative(a, &native_policies[i], native_captures[i].receipt, key, id, leaf_schedule.?);
            child_count += 1;
        }
        open_sum = open_sum.add(native_captures[i].receipt.open_sum);
    }
    if (staged_files) {
        leaf_plan.?.deinit();
        leaf_plan = null;
        var wrong_security = expected[0].recursive_key;
        wrong_security.config = parent.protocol.CSP_CONFIG;
        try std.testing.expectError(error.NativeV5RecursiveSecurityMismatch, leaf_receiver.verify(a, &.{}, wrong_security, expected[0].recursive_key_id, expected[0].recursive_schedule, expected[0].native, expected[0].exported));
        wrong_security = expected[0].recursive_key;
        wrong_security.context.child_config = parent.protocol.CSP_CONFIG;
        try std.testing.expectError(error.NativeV5RecursiveSecurityMismatch, normalized.fromNative(a, expected[0].native, expected[0].exported, wrong_security, expected[0].recursive_key_id, expected[0].recursive_schedule));
        var staged = if (incremental) done: {
            const result = try stream.?.finish();
            stream = null;
            break :done result;
        } else try file_stage.prove(a, tmp.dir, &leaf_files, pins_public, stage_options);
        defer staged.deinit();
        if (incremental) {
            try std.testing.expectEqual(@as(usize, 3), staged.parents.len);
            try std.testing.expect(staged.setup_cache_stats.hits >= 1);
            try std.testing.expectEqualDeep(staged.parents[0].node.expected_id, staged.parents[1].node.expected_id);
            try std.testing.expect(!std.meta.eql(staged.parents[0].file.sha256, staged.parents[1].file.sha256));
            std.debug.print("BLOCK_V5_INCREMENTAL_OPEN cache_hits={d} cache_misses={d} first_fold_before_remaining_native=true native_leaves=8 setup_reused=true dynamic_admission=true peak_bytes={d}\n", .{ staged.setup_cache_stats.hits, staged.setup_cache_stats.misses, staged.stage_owned_peak_bytes });
        }
        const limits = manifest.Limits{ .max_execution_count = COUNT, .max_manifest_bytes = 64 * 1024 * 1024, .max_proof_bytes = 64 * 1024 * 1024 };
        // Provisional setup proposals are captured before reading transport;
        // production Complete obtains this policy from its independent scheduler.
        const independent = try a.alloc(exact.NodePin, staged.parents.len);
        defer a.free(independent);
        for (staged.parents, independent) |pin, *node| node.* = pin.node;
        const digest = try manifest.write(a, tmp.dir, &staged, &leaf_files, .diagnostic_q8_pow0, limits);
        var received = try manifest.verifyDetached(a, tmp.dir, digest, &expected, independent, staged.outer.node, pins_public, open_sum, limits);
        defer received.deinit();
        try std.testing.expectEqual(@as(u32, COUNT), received.execution_count);
        try std.testing.expect(received.combined_native_open_sum.eql(open_sum));
        var wrong_digest = digest;
        wrong_digest[0] ^= 1;
        try std.testing.expectError(error.TamperedV5OpenManifest, manifest.verifyDetached(a, tmp.dir, wrong_digest, &expected, independent, staged.outer.node, pins_public, open_sum, limits));
        var wrong_policy = staged.outer.node;
        wrong_policy.expected_id[0] ^= 1;
        try std.testing.expectError(error.UntrustedV5DetachedRecursivePolicy, manifest.verifyDetached(a, tmp.dir, digest, &expected, independent, wrong_policy, pins_public, open_sum, limits));
        var file = try tmp.dir.openFile(file_stage.OUTER_FILE, .{ .mode = .read_write });
        defer file.close();
        var first: [1]u8 = undefined;
        try file.seekTo(0);
        _ = try file.readAll(&first);
        first[0] ^= 1;
        try file.seekTo(0);
        try file.writeAll(&first);
        try file.sync();
        try std.testing.expectError(error.TamperedV5OpenProofFile, manifest.verifyDetached(a, tmp.dir, digest, &expected, independent, staged.outer.node, pins_public, open_sum, limits));
        std.debug.print("BLOCK_V5_OPEN_FILE_FOREST verified=true native_leaves=5 fold_levels=2 exact_roots=4+1 parents={d} outer_bytes={d} leaf_bytes={d} stage_owned_peak_bytes={d} host_limit_bytes={d} detached_manifest=true changed_policy_rejected=true transport_tamper_rejected=true global_claims_open=true\n", .{ staged.parents.len, staged.outer.file.byte_len, leaf_bytes, staged.stage_owned_peak_bytes, @as(usize, 12 * 1024 * 1024 * 1024) });
        return;
    }
    const quartet_captures = [_]*const parent_verifier.Verified{ &leaf_equations[0].equation, &leaf_equations[1].equation, &leaf_equations[2].equation, &leaf_equations[3].equation };
    var quartet = try proveFold(a, .local, children[0..4], &quartet_captures);
    defer quartet.deinit();
    var quartet_child = try normalized.fromOpenV2(a, quartet.policy);
    defer quartet_child.deinit();
    const roots = [_]normalized.Child{ quartet_child, children[4] }; // borrowed snapshots
    const root_captures = [_]*const parent_verifier.Verified{ &quartet.equation, &leaf_equations[4].equation };
    var outer = try proveFold(a, .exact_outer, &roots, &root_captures);
    defer outer.deinit();
    var sha: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(outer.bytes, &sha, .{});
    const file_pin = exact.FilePin{ .byte_len = outer.bytes.len, .sha256 = sha };
    const parent_pins = [_]exact.NodePin{.{ .key = quartet.key, .expected_id = quartet.policy.expected_id, .schedule = quartet.prepared.wires }};
    const outer_pin = exact.NodePin{ .key = outer.key, .expected_id = outer.policy.expected_id, .schedule = outer.prepared.wires };
    const public_pins = exact.OuterPins{ .job_id = pins.job_id, .source_image_digest = pins.source_image_digest, .sealed_digest = sealed.digest, .segment_count = COUNT, .first_cycle = segments[0].global_first_cycle, .last_cycle = segments[COUNT - 1].global_first_cycle + segments[COUNT - 1].cycle_count - 1, .initial_pc = fixtures[0].owner.statement.initial_pc, .final_pc = fixtures[COUNT - 1].owner.statement.final_pc };
    var fresh = try exact.verifyLoaded(a, Loader{ .bytes = outer.bytes }, file_pin, &expected, &parent_pins, outer_pin, public_pins, open_sum);
    defer fresh.deinit();
    try std.testing.expectEqual(@as(u32, COUNT), fresh.execution_count);
    try std.testing.expectEqual(@as(u32, COUNT), fresh.span.segment_count);
    try std.testing.expect(fresh.combined_native_open_sum.eql(open_sum));
    var wrong_sum = expected;
    wrong_sum[4].exported.open_sum = wrong_sum[4].exported.open_sum.add(core.fields.qm31.QM31.one());
    try std.testing.expectError(error.NativeV5BaseRecursiveClaimMismatch, exact.verifyLoaded(a, Loader{ .bytes = outer.bytes }, file_pin, &wrong_sum, &parent_pins, outer_pin, public_pins, open_sum));
    var wrong_outer = public_pins;
    wrong_outer.final_pc ^= 4;
    try std.testing.expectError(error.UntrustedV5ExactOuterStatement, exact.verifyLoaded(a, Loader{ .bytes = outer.bytes }, file_pin, &expected, &parent_pins, outer_pin, wrong_outer, open_sum));
    var wrong_sha = file_pin;
    wrong_sha.sha256[0] ^= 1;
    try std.testing.expectError(error.TamperedV5ExactOuterTransport, exact.verifyLoaded(a, Loader{ .bytes = outer.bytes }, wrong_sha, &expected, &parent_pins, outer_pin, public_pins, open_sum));
    var quartet_rows: usize = 0;
    var outer_rows: usize = 0;
    inline for (quartet.prepared.recursive.rows.fixed) |rows| quartet_rows += rows.len;
    inline for (outer.prepared.recursive.rows.fixed) |rows| outer_rows += rows.len;
    std.debug.print("BLOCK_V5_NESTED_EXACT verified=true native_leaves=5 fold_levels=2 quartet=true exact_roots=4+1 padding=false leaf_key_reused=true leaf_bytes={d} quartet_bytes={d} outer_bytes={d} quartet_rows={d} outer_rows={d} quartet_public_wires={d} outer_public_wires={d} production_receive_api=true global_claims_open=true\n", .{ leaf_bytes, quartet.bytes.len, outer.bytes.len, quartet_rows, outer_rows, quartet.prepared.wires.len, outer.prepared.wires.len });
}

test "block-v5 exact five native leaf forest proves nested open quartet and outer equations" {
    try qualify(false, false);
}

test "block-v5 detached staged five native leaf open forest proves exact outer equations" {
    try qualify(true, false);
}

test "block-v5 incremental eight native leaf forest reuses authenticated setup and freshly verifies detached exact output" {
    try qualify(true, true);
}
