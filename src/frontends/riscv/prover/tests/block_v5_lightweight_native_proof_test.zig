//! Real native/recursive proof without importing any commitment witness/Plan.
const std = @import("std");
const core = @import("stwo_core");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const runner = @import("../../runner/mod.zig");
const public = @import("../blake3_segment_public.zig");
const native = @import("../blake3_execution_trace.zig");
const proof = @import("../block_v5_native_execution_proof_v3.zig");
const admission_mod = @import("../block_v5_native_public_admission_v1.zig");
const recursive_admission = @import("../block_v5_native_recursive_admission_v3.zig");
const seals = @import("../block_v5_source_seal_v1.zig");
const catalog_mod = @import("../block_v5_native_template_catalog_v1.zig");
const parent = @import("../../recursion/blake3_execution_parent_proof.zig");
const bus = @import("../../recursion/block_v5_recursive_public_bus_v1.zig");
const recursive_protocol = @import("../../recursion/block_v5_reusable_native_parent_protocol_v1.zig");
const leaf = @import("../../recursion/block_v5_reusable_native_leaf_v1.zig");

pub const Fixture = struct {
    io: public.Owned,
    owner: *native.Owner,
    pin: admission_mod.Admission,
    pub fn init(a: std.mem.Allocator, segment: *const @import("../../runner/result.zig").SegmentResult, pins: seals.Pins) !Fixture {
        var io = try public.Owned.init(a, segment);
        errdefer io.deinit();
        // This focused test supplies independently declared global ROM policy;
        // its provider proof remains open. No per-leaf hash witness is built.
        io.data.program_root = .{ .bytes = pins.program_root };
        const pin = try admission_mod.Admission.init(.{
            .job_id = pins.job_id,
            .source_image_digest = pins.source_image_digest,
            .program_root = pins.program_root,
            .program_plan_digest = pins.program_plan_digest,
            .memory_plan_digest = pins.memory_plan_digest,
            .initial_source_plan_digest = pins.initial_source_plan_digest,
            .rw_endpoint_plan_digest = pins.rw_endpoint_plan_digest,
            .execution_index = segment.segment_index,
            .first_cycle = segment.global_first_cycle,
            .last_cycle = segment.global_first_cycle + segment.cycle_count - 1,
        }, &io.data);
        const owner = try native.Owner.init(a, &segment.execution_trace, io.data, &segment.state_chain_tracker);
        errdefer owner.deinit();
        try owner.sealNativeOnly();
        return .{ .io = io, .owner = owner, .pin = pin };
    }
    pub fn deinit(self: *Fixture) void {
        self.owner.deinit();
        self.io.deinit();
    }
};

test "block-v5 lightweight native v3 proves reusable recursion without perleaf custody" {
    try qualify(false, false);
}
test "block-v5 open native v3 parent verifies two child equations and PC clock edges" {
    try qualify(true, false);
}
test "block-v5 persistent native recursive worker rebinds two actual same-key instance admissions" {
    try qualify(false, true);
}
fn qualify(comptime fold: bool, comptime use_worker: bool) !void {
    const a = std.testing.allocator;
    const instructions = [_]u32{ 0x00500093, 0x00600093, 0x0000006f };
    const elf = @import("../../runner/guest_precompile/test_elf.zig").buildProgram(instructions.len, &instructions, 0, .rv32im_zkvm_v1);
    var session = try runner.BaseExecutionSession.init(a, &elf, .{ .trace_retention = .segment_owned, .clock_frame = .leaf_local });
    defer session.deinit();
    var segment_a = try session.startSegment(1);
    defer segment_a.deinit();
    var segment_b = try session.resumeSegment(segment_a.continuation.?, 1);
    defer segment_b.deinit();
    var counts: [seals.family_count]u32 = @splat(0);
    counts[@intFromEnum(seals.Family.program) - 1] = 1;
    counts[@intFromEnum(seals.Family.execution) - 1] = 2;
    counts[@intFromEnum(seals.Family.execution_sidecar) - 1] = 2;
    counts[@intFromEnum(seals.Family.program_request) - 1] = 2;
    counts[@intFromEnum(seals.Family.memory) - 1] = 1;
    var pins_a = seals.Pins{ .job_id = @splat(1), .source_image_digest = @splat(2), .program_root = @splat(3), .program_plan_digest = @splat(4), .memory_plan_digest = @splat(5), .initial_source_plan_digest = @splat(6), .rw_endpoint_plan_digest = @splat(25), .native_template_catalog_digest = @splat(26), .config = parent.protocol.PCS_CONFIG, .counts = counts };
    var pins_b = pins_a;
    if (!fold) pins_b.job_id[0] ^= 1;
    var first = try Fixture.init(a, &segment_a, pins_a);
    defer first.deinit();
    var second = try Fixture.init(a, &segment_b, pins_b);
    defer second.deinit();
    const Api = proof.ForBackend(Cpu);
    var round_a = try Api.commitFirstRound(a, first.owner, first.pin, pins_a.config, .rv32im_zkvm_v1, 0);
    defer round_a.deinit(a);
    var round_b = try Api.commitFirstRound(a, second.owner, second.pin, pins_b.config, .rv32im_zkvm_v1, 1);
    defer round_b.deinit(a);
    try std.testing.expectEqualDeep(round_a.template_id, round_b.template_id);
    const records = [_]catalog_mod.Record{
        .{ .index = 0, .template_id = round_a.template_id, .geometry_digest = round_a.template.geometry_digest, .fixed_root = round_a.roots[0] },
        .{ .index = 1, .template_id = round_b.template_id, .geometry_digest = round_b.template.geometry_digest, .fixed_root = round_b.roots[0] },
    };
    const catalog = catalog_mod.Admission{ .records = &records };
    pins_a.native_template_catalog_digest = try catalog.digest();
    pins_b.native_template_catalog_digest = pins_a.native_template_catalog_digest;
    const entries = [_]seals.Entry{
        .{ .family = .program, .index = 0, .instance_id = @splat(7), .roots = .{ @splat(8), @splat(9) } },
        round_a.entry(),
        round_b.entry(),
        .{ .family = .execution_sidecar, .index = 0, .instance_id = @splat(10), .roots = .{ @splat(11), @splat(12) } },
        .{ .family = .execution_sidecar, .index = 1, .instance_id = @splat(13), .roots = .{ @splat(14), @splat(15) } },
        .{ .family = .program_request, .index = 0, .instance_id = @splat(16), .roots = .{ @splat(17), @splat(18) } },
        .{ .family = .program_request, .index = 1, .instance_id = @splat(19), .roots = .{ @splat(20), @splat(21) } },
        .{ .family = .memory, .index = 0, .instance_id = @splat(22), .roots = .{ @splat(23), @splat(24) } },
    };
    const sealed_a = try seals.seal(pins_a, &entries);
    const sealed_b = try seals.seal(pins_b, &entries);
    const native_a = try Api.proveWithCatalog(a, &round_a, sealed_a, pins_a, &entries, catalog);
    const native_b = try Api.proveWithCatalog(a, &round_b, sealed_b, pins_b, &entries, catalog);
    var capture_a = try Api.verifyCaptureOwnedWithCatalog(a, native_a, &first.owner.statement, first.pin, round_a.template, round_a.template_id, .rv32im_zkvm_v1, 0, sealed_a, pins_a, &entries, catalog);
    defer capture_a.deinit();
    var capture_b = try Api.verifyCaptureOwnedWithCatalog(a, native_b, &second.owner.statement, second.pin, round_b.template, round_b.template_id, .rv32im_zkvm_v1, 1, sealed_b, pins_b, &entries, catalog);
    defer capture_b.deinit();
    const captures = [_]*const proof.VerifiedCapture{ &capture_a, &capture_b };
    const fixtures = [_]*const Fixture{ &first, &second };
    const rounds = .{ &round_a, &round_b };
    const all_sealed = [_]seals.Sealed{ sealed_a, sealed_b };
    const all_pins = [_]seals.Pins{ pins_a, pins_b };
    const Plan = @import("../../recursion/blake3_native_parent_producer.zig").PlanForProtocol(Cpu, recursive_protocol);
    const Worker = @import("../../recursion/blake3_native_parent_worker.zig").WorkerForProtocol(Cpu, recursive_protocol);
    var schedule: ?[]bus.Wire = null;
    defer if (schedule) |owned| a.free(owned);
    var plan: ?*Plan = null;
    defer if (plan) |owned| owned.deinit();
    var worker: ?*Worker = null;
    defer if (worker) |owned| owned.deinit();
    var worker_plan: ?*Plan = null;
    var expected_key: ?[32]u8 = null;
    var byte_counts: [2]usize = undefined;
    var fixed_rows: usize = 0;
    var open_equations: [2]?leaf.OpenEquation = @splat(null);
    defer for (&open_equations) |*equation| if (equation.*) |*owned| owned.deinit();
    var recursive_keys: [2]recursive_protocol.Key = undefined;
    inline for (0..2) |i| {
        var admitted = try recursive_admission.Prepared.init(a, &fixtures[i].owner.statement, fixtures[i].pin, rounds[i].template, rounds[i].template_id, i, all_sealed[i], all_pins[i], &entries, catalog);
        defer admitted.deinit();
        var prepared = try bus.prepare(a, &admitted, captures[i], 2);
        defer prepared.deinit();
        const geometry = try parent.ForBackend(Cpu).deriveKey(a, &prepared.recursive);
        const key = try recursive_protocol.Key.fromGeometry(geometry, prepared.wires);
        const key_id = try key.identity();
        recursive_keys[i] = key;
        if (schedule == null) schedule = try a.dupe(bus.Wire, prepared.wires);
        const authority = try recursive_protocol.Admission.init(key, key_id, schedule.?, prepared.values);
        if (expected_key) |expected| {
            try std.testing.expectEqualDeep(expected, key_id);
            if (!use_worker) try std.testing.expect(try plan.?.tryRebindAdmission(&prepared.recursive.rows, authority));
        } else {
            expected_key = key_id;
            if (use_worker) {
                worker = try Worker.init(a, &prepared.recursive.rows, authority, .{ .worker_count = 2, .host_byte_limit = 8 * 1024 * 1024 * 1024, .retained_scratch_limit = 64 * 1024 * 1024 });
                worker_plan = worker.?.plan;
            } else plan = try Plan.init(a, &prepared.recursive.rows, authority);
            inline for (prepared.recursive.rows.fixed) |rows| fixed_rows += rows.len;
        }
        if (use_worker and i == 1) {
            try std.testing.expect(!std.meta.eql(worker.?.plan.admission.values, authority.values));
            try std.testing.expect(!std.meta.eql(worker.?.plan.admission.values.roots[1], authority.values.roots[1]));
        }
        var artifact = if (use_worker)
            try worker.?.proveAdmitted(&prepared.recursive.rows, authority)
        else
            try plan.?.prove(a, &prepared.recursive.rows);
        defer artifact.deinit();
        if (use_worker) {
            try std.testing.expect(worker.?.plan == worker_plan.?);
            try std.testing.expectEqualDeep(authority.values, worker.?.plan.admission.values);
        }
        const bytes = try parent.codec.encode(a, &artifact, &authority);
        defer a.free(bytes);
        byte_counts[i] = bytes.len;
        var fresh = try leaf.verify(a, bytes, key, key_id, prepared.wires, &admitted, captures[i].receipt);
        var fresh_transferred = false;
        defer if (!fresh_transferred) fresh.deinit();
        var total = core.fields.qm31.QM31.zero();
        const shape = &fixtures[i].owner.statement;
        for (shape.component_descs[0..shape.n_components], 0..) |desc, slot|
            total = total.add(try captures[i].native_claims.opcodeClaimTotal(desc.family, slot));
        for (shape.infra_descs[0..shape.n_infra], 0..) |desc, slot|
            total = total.add(try captures[i].native_claims.infraClaimTotal(desc.kind, slot));
        try std.testing.expect(total.add(prepared.values.compensation).eql(captures[i].receipt.open_sum));
        var wrong = authority;
        wrong.values.open_sum = wrong.values.open_sum.add(core.fields.qm31.QM31.one());
        try std.testing.expectError(error.InvalidReusableNativeParentPublicClosure, fresh.equation.validate(&wrong, key_id));
        var foreign = fixtures[i].pin;
        foreign.context.memory_plan_digest[0] ^= 1;
        try std.testing.expectError(error.UntrustedNativeV5PublicContext, foreign.require(all_pins[i], &shape.public_data));
        if (fold) {
            open_equations[i] = fresh;
            fresh_transferred = true;
        }
    }
    if (use_worker) std.debug.print("BLOCK_V5_NATIVE_WORKER_REUSE verified=true native_instances=2 recursive_key_reused=true fixed_plan_reused=true same_key_dynamic_admission_rebound=true both_recursive_equations_fresh_verified=true proof_bytes={d}+{d} global_claims_open=true\n", .{ byte_counts[0], byte_counts[1] });
    if (fold) {
        const fold_bus = @import("../../recursion/block_v5_open_parent_public_bus_v1.zig");
        const fold_prepare = @import("../../recursion/block_v5_open_parent_preparation_v1.zig");
        const fold_protocol = @import("../../recursion/block_v5_reusable_open_parent_protocol_v1.zig");
        const fold_receiver = @import("../../recursion/block_v5_open_parent_receiver_v1.zig");
        var native_policies: [2]recursive_admission.Prepared = undefined;
        var policy_count: usize = 0;
        defer for (native_policies[0..policy_count]) |*policy| policy.deinit();
        var expected: [2]fold_receiver.ExpectedChild = undefined;
        var children: [2]fold_bus.Child = undefined;
        inline for (0..2) |i| {
            native_policies[i] = try recursive_admission.Prepared.init(a, &fixtures[i].owner.statement, fixtures[i].pin, rounds[i].template, rounds[i].template_id, i, all_sealed[i], all_pins[i], &entries, catalog);
            policy_count += 1;
            expected[i] = .{ .native = &native_policies[i], .exported = captures[i].receipt, .recursive_key = recursive_keys[i], .recursive_key_id = expected_key.?, .recursive_schedule = schedule.? };
            children[i] = try expected[i].publicChild(a);
        }
        const verified_children = [_]*const @import("../../recursion/blake3_native_parent_verifier.zig").Verified{ &open_equations[0].?.equation, &open_equations[1].?.equation };
        // Exercise the actual arithmetic edge constraint independently of the
        // host span preflight: mutate only a routed public PC graph input.
        const edge_spans: [2]@import("../../recursion/block_v5_pc_clock_span_v1.zig").Span = .{ children[0].span, children[1].span };
        const edge_admission = fold_bus.ChildAdmission.init(children[0].admission, &edge_spans);
        var edge_plan = try @import("../../recursion/blake3_execution_parent_preparation.zig").State.plan(a, &edge_admission, verified_children[0], edge_admission.expected_id, 2);
        defer edge_plan.deinit();
        const edge_graph = &edge_plan.state.?.composition;
        var edge_mutated = false;
        for (edge_graph.sources, 0..) |source, node| if (source == .public_input and source.public_input == 4 * children[0].admission.wires.len + 6 + 4) {
            edge_graph.inputs[node] = edge_graph.inputs[node].add(core.fields.qm31.QM31.fromBase(core.fields.m31.M31.fromCanonical(4)));
            edge_mutated = true;
            break;
        };
        try std.testing.expect(edge_mutated);
        try std.testing.expectError(error.UnsatisfiedCircuit, edge_graph.circuit.evaluateInto(edge_graph.inputs, edge_graph.values));
        // Release the deliberately invalid graph before assembling/proving rows.
        edge_plan.deinit();
        var combined = try fold_prepare.prepare(a, &children, &verified_children, 2);
        defer combined.deinit();
        const fold_geometry = try parent.ForBackend(Cpu).deriveKey(a, &combined.recursive);
        const fold_key = try fold_protocol.Key.fromGeometry(fold_geometry, combined.wires);
        const fold_key_id = try fold_key.identity();
        const fold_authority = try fold_protocol.Admission.init(fold_key, fold_key_id, combined.wires, combined.values);
        const FoldPlan = @import("../../recursion/blake3_native_parent_producer.zig").PlanForProtocol(Cpu, fold_protocol);
        const fold_plan = try FoldPlan.init(a, &combined.recursive.rows, fold_authority);
        defer fold_plan.deinit();
        var folded = try fold_plan.prove(a, &combined.recursive.rows);
        defer folded.deinit();
        const fold_bytes = try parent.codec.encode(a, &folded, &fold_authority);
        defer a.free(fold_bytes);
        var fresh_fold = try fold_receiver.verify(a, fold_bytes, fold_key, fold_key_id, combined.wires, &expected);
        defer fresh_fold.deinit();
        try std.testing.expectEqual(@as(u32, 2), fresh_fold.pc_clock_span.segment_count);
        try std.testing.expectEqual(segment_a.global_first_cycle, fresh_fold.pc_clock_span.first_cycle);
        try std.testing.expectEqual(segment_b.global_first_cycle + segment_b.cycle_count - 1, fresh_fold.pc_clock_span.last_cycle);
        try std.testing.expect(fresh_fold.combined_native_open_sum.eql(capture_a.receipt.open_sum.add(capture_b.receipt.open_sum)));
        // Independently altered native claim and PC span cannot select the same
        // external public supply. Globals remain deliberately open.
        var wrong = expected;
        wrong[1].exported.open_sum = wrong[1].exported.open_sum.add(core.fields.qm31.QM31.one());
        try std.testing.expectError(error.InvalidReusableOpenParentPublicClosure, fold_receiver.verify(a, fold_bytes, fold_key, fold_key_id, combined.wires, &wrong));
        var nonadjacent = children;
        nonadjacent[1].span.initial_pc ^= 4;
        try std.testing.expectError(error.DiscontinuousV5PcClockSpan, fold_bus.Values.validate(.{ .children = &nonadjacent }));
        var row_count: usize = 0;
        inline for (combined.recursive.rows.fixed) |rows| row_count += rows.len;
        std.debug.print("BLOCK_V5_OPEN_PARENT verified=true native_version=3 children=2 child_equations=true public_supply_closed=true pc_clock_edges=true fixed_rows={d} public_wires={d} proof_bytes={d} global_claims_open=true\n", .{ row_count, combined.wires.len, fold_bytes.len });
    }
    std.debug.print("BLOCK_V5_LIGHTWEIGHT_NATIVE verified=true states=2 native_version=3 perleaf_plan=false custody_witness=false compensation=pc_clock_only recursive_key_reused=true fixed_rows={d} proof_bytes={d}+{d} global_claims_open=true\n", .{ fixed_rows, byte_counts[0], byte_counts[1] });
}
