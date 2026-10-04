const std = @import("std");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const runner = @import("../../runner/mod.zig");
const Segment = @import("../../runner/result.zig").SegmentResult;
const public = @import("../blake3_segment_public.zig");
const memory_mod = @import("../blake3_commitment_witness.zig");
const plan_mod = @import("../blake3_commitment_plan.zig");
const native_mod = @import("../blake3_execution_trace.zig");
const v5 = @import("../block_v5_native_execution_proof_v1.zig");
const seal_mod = @import("../block_v5_source_seal_v1.zig");
const catalog_mod = @import("../block_v5_native_template_catalog_v1.zig");
const profile = @import("../../isa/execution_profile.zig").ExecutionProfile;

const Fixture = struct {
    a: std.mem.Allocator,
    io: public.Owned,
    memory: memory_mod.Witness,
    plan: plan_mod.Plan,
    native: *native_mod.Owner,

    fn init(a: std.mem.Allocator, segment: *const Segment) !Fixture {
        var io = try public.Owned.init(a, segment);
        errdefer io.deinit();
        var data = io.data;
        var memory = try memory_mod.build(
            a,
            @as(@import("../../air/program/commitment.zig").DeclaredDecodeAuthority, .base),
            .{segment.execution_trace.rows.items},
            &segment.rw_memory,
            @import("../commitment_program_witness.zig").completionFetch(data.completion),
            100,
        );
        errdefer memory.deinit();
        try memory.bindPublic(&data);
        io.data = data;
        var plan = try memory.plan(a);
        errdefer plan.deinit();
        const native = try native_mod.Owner.init(a, &segment.execution_trace, data, &segment.state_chain_tracker);
        errdefer native.deinit();
        try native.sealNativeOnly();
        return .{ .a = a, .io = io, .memory = memory, .plan = plan, .native = native };
    }
    fn pin(self: *const Fixture) !plan_mod.Admission {
        return plan_mod.Admission.init(&self.plan, try self.plan.identity());
    }
    fn deinit(self: *Fixture) void {
        self.native.deinit();
        self.plan.deinit();
        self.memory.deinit();
        self.io.deinit();
        self.* = undefined;
    }
};

test "block-v5 native-only catalog admits two different leaf geometries" {
    try qualify(true);
}
test "block-v5 reusable recursion proves two changing native instances with one key" {
    try qualify(false);
}
fn qualify(varied: bool) !void {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const instructions = [_]u32{ 0x00500093, if (varied) 0x002081b3 else 0x00600093, 0x0000006f };
    const elf = @import("../../runner/guest_precompile/test_elf.zig").buildProgram(
        instructions.len,
        &instructions,
        0,
        .rv32im_zkvm_v1,
    );
    var session = try runner.BaseExecutionSession.init(a, &elf, .{
        .trace_retention = .segment_owned,
        .clock_frame = .leaf_local,
    });
    defer session.deinit();
    var first_segment = try session.startSegment(1);
    defer first_segment.deinit();
    var second_segment = try session.resumeSegment(first_segment.continuation.?, 1);
    defer second_segment.deinit();
    var first = try Fixture.init(a, &first_segment);
    defer first.deinit();
    var second = try Fixture.init(a, &second_segment);
    defer second.deinit();
    const config = @import("../../recursion/blake3_execution_parent_protocol.zig").PCS_CONFIG;
    const Api = v5.ForBackend(Cpu);
    var a_first = try Api.commitFirstRound(a, first.native, try first.pin(), config, profile.rv32im_zkvm_v1, 0);
    defer a_first.deinit(a);
    var b_first = try Api.commitFirstRound(a, second.native, try second.pin(), config, profile.rv32im_zkvm_v1, 1);
    defer b_first.deinit(a);
    try std.testing.expectEqual(varied, !std.meta.eql(a_first.template.geometry_digest, b_first.template.geometry_digest));
    try std.testing.expectEqual(varied, !std.meta.eql(a_first.template_id, b_first.template_id));
    try std.testing.expect(!std.meta.eql(a_first.instance_id, b_first.instance_id));

    var counts: [seal_mod.family_count]u32 = @splat(0);
    counts[@intFromEnum(seal_mod.Family.program) - 1] = 1;
    counts[@intFromEnum(seal_mod.Family.execution) - 1] = 2;
    counts[@intFromEnum(seal_mod.Family.execution_sidecar) - 1] = 2;
    counts[@intFromEnum(seal_mod.Family.program_request) - 1] = 2;
    counts[@intFromEnum(seal_mod.Family.memory) - 1] = 1;
    const catalog_records = [_]catalog_mod.Record{
        .{ .index = 0, .template_id = a_first.template_id, .geometry_digest = a_first.template.geometry_digest, .fixed_root = a_first.roots[0] },
        .{ .index = 1, .template_id = b_first.template_id, .geometry_digest = b_first.template.geometry_digest, .fixed_root = b_first.roots[0] },
    };
    const catalog = catalog_mod.Admission{ .records = &catalog_records };
    const pins = seal_mod.Pins{
        .job_id = @splat(1),
        .source_image_digest = @splat(2),
        .native_template_catalog_digest = try catalog.digest(),
        .program_root = @splat(3),
        .program_plan_digest = @splat(4),
        .memory_plan_digest = @splat(5),
        .initial_source_plan_digest = @splat(6),
        .config = config,
        .counts = counts,
    };
    const entries = [_]seal_mod.Entry{
        .{ .family = .program, .index = 0, .instance_id = @splat(7), .roots = .{ @splat(8), @splat(9) } },
        a_first.entry(),
        b_first.entry(),
        .{ .family = .execution_sidecar, .index = 0, .instance_id = @splat(10), .roots = .{ @splat(11), @splat(12) } },
        .{ .family = .execution_sidecar, .index = 1, .instance_id = @splat(13), .roots = .{ @splat(14), @splat(15) } },
        .{ .family = .program_request, .index = 0, .instance_id = @splat(16), .roots = .{ @splat(17), @splat(18) } },
        .{ .family = .program_request, .index = 1, .instance_id = @splat(19), .roots = .{ @splat(20), @splat(21) } },
        .{ .family = .memory, .index = 0, .instance_id = @splat(22), .roots = .{ @splat(23), @splat(24) } },
    };
    const sealed = try seal_mod.seal(pins, &entries);
    try std.testing.expectError(error.UntrustedNativeV5Template, Api.prove(a, &a_first, sealed, pins, &entries));
    var changed_records = catalog_records;
    changed_records[1].fixed_root[0] ^= 1;
    try std.testing.expectError(error.UntrustedNativeV5TemplateCatalog, (catalog_mod.Admission{ .records = &changed_records }).admit(pins, sealed, 0, a_first.template, a_first.template_id));
    const proof_a = try Api.proveWithCatalog(a, &a_first, sealed, pins, &entries, catalog);
    var second_pins = pins;
    if (!varied) second_pins.job_id[0] ^= 1;
    const second_sealed = try seal_mod.seal(second_pins, &entries);
    const proof_b = try Api.proveWithCatalog(a, &b_first, second_sealed, second_pins, &entries, catalog);
    var capture_a = try Api.verifyCaptureOwnedWithCatalog(a, proof_a, &first.native.statement, try first.pin(), a_first.template, a_first.template_id, .rv32im_zkvm_v1, 0, sealed, pins, &entries, catalog);
    defer capture_a.deinit();
    const receipt_a = capture_a.receipt;
    var capture_b = try Api.verifyCaptureOwnedWithCatalog(a, proof_b, &second.native.statement, try second.pin(), b_first.template, b_first.template_id, .rv32im_zkvm_v1, 1, second_sealed, second_pins, &entries, catalog);
    defer capture_b.deinit();
    const receipt_b = capture_b.receipt;
    try std.testing.expectEqual(varied, !std.meta.eql(receipt_a.template_id, receipt_b.template_id));
    try std.testing.expect(!std.meta.eql(receipt_a.instance_id, receipt_b.instance_id));
    try std.testing.expectEqualDeep(sealed.digest, receipt_a.sealed_digest);
    try std.testing.expectEqualDeep(second_sealed.digest, receipt_b.sealed_digest);
    if (varied and std.posix.getenv("STWO_NATIVE_V5_RECURSIVE") != null) {
        const parent = @import("../../recursion/blake3_execution_parent_proof.zig");
        const Recursive = parent.ForBackend(Cpu);
        const rec_a = std.testing.allocator;
        var admitted = try @import("../block_v5_native_recursive_admission_v1.zig").Prepared.init(
            rec_a,
            &first.native.statement,
            try first.pin(),
            a_first.template,
            a_first.template_id,
            0,
            sealed,
            pins,
            &entries,
            catalog,
        );
        defer admitted.deinit();
        const original_open_sum = capture_a.receipt.open_sum;
        const original_capture_seal = capture_a.seal;
        capture_a.receipt.open_sum = original_open_sum.add(@import("stwo_core").fields.qm31.QM31.one());
        capture_a.seal = try capture_a.identity(&first.native.statement);
        try std.testing.expectError(error.UnsatisfiedCircuit, @import("../../recursion/air/block_v5_native_composition.zig").prepare(rec_a, &admitted, &capture_a, a_first.template_id));
        capture_a.receipt.open_sum = original_open_sum;
        capture_a.seal = original_capture_seal;
        var prepared = try parent.preparation.prepare(rec_a, &admitted, &capture_a, a_first.template_id, 2);
        defer prepared.deinit();
        const key = try Recursive.deriveKey(rec_a, &prepared);
        const admission = try parent.protocol.Admission.init(key, try key.identity());
        const plan = try Recursive.Plan.init(rec_a, &prepared.rows, admission);
        defer plan.deinit();
        var artifact = try plan.prove(rec_a, &prepared.rows);
        defer artifact.deinit();
        const bytes = try parent.codec.encode(rec_a, &artifact, &admission);
        defer rec_a.free(bytes);
        var reopened = try parent.codec.decode(rec_a, bytes, &admission);
        var fresh = try parent.verify(&reopened, &admission);
        defer fresh.deinit();
        try fresh.validate(&admission, admission.expected_id);
        var fixed_rows: usize = 0;
        inline for (prepared.rows.fixed) |rows| fixed_rows += rows.len;
        std.debug.print("BLOCK_V5_NATIVE_RECURSIVE verified=true leaves=1 native_equation=true transcript_v2=true exported_open_claim=true fixed_rows={d} proof_bytes={d}\n", .{ fixed_rows, bytes.len });
    }
    if (!varied) {
        try qualifyReusable(&first, &second, &a_first, &b_first, &capture_a, &capture_b, sealed, second_sealed, pins, second_pins, &entries, catalog);
    }
    std.debug.print("BLOCK_V5_NATIVE_TEMPLATE verified=true states=2 varied_geometry=true catalog_mode=true open_global_relations=true\n", .{});
}

fn qualifyReusable(first: *Fixture, second: *Fixture, a_first: anytype, b_first: anytype, capture_a: *const v5.VerifiedCapture, capture_b: *const v5.VerifiedCapture, sealed: seal_mod.Sealed, second_sealed: seal_mod.Sealed, pins: seal_mod.Pins, second_pins: seal_mod.Pins, entries: []const seal_mod.Entry, catalog: catalog_mod.Admission) !void {
    const parent = @import("../../recursion/blake3_execution_parent_proof.zig");
    const bus = @import("../../recursion/block_v5_recursive_public_bus_v1.zig");
    const protocol = @import("../../recursion/block_v5_reusable_native_parent_protocol_v1.zig");
    const Plan = @import("../../recursion/blake3_native_parent_producer.zig").PlanForProtocol(Cpu, protocol);
    const a = std.testing.allocator;
    var admitted_a = try @import("../block_v5_native_recursive_admission_v1.zig").Prepared.init(a, &first.native.statement, try first.pin(), a_first.template, a_first.template_id, 0, sealed, pins, entries, catalog);
    defer admitted_a.deinit();
    var admitted_b = try @import("../block_v5_native_recursive_admission_v1.zig").Prepared.init(a, &second.native.statement, try second.pin(), b_first.template, b_first.template_id, 1, second_sealed, second_pins, entries, catalog);
    defer admitted_b.deinit();
    var first_prepared = try bus.prepare(a, &admitted_a, capture_a, 2);
    defer first_prepared.deinit();
    const first_geometry = try parent.ForBackend(Cpu).deriveKey(a, &first_prepared.recursive);
    const key = try protocol.Key.fromGeometry(first_geometry, first_prepared.wires);
    const expected = try key.identity();
    const first_admission = try protocol.Admission.init(key, expected, first_prepared.wires, first_prepared.values);
    const plan = try Plan.init(a, &first_prepared.recursive.rows, first_admission);
    defer plan.deinit();
    var proof_a = try plan.prove(a, &first_prepared.recursive.rows);
    defer proof_a.deinit();
    const bytes_a = try parent.codec.encode(a, &proof_a, &first_admission);
    defer a.free(bytes_a);
    var reopened_a = try parent.codec.decode(a, bytes_a, &first_admission);
    var fresh_a = try parent.verify(&reopened_a, &first_admission);
    defer fresh_a.deinit();
    try fresh_a.validate(&first_admission, expected);
    var wrong = first_admission;
    wrong.values.open_sum = wrong.values.open_sum.add(@import("stwo_core").fields.qm31.QM31.one());
    try std.testing.expectError(error.InvalidReusableNativeParentPublicClosure, fresh_a.validate(&wrong, expected));
    var wrong_statement = first_admission;
    wrong_statement.values.statement_digest[0] ^= 1;
    try std.testing.expectError(error.UntrustedBlake3ParentPublicInputs, fresh_a.validate(&wrong_statement, expected));
    var second_prepared = try bus.prepare(a, &admitted_b, capture_b, 2);
    defer second_prepared.deinit();
    const second_geometry = try parent.ForBackend(Cpu).deriveKey(a, &second_prepared.recursive);
    const second_key = try protocol.Key.fromGeometry(second_geometry, second_prepared.wires);
    try std.testing.expectEqualDeep(expected, try second_key.identity());
    try std.testing.expect(!std.meta.eql(first_prepared.values.sealed, second_prepared.values.sealed));
    try std.testing.expect(!std.meta.eql(first_prepared.values.instance, second_prepared.values.instance));
    try std.testing.expect(!std.meta.eql(first_prepared.values.roots[1], second_prepared.values.roots[1]));
    try std.testing.expect(!std.meta.eql(first_prepared.values.statement_digest, second_prepared.values.statement_digest));
    const second_admission = try protocol.Admission.init(key, expected, second_prepared.wires, second_prepared.values);
    try std.testing.expect(try plan.tryRebindAdmission(&second_prepared.recursive.rows, second_admission));
    var proof_b = try plan.prove(a, &second_prepared.recursive.rows);
    defer proof_b.deinit();
    const bytes_b = try parent.codec.encode(a, &proof_b, &second_admission);
    defer a.free(bytes_b);
    var reopened_b = try parent.codec.decode(a, bytes_b, &second_admission);
    var fresh_b = try parent.verify(&reopened_b, &second_admission);
    defer fresh_b.deinit();
    try fresh_b.validate(&second_admission, expected);
    var wrong_root = second_admission;
    wrong_root.values.roots[1][0] ^= 1;
    try std.testing.expectError(error.InvalidReusableNativeParentPublicClosure, fresh_b.validate(&wrong_root, expected));
    var rows: usize = 0;
    inline for (first_prepared.recursive.rows.fixed) |fixed| rows += fixed.len;
    std.debug.print("BLOCK_V5_REUSABLE_RECURSIVE verified=true states=2 key_reused=true setup_rebound=true changing_b5ss=true native_equation=true public_supply_closed=true fixed_rows={d} public_wires={d} proof_bytes={d}+{d} global_claims_open=true\n", .{ rows, first_prepared.wires.len, bytes_a.len, bytes_b.len });
}
