//! Matched independent native+companion versus one joint STARK, real RAM.
const std = @import("std");
const core = @import("stwo_core");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const Q = core.fields.qm31.QM31;
const Native = @import("../block_v5_native_execution_proof_v3.zig");
const Joint = @import("../block_v6_joint_native_proof_v1.zig");
const Fused = @import("../block_v5_native_projection_fused_proof_v2.zig");
const Receiver = @import("../block_v5_native_projection_fused_receiver_v2.zig");
const Stage = @import("../block_v5_native_memory_stage_v1.zig");
const Source = @import("../block_v5_native_projection_fused_source_v1.zig");
const Seal = @import("../block_v5_source_seal_v1.zig");
const Catalog = @import("../block_v5_native_template_catalog_v1.zig");
const Memory = @import("../block_v5_opcode_memory_sidecar_proof_v1.zig");
const Profile = @import("../../recursion/blake3_execution_parent_protocol.zig").Profile;
const Fixture = @import("block_v5_lightweight_native_proof_test.zig").Fixture;
const Summary = struct {
    native: Native.OpenReceipt,
    companion: Fused.Verified,
    fn deinit(self: *Summary, a: std.mem.Allocator) void {
        self.companion.deinit(a);
    }
};
test "block-v6 joint native and companion diagnostic real RAM" {
    try compare(.diagnostic_q8_pow0, false);
}
test "block-v6 joint native and companion canonical real RAM" {
    try compare(.csp_q70_pow26, false);
}
test "block-v6 pruned native and companion diagnostic real RAM" {
    try compare(.diagnostic_q8_pow0, true);
}
test "block-v6 pruned native and companion canonical real RAM" {
    try compare(.csp_q70_pow26, true);
}
fn compare(profile: Profile, comptime prune: bool) !void {
    const engine = @import("stwo_prover_engine");
    var pool: engine.work_pool.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{ .worker_count = 8, .backing_allocator = std.testing.allocator });
    defer pool.deinit();
    var binding = try engine.work_pool.ScopedPoolBinding.init(&pool);
    defer binding.deinit();
    for ([_]u32{ 0, 1 }) |mode| {
        var previous = try run(false, false, profile, mode, true);
        defer previous.deinit(std.testing.allocator);
        var current = try run(true, false, profile, mode, true);
        defer current.deinit(std.testing.allocator);
        try std.testing.expectEqualDeep(previous, current);
        if (prune) {
            var pruned = try run(true, true, profile, mode, true);
            defer pruned.deinit(std.testing.allocator);
            try std.testing.expectEqualDeep(previous, pruned);
        }
    }
    var previous = try run(false, false, profile, 1, false);
    defer previous.deinit(std.testing.allocator);
    var current = try run(true, false, profile, 1, false);
    defer current.deinit(std.testing.allocator);
    try std.testing.expectEqualDeep(previous, current);
    if (prune) {
        var pruned = try run(true, true, profile, 1, false);
        defer pruned.deinit(std.testing.allocator);
        try std.testing.expectEqualDeep(previous, pruned);
    }
}
fn run(comptime joint: bool, comptime reuse: bool, profile: Profile, mode: u32, comptime ram: bool) !Summary {
    const a = std.testing.allocator;
    const JointBackend = Joint.ForBackendWithProjectionReuse(Cpu, reuse);
    const iterations = if (std.posix.getenv("STWO_JOINT_ITERATIONS")) |raw| try std.fmt.parseInt(u32, raw, 10) else 1;
    if (iterations == 0 or iterations > 1024) return error.InvalidJointBenchmarkIterations;
    const seed = if (std.posix.getenv("STWO_JOINT_SEED")) |raw| try std.fmt.parseInt(u8, raw, 10) else 1;
    if (seed == 0) return error.InvalidJointBenchmarkSeed;
    const cycles = 3 + 5 * iterations;
    const instructions = [_]u32{ 0x00100137, 0x00000193, (iterations << 20) | (7 << 7) | 0x13, 0x00118193, if (ram) 0x02312023 else 0x00018213, if (ram) 0x02012203 else 0x00320233, 0xfff38393, 0xfe0398e3, 0x0000006f };
    const elf = @import("../../runner/guest_precompile/test_elf.zig").buildProgram(instructions.len, &instructions, 256, .rv32im_zkvm_v1);
    var session = try @import("../../runner/mod.zig").BaseExecutionSession.init(a, &elf, .{ .trace_retention = .segment_owned, .clock_frame = .leaf_local });
    defer session.deinit();
    var segment = try session.startSegment(cycles);
    defer segment.deinit();
    var counts: [Seal.family_count]u32 = @splat(0);
    for ([_]Seal.Family{ .program, .execution, .execution_sidecar, .program_request, .memory }) |f| counts[@intFromEnum(f) - 1] = 1;
    var pins = Seal.Pins{ .job_id = @splat(seed), .source_image_digest = @splat(2), .program_root = @splat(3), .program_plan_digest = @splat(4), .memory_plan_digest = @splat(5), .initial_source_plan_digest = @splat(6), .rw_endpoint_plan_digest = @splat(25), .native_template_catalog_digest = @splat(26), .config = profile.config(), .counts = counts, .register_custody_mode = mode, .register_endpoint_plan_digest = if (mode == 1) @splat(27) else @splat(0) };
    var fixture = try Fixture.init(a, &segment, pins);
    defer fixture.deinit();
    var context = fixture.pin.context;
    context.register_custody_mode = mode;
    context.register_endpoint_plan_digest = pins.register_endpoint_plan_digest;
    fixture.pin = try @import("../block_v5_native_public_admission_v1.zig").Admission.init(context, &fixture.owner.statement.public_data);
    var first = try Native.ForBackend(Cpu).commitFirstRound(a, fixture.owner, fixture.pin, pins.config, .rv32im_zkvm_v1, 0);
    defer first.deinit(a);
    const records = [_]Catalog.Record{.{ .index = 0, .template_id = first.template_id, .geometry_digest = first.template.geometry_digest, .fixed_root = first.roots[0] }};
    const catalog = Catalog.Admission{ .records = &records };
    pins.native_template_catalog_digest = try catalog.digest();
    const frame = @import("../../air/block/memory_event.zig").Frame{ .clock_frame = .leaf_local, .global_first_cycle = 1, .cycle_count = cycles };
    var source = try Stage.Traces.init(a, fixture.owner, frame, .{ .max_slots = 100, .max_witness_cells = 1 << 20, .max_metadata_bytes = 1 << 20, .register_custody_mode = mode });
    defer source.deinit();
    var counter = try @import("../../air/lookups/tables/counter.zig").Counter.init(a, .range_check_8_8);
    defer counter.deinit(a);
    const absence: ?Seal.Entry = if (source.slots.len == 0) try @import("../block_v5_empty_opcode_memory_v1.zig").firstRoundEntryForMode(a, &fixture.owner.statement, frame, first.entry(), 0, mode) else null;
    var access = if (absence) |empty| try @import("../block_v5_native_projection_fused_stage_v2.zig").ForBackend(Cpu).borrowProjectionFirstRound(a, &first.scheme, empty.roots[0]) else try Stage.ForBackend(Cpu).borrow(a, &first.scheme, source.inputs, source.slots, &counter, 0, first.template_id);
    defer access.deinit(a);
    const projections = try Source.slotsFromShapeForMode(a, &fixture.owner.statement, 0, mode);
    defer a.free(projections);
    const entries = [_]Seal.Entry{
        .{ .family = .program, .index = 0, .instance_id = @splat(7), .roots = .{ @splat(8), @splat(9) } },
        first.entry(),
        absence orelse Memory.packedEntry(first.instance_id, first.roots, access.roots[2], 0, source.slots),
        Fused.entry(first.template_id, first.instance_id, first.roots, access.roots[2], 0, frame, projections, source.slots),
        .{ .family = .memory, .index = 0, .instance_id = @splat(16), .roots = .{ @splat(17), @splat(18) } },
    };
    const sealed = try Seal.seal(pins, &entries);
    const pin = Receiver.InstancePin{ .shape = &fixture.owner.statement, .admission = fixture.pin, .template = first.template, .template_id = first.template_id, .profile = .rv32im_zkvm_v1 };
    const memory = Receiver.MemoryPin{ .frame = frame, .expected_events = try source.census(), .witness_root = access.roots[2] };
    var timer = try std.time.Timer.start();
    if (joint) {
        var proof = try JointBackend.prove(a, &first, &access, source.inputs, source.slots, memory, sealed, pins, &entries, catalog);
        var owns = true;
        defer if (owns) proof.deinit(a);
        const prove_ns = timer.lap();
        const stark_bytes = try starkSize(a, proof.body.stark);
        try std.testing.expectEqual(@as(usize, if (source.slots.len == 0) 5 else 6), proof.body.stark.commitment_scheme_proof.commitments.items.len);
        // Borrowed proofs let each hostile attempt consume a complete clone.
        var bad = try clone(a, proof);
        bad.native_claims.opcode_claims[0][0] = bad.native_claims.opcode_claims[0][0].add(Q.one());
        bad.native_claims.opcode_claims[1][0] = bad.native_claims.opcode_claims[1][0].sub(Q.one());
        if (JointBackend.verifyOwned(a, bad, 0, pin, memory, sealed, pins, &entries, catalog)) |accepted| {
            var value = accepted;
            value.deinit(a);
            return error.AcceptedChangedJointNativeClaim;
        } else |_| {}
        bad = try clone(a, proof);
        bad.body.claims[0].sum = bad.body.claims[0].sum.add(Q.one());
        bad.body.claims[1].sum = bad.body.claims[1].sum.sub(Q.one());
        if (JointBackend.verifyOwned(a, bad, 0, pin, memory, sealed, pins, &entries, catalog)) |accepted| {
            var value = accepted;
            value.deinit(a);
            return error.AcceptedCancellingJointClaims;
        } else |_| {}
        bad = try clone(a, proof);
        if (Joint.ForBackendWithProjectionReuse(Cpu, !reuse).verifyOwned(a, bad, 0, pin, memory, sealed, pins, &entries, catalog)) |accepted| {
            var value = accepted;
            value.deinit(a);
            return error.AcceptedWrongJointProtocol;
        } else |_| {}
        var alias_count: usize = 0;
        var alias_cells: u64 = 0;
        for (projections, 0..) |slot, i| {
            const alias = try @import("../block_v6_projection_alias_v1.zig").claim(a, &fixture.owner.statement, proof.native_claims, slot);
            if (alias == null) continue;
            alias_count += 1;
            alias_cells += @as(u64, 4) << @intCast(slot.log_size);
            if (reuse and alias_count == 1) {
                bad = try clone(a, proof);
                bad.body.claims[i].sum = bad.body.claims[i].sum.add(Q.one());
                try std.testing.expectError(error.UntrustedJointProjectionAlias, JointBackend.verifyOwned(a, bad, 0, pin, memory, sealed, pins, &entries, catalog));
            }
        }
        try std.testing.expect(alias_count > 0);
        _ = timer.lap();
        owns = false;
        var fresh = try JointBackend.verifyOwned(a, proof, 0, pin, memory, sealed, pins, &entries, catalog);
        defer fresh.deinit(a);
        const verify_ns = timer.lap();
        if (reuse) std.debug.print("BLOCK_V6_PRUNED profile={s} mode={d} ram={} cycles={d} seed={d} aliases={d} projections={d} alias_cells={d} prove_ns={d} verify_ns={d} stark_bytes={d} starks=1 globals_open=true\n", .{ @tagName(profile), mode, ram, cycles, seed, alias_count, projections.len, alias_cells, prove_ns, verify_ns, stark_bytes }) else std.debug.print("BLOCK_V6_JOINT profile={s} mode={d} ram={} cycles={d} seed={d} joint=true prove_ns={d} verify_ns={d} stark_bytes={d} starks=1 globals_open=true\n", .{ @tagName(profile), mode, ram, cycles, seed, prove_ns, verify_ns, stark_bytes });
        return summary(a, fresh.native, fresh.companion);
    } else {
        var proof = try Fused.ForBackend(Cpu).proveForNativeFirstRound(a, &access, source.inputs, source.slots, projections, sealed, pins, &entries, catalog, &first, 0, frame, memory.witness_root);
        var owns = true;
        defer if (owns) proof.deinit(a);
        const native = try Native.ForBackend(Cpu).proveWithCatalog(a, &first, sealed, pins, &entries, catalog);
        const prove_ns = timer.lap();
        const stark_bytes = try std.math.add(usize, try starkSize(a, proof.stark), try starkSize(a, native.stark));
        _ = timer.lap();
        owns = false;
        var fresh = try Receiver.ForBackend(Cpu).verifyOwned(a, native, proof, 0, pin, memory, sealed, pins, &entries, catalog);
        defer fresh.deinit(a);
        std.debug.print("BLOCK_V6_JOINT profile={s} mode={d} ram={} cycles={d} seed={d} joint=false prove_ns={d} verify_ns={d} stark_bytes={d} starks=2 globals_open=true\n", .{ @tagName(profile), mode, ram, cycles, seed, prove_ns, timer.lap(), stark_bytes });
        return summary(a, fresh.native, fresh.fused);
    }
}
fn summary(a: std.mem.Allocator, native: Native.OpenReceipt, fused: Fused.Verified) !Summary {
    var copy = fused;
    if (copy.memory) |*memory| memory.range_claims = try a.dupe(@import("../block_execution_byte_range_v2.zig").Claims, memory.range_claims);
    return .{ .native = native, .companion = copy };
}
fn clone(a: std.mem.Allocator, proof: Joint.Proof) !Joint.Proof {
    const postcard = @import("interop_postcard");
    var writer = std.Io.Writer.Allocating.init(a);
    defer writer.deinit();
    try postcard.serializeProof(core.proof_suites.Blake3.Hasher, &writer.writer, proof.body.stark);
    var stream = std.io.fixedBufferStream(writer.written());
    var stark = try postcard.deserializeProof(core.proof_suites.Blake3.Hasher, a, stream.reader());
    errdefer stark.deinit(a);
    const claims = try a.create(@import("../../air/statement.zig").RiscVInteractionClaim);
    errdefer a.destroy(claims);
    claims.* = proof.native_claims.*;
    const projections = try a.dupe(Fused.Claim, proof.body.claims);
    errdefer a.free(projections);
    return .{ .body = .{ .stark = stark, .claims = projections, .memory_claims = try a.dupe(Memory.Claim, proof.body.memory_claims) }, .native_claims = claims };
}

fn starkSize(a: std.mem.Allocator, stark: core.proof_suites.Blake3.Proof) !usize {
    var writer = std.Io.Writer.Allocating.init(a);
    defer writer.deinit();
    try @import("interop_postcard").serializeProof(core.proof_suites.Blake3.Hasher, &writer.writer, stark);
    return writer.written().len;
}
