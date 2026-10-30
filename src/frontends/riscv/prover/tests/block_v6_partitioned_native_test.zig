//! Matched independent native+companion versus one joint STARK, real RAM.
const std = @import("std");
const core = @import("stwo_core");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const Q = core.fields.qm31.QM31;
const Native = @import("../block_v5_native_execution_proof_v3.zig");
const Partitioned = @import("../block_v6_partitioned_native_proof_v1.zig");
const Layout = @import("../block_v6_relation_layout_v1.zig").Layout;
const Fused = @import("../block_v5_native_projection_fused_proof_v2.zig");
const Receiver = @import("../block_v5_native_projection_fused_receiver_v2.zig");
const Stage = @import("../block_v5_native_memory_stage_v1.zig");
const Source = @import("../block_v5_native_projection_fused_source_v1.zig");
const Seal = @import("../block_v5_source_seal_v1.zig");
const Catalog = @import("../block_v5_native_template_catalog_v1.zig");
const Memory = @import("../block_v5_opcode_memory_sidecar_proof_v1.zig");
const Profile = @import("../../recursion/blake3_execution_parent_protocol.zig").Profile;
const FixedClaims = @import("../../recursion/block_v6_partitioned_public_bus_v1.zig").Claims;
const Fixture = @import("block_v5_lightweight_native_proof_test.zig").Fixture;
test "block-v6 partitioned complete relation native parity and hostile claims" {
    for ([_]u32{ 0, 1 }) |mode| try run(.diagnostic_q8_pow0, mode, true, false, false);
    try run(.diagnostic_q8_pow0, 1, false, false, false);
}
test "block-v6 partitioned local-zero fails closed pending genuine geometry qualification" {
    try std.testing.expectError(error.UnqualifiedPartitionedLocalZeroRecipe, run(.diagnostic_q8_pow0, 1, false, true, false));
    try std.testing.expectError(error.UnqualifiedPartitionedLocalZeroRecipe, run(.diagnostic_q8_pow0, 1, true, true, false));
}
test "block-v6 partitioned cold fixed compiler derives original metadata without proofs" {
    for ([_]u32{ 0, 1 }) |mode| try run(.diagnostic_q8_pow0, mode, true, false, true);
    try run(.diagnostic_q8_pow0, 1, false, false, true);
}
fn run(profile: Profile, mode: u32, comptime ram: bool, comptime local_zero: bool, comptime cold_only: bool) !void {
    const a = std.testing.allocator;
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
    if (local_zero) {
        const local = try @import("../blake3_execution_trace.zig").Owner.initLocalZeroWithExternal(a, &segment.execution_trace, fixture.io.data, &segment.state_chain_tracker, 0);
        errdefer local.deinit();
        try local.sealNativeOnly();
        fixture.owner.deinit();
        fixture.owner = local;
    }
    var context = fixture.pin.context;
    context.register_custody_mode = mode;
    context.register_endpoint_plan_digest = pins.register_endpoint_plan_digest;
    fixture.pin = try @import("../block_v5_native_public_admission_v1.zig").Admission.init(context, &fixture.owner.statement.public_data);
    if (local_zero) {
        var offset: usize = 0;
        for (fixture.owner.statement.component_descs[0..fixture.owner.statement.n_components]) |desc| {
            const semantic = try @import("../../air/semantic_component.zig").SemanticComponent.initLocalZero(desc.family, desc.log_size, 0, 0);
            for (0..@as(usize, 1) << @intCast(desc.log_size)) |logical| {
                const physical = @import("../../recursion/air/framework_interaction.zig").committedRow(logical, desc.log_size);
                var row: [@import("../../runner/trace.zig").MAX_FAMILY_COLUMNS]Q = undefined;
                for (row[0..desc.n_columns], fixture.owner.main.items[offset..][0..desc.n_columns]) |*value, column| value.* = Q.fromBase(column.values[physical]);
                const evaluated = try semantic.evaluateRow(row[0..desc.n_columns], if (logical < desc.n_rows) Q.one() else Q.zero());
                for (evaluated.values[0..evaluated.len], 0..) |value, ordinal| if (!value.isZero()) {
                    std.debug.print("local-zero semantic family={s} row={} constraint={}\n", .{ @tagName(desc.family), logical, ordinal });
                    return error.InvalidLocalZeroSemanticWitness;
                };
            }
            offset += desc.n_columns;
        }
    }
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
    var layout = try Layout.init(a, &fixture.owner.statement, 0, mode);
    defer layout.deinit();
    const projections = layout.slots;
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
    if (cold_only) {
        const NativeAdmission = @import("../block_v5_native_recursive_admission_v3.zig");
        const Admission = @import("../block_v6_partitioned_recursive_admission_v1.zig");
        const Fixed = @import("../../recursion/block_v6_partitioned_recursive_fixed_v1.zig");
        var native_admission = try NativeAdmission.Prepared.init(a, pin.shape, pin.admission, pin.template, pin.template_id, 0, sealed, pins, &entries, catalog);
        defer native_admission.deinit();
        var admitted = try Admission.Prepared.init(a, &native_admission, memory, .{});
        defer admitted.deinit();
        const claims = try a.alloc(Fused.Claim, admitted.projections.len);
        defer a.free(claims);
        for (claims, admitted.projections) |*claim, slot| claim.* = .{ .sum = Q.zero(), .row_count = slot.n_rows };
        const memory_claims = try a.alloc(Memory.Claim, admitted.slots.len);
        defer a.free(memory_claims);
        for (memory_claims) |*claim| claim.* = .{ .transition_sum = Q.zero(), .universal_sum = Q.zero(), .active_count = 0, .range_claims = @splat(Q.zero()) };
        const proposed = FixedClaims{ .projection = claims, .memory = memory_claims };
        const fixed = try Fixed.Owned.derive(a, &admitted, proposed, .{});
        defer fixed.deinit();
        try std.testing.expectEqual(admitted.tree_count + 1, fixed.columns.len);
        try std.testing.expectEqual(fixed.composition.input_count, fixed.sources.len);
        try fixed.validateAgainst(&admitted, proposed, .{});
        try std.testing.expectError(error.MissingPartitionedFixedTranscriptSourcesPcsAndRoster, fixed.requireComplete());
        fixed.template_id[0] ^= 1;
        try std.testing.expectError(error.UntrustedPartitionedFixedSetup, fixed.validateAgainst(&admitted, proposed, .{}));
        fixed.template_id[0] ^= 1;
        fixed.mask_log += 1;
        try std.testing.expectError(error.UntrustedPartitionedFixedSetup, fixed.validateAgainst(&admitted, proposed, .{}));
        fixed.mask_log -= 1;
        // Claim values must not alter the equation DAG or sample geometry.
        claims[0].sum = Q.one();
        const changed = try Fixed.Owned.derive(a, &admitted, proposed, .{});
        defer changed.deinit();
        try std.testing.expectEqualDeep(fixed.composition.identity_digest, changed.composition.identity_digest);
        try std.testing.expectEqualDeep(fixed.deep_graph.graph().identity_digest, changed.deep_graph.graph().identity_digest);
        if (std.posix.getenv("STWO_B6_PARTITIONED_FIXED_ROSTER") != null) {
            var roster = try @import("../../recursion/block_v6_partitioned_fixed_roster_v1.zig").Owned.derive(a, &admitted, proposed, 2, profile, .{});
            defer roster.deinit();
            try std.testing.expect(roster.wires.len > 0);
            try roster.namespace.requireIndependentMainPort();
            try std.testing.expectEqualDeep(admitted.template_id, roster.context.child_key_id);
        }
        return;
    }
    var proof = try Partitioned.ForBackend(Cpu).prove(a, &first, &access, source.inputs, source.slots, memory, sealed, pins, &entries, catalog);
    var owns = true;
    defer if (owns) proof.deinit(a);
    try std.testing.expectEqual(@as(usize, if (source.slots.len == 0) 4 else 5), proof.stark.commitment_scheme_proof.commitments.items.len);
    const Codec = @import("../block_v6_partitioned_native_codec_v1.zig");
    const expected = Codec.Expected{ .shape = pin.shape, .external_retirements = 0, .template_id = first.template_id, .native_instance_id = first.instance_id, .fused_instance_id = entries[3].instance_id, .native_roots = first.roots, .witness_root = memory.witness_root, .sealed_digest = sealed.digest, .index = 0, .frame = frame, .register_custody_mode = mode, .config = pins.config };
    const encoded = try Codec.encode(a, &proof, expected, .{});
    defer a.free(encoded);
    var decoded = try Codec.decode(a, encoded, expected, .{});
    defer decoded.deinit(a);
    try std.testing.expectEqualDeep(proof.claims, decoded.claims);
    var wrong_policy = expected;
    wrong_policy.sealed_digest[0] ^= 1;
    try std.testing.expectError(error.UntrustedPartitionedNativeWirePolicy, Codec.decode(a, encoded, wrong_policy, .{}));
    if (mode == 1 and ram and !local_zero and std.posix.getenv("STWO_B6_PARTITIONED_RECURSION") != null) {
        const NativeAdmission = @import("../block_v5_native_recursive_admission_v3.zig");
        const Admission = @import("../block_v6_partitioned_recursive_admission_v1.zig");
        const Capture = @import("../block_v6_partitioned_recursive_capture_v1.zig");
        const Bus = @import("../../recursion/block_v6_partitioned_public_bus_v1.zig");
        var native_admission = try NativeAdmission.Prepared.init(a, pin.shape, pin.admission, pin.template, pin.template_id, 0, sealed, pins, &entries, catalog);
        defer native_admission.deinit();
        var admitted = try Admission.Prepared.init(a, &native_admission, memory, .{ .max_preparation_bytes = 2 << 30 });
        defer admitted.deinit();
        var recursive_capture = try Capture.ForBackend(Cpu).verifyOwned(a, try clone(a, proof), &admitted, admitted.template_id);
        defer recursive_capture.deinit();
        var prepared = try Bus.prepare(a, &admitted, &recursive_capture, 2);
        defer prepared.deinit();
        if (std.posix.getenv("STWO_B6_PARTITIONED_FIXED_PARITY") != null) {
            var cold = try @import("../../recursion/block_v6_partitioned_fixed_roster_v1.zig").Owned.derive(a, &admitted, .{ .projection = recursive_capture.metadata.claims, .memory = recursive_capture.metadata.memory_claims }, 2, profile, .{});
            defer cold.deinit();
            try cold.validateLive(&prepared);
        }
        try std.testing.expect(prepared.wires.len > 0);
        try prepared.values.validate();
        var public_exports = try Bus.exportsFromValues(a, &admitted, prepared.values);
        defer public_exports.deinit(a);
        try std.testing.expectEqualDeep(recursive_capture.receipt, public_exports.native);
        try std.testing.expectError(error.MissingPartitionedRegisterPlan, @import("../block_v6_partitioned_accounting_v1.zig").extract(a, &admitted, &public_exports, null));
        var changed_values = try prepared.values.clone(a);
        defer changed_values.deinit();
        changed_values.statement.roots_offset[0] += 1;
        try std.testing.expectError(error.UntrustedPartitionedPublicExports, Bus.exportsFromValues(a, &admitted, changed_values));

        if (std.posix.getenv("STWO_B6_PARTITIONED_PARENT_PROOF") != null) {
            const Parent = @import("../../recursion/blake3_execution_parent_proof.zig");
            const Protocol = @import("../../recursion/block_v6_partitioned_parent_protocol_v1.zig");
            const geometry = try Parent.ForBackend(Cpu).deriveKeyWithProfile(a, &prepared.recursive, profile);
            const key = try Protocol.Key.fromGeometry(geometry, prepared.wires);
            const key_id = try key.identity();
            const authority = try Protocol.Admission.init(key, key_id, prepared.wires, prepared.values);
            const Plan = @import("../../recursion/blake3_native_parent_producer.zig").PlanForProtocol(Cpu, Protocol);
            const plan = try Plan.init(a, &prepared.recursive.rows, authority);
            defer plan.deinit();
            var proved = try plan.prove(a, &prepared.recursive.rows);
            defer proved.deinit();
            const bytes = try Parent.codec.encode(a, &proved, &authority);
            defer a.free(bytes);
            var received = try Parent.codec.decode(a, bytes, &authority);
            var verified = try Parent.verify(&received, &authority);
            defer verified.deinit();
            try verified.validate(&authority, key_id);
            var changed = try prepared.values.clone(a);
            defer changed.deinit();
            changed.public[8] = changed.public[8].add(Q.one());
            const wrong_authority = try Protocol.Admission.init(key, key_id, prepared.wires, changed);
            if (Parent.codec.decode(a, bytes, &wrong_authority)) |bad_received| {
                var bad = bad_received;
                if (Parent.verify(&bad, &wrong_authority)) |accepted| {
                    var wrong = accepted;
                    wrong.deinit();
                    return error.AcceptedChangedPartitionedRecursiveClaim;
                } else |_| {}
            } else |_| {}
        }
    }
    const native_proof = try Native.ForBackend(Cpu).proveWithCatalog(a, &first, sealed, pins, &entries, catalog);
    const original = try Native.ForBackend(Cpu).verifyOwnedWithCatalog(a, native_proof, &fixture.owner.statement, fixture.pin, first.template, first.template_id, .rv32im_zkvm_v1, 0, sealed, pins, &entries, catalog);
    var bad = try clone(a, proof);
    bad.claims[0].sum = bad.claims[0].sum.add(Q.one());
    bad.claims[1].sum = bad.claims[1].sum.sub(Q.one());
    if (Partitioned.ForBackend(Cpu).verifyOwned(a, bad, 0, pin, memory, sealed, pins, &entries, catalog)) |accepted| {
        var value = accepted;
        value.deinit(a);
        return error.AcceptedCancellingPartitionedClaims;
    } else |_| {}
    var capture: Partitioned.Capture = undefined;
    owns = false;
    var fresh = try Partitioned.ForBackend(Cpu).verifyOwnedCapture(a, proof, 0, pin, memory, sealed, pins, &entries, catalog, &capture);
    defer fresh.deinit(a);
    defer capture.deinit();
    try std.testing.expectEqualDeep(original.open_sum, fresh.native.open_sum);
    try std.testing.expectEqualDeep(layout.digest, fresh.native.layout_digest);
    try std.testing.expectEqual(projections.len, capture.claims.len);
}
fn clone(a: std.mem.Allocator, proof: Fused.Proof) !Fused.Proof {
    const postcard = @import("interop_postcard");
    var writer = std.Io.Writer.Allocating.init(a);
    defer writer.deinit();
    try postcard.serializeProof(core.proof_suites.Blake3.Hasher, &writer.writer, proof.stark);
    var stream = std.io.fixedBufferStream(writer.written());
    var stark = try postcard.deserializeProof(core.proof_suites.Blake3.Hasher, a, stream.reader());
    errdefer stark.deinit(a);
    const claims = try a.dupe(Fused.Claim, proof.claims);
    errdefer a.free(claims);
    return .{ .stark = stark, .claims = claims, .memory_claims = try a.dupe(Memory.Claim, proof.memory_claims) };
}

test "block-v6 partitioned caller-only physical frame proves without invented relation claims" {
    const a = std.testing.allocator;
    const Elf = @import("../../runner/guest_precompile/test_elf.zig");
    const diagnostic = Elf.buildEthereumSha(.rv32im_zkvm_ethereum_sha_v1);
    const elf = Elf.withReleaseAbi(diagnostic.len, &diagnostic);
    var session = try @import("../../runner/mod.zig").EthereumShaExecutionSession.init(a, &elf, .{ .clock_frame = .leaf_local, .trace_retention = .segment_owned });
    defer session.deinit();
    var setup = try session.startSegment(3);
    defer setup.deinit();
    var segment = try session.resumeSegment(setup.base.continuation.?, 4);
    defer segment.deinit();
    var io = try @import("../blake3_segment_public.zig").Owned.init(a, &segment.base);
    defer io.deinit();
    io.data.program_root = .{ .bytes = @splat(3) };
    const external_count: u32 = 3;
    const owner = try @import("../blake3_execution_trace.zig").Owner.initWithExternal(a, &segment.base.execution_trace, io.data, &segment.base.state_chain_tracker, external_count);
    defer owner.deinit();
    try owner.sealNativeOnly();
    try std.testing.expect(@import("../block_v5_native_frame_v1.zig").required(&owner.statement));
    var counts: [Seal.family_count]u32 = @splat(0);
    for ([_]Seal.Family{ .program, .execution, .execution_sidecar, .program_request, .memory }) |f| counts[@intFromEnum(f) - 1] = 1;
    var pins = Seal.Pins{ .job_id = @splat(1), .source_image_digest = @splat(2), .program_root = @splat(3), .program_plan_digest = @splat(4), .memory_plan_digest = @splat(5), .initial_source_plan_digest = @splat(6), .rw_endpoint_plan_digest = @splat(25), .native_template_catalog_digest = @splat(26), .config = Profile.diagnostic_q8_pow0.config(), .counts = counts };
    const admission = try @import("../block_v5_native_public_admission_v1.zig").Admission.init(.{ .job_id = pins.job_id, .source_image_digest = pins.source_image_digest, .program_root = pins.program_root, .program_plan_digest = pins.program_plan_digest, .memory_plan_digest = pins.memory_plan_digest, .initial_source_plan_digest = pins.initial_source_plan_digest, .rw_endpoint_plan_digest = pins.rw_endpoint_plan_digest, .execution_index = 0, .first_cycle = segment.base.global_first_cycle, .last_cycle = segment.base.global_first_cycle + segment.base.cycle_count - 1 }, &owner.statement.public_data);
    var first = try Native.ForBackend(Cpu).commitFirstRound(a, owner, admission, pins.config, .rv32im_zkvm_ethereum_sha_v1, 0);
    defer first.deinit(a);
    const records = [_]Catalog.Record{.{ .index = 0, .template_id = first.template_id, .geometry_digest = first.template.geometry_digest, .fixed_root = first.roots[0] }};
    const catalog = Catalog.Admission{ .records = &records };
    pins.native_template_catalog_digest = try catalog.digest();
    const frame = @import("../../air/block/memory_event.zig").Frame{ .clock_frame = .leaf_local, .global_first_cycle = segment.base.global_first_cycle, .cycle_count = @intCast(segment.base.cycle_count) };
    const empty = try @import("../block_v5_empty_opcode_memory_v1.zig").firstRoundEntryForMode(a, &owner.statement, frame, first.entry(), 0, 0);
    var access = try @import("../block_v5_native_projection_fused_stage_v2.zig").ForBackend(Cpu).borrowProjectionFirstRound(a, &first.scheme, empty.roots[0]);
    defer access.deinit(a);
    var layout = try Layout.init(a, &owner.statement, external_count, 0);
    defer layout.deinit();
    try std.testing.expectEqual(@as(usize, 0), layout.slots.len);
    const entries = [_]Seal.Entry{ .{ .family = .program, .index = 0, .instance_id = @splat(7), .roots = .{ @splat(8), @splat(9) } }, first.entry(), empty, Fused.entry(first.template_id, first.instance_id, first.roots, access.roots[2], 0, frame, layout.slots, &.{}), .{ .family = .memory, .index = 0, .instance_id = @splat(16), .roots = .{ @splat(17), @splat(18) } } };
    const sealed = try Seal.seal(pins, &entries);
    const pin = Receiver.InstancePin{ .shape = &owner.statement, .admission = admission, .template = first.template, .template_id = first.template_id, .profile = .rv32im_zkvm_ethereum_sha_v1 };
    const memory = Receiver.MemoryPin{ .frame = frame, .expected_events = 0, .witness_root = access.roots[2] };
    var proof = try Partitioned.ForBackend(Cpu).prove(a, &first, &access, &.{}, &.{}, memory, sealed, pins, &entries, catalog);
    var owns = true;
    defer if (owns) proof.deinit(a);
    try std.testing.expectEqual(@as(usize, 0), proof.claims.len);
    const Codec = @import("../block_v6_partitioned_native_codec_v1.zig");
    const expected = Codec.Expected{ .shape = pin.shape, .external_retirements = external_count, .template_id = first.template_id, .native_instance_id = first.instance_id, .fused_instance_id = entries[3].instance_id, .native_roots = first.roots, .witness_root = memory.witness_root, .sealed_digest = sealed.digest, .index = 0, .frame = frame, .register_custody_mode = 0, .config = pins.config };
    const encoded = try Codec.encode(a, &proof, expected, .{});
    defer a.free(encoded);
    var decoded = try Codec.decode(a, encoded, expected, .{});
    defer decoded.deinit(a);
    owns = false;
    var fresh = try Partitioned.ForBackend(Cpu).verifyOwned(a, proof, 0, pin, memory, sealed, pins, &entries, catalog);
    defer fresh.deinit(a);
    try std.testing.expect(fresh.native.program_sum.isZero());
    for (fresh.native.partition_sums) |sum| try std.testing.expect(sum.isZero());
}
