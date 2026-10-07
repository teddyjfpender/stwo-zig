//! Heavy gate: independently pinned strong native child enters a strong local outer proof.
//! This does not construct or publish the 49-row V3 wrapper.
const std = @import("std");
const builtin = @import("builtin");
const frontend = @import("stwo_riscv_frontend");
const CpuBackend = @import("stwo_cpu_backend").CpuBackend;
const fixture = @import("recursive_segment_v3_native_test_fixture.zig");
const pinned_ingress = @import("recursive_segment_v3_native_security_ingress.zig");
const leaf_outer = @import("recursive_segment_v2_leaf_outer.zig");
const outer_cohort = @import("recursive_segment_v2_outer_cohort.zig");
const M31 = @import("stwo_core").fields.m31.M31;
const recursion = frontend.recursion;
const fixed_rows = @import("native_v3_strong_chain_fixed_rows.zig");
const Engine = recursion.engine.ProverEngineForBackend(CpuBackend);

// Independently recorded for this ELF and local V2 projection, as in the
// pinned-native gate. These values are never derived from the proof under test.
const known_tree0 = [8]u32{
    2053578112, 2007969840, 1758814271, 1936034131,
    1603516961, 444025432,  32631551,   1362738667,
};
const known_key_id = [32]u8{
    0x0d, 0xe4, 0xa3, 0x90, 0x93, 0x1c, 0xa0, 0xa3,
    0x66, 0x39, 0x57, 0x5a, 0x0b, 0x76, 0x40, 0x38,
    0x0c, 0xfb, 0x4b, 0xa7, 0x1d, 0xc1, 0x34, 0x23,
    0xbc, 0xa4, 0x47, 0x36, 0xa1, 0x41, 0x61, 0xe9,
};

test "real q193 native child feeds freshly verified q193 local outer" {
    const allocator = std.testing.allocator;
    const elf = frontend.testing.guest_precompile_test_elf.build(false, .self_loop);
    var session = try frontend.runner.Poseidon2ExecutionSession.init(allocator, &elf, .{
        .trace_retention = .segment_owned,
        .clock_frame = .leaf_local,
    });
    defer session.deinit();
    var left = try session.startSegment(1);
    defer left.deinit();
    var right = try session.resumeSegment(left.base.continuation.?, 16);
    defer right.deinit();
    const source = try fixture.rightGlobal(allocator, &left.base, &right.base);
    const pinned_key = try pinned_ingress.PinnedKeyV1.admit(known_tree0, known_key_id);
    const preleaf_core = try recursion.air.segment_leaf_wrapper_template_v6.testFrozenCoreProfileV6();
    const session_id = recursion.poseidon2_channel.hashBytes("native-local-v3-session", 0x4e56_3250);
    var selected_wire = try fixed_rows.selectV12BeforeProof(allocator, &source, session_id, &preleaf_core, known_tree0, fixed_rows.Q193_GRAPH_PINS);
    defer selected_wire.deinit();
    var timer = try std.time.Timer.start();
    var verified = try pinned_ingress.proveAndVerifyPinned(
        Engine,
        allocator,
        &source,
        session_id,
        pinned_key,
    );
    defer verified.deinit();
    const native_ns = timer.lap();
    const shape = selected_wire.schedule_shape;
    const keys = try recursion.segment_leaf_authority_v2.VerifierKeyAuthorityV2.init(
        recursion.poseidon2_channel.hashBytes("strong-v3-local-segment-vk", 0x4b56_3353),
        recursion.poseidon2_channel.hashBytes("strong-v3-local-parent-vk", 0x4b56_3350),
    );
    try fixed_rows.checkV12SelectedFixedWire(allocator, &verified, &selected_wire);
    try fixed_rows.checkV12CapturedPreleafLayout(&selected_wire, &verified.native.capture);
    const original_tree0_log = verified.native.capture.proof.column_log_sizes[0][0];
    verified.native.capture.proof.column_log_sizes[0][0] = original_tree0_log ^ 1;
    const altered_layout_result = fixed_rows.checkV12CapturedPreleafLayout(&selected_wire, &verified.native.capture);
    verified.native.capture.proof.column_log_sizes[0][0] = original_tree0_log;
    try std.testing.expectError(error.V12PreleafLayoutMismatch, altered_layout_result);
    std.debug.print("DIRECT50_V12_FIXED_WIRE selected_shape=true native_capture_parity=true tamper_rejected=true proof_created=false\n", .{});
    std.debug.print("DIRECT50_V11_PRELEAF_LAYOUT trees0_2_from_statement=true tree3_from_pinned_core=true proof_created=false\n", .{});
    var prepared = try leaf_outer.PreparedNativeV2LeafOuter.init(
        allocator,
        allocator,
        &verified.native.capture,
        recursion.protocol.PCS_CONFIG,
        verified.native.interaction_pow,
        keys,
        try fixed_rows.diagnosticRelations(allocator, known_key_id, known_tree0),
        .{ .vm = &selected_wire.vm_plan, .recursion = &selected_wire.recursion_plan },
    );
    verified.native.capture_owned = false;
    defer prepared.deinit();
    try pinned_ingress.admitPreparedNativeV2(&prepared, pinned_key);
    try fixed_rows.checkV12CapturedVmGraph(allocator, &selected_wire, &prepared.capture);
    try fixed_rows.checkV12CapturedCoreCircuits(&selected_wire, &prepared);
    selected_wire.pcs_circuit_id[0] ^= 1;
    const altered_pcs_result = fixed_rows.checkV12CapturedCoreCircuits(&selected_wire, &prepared);
    selected_wire.pcs_circuit_id[0] ^= 1;
    try std.testing.expectError(error.V12PreleafCoreCircuitMismatch, altered_pcs_result);
    std.debug.print("DIRECT50_V12_VM_GRAPH selected_before_proof=true captured_graph_parity=true proof_created=false\n", .{});
    std.debug.print("DIRECT50_V12_CORE_CIRCUITS selected_before_proof=true pcs_fri_capture_parity=true proof_created=false\n", .{});
    var cohort = try outer_cohort.Cohort.init(allocator, &prepared);
    defer cohort.deinit();
    const prepare_ns = timer.lap();
    try diagnoseDirect47(allocator, &prepared, &verified.native.global_metadata, &verified.native.link, &cohort);
    const direct47_ns = timer.lap();
    diagnoseDirect50(allocator, &prepared, shape, &verified.native.global_metadata, &verified.native.link, &cohort, &selected_wire.preleaf_layout, &selected_wire.preleaf_masks, &selected_wire) catch |err| {
        std.debug.print("DIRECT50_ERROR={s}\n", .{@errorName(err)});
        return err;
    };
    const direct50_ns = timer.lap();
    if (std.process.hasEnvVarConstant("STWO_V5_TUPLE_DIAG_ONLY")) {
        std.debug.print("DIRECT50_TIMING native_ingress_ns={d} recursive_prepare_ns={d} direct47_ns={d} direct50_ns={d} peak_rss_bytes={d} strong_outer_skipped=true\n", .{
            native_ns, prepare_ns, direct47_ns, direct50_ns, peakRssBytes(),
        });
        return;
    }

    const strong_outer = recursion.segment_outer_transaction_v3.ForBackend(CpuBackend);
    const StrongKernel = strong_outer.EngineKernel(outer_cohort.Cohort);
    var strong = try StrongKernel.proveAndVerify(allocator, &prepared);
    defer strong.deinit(allocator);
    try strong.receipt.validate();
    try strong.artifact.validateEncoding();
    try strong.field_snapshot.validateAgainst(cohort.manifest(), &strong.artifact);
    std.debug.print(
        "V3_STRONG_CHAIN native_ns={d} outer_transaction_ns={d} outer_prepare_ns={d} outer_prove_ns={d} outer_serialize_ns={d} outer_destroy_ns={d} outer_verify_ns={d} native_proof_bytes={d} outer_proof_bytes={d} outer_producer_peak_bytes={d} wrapper_proof_created=false\n",
        .{ native_ns, strong.receipt.transaction_ns, strong.receipt.producer_prepare_ns, strong.receipt.prover_ns, strong.receipt.serialize_ns, strong.receipt.producer_destroy_ns, strong.receipt.fresh_verifier_ns, verified.native.proof_bytes.len, strong.artifact.proof_bytes.len, strong.receipt.producer_peak_bytes },
    );
}

fn diagnoseDirect47(
    allocator: std.mem.Allocator,
    prepared: *const leaf_outer.PreparedNativeV2LeafOuter,
    metadata: *const recursion.segment_leaf_local_authority_v3.MetadataV3,
    link: *const recursion.segment_leaf_local_verified_link_v3.VerifiedLinkV3,
    cohort: *outer_cohort.Cohort,
) !void {
    const program_mod = recursion.ethereum_leaf_link_program_v3;
    const hash_mod = recursion.segment_leaf_wrapper_field_hash_witness_v3;
    const source_air = recursion.air.ethereum_leaf_link_source_v1;
    const arithmetic_air = recursion.air.ethereum_leaf_link_arithmetic_v1;
    const arithmetic_witness = recursion.air.ethereum_leaf_link_arithmetic_witness_v1;
    const direct_rows = recursion.segment_leaf_wrapper_cohort_direct_rows_v4;
    const candidate = recursion.segment_leaf_wrapper_cohort_candidate_v4;
    const call_buffer = recursion.segment_leaf_wrapper_cohort_calls_v3;
    const provider_mod = recursion.segment_leaf_wrapper_cohort_provider_v3;
    const plan_mod = recursion.segment_leaf_wrapper_roster_direct_v4;
    var native = try recursion.segment_leaf_wrapper_field_witness_v3.NativeV1.initFromPrepared(allocator, prepared);
    defer native.deinit();
    var program = try program_mod.ProgramV3.init(allocator);
    defer program.deinit();
    var source = try recursion.segment_leaf_wrapper_source_projection_direct_v3.initFromNative(allocator, &program, prepared, metadata, link, &native);
    defer source.deinit();
    const metadata_words = try metadata.identityWords();
    const link_words = try link.identityWords();
    var metadata_hash = try hash_mod.HashV1.init(allocator, &metadata_words, recursion.segment_leaf_local_authority_v3.METADATA_ID_DOMAIN, source_air.METADATA_SCOPE, source_air.METADATA_DIGEST_KIND, recursion.ethereum_leaf_link_program_v1.METADATA_HASH_STEP_BASE, try metadata.identity());
    defer metadata_hash.deinit();
    var link_hash = try hash_mod.HashV1.init(allocator, &link_words, recursion.segment_leaf_local_verified_link_v3.IDENTITY_DOMAIN, source_air.LINK_SCOPE, source_air.LINK_DIGEST_KIND, recursion.ethereum_leaf_link_program_v1.LINK_HASH_STEP_BASE, link.identity);
    defer link_hash.deinit();
    var arithmetic = [_]arithmetic_air.Row{[_]M31{M31.zero()} ** arithmetic_air.LOGICAL_INPUT_COUNT} ** 16;
    arithmetic[0] = try arithmetic_witness.logicalRow(.entry_root, metadata.entry.continuation_root, false, 0, 0);
    arithmetic[1] = try arithmetic_witness.logicalRow(.exit_root, metadata.exit.continuation_root, false, 0, 0);
    arithmetic[2] = try arithmetic_witness.logicalRow(.completion, 0, metadata.completion != null, 0, 0);
    arithmetic[3] = try arithmetic_witness.logicalRow(.position, 0, false, metadata.global_cycle_start, metadata.local_cycle_count);
    const base_calls = try cohort.core.completePoseidonCalls();
    const plan = try plan_mod.Plan.build(allocator, cohort.manifest(), &program, .{
        .program_words = native.program.words.len,
        .base_poseidon_calls = base_calls.len,
    });
    const parts = [_][]const call_buffer.Call{
        base_calls, metadata_hash.calls, link_hash.calls, native.program_hash.calls,
    };
    var buffer = try call_buffer.Buffer.init(allocator, &parts);
    defer buffer.deinit();
    const writer = try provider_mod.Writer.initForDirectPlan(allocator, &plan, &buffer, &parts);
    var rows = try direct_rows.Rows.init(allocator, &plan, &program, &source, &arithmetic, &native, &metadata_hash, &link_hash);
    defer rows.deinit();
    const pp = try allocateDirectTree(allocator, &plan, 0);
    defer freeDirectTree(allocator, pp);
    const main = try allocateDirectTree(allocator, &plan, 1);
    defer freeDirectTree(allocator, main);
    const interaction = try allocateDirectTree(allocator, &plan, 2);
    defer freeDirectTree(allocator, interaction);
    try candidate.fillPreprocessed(allocator, cohort, &plan, &writer, &rows, pp);
    try candidate.fillMain(allocator, cohort, &plan, &writer, &rows, main);
    const relations = prepared.outer_relations;
    const shared = try recursion.air.universal_shared_provider.SharedProviderRelations.init(&relations);
    const claims = try candidate.fillInteraction(allocator, cohort, &plan, &writer, &rows, &relations, &shared, main, interaction);
    const boundary = try cohort.publicWireBoundary(&relations);
    const residuals = try claims.residuals(&plan, &boundary);
    var nonzero_domains: usize = 0;
    for (residuals.domain_totals, 0..) |sum, domain| {
        if (sum.isZero()) continue;
        nonzero_domains += 1;
        const limbs = sum.toM31Array();
        std.debug.print("DIRECT47_RESIDUAL domain={d} limbs={d},{d},{d},{d}\n", .{ domain, limbs[0].toU32(), limbs[1].toU32(), limbs[2].toU32(), limbs[3].toU32() });
        for (claims.audits, 0..) |audit, row| {
            const contribution = audit.values[domain];
            if (contribution.isZero()) continue;
            const term = contribution.toM31Array();
            std.debug.print("DIRECT47_TERM domain={d} row={d} limbs={d},{d},{d},{d}\n", .{
                domain, row, term[0].toU32(), term[1].toU32(), term[2].toU32(), term[3].toU32(),
            });
        }
    }
    std.debug.print("DIRECT47_CANDIDATE claims=47 nonzero_domains={d} framework_zero={} proof_created=false\n", .{ nonzero_domains, residuals.framework_total.isZero() });
    if (nonzero_domains == 0) _ = try claims.verifyAllDomains(&plan, &boundary);
}

fn diagnoseDirect50(
    allocator: std.mem.Allocator,
    prepared: *const leaf_outer.PreparedNativeV2LeafOuter,
    admitted_shape: recursion.air.verifier_schedule.ScheduleShape,
    metadata: *const recursion.segment_leaf_local_authority_v3.MetadataV3,
    link: *const recursion.segment_leaf_local_verified_link_v3.VerifiedLinkV3,
    cohort: *outer_cohort.Cohort,
    preleaf_layout: *const recursion.segment_core_expected_layout_from_statement_v11.OwnedLayout,
    preleaf_masks: *const recursion.segment_core_expected_pcs_masks_v12.OwnedMasks,
    selected: *const fixed_rows.SelectedV12,
) !void {
    var phase_timer = try std.time.Timer.start();
    const link_program = recursion.ethereum_leaf_link_program_v3;
    const local_program = recursion.ethereum_leaf_child_field_program_v1;
    const local_witness = recursion.ethereum_leaf_child_field_witness_v1;
    const local_rows = recursion.segment_leaf_wrapper_local_identity_v5;
    const statement_air = recursion.segment_leaf_statement_source_direct_v5;
    const hash_mod = recursion.segment_leaf_wrapper_field_hash_witness_v3;
    const source_air = recursion.air.ethereum_leaf_link_source_v1;
    const arithmetic_air = recursion.air.ethereum_leaf_link_arithmetic_v1;
    const arithmetic_witness = recursion.air.ethereum_leaf_link_arithmetic_witness_v1;
    const direct_rows = recursion.segment_leaf_wrapper_cohort_direct_rows_v4;
    const v5_rows = recursion.segment_leaf_wrapper_cohort_rows_v5;
    const candidate = recursion.segment_leaf_wrapper_cohort_candidate_v5;
    const call_buffer = recursion.segment_leaf_wrapper_cohort_calls_v3;
    const provider_mod = recursion.segment_leaf_wrapper_cohort_provider_v3;
    const plan_mod = recursion.segment_leaf_wrapper_roster_direct_v5;
    const las2_mod = recursion.segment_leaf_wrapper_las2_boundary_v4;
    var native = try recursion.segment_leaf_wrapper_field_witness_v3.NativeV1.initFromPrepared(allocator, prepared);
    defer native.deinit();
    var program = try link_program.ProgramV3.init(allocator);
    defer program.deinit();
    var source = try recursion.segment_leaf_wrapper_source_projection_direct_v3.initFromNative(allocator, &program, prepared, metadata, link, &native);
    defer source.deinit();
    const metadata_words = try metadata.identityWords();
    const link_words = try link.identityWords();
    var metadata_hash = try hash_mod.HashV1.init(allocator, &metadata_words, recursion.segment_leaf_local_authority_v3.METADATA_ID_DOMAIN, source_air.METADATA_SCOPE, source_air.METADATA_DIGEST_KIND, recursion.ethereum_leaf_link_program_v1.METADATA_HASH_STEP_BASE, try metadata.identity());
    defer metadata_hash.deinit();
    var link_hash = try hash_mod.HashV1.init(allocator, &link_words, recursion.segment_leaf_local_verified_link_v3.IDENTITY_DOMAIN, source_air.LINK_SCOPE, source_air.LINK_DIGEST_KIND, recursion.ethereum_leaf_link_program_v1.LINK_HASH_STEP_BASE, link.identity);
    defer link_hash.deinit();
    var arithmetic = [_]arithmetic_air.Row{[_]M31{M31.zero()} ** arithmetic_air.LOGICAL_INPUT_COUNT} ** 16;
    arithmetic[0] = try arithmetic_witness.logicalRow(.entry_root, metadata.entry.continuation_root, false, 0, 0);
    arithmetic[1] = try arithmetic_witness.logicalRow(.exit_root, metadata.exit.continuation_root, false, 0, 0);
    arithmetic[2] = try arithmetic_witness.logicalRow(.completion, 0, metadata.completion != null, 0, 0);
    arithmetic[3] = try arithmetic_witness.logicalRow(.position, 0, false, metadata.global_cycle_start, metadata.local_cycle_count);
    const descriptors = prepared.capture.vm_air.component_descs;
    const infra = prepared.capture.vm_air.infra_descs;
    var child_program = try local_program.ProgramV1.initWithNativeProgramBridge(allocator, descriptors, infra);
    defer child_program.deinit();
    const inputs = local_witness.InputsV1{
        .public_data = &prepared.capture.public_data.data,
        .context = &prepared.authority_prepared.source.context,
        .receipt = &prepared.capture.receipt,
        .tree0_root = native.tree0_root,
        .component_descs = descriptors,
        .infra_descs = infra,
    };
    var child_witness = try local_witness.WitnessV1.init(allocator, &child_program, inputs);
    defer child_witness.deinit();
    const base_calls = try cohort.core.completePoseidonCalls();
    const plan = try plan_mod.Plan.build(allocator, cohort.manifest(), &program, .{
        .program_words = native.program.words.len,
        .base_poseidon_calls = base_calls.len,
    }, &child_program, descriptors, infra);
    const parts = [_][]const call_buffer.Call{
        base_calls,                                  metadata_hash.calls,                       link_hash.calls, native.program_hash.calls,
        child_witness.authority_hash.poseidon_calls, child_witness.receipt_hash.poseidon_calls,
    };
    var buffer = try call_buffer.Buffer.init(allocator, &parts);
    defer buffer.deinit();
    const writer = try provider_mod.Writer.init(allocator, &buffer, &parts);
    var rows47 = try direct_rows.Rows.init(allocator, &plan.base_plan, &program, &source, &arithmetic, &native, &metadata_hash, &link_hash);
    defer rows47.deinit();
    const local = try local_rows.Rows.init(allocator, &child_program, &child_witness, inputs);
    var statement = try statement_air.Schedule.init(allocator, &child_program, cohort.noncore.boundary_workspace.statement_rows);
    defer statement.deinit();
    var template = try recursion.transcript_program_v2_template_words_v6.Template.initFromShape(
        allocator,
        &prepared.vm_plan,
        prepared.pcs_config,
        @intCast(prepared.capture.public_data.data.words().len),
        descriptors,
        infra,
        true,
    );
    defer template.deinit();
    try template.checkCanonicalWords(native.program.words);
    std.debug.print("DIRECT50_TEMPLATE words={d} dynamic={d} shape_parity=true\n", .{
        template.words.len, recursion.transcript_program_v2_template_words_v6.DYNAMIC_COUNT,
    });
    var rows50 = try v5_rows.Rows.initWithTemplate(allocator, &plan, &rows47, &statement, &local, &template);
    defer rows50.deinit();
    const pp = try allocateDirectTree(allocator, &plan, 0);
    defer freeDirectTree(allocator, pp);
    const main = try allocateDirectTree(allocator, &plan, 1);
    defer freeDirectTree(allocator, main);
    const interaction = try allocateDirectTree(allocator, &plan, 2);
    defer freeDirectTree(allocator, interaction);
    const setup_ns = phase_timer.lap();
    try candidate.fillPreprocessed(allocator, cohort, &plan, &writer, &rows50, pp);
    try fixed_rows.checkV12Row11FixedParity(allocator, selected, &plan, pp);
    std.debug.print("DIRECT50_V12_ROW11_FIXED selected_before_proof=true source_parity=true proof_created=false\n", .{});
    try fixed_rows.checkV12Row18FixedParity(allocator, selected, &plan, pp);
    std.debug.print("DIRECT50_V12_ROW18_FIXED graph_pinned_before_proof=true source_parity=true proof_created=false\n", .{});
    try fixed_rows.checkV12Row19FixedParity(allocator, selected, &plan, pp);
    std.debug.print("DIRECT50_V12_ROW19_FIXED plans_before_proof=true source_parity=true proof_created=false\n", .{});
    const preprocessed_ns = phase_timer.lap();
    try candidate.fillMain(allocator, cohort, &plan, &writer, &rows50, main);
    const main_ns = phase_timer.lap();
    const relations = prepared.outer_relations;
    const shared = try recursion.air.universal_shared_provider.SharedProviderRelations.init(&relations);
    const claims = try candidate.fillInteraction(allocator, cohort, &plan, &writer, &rows50, &relations, &shared, main, interaction);
    const interaction_ns = phase_timer.lap();
    const boundary = try cohort.publicWireBoundary(&relations);
    const expected = las2_mod.ExpectedPublic{
        .link = link.identity,
        .native_program = native.program.digest,
        .native_tree0 = native.tree0_root,
    };
    const las2 = try las2_mod.BoundaryV4.derive(expected, &relations);
    const residuals = try claims.residuals(&plan, &boundary, &las2, expected, &relations);
    if (std.process.hasEnvVarConstant("STWO_V5_TUPLE_DIAG_ONLY")) {
        var row5_fanout = try recursion.segment_leaf_wrapper_row5_fanout_v6.Schedule.init(
            allocator,
            &program,
            cohort.noncore.transcript_workspace.transcript_payload_rows,
        );
        defer row5_fanout.deinit();
        var row5_fixed = try recursion.segment_leaf_template_payload_fixed_v7.Template.initFromShape(
            allocator,
            &prepared.vm_plan,
            @intCast(prepared.capture.public_data.data.words().len),
            descriptors,
            infra,
            true,
            &program,
        );
        defer row5_fixed.deinit();
        const row5_mismatch = try row5_fixed.firstSourceMismatch(
            allocator,
            &program,
            cohort.noncore.transcript_workspace.transcript_payload_rows,
            rows47.native.program.words[10..18],
        );
        if (row5_mismatch) |mismatch| {
            std.debug.print("DIRECT50_ROW5_FIXED_MISMATCH row={d} column={d} actual={d} expected={d}\n", .{
                mismatch.row, mismatch.column, mismatch.actual, mismatch.expected,
            });
            return error.V7PayloadFixedSourceMismatch;
        }
        std.debug.print("DIRECT50_ROW5_FIXED rows={d} shape_parity=true\n", .{row5_fixed.rows.len});
        const catalog_mod = recursion.air.segment_outer_typed_catalog_v2;
        var log_sizes: recursion.air.universal_manifest.LogSizes = undefined;
        for (&log_sizes, 0..) |*log_size, index|
            log_size.* = cohort.manifest().placements[index].?.geometry.log_size;
        const catalog = try catalog_mod.buildWithProviderShape(
            log_sizes,
            prepared.authority_prepared.manifest.components,
            cohort.noncore.input_provider_workspace.shape,
        );
        if (!std.meta.eql(catalog.identity, cohort.manifest().catalog_identity))
            return error.V7PhysicalCatalogMismatch;
        const core_query_mapping = cohort.core.authority.query_mapping_reference;
        const core_profile = try recursion.air.segment_leaf_wrapper_template_v6.CoreProfileV6.init(
            core_query_mapping.vm,
            core_query_mapping.recursion,
        );
        const v7_template = try recursion.air.segment_leaf_wrapper_template_v7.TemplateManifestV7.build(
            allocator,
            &catalog,
            .{ .program_words = native.program.words.len, .base_poseidon_calls = base_calls.len },
            descriptors,
            infra,
            &prepared.vm_plan,
            &core_profile,
            &core_query_mapping,
            @intCast(prepared.capture.public_data.data.words().len),
            true,
        );
        if (!std.meta.eql(v7_template.v6_template.shape.native_instruction_schedule_id, selected.instruction_template.schedule_id) or
            selected.instruction_template.instruction_count != prepared.transcript_program.instructions.len)
            return error.PreselectedNativeInstructionScheduleMismatch;
        std.debug.print("DIRECT50_V12_PRESELECT plans_before_proof=true instruction_count={d} schedule_bound=true proof_created=false\n", .{selected.instruction_template.instruction_count});
        const v7_plan = try recursion.segment_leaf_wrapper_roster_direct_v7.Plan.fromTemplate(&v7_template);
        const v8_template = try recursion.air.segment_leaf_wrapper_template_v8.TemplateManifestV8.fromVerifierTemplate(allocator, &v7_template);
        const v8_plan = try recursion.segment_leaf_wrapper_roster_direct_v8.Plan.fromTemplate(&v8_template);
        const v8_wire_parameters = try v8_template.admitWireParameter(
            &prepared.capture.public_data.data,
            &prepared.authority_prepared.source.manifest,
        );
        if (v8_wire_parameters[0].toU32() != prepared.capture.public_data.data.words().len or
            v8_plan.placements[36].geometry.log_size != recursion.air.segment_leaf_statement_source_direct_v8.LOG_SIZE)
            return error.V8RealLeafRosterParameterMismatch;
        // This prefix binds the eventual wrapper draw; the current algebraic
        // gate uses a separate draw from pinned native fixture identities.
        const global_statement_expected = recursion.segment_leaf_wrapper_global_statement_boundary_v6.ExpectedPublic{ .words = metadata.base_statement_words };
        var v8_admission_channel = Engine.Channel{};
        try v8_plan.mixBeforeRelationDraw(
            &v8_admission_channel,
            global_statement_expected,
            &prepared.capture.public_data.data,
            &prepared.authority_prepared.source.manifest,
        );
        std.debug.print("DIRECT50_V8_CANDIDATE_ROSTER row36_wire_count={d} shape_admitted=true transcript_bound=true proof_created=false\n", .{v8_wire_parameters[0].toU32()});
        const v9_template = try recursion.air.segment_leaf_wrapper_template_v9.TemplateManifestV9.fromVerifierTemplate(
            allocator,
            &v8_template,
            &prepared.vm_plan,
            admitted_shape,
        );
        var row28_fixed = try recursion.segment_core_fri_row28_fixed_v8.Writer.init(
            allocator,
            &core_profile,
            &prepared.vm_plan,
            &prepared.recursion_plan,
        );
        defer row28_fixed.deinit();
        try v9_template.admitRow28Writer(allocator, &row28_fixed);
        try fixed_rows.checkV9CoreFriAnchorFixedParity(allocator, &v9_template, &plan, pp);
        try fixed_rows.checkV9CoreFriControlFixedParity(allocator, &v9_template, &row28_fixed, &plan, pp);
        try fixed_rows.checkV9CoreFriInputFixedParity(allocator, &v9_template, selected.fri_circuit_id, &plan, pp);
        std.debug.print("DIRECT50_V9_FRI_FIXED row27_source_parity=true row28_source_parity=true row29_source_parity=true recursion_plan_admitted=true proof_created=false\n", .{});
        const v10_template = try recursion.air.segment_leaf_wrapper_template_v10.TemplateManifestV10.fromVerifierTemplate(allocator, &v9_template);
        var row27_fixed = try recursion.segment_core_fri_row27_fixed_v9.Writer.initFromVerifierTemplate(allocator, &v9_template);
        defer row27_fixed.deinit();
        var row29_fixed = try recursion.segment_core_fri_row29_fixed_v9.Writer.initFromVerifierTemplate(allocator, &v9_template);
        defer row29_fixed.deinit();
        try v10_template.admitRow27Writer(allocator, &row27_fixed);
        try v10_template.admitRow29Writer(allocator, &row29_fixed);
        std.debug.print("DIRECT50_V10_FRI_KEY rows27_29_admitted=true full_preprocessing=false proof_created=false\n", .{});
        // All four tree layouts and PCS masks come from verifier-selected
        // inputs; this diagnostic still lacks a complete physical roster.
        const row23_expected = preleaf_layout.expected();
        const row23_layout_hex = std.fmt.bytesToHex(row23_expected.identityDigest(), .lower);
        if (!std.mem.eql(u8, &row23_layout_hex, "7f2265220644e9bde63d10ef1286b6b4ddf3360186e01b1246b0a0239e8e54e1"))
            return error.V11RealLeafLayoutPinMismatch;
        std.debug.print("DIRECT50_V11_ROW23_LAYOUT id={s} source=statement_and_pinned_core_diagnostic\n", .{&row23_layout_hex});
        try fixed_rows.checkV11TraceMerkleFixedParity(allocator, &v10_template, row23_expected, &plan, pp);
        std.debug.print("DIRECT50_V11_ROW23_FIXED source_parity=true key_admitted=false proof_created=false\n", .{});
        const captured_pcs_profile = prepared.captured_fri.pcs_circuit.profile();
        if (!std.mem.eql(recursion.air.pcs_deep_circuit.SamplePointLayout, preleaf_masks.layouts, captured_pcs_profile.sample_layouts) or
            captured_pcs_profile.mask_log_sizes.len != 0) return error.V12PreleafPcsMaskMismatch;
        const row24_expected = recursion.segment_core_pcs_row24_fixed_v11.ExpectedProfile{
            .ordered_tree_logs = &preleaf_layout.views,
            .sample_layouts = preleaf_masks.layouts,
        };
        const row24_circuit_id = try fixed_rows.checkV11PcsInputFixedParity(
            allocator,
            &v10_template,
            row24_expected,
            selected.pcs_circuit_id,
            &plan,
            pp,
        );
        const row24_circuit_hex = std.fmt.bytesToHex(row24_circuit_id, .lower);
        if (!std.mem.eql(u8, &row24_circuit_hex, "01ffe0f7672b593a694f67bb5855c7b11773bbab76e4b2c9b02e2c25a8287f2e"))
            return error.V11RealLeafPcsCircuitPinMismatch;
        std.debug.print("DIRECT50_V11_ROW24_FIXED circuit={s} source_parity=true key_admitted=false proof_created=false\n", .{&row24_circuit_hex});
        const preleaf_key = try recursion.segment_core_preleaf_key_v12.buildForSegmentV2(allocator, &selected.statement.core, &v10_template);
        try fixed_rows.checkV11CandidateAdmission(allocator, &v10_template, &preleaf_key, row24_expected);
        std.debug.print("DIRECT50_V12_CANDIDATE rows23_24_admitted=true source=statement_and_pinned_core_diagnostic full_preprocessing=false proof_created=false\n", .{});
        try fixed_rows.checkV7CoreFriFixedParity(allocator, &core_profile, &v7_plan, &plan, pp);
        std.debug.print("DIRECT50_V7_CORE_FRI_FIXED rows25_26_source_parity=true proof_created=false\n", .{});
        var physical = try recursion.segment_leaf_wrapper_physical_bridge_v7.Writer.init(
            allocator,
            &v7_plan,
            &row5_fixed,
            &template,
            row5_fanout.rows,
            native.program.words,
        );
        defer physical.deinit();
        const source39 = try recursion.segment_leaf_wrapper_source_physical_v7.Writer.init(
            allocator,
            &v7_plan,
            &program,
            rows50.base.source,
        );
        var wire_rows: [recursion.segment_leaf_wrapper_range_provider_v7.WIRE_ROW_COUNT]recursion.air.transcript_program_v2_field_bridge_v6.Row = undefined;
        @memcpy(&wire_rows, physical.row42[10..18]);
        var range_v7 = try recursion.segment_leaf_wrapper_range_provider_v7.Provider.init(
            allocator,
            &cohort.noncore.range_prepared.range_check,
            &arithmetic,
            &wire_rows,
            native.program.words[10..18],
        );
        defer range_v7.deinit();
        var v7_pp = try fixed_rows.V7ChangedTree.init(allocator, &v7_plan, .preprocessed);
        defer v7_pp.deinit();
        var v7_main = try fixed_rows.V7ChangedTree.init(allocator, &v7_plan, .main);
        defer v7_main.deinit();
        var v7_interaction = try fixed_rows.V7ChangedTree.init(allocator, &v7_plan, .interaction);
        defer v7_interaction.deinit();
        try physical.fillPreprocessed(v7_pp.columns);
        try source39.fillPreprocessed(v7_pp.columns);
        try physical.fillMain(v7_main.columns);
        try source39.fillMain(v7_main.columns);
        try range_v7.fillMain(&v7_plan, v7_main.columns);
        const physical_claims = try physical.fillInteraction(&relations, v7_interaction.columns);
        const source39_claim = try source39.fillInteraction(&relations, v7_interaction.columns);
        const range_claim = try range_v7.fillInteraction(&v7_plan, &shared, v7_interaction.columns);
        const half_residual = try physical.wireHalfResidual(&relations);
        if (!half_residual.isZero() or
            !physical_claims.row5.audit.total.eql(physical_claims.row5.claim) or
            !physical_claims.row42.audit.total.eql(physical_claims.row42.claim) or
            !source39_claim.audit.total.eql(source39_claim.claim) or
            !range_claim.audit.total.eql(range_claim.claim))
            return error.V7PhysicalClaimMismatch;
        std.debug.print("DIRECT50_V7_PHYSICAL row5={d} row42={d} row35_requests={d} row39={d} half_scope_zero=true proof_created=false\n", .{
            physical.row5.rows.len, physical.row42.len, range_v7.wire_requests, source39.rows.len,
        });
        const changed_rows = [_]usize{ 5, 35, 39, 42 };
        const changed_audits = [_]recursion.air.relation_interaction.DomainAudit{
            physical_claims.row5.audit, range_claim.audit, source39_claim.audit, physical_claims.row42.audit,
        };
        for ([_]usize{ 25, 29, 30 }) |domain| {
            var adjusted = residuals.domain_totals[domain];
            for (changed_rows, changed_audits) |row, audit|
                adjusted = adjusted.sub(claims.audits[row].values[domain]).add(audit.values[domain]);
            // The versioned source and half-word bridges must close these
            // complete domains in the real cohort. Domain 29 still retains
            // the leaf-dependent V5 statement source and is diagnostic.
            if ((domain == 25 or domain == 30) and !adjusted.isZero())
                return error.V7PhysicalBridgeDomainUnclosed;
            const limbs = adjusted.toM31Array();
            std.debug.print("DIRECT50_V7_CHANGED_RESIDUAL domain={d} zero={} limbs={d},{d},{d},{d}\n", .{
                domain, adjusted.isZero(), limbs[0].toU32(), limbs[1].toU32(), limbs[2].toU32(), limbs[3].toU32(),
            });
        }
        var statement_v6 = try recursion.segment_leaf_statement_source_direct_v6.Schedule.init(
            allocator,
            &program,
            &child_program,
            cohort.noncore.boundary_workspace.statement_rows,
        );
        defer statement_v6.deinit();
        const statement_v8_key = try recursion.segment_leaf_wrapper_row36_direct_v8.FixedKey.compile(allocator);
        if (!std.meta.eql(statement_v8_key.column_digest, v8_template.row36_fixed_ordinal_id))
            return error.V8RealLeafRosterFixedMismatch;
        var statement_v8 = try recursion.segment_leaf_wrapper_row36_direct_v8.Writer.init(
            allocator,
            &statement_v8_key,
            &prepared.capture.public_data.data,
            &prepared.authority_prepared.source.manifest,
            &program,
            &child_program,
            cohort.noncore.boundary_workspace.statement_rows,
            &statement_v6,
        );
        defer statement_v8.deinit();
        const statement_pp = try fixed_rows.allocateV8StatementColumns(allocator, recursion.air.segment_leaf_statement_source_direct_v8.PREPROCESSED_COLUMN_COUNT);
        defer fixed_rows.freeV8StatementColumns(allocator, statement_pp);
        const statement_main = try fixed_rows.allocateV8StatementColumns(allocator, recursion.air.segment_leaf_statement_source_direct_v8.PHYSICAL_MAIN_COLUMN_COUNT);
        defer fixed_rows.freeV8StatementColumns(allocator, statement_main);
        const statement_interaction = try fixed_rows.allocateV8StatementColumns(allocator, recursion.air.segment_leaf_statement_source_direct_v8.INTERACTION_COLUMN_COUNT);
        defer fixed_rows.freeV8StatementColumns(allocator, statement_interaction);
        try statement_v8.fillPreprocessed(statement_pp);
        try statement_v8.fillMain(statement_main);
        const statement_claim = try statement_v8.fillInteraction(&relations, statement_interaction);
        if (!statement_claim.audit.total.eql(statement_claim.total)) return error.V8StatementPhysicalClaimMismatch;
        const statement_adjusted = residuals.domain_totals[29]
            .sub(claims.audits[36].values[29])
            .add(statement_claim.audit.values[29]);
        const statement_limbs = statement_adjusted.toM31Array();
        std.debug.print("DIRECT50_V8_STATEMENT_PHYSICAL rows={d} wire_count={d} domain29_zero={} limbs={d},{d},{d},{d} proof_created=false\n", .{
            statement_v8.rows.len,      statement_v8.wire_count,    statement_adjusted.isZero(),
            statement_limbs[0].toU32(), statement_limbs[1].toU32(), statement_limbs[2].toU32(),
            statement_limbs[3].toU32(),
        });
        std.debug.print("DIRECT50_V6_SCHEDULE row5_fanout={d} statement_link={d} statement_local={d} statement_arithmetic={d} overlaps={d}\n", .{
            row5_fanout.selected_count, statement_v6.link_uses, statement_v6.local_uses, statement_v6.arithmetic_uses, statement_v6.overlaps,
        });
        // Diagnostic only: production must receive these words as verifier public input.
        const global_statement_boundary = try recursion.segment_leaf_wrapper_global_statement_boundary_v6.BoundaryV6.derive(global_statement_expected, &relations);
        try global_statement_boundary.mixClaimAfterRelations(&v8_admission_channel, global_statement_expected, &relations);
        const statement_with_public = statement_adjusted.add(global_statement_boundary.claimed_sum);
        const public_limbs = statement_with_public.toM31Array();
        std.debug.print("DIRECT50_V8_STATEMENT_WITH_PUBLIC domain29_zero={} limbs={d},{d},{d},{d} proof_created=false\n", .{
            statement_with_public.isZero(), public_limbs[0].toU32(), public_limbs[1].toU32(), public_limbs[2].toU32(), public_limbs[3].toU32(),
        });
        if (!statement_with_public.isZero()) return error.V8StatementPublicDomainUnclosed;
        var full_closure = try recursion.segment_leaf_wrapper_cohort_closure_v8.residuals(
            &claims,
            &plan,
            &boundary,
            &las2,
            expected,
            &statement_v8_key,
            statement_claim,
            &global_statement_boundary,
            global_statement_expected,
            &relations,
        );
        const changed_claims = [_]@import("stwo_core").fields.qm31.QM31{
            physical_claims.row5.claim, range_claim.claim, source39_claim.claim, physical_claims.row42.claim,
        };
        for (changed_rows, changed_claims, changed_audits) |row, claim, audit| {
            for (audit.values, 0..) |value, domain|
                full_closure.domain_totals[domain] = full_closure.domain_totals[domain]
                    .sub(claims.audits[row].values[domain]).add(value);
            full_closure.framework_total = full_closure.framework_total.sub(claims.claims[row]).add(claim);
            full_closure.logical_rows = try std.math.add(u64, try std.math.sub(u64, full_closure.logical_rows, claims.audits[row].logical_rows), audit.logical_rows);
            full_closure.event_terms = try std.math.add(u64, try std.math.sub(u64, full_closure.event_terms, claims.audits[row].event_terms), audit.event_terms);
        }
        var full_nonzero: usize = 0;
        for (full_closure.domain_totals, 0..) |sum, domain| {
            if (sum.isZero()) continue;
            full_nonzero += 1;
            const limbs = sum.toM31Array();
            std.debug.print("DIRECT50_V8_FULL_RESIDUAL domain={d} limbs={d},{d},{d},{d}\n", .{
                domain, limbs[0].toU32(), limbs[1].toU32(), limbs[2].toU32(), limbs[3].toU32(),
            });
        }
        std.debug.print("DIRECT50_V8_FULL_CLOSURE nonzero_domains={d} framework_zero={} proof_created=false\n", .{
            full_nonzero, full_closure.framework_total.isZero(),
        });
        if (full_nonzero != 0 or !full_closure.framework_total.isZero())
            return error.V8FullPhysicalRelationNotClosed;
        try diagnoseDirect50Tuples(allocator, cohort, &rows50, &template, &child_witness, &las2, &row5_fanout, &statement_v6, &global_statement_boundary);
    }
    const tuple_ns = phase_timer.lap();
    var nonzero_domains: usize = 0;
    for (residuals.domain_totals, 0..) |sum, domain| {
        if (sum.isZero()) continue;
        nonzero_domains += 1;
        const limbs = sum.toM31Array();
        std.debug.print("DIRECT50_RESIDUAL domain={d} limbs={d},{d},{d},{d}\n", .{ domain, limbs[0].toU32(), limbs[1].toU32(), limbs[2].toU32(), limbs[3].toU32() });
        for (claims.audits, 0..) |audit, row| {
            const contribution = audit.values[domain];
            if (contribution.isZero()) continue;
            const term = contribution.toM31Array();
            std.debug.print("DIRECT50_TERM domain={d} row={d} limbs={d},{d},{d},{d}\n", .{ domain, row, term[0].toU32(), term[1].toU32(), term[2].toU32(), term[3].toU32() });
        }
    }
    std.debug.print("DIRECT50_CANDIDATE claims=50 nonzero_domains={d} framework_zero={} proof_created=false\n", .{ nonzero_domains, residuals.framework_total.isZero() });
    std.debug.print("DIRECT50_PHASE setup_ns={d} preprocessed_ns={d} main_ns={d} interaction_ns={d} tuple_audit_ns={d} peak_rss_bytes={d}\n", .{
        setup_ns, preprocessed_ns, main_ns, interaction_ns, tuple_ns, peakRssBytes(),
    });
    if (nonzero_domains == 0) _ = try claims.verifyAllDomains(&plan, &boundary, &las2, expected, &relations);
}

fn diagnoseDirect50Tuples(
    allocator: std.mem.Allocator,
    cohort: *outer_cohort.Cohort,
    rows: *const recursion.segment_leaf_wrapper_cohort_rows_v5.Rows,
    template: *const recursion.transcript_program_v2_template_words_v6.Template,
    child_witness: *const recursion.ethereum_leaf_child_field_witness_v1.WitnessV1,
    las2: *const recursion.segment_leaf_wrapper_las2_boundary_v4.BoundaryV4,
    row5_fanout: *const recursion.segment_leaf_wrapper_row5_fanout_v6.Schedule,
    statement_v6: *const recursion.segment_leaf_statement_source_direct_v6.Schedule,
    global_statement_boundary: *const recursion.segment_leaf_wrapper_global_statement_boundary_v6.BoundaryV6,
) !void {
    const ri = recursion.air.relation_interaction;
    const relation = frontend.air.relation;
    const mask = (@as(u64, 1) << @intFromEnum(relation.Domain.recursion_verifier_input_word)) |
        (@as(u64, 1) << @intFromEnum(relation.Domain.recursion_statement_word)) |
        (@as(u64, 1) << @intFromEnum(relation.Domain.recursion_vm_public_claim_word));
    var ledger = ri.TupleLedger.init(allocator);
    defer ledger.deinit();
    try cohort.noncore.appendTupleContributions(&ledger, mask);
    try cohort.core.appendTupleContributions(allocator, &ledger, mask);
    var keep: usize = 0;
    for (ledger.contributions.items) |entry| {
        if (entry.component == 4 or entry.component == 5 or entry.component == 34 or entry.component == 35 or entry.component == 36) continue;
        ledger.contributions.items[keep] = entry;
        keep += 1;
    }
    ledger.contributions.items = ledger.contributions.items[0..keep];

    var row5_wire = try recursion.segment_leaf_wrapper_row5_halves_v7.Schedule.init(
        allocator,
        row5_fanout.rows,
        rows.base.native.program.words[10..18],
    );
    defer row5_wire.deinit();
    try appendDirectAirTuples(recursion.air.transcript_payload_direct_v7, allocator, &ledger, 5, row5_wire.rows, mask);
    try appendDirectAirTuples(recursion.segment_leaf_statement_source_direct_v6, allocator, &ledger, 36, statement_v6.rows, mask);
    try appendDirectAirTuples(recursion.ethereum_leaf_link_source_direct_v6, allocator, &ledger, 39, rows.base.source, mask);
    try appendDirectAirTuples(recursion.air.ethereum_leaf_link_projection_v1, allocator, &ledger, 40, rows.base.projection, mask);
    try appendDirectAirTuples(recursion.air.ethereum_leaf_link_arithmetic_v1, allocator, &ledger, 41, rows.base.arithmetic, mask);
    const program_air = recursion.air.transcript_program_v2_field_bridge_v6;
    const program_schedule = try program_air.FixedSchedule.initFromTemplate(template.words);
    const program_rows = try allocator.alloc(program_air.Row, program_schedule.rowCapacity());
    defer allocator.free(program_rows);
    for (program_rows, 0..) |*row, index| {
        const value = if (index < rows.base.native.program.words.len) rows.base.native.program.words[index] else M31.zero();
        row.* = try program_schedule.logicalRow(index, value);
    }
    try appendDirectAirTuples(program_air, allocator, &ledger, 42, program_rows, mask);
    try appendDirectHashTuples(allocator, &ledger, 43, &rows.base.native.program_hash, mask);
    try appendDirectAirTuples(recursion.air.segment_v2_tree0_field_link_direct_v4, allocator, &ledger, 44, &rows.base.native.tree0_link.rows, mask);
    try appendDirectHashTuples(allocator, &ledger, 45, rows.base.metadata_hash, mask);
    try appendDirectHashTuples(allocator, &ledger, 46, rows.base.link_hash, mask);

    const router_air = recursion.air.ethereum_leaf_child_field_router_v1;
    const router = try allocator.alloc(router_air.Row, @as(usize, 1) << @intCast(rows.local.layout.placements[0].log_size));
    defer allocator.free(router);
    @memset(router, [_]M31{M31.zero()} ** router_air.LOGICAL_INPUT_COUNT);
    const active = child_witness.router_rows.len - recursion.segment_leaf_wrapper_local_identity_v5.REMOVED_TREE0_FORWARD_ROWS;
    @memcpy(router[0..active], child_witness.router_rows[0..active]);
    try appendDirectAirTuples(router_air, allocator, &ledger, 47, router, mask);
    const hash_air = recursion.air.vm_public_claim_hash;
    const authority_rows = try allocator.alloc(recursion.air.vm_public_claim_hash_relation.Row, @as(usize, 1) << @intCast(rows.local.layout.placements[1].log_size));
    defer allocator.free(authority_rows);
    @memset(authority_rows, [_]M31{M31.zero()} ** hash_air.LOGICAL_INPUT_COUNT);
    for (authority_rows[0..child_witness.authority_hash.main_rows.len], 0..) |*row, index|
        row.* = try child_witness.authorityHashLogicalRow(rows.local.program, index);
    try appendDirectHashAirTuples(allocator, &ledger, 48, authority_rows, mask);
    const receipt_rows = try allocator.alloc(recursion.air.vm_public_claim_hash_relation.Row, @as(usize, 1) << @intCast(rows.local.layout.placements[2].log_size));
    defer allocator.free(receipt_rows);
    @memset(receipt_rows, [_]M31{M31.zero()} ** hash_air.LOGICAL_INPUT_COUNT);
    for (receipt_rows[0..child_witness.receipt_hash.main_rows.len], 0..) |*row, index|
        row.* = try child_witness.receiptHashLogicalRow(rows.local.program, index);
    try appendDirectHashAirTuples(allocator, &ledger, 49, receipt_rows, mask);

    const public_authority = recursion.ethereum_leaf_direct_public_authority_v3;
    const expected_authority = try public_authority.AuthorityV1.fromSlice(&las2.expected_words);
    for (0..recursion.segment_leaf_wrapper_las2_boundary_v4.TERM_COUNT) |index| {
        const tuple = try expected_authority.statementTuple(index);
        const secure = [_]@import("stwo_core").fields.qm31.QM31{
            .fromBase(tuple[0]), .fromBase(tuple[1]), .fromBase(tuple[2]),
        };
        try ledger.append(.recursion_statement_word, 50, 0, .consume, @import("stwo_core").fields.qm31.QM31.one().neg(), &secure);
    }
    try global_statement_boundary.appendTupleContributions(&ledger);
    const report = ledger.classify();
    std.debug.print("DIRECT50_TUPLES total={d} unmatched={d} domain25={d} domain29={d} domain30={d}\n", .{
        report.contribution_count,
        report.unmatched_tuple_count,
        report.unmatched_by_domain[25],
        report.unmatched_by_domain[29],
        report.unmatched_by_domain[30],
    });
    var unmatched_by_row: [3][52]usize = @splat(@splat(0));
    var cursor: usize = 0;
    while (cursor < ledger.contributions.items.len) {
        const first = ledger.contributions.items[cursor];
        var end = cursor + 1;
        var residual = first.signed_weight;
        var components: u64 = @as(u64, 1) << @intCast(first.component);
        while (end < ledger.contributions.items.len and
            ledger.contributions.items[end].domain == first.domain and
            std.mem.eql(u8, &ledger.contributions.items[end].tuple_hash, &first.tuple_hash)) : (end += 1)
        {
            residual = residual.add(ledger.contributions.items[end].signed_weight);
            components |= @as(u64, 1) << @intCast(ledger.contributions.items[end].component);
        }
        const domain_index: ?usize = switch (first.domain) {
            .recursion_verifier_input_word => 0,
            .recursion_statement_word => 1,
            .recursion_vm_public_claim_word => 2,
            else => null,
        };
        if (domain_index) |domain| {
            if (!residual.isZero()) {
                for (0..52) |component| {
                    if (components & (@as(u64, 1) << @intCast(component)) != 0)
                        unmatched_by_row[domain][component] += 1;
                }
            }
        }
        cursor = end;
    }
    for (unmatched_by_row, [_]u8{ 25, 29, 30 }) |histogram, domain| {
        std.debug.print("DIRECT50_UNMATCHED_ROWS domain={d}", .{domain});
        for (histogram, 0..) |count, row| if (count != 0)
            std.debug.print(" row{d}={d}", .{ row, count });
        std.debug.print("\n", .{});
    }
    ledger.printUnmatched(3);
}

fn appendDirectAirTuples(comptime Air: type, allocator: std.mem.Allocator, ledger: *recursion.air.relation_interaction.TupleLedger, component: u8, rows: []const Air.Row, mask: u64) !void {
    var definition = try Air.build(allocator);
    defer definition.deinit();
    const plan = try Air.authenticate(&definition);
    try plan.appendPreparedTupleContributions(ledger, component, rows, mask);
}

fn appendDirectHashAirTuples(allocator: std.mem.Allocator, ledger: *recursion.air.relation_interaction.TupleLedger, component: u8, rows: []const recursion.air.vm_public_claim_hash_relation.Row, mask: u64) !void {
    const Air = recursion.air.vm_public_claim_hash;
    var definition = try Air.build(allocator);
    defer definition.deinit();
    const plan = try recursion.air.vm_public_claim_hash_relation.authenticate(&definition);
    try plan.appendPreparedTupleContributions(ledger, component, rows, mask);
}

fn appendDirectHashTuples(allocator: std.mem.Allocator, ledger: *recursion.air.relation_interaction.TupleLedger, component: u8, witness: *const recursion.segment_leaf_wrapper_field_hash_witness_v3.HashV1, mask: u64) !void {
    const Air = recursion.air.vm_public_claim_hash;
    const rows = try allocator.alloc(recursion.air.vm_public_claim_hash_relation.Row, @as(usize, 1) << @intCast(witness.log_size));
    defer allocator.free(rows);
    @memset(rows, [_]M31{M31.zero()} ** Air.LOGICAL_INPUT_COUNT);
    for (rows[0..witness.main.len], 0..) |*row, index| row.* = try witness.logicalRow(index);
    try appendDirectHashAirTuples(allocator, ledger, component, rows, mask);
}

fn peakRssBytes() u64 {
    if (builtin.os.tag != .linux and builtin.os.tag != .macos) return 0;
    const rss = std.posix.getrusage(std.posix.rusage.SELF).maxrss;
    if (rss <= 0) return 0;
    const value: u64 = @intCast(rss);
    return if (builtin.os.tag == .linux) value * 1024 else value;
}

fn allocateDirectTree(allocator: std.mem.Allocator, plan: anytype, tree: u8) ![][]M31 {
    const count = switch (tree) {
        0 => plan.total_preprocessed_columns,
        1 => plan.total_main_columns,
        2 => plan.total_interaction_columns,
        else => return error.InvalidDirectTree,
    };
    const columns = try allocator.alloc([]M31, count);
    var written: usize = 0;
    errdefer {
        for (columns[0..written]) |column| allocator.free(column);
        allocator.free(columns);
    }
    for (plan.placements) |maybe_item| {
        const item = maybe_item.?;
        const offset = switch (tree) {
            0 => item.preprocessed_offset,
            1 => item.main_offset,
            2 => item.interaction_offset,
            else => unreachable,
        };
        const n = switch (tree) {
            0 => item.geometry.preprocessed_columns,
            1 => item.geometry.main_columns,
            2 => item.geometry.interaction_columns,
            else => unreachable,
        };
        if (offset != written) return error.InvalidDirectTree;
        const rows = @as(usize, 1) << @intCast(item.geometry.log_size);
        for (columns[offset..][0..n]) |*column| {
            column.* = try allocator.alloc(M31, rows);
            @memset(column.*, M31.zero());
            written += 1;
        }
    }
    return columns;
}

fn freeDirectTree(allocator: std.mem.Allocator, columns: [][]M31) void {
    for (columns) |column| allocator.free(column);
    allocator.free(columns);
}
