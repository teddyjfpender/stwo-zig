//! admission contract cases for request_compiler.
//! Fail-closed Cairo request compilation into the resident CUDA plan.
//!
//! This seam deliberately stops before device execution. It binds the
//! authenticated Cairo input, proof-derived semantic pack, exact component
//! geometry, generic ProofProgram, and CUDA target into one receipt while
//! enumerating every component whose CUDA AOT lowering is still absent.

const std = @import("std");
const cuda_plan = @import("stwo_cuda_backend").runtime.execution_plan;
const product_aot = @import("stwo_cuda_backend").aot.product_registry;
const proof_plan = @import("stwo_cairo_frontend").proof_plan;
const semantic_authority = @import("stwo_cairo_frontend").proof_plan.semantic_authority;
const statement_bootstrap = @import("stwo_cairo_frontend").statement_bootstrap;
const composition = @import("stwo_cairo_frontend").witness.composition_bundle;
const feed_bundle = @import("stwo_cairo_frontend").witness.feed_bundle;
const subject_program = @import("program.zig");
const resident_plan = @import("executor/resident_plan.zig");
const resident_ingress = @import(
    "executor/resident_ingress_compiler.zig",
);
const resident_sn2_gate = @import("executor/resident_plan_sn2_gate.zig");
const statement_ingress = @import("executor/statement_ingress.zig");
const execution_schedule = @import(
    "executor/execution_schedule.zig",
);
const trace_schedule = @import("executor/trace_schedule.zig");
const admission_receipt = @import(
    "request_compiler/admission_receipt.zig",
);
const constraint_admission = @import(
    "request_compiler/constraint_admission.zig",
);
const interaction_admission = @import(
    "request_compiler/interaction_admission.zig",
);
const sn2_test_support = @import("request_compiler/sn2_test_support.zig");

const Owner = @import("request_compiler.zig");
const sn2_diagnostic_fixture = Owner.sn2_diagnostic_fixture;
const LoweringKind = Owner.LoweringKind;
const buildBufferDescriptions = Owner.buildBufferDescriptions;
const compileLoweringAdmission = Owner.compileLoweringAdmission;
const interactionIdentity = Owner.interactionIdentity;
const constraintPartIdentity = Owner.constraintPartIdentity;
const traceBytes = Owner.traceBytes;
const findComponent = Owner.findComponent;
const digestEmpty = Owner.digestEmpty;

test {
    _ = @import("request_compiler/proof_plan_test.zig");
}

test "Cairo CUDA request buffers preserve component-local mixed heights" {
    try sn2_test_support.expectMixedHeightBuffers(
        buildBufferDescriptions,
        findComponent,
        traceBytes,
    );
}

test "Cairo CUDA compiles the complete authenticated SN2 structure and only reports AOT gaps" {
    const allocator = std.testing.allocator;
    const adapter = @import("stwo_cairo_frontend").adapter;
    const fixed_table_bundle = @import("stwo_cairo_frontend").witness.fixed_table_bundle;
    const relation_bundle = @import("stwo_cairo_frontend").witness.relation_bundle;
    const witness_bundle = @import("stwo_cairo_frontend").witness.bundle;
    const adapted_path = std.process.getEnvVarOwned(
        allocator,
        "STWO_ZIG_TEST_SN2_ADAPTED_INPUT",
    ) catch return error.SkipZigTest;
    defer allocator.free(adapted_path);
    const adapted_digest = try sn2_test_support.sha256File(adapted_path);
    const adapted_file = try std.fs.cwd().openFile(adapted_path, .{});
    defer adapted_file.close();
    try std.testing.expectEqual(
        @as(u64, sn2_diagnostic_fixture.adapted_input_size_bytes),
        (try adapted_file.stat()).size,
    );
    try std.testing.expectEqualStrings(
        sn2_diagnostic_fixture.adapted_input_sha256,
        &std.fmt.bytesToHex(adapted_digest, .lower),
    );
    var input = try adapter.adapted_input.readFile(allocator, adapted_path);
    defer input.deinit(allocator);
    var witnesses = try witness_bundle.Bundle.readFile(
        allocator,
        "vectors/cairo/sn_pie_2_witness_programs.bin",
    );
    defer witnesses.deinit();
    var feeds = try feed_bundle.Bundle.readFile(
        allocator,
        "vectors/cairo/sn_pie_2_multiplicity_feeds.bin",
    );
    defer feeds.deinit();
    var bundle = try composition.Bundle.readFile(
        allocator,
        "vectors/cairo/sn_pie_2_composition.bin",
    );
    defer bundle.deinit();
    var relations = try relation_bundle.Bundle.readFile(
        allocator,
        "vectors/cairo/cairo_relation_templates.bin",
    );
    defer relations.deinit();
    var fixed_tables = try fixed_table_bundle.Bundle.readFile(
        allocator,
        "vectors/cairo/cairo_fixed_tables.bin",
    );
    defer fixed_tables.deinit();
    var proof = try proof_plan.CairoProofPlan.fromSemanticArtifacts(
        allocator,
        witnesses,
        feeds,
        fixed_tables,
        bundle,
        &input,
    );
    defer proof.deinit();
    const statement = try statement_bootstrap.encodeCompactStatementV1(
        allocator,
        &bundle,
        &input,
    );
    defer allocator.free(statement);
    const protocol = try sn2_test_support.protocol(
        &bundle,
        fixed_tables.preprocessed_identities.len,
    );
    const buffers = try buildBufferDescriptions(allocator, &proof, bundle, statement.len);
    defer allocator.free(buffers);
    const preprocessed_logs = try semantic_authority.preprocessedLogs(
        allocator,
        fixed_tables,
    );
    defer allocator.free(preprocessed_logs);
    const verifier_log = try bundle.verifierMaxLogDegreeBound();
    var program = try subject_program.testing.emit(allocator, .{
        .proof = &proof,
        .pack = sn2_test_support.pack(bundle, verifier_log),
        .composition = &bundle,
        .preprocessed_logs = preprocessed_logs,
        .compact_statement = statement,
        .protocol = protocol,
        .buffers = buffers,
    });
    defer program.deinit(allocator);
    var cuda = try cuda_plan.CudaPlan.compile(
        allocator,
        program,
        sn2_test_support.target(),
    );
    defer cuda.deinit(allocator);
    var product_registry = try product_aot.Registry.initProduct(allocator);
    defer product_registry.deinit();
    var bootstrap = try statement_ingress.derive(
        allocator,
        protocol,
        &bundle,
        &input,
    );
    defer bootstrap.deinit();
    var lowering_admission = try compileLoweringAdmission(
        allocator,
        &proof,
        witnesses,
        fixed_tables,
        feeds,
        bundle,
        relations,
        &input,
        program.constraints,
        product_registry,
        (try adapted_file.stat()).size,
        adapted_digest,
        &bootstrap,
        null,
    );
    defer lowering_admission.deinit(allocator);
    const missing = lowering_admission.missing;
    var resident = try resident_plan.Plan.init(
        allocator,
        program,
        protocol,
        bundle,
        lowering_admission.resident_ingress,
    );
    defer resident.deinit(allocator);
    const ingress = lowering_admission.resident_ingress;
    try resident_sn2_gate.assert(resident, ingress);

    var writer_counts = [_]usize{0} ** std.meta.fields(proof_plan.WriterKind).len;
    for (proof.components) |component|
        writer_counts[@intFromEnum(component.writer)] += 1;
    for (writer_counts) |count| try std.testing.expect(count > 0);
    for (feeds.feeds) |feed| {
        var scheduled = false;
        for (proof.components) |component| {
            for (component.capacity_feeds) |capacity| {
                if (std.mem.eql(u8, capacity.producer, feed.producer))
                    scheduled = true;
            }
        }
        try std.testing.expect(scheduled);
    }
    var lowering_counts = [_]usize{0} ** std.meta.fields(LoweringKind).len;
    for (missing) |lowering| {
        lowering_counts[@intFromEnum(lowering.kind)] += 1;
        try std.testing.expect(!digestEmpty(lowering.semantic));
        try std.testing.expect(
            proof.findInstance(lowering.component, lowering.component_instance) != null,
        );
    }
    try std.testing.expectEqual(@as(usize, 58), proof.components.len);
    try std.testing.expectEqual(bundle.components.len, program.constraints.len);
    try std.testing.expectEqual(1 + 2 * bundle.components.len, program.buffers.len);
    try std.testing.expectEqual(@as(usize, 0), missing.len);
    try std.testing.expect(!digestEmpty(lowering_admission.identity));
    try std.testing.expectEqual(
        @as(usize, trace_schedule.expected_entry_count),
        lowering_admission.trace_dispatch.entries.len,
    );
    try std.testing.expectEqual(
        @as(usize, trace_schedule.expected_launch_count),
        lowering_admission.trace_dispatch.launch_order.len,
    );
    try std.testing.expectEqual(
        @as(usize, 0),
        lowering_counts[@intFromEnum(LoweringKind.base_writer)],
    );
    try std.testing.expectEqual(
        @as(usize, 0),
        lowering_counts[@intFromEnum(LoweringKind.interaction)],
    );
    try std.testing.expectEqual(
        @as(usize, 0),
        lowering_counts[@intFromEnum(LoweringKind.constraint_part)],
    );
    try std.testing.expectEqual(program.nodes.len, cuda.schedule.len);
    try std.testing.expect(cuda.prediction.request_bytes > 0);

    var mutated_program = program.constraints[0].expression;
    mutated_program[0] ^= 1;
    try std.testing.expect(!std.mem.eql(
        u8,
        &interactionIdentity(program.constraints[0].expression),
        &interactionIdentity(mutated_program),
    ));
    try std.testing.expect(!std.mem.eql(
        u8,
        &constraintPartIdentity(
            program.constraints[0].expression,
            0,
            bundle.components[0].parts[0],
        ),
        &constraintPartIdentity(
            mutated_program,
            0,
            bundle.components[0].parts[0],
        ),
    ));
}
