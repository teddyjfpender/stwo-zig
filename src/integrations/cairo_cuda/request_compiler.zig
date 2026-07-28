//! Fail-closed Cairo request compilation into the resident CUDA plan.
//!
//! This seam deliberately stops before device execution. It binds the
//! authenticated Cairo input, proof-derived semantic pack, exact component
//! geometry, generic ProofProgram, and CUDA target into one receipt while
//! enumerating every component whose CUDA AOT lowering is still absent.

const std = @import("std");
const cuda_plan = @import("../../backends/cuda/runtime/execution_plan.zig");
const product_aot = @import("../../backends/cuda/aot/product_registry.zig");
const prover = @import("stwo_cairo_frontend").prover;
const proof_plan = @import("stwo_cairo_frontend").proof_plan;
const semantic_authority = @import("stwo_cairo_frontend").proof_plan.semantic_authority;
const compact = @import("stwo_cairo_frontend").compact_verifier_interchange;
const statement_bootstrap = @import("stwo_cairo_frontend").statement_bootstrap;
const composition = @import("stwo_cairo_frontend").witness.composition_bundle;
const feed_bundle = @import("stwo_cairo_frontend").witness.feed_bundle;
const subject_program = @import("program.zig");
const subject_identity = @import("identity.zig");
const relation_adapter = @import("relation_adapter.zig");
const base_writer_catalog = @import("base_writer_plan/catalog.zig");
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
const proof_ir = @import("stwo_backend_contracts").proof_program;

pub const production_ready = false;

/// Branch-head compatibility fixture for development admission only. These
/// identities do not replace the public Rust-oracle pins in `prover.zig`.
pub const sn2_diagnostic_fixture = .{
    .stwo_cairo_revision = "6a9c1c895b821eb5542843e7d9398e02e8f378d0",
    .stwo_revision = "1d1d10c31fdac45c9ecb7aee9d3e8935b5cf8035",
    .diagnostic_patch_files = [_][]const u8{
        "stwo_cairo_prover/crates/gpu-prover/src/bin/gpu_bench.rs",
        "stwo_cairo_prover/crates/gpu-prover/src/gpu_bench_physical.rs",
        "stwo_cairo_prover/crates/gpu-prover/src/resident_oods/receipt.rs",
    },
    .diagnostic_patch_closure_sha256 = "79e73e64044278751f06695e8dbcdb07846d7999bbdea10edc6477c0f4aaea91",
    .adapted_input_file = "SN_PIE_2.6a9c1c89-1d1d10c3.stwzcpi",
    .adapted_input_size_bytes = 162_102_548,
    .adapted_input_sha256 = "fe78e1549f66c2c175d075fad5e0c1ea174df29f9331684e654ef9e9c8821704",
};

pub const Blocker = admission_receipt.Blocker;
pub const AdmissionReceipt = admission_receipt.Receipt;

pub const LoweringKind = enum(u8) {
    base_writer,
    interaction,
    constraint_part,
};

pub const MissingLowering = struct {
    kind: LoweringKind,
    component_index: u32,
    component: []const u8,
    component_instance: u32,
    ordinal: u32,
    semantic: [32]u8,
};

const LoweringAdmission = struct {
    missing: []MissingLowering,
    identity: [32]u8,
    trace_dispatch: trace_schedule.Schedule,
    relation_plan: relation_adapter.Plan,
    resident_ingress: resident_plan.IngressGeometry,

    fn deinit(self: *LoweringAdmission, allocator: std.mem.Allocator) void {
        self.relation_plan.deinit();
        self.trace_dispatch.deinit();
        allocator.free(self.missing);
        self.* = undefined;
    }
};

pub const PreparedRequest = struct {
    allocator: std.mem.Allocator,
    proof: proof_plan.CairoProofPlan,
    buffers: []subject_program.BufferDescription,
    proof_program: @import("stwo_backend_contracts").proof_program.ProofProgram,
    plan: cuda_plan.CudaPlan,
    resident: resident_plan.Plan,
    execution_schedule: execution_schedule.Schedule,
    trace_dispatch: trace_schedule.Schedule,
    relation_plan: relation_adapter.Plan,
    statement_bootstrap: statement_bootstrap.OwnedStatementBootstrap,
    missing_lowerings: []MissingLowering,
    receipt: AdmissionReceipt,

    pub fn deinit(self: *PreparedRequest) void {
        self.resident.deinit(self.allocator);
        self.statement_bootstrap.deinit();
        self.relation_plan.deinit();
        self.trace_dispatch.deinit();
        self.allocator.free(self.missing_lowerings);
        self.plan.deinit(self.allocator);
        self.proof_program.deinit(self.allocator);
        self.allocator.free(self.buffers);
        self.proof.deinit();
        self.* = undefined;
    }
};

/// Content-addressed proof-derived inputs for a diagnostic request. This
/// bypasses only the absent semantic-pack manifest; it does not bypass any AIR,
/// lowering, resident-plan, protocol, or CUDA admission check.
pub const ProofDerivedDiagnosticInput = struct {
    adapted_input: *const @import("stwo_cairo_frontend").adapter.ProverInput,
    adapted_input_bytes: u64,
    adapted_input_identity: [32]u8,
    witnesses: @import("stwo_cairo_frontend").witness.bundle.Bundle,
    multiplicity_feeds: feed_bundle.Bundle,
    fixed_tables: @import("stwo_cairo_frontend").witness.fixed_table_bundle.Bundle,
    composition: composition.Bundle,
    relation_templates: @import("stwo_cairo_frontend").witness.relation_bundle.Bundle,
    compact_statement: []const u8,
    preprocessed_logs: []const u32,
    pack: subject_identity.PackIdentity,
};

pub fn compileDevelopmentRequest(
    allocator: std.mem.Allocator,
    prepared: *const prover.PreparedProgram,
    protocol: compact.CompactProtocolV1,
    target: cuda_plan.CompileOptions,
) !PreparedRequest {
    if (prepared.artifacts.provenance != .proof_derived)
        return error.DevelopmentSemanticsRequired;
    try prepared.artifacts.assertUnchanged();
    try protocol.validate();

    var proof = try proof_plan.CairoProofPlan.fromSemanticArtifacts(
        allocator,
        prepared.artifacts.witness_programs,
        prepared.artifacts.multiplicity_feeds,
        prepared.artifacts.fixed_tables,
        prepared.artifacts.composition,
        &prepared.input,
    );
    errdefer proof.deinit();
    const buffers = try buildBufferDescriptions(
        allocator,
        &proof,
        prepared.artifacts.composition,
        prepared.compact_statement.len,
    );
    errdefer allocator.free(buffers);
    var proof_program = try subject_program.emitDevelopmentOnly(allocator, .{
        .proof = &proof,
        .semantics = &prepared.artifacts,
        .compact_statement = prepared.compact_statement,
        .protocol = protocol,
        .buffers = buffers,
    });
    errdefer proof_program.deinit(allocator);
    try prepared.artifacts.assertUnchanged();
    return finishDevelopmentRequest(
        allocator,
        proof,
        buffers,
        proof_program,
        prepared.artifacts.witness_programs,
        prepared.artifacts.multiplicity_feeds,
        prepared.artifacts.fixed_tables,
        prepared.artifacts.composition,
        prepared.artifacts.relation_templates,
        &prepared.input,
        prepared.input_measurement.stat.size,
        prepared.input_sha256,
        protocol,
        target,
    );
}

/// Compiles one explicitly non-production request from authenticated staged
/// artifacts. Every supplied digest participates in the proof-program identity.
pub fn compileProofDerivedDiagnostic(
    allocator: std.mem.Allocator,
    input: ProofDerivedDiagnosticInput,
    protocol: compact.CompactProtocolV1,
    target: cuda_plan.CompileOptions,
) !PreparedRequest {
    if (input.pack.provenance != .proof_derived)
        return error.DevelopmentSemanticsRequired;
    try protocol.validate();
    var proof = try proof_plan.CairoProofPlan.fromSemanticArtifacts(
        allocator,
        input.witnesses,
        input.multiplicity_feeds,
        input.fixed_tables,
        input.composition,
        input.adapted_input,
    );
    errdefer proof.deinit();
    const buffers = try buildBufferDescriptions(
        allocator,
        &proof,
        input.composition,
        input.compact_statement.len,
    );
    errdefer allocator.free(buffers);
    var proof_program = try subject_program.emitProofDerivedDiagnostic(
        allocator,
        .{
            .proof = &proof,
            .pack = input.pack,
            .composition = &input.composition,
            .preprocessed_logs = input.preprocessed_logs,
            .compact_statement = input.compact_statement,
            .protocol = protocol,
            .buffers = buffers,
        },
    );
    errdefer proof_program.deinit(allocator);
    return finishDevelopmentRequest(
        allocator,
        proof,
        buffers,
        proof_program,
        input.witnesses,
        input.multiplicity_feeds,
        input.fixed_tables,
        input.composition,
        input.relation_templates,
        input.adapted_input,
        input.adapted_input_bytes,
        input.adapted_input_identity,
        protocol,
        target,
    );
}

fn finishDevelopmentRequest(
    allocator: std.mem.Allocator,
    proof: proof_plan.CairoProofPlan,
    buffers: []subject_program.BufferDescription,
    proof_program: proof_ir.ProofProgram,
    witnesses: @import("stwo_cairo_frontend").witness.bundle.Bundle,
    feeds: feed_bundle.Bundle,
    fixed_tables: @import("stwo_cairo_frontend").witness.fixed_table_bundle.Bundle,
    bundle: composition.Bundle,
    relations: @import("stwo_cairo_frontend").witness.relation_bundle.Bundle,
    adapted_input: *const @import("stwo_cairo_frontend").adapter.ProverInput,
    adapted_input_bytes: u64,
    adapted_input_identity: [32]u8,
    protocol: compact.CompactProtocolV1,
    target: cuda_plan.CompileOptions,
) !PreparedRequest {
    const coalesced_schedule = try execution_schedule.Schedule.derive(
        proof_program,
    );
    var plan = try cuda_plan.CudaPlan.compile(allocator, proof_program, target);
    errdefer plan.deinit(allocator);

    var product_registry = try product_aot.Registry.initProduct(allocator);
    defer product_registry.deinit();
    var bootstrap = try statement_ingress.derive(
        allocator,
        protocol,
        &bundle,
        adapted_input,
    );
    errdefer bootstrap.deinit();
    var lowering_admission = try compileLoweringAdmission(
        allocator,
        &proof,
        witnesses,
        fixed_tables,
        feeds,
        bundle,
        relations,
        adapted_input,
        proof_program.constraints,
        product_registry,
        adapted_input_bytes,
        adapted_input_identity,
        &bootstrap,
    );
    errdefer lowering_admission.deinit(allocator);
    var resident = try resident_plan.Plan.init(
        allocator,
        proof_program,
        protocol,
        bundle,
        lowering_admission.resident_ingress,
    );
    errdefer resident.deinit(allocator);
    const receipt = AdmissionReceipt{
        .adapted_input_sha256 = adapted_input_identity,
        .statement = proof_program.identity.statement,
        .semantic_program = proof_program.semantic_digest,
        .complete_program = proof_program.program_digest,
        .cuda_plan_cache_key = plan.cache_key,
        .aot_lowering_identity = lowering_admission.identity,
        .resident_plan_identity = resident.identity,
        .missing_lowering_digest = loweringDigest(
            lowering_admission.missing,
        ),
        .component_count = @intCast(proof.components.len),
        .missing_lowering_count = @intCast(
            lowering_admission.missing.len,
        ),
        .blocker_mask = admission_receipt.blockerMask(
            @intCast(lowering_admission.missing.len),
        ),
    };
    try receipt.validate();
    return .{
        .allocator = allocator,
        .proof = proof,
        .buffers = buffers,
        .proof_program = proof_program,
        .plan = plan,
        .resident = resident,
        .execution_schedule = coalesced_schedule,
        .trace_dispatch = lowering_admission.trace_dispatch,
        .relation_plan = lowering_admission.relation_plan,
        .statement_bootstrap = bootstrap,
        .missing_lowerings = lowering_admission.missing,
        .receipt = receipt,
    };
}

fn buildBufferDescriptions(
    allocator: std.mem.Allocator,
    proof: *const proof_plan.CairoProofPlan,
    bundle: composition.Bundle,
    statement_bytes: usize,
) ![]subject_program.BufferDescription {
    const count = try std.math.add(
        usize,
        1,
        try std.math.mul(usize, proof.components.len, 2),
    );
    const descriptions = try allocator.alloc(subject_program.BufferDescription, count);
    errdefer allocator.free(descriptions);
    descriptions[0] = .{ .staged = .{
        .logical_id = 0,
        .component_index = null,
        .role = .protocol_persistent,
        .size_bytes = try alignedBytes(@max(statement_bytes, 4)),
        .alignment = 256,
    } };
    for (proof.components, 0..) |component, index| {
        const captured = findComponent(bundle, component.name, component.instance) orelse
            return error.MissingCompositionComponent;
        const rows = try pow2(captured.trace_log_size);
        const base_bytes = try traceBytes(captured.*, 1, rows);
        const interaction_bytes = try traceBytes(captured.*, 2, rows);
        const base_id = std.math.cast(u32, 1 + index * 2) orelse
            return error.CairoCudaGeometryOverflow;
        descriptions[1 + index * 2] = .{ .staged = .{
            .logical_id = base_id,
            .component_index = @intCast(index),
            .role = .base_coefficients,
            .size_bytes = base_bytes,
            .alignment = 256,
        } };
        descriptions[2 + index * 2] = .{ .staged = .{
            .logical_id = std.math.add(u32, base_id, 1) catch
                return error.CairoCudaGeometryOverflow,
            .component_index = @intCast(index),
            .role = .interaction_coefficients,
            .size_bytes = interaction_bytes,
            .alignment = 256,
        } };
    }
    return descriptions;
}

fn compileLoweringAdmission(
    allocator: std.mem.Allocator,
    proof: *const proof_plan.CairoProofPlan,
    witnesses: @import("stwo_cairo_frontend").witness.bundle.Bundle,
    fixed: @import("stwo_cairo_frontend").witness.fixed_table_bundle.Bundle,
    feeds: feed_bundle.Bundle,
    bundle: composition.Bundle,
    relations: @import("stwo_cairo_frontend").witness.relation_bundle.Bundle,
    input: *const @import("stwo_cairo_frontend").adapter.ProverInput,
    constraints: []const @import("stwo_backend_contracts").proof_program.ConstraintProgram,
    product_registry: product_aot.Registry,
    adapted_input_bytes: u64,
    adapted_input_identity: [32]u8,
    bootstrap: *const statement_bootstrap.OwnedStatementBootstrap,
) !LoweringAdmission {
    if (constraints.len != proof.components.len or constraints.len != bundle.components.len)
        return error.CairoCudaConstraintCardinalityMismatch;
    var base_catalog = try base_writer_catalog.compile(
        allocator,
        proof,
        bundle,
        witnesses,
        fixed,
        input,
        product_registry,
    );
    defer base_catalog.deinit();
    var trace_dispatch = try trace_schedule.compile(
        allocator,
        proof,
        base_catalog,
    );
    errdefer trace_dispatch.deinit();
    var constraint_catalog = try constraint_admission.Catalog.init(
        allocator,
        bundle,
    );
    defer constraint_catalog.deinit();
    var interaction_catalog = try interaction_admission.Catalog.init(
        allocator,
        proof,
        relations,
    );
    var interaction_catalog_live = true;
    defer if (interaction_catalog_live) interaction_catalog.deinit();
    const ingress_geometry = try resident_ingress.compile(
        allocator,
        .{
            .adapted_input_bytes = adapted_input_bytes,
            .adapted_input_identity = adapted_input_identity,
            .statement_bootstrap_words = try statement_ingress.wordCount(bootstrap),
            .statement_bootstrap_identity = statement_ingress.identity(bootstrap),
            .proof = proof,
            .components = bundle,
            .witnesses = witnesses,
            .fixed_tables = fixed,
            .feeds = feeds,
            .prover_input = input,
            .relations = &interaction_catalog.plan,
            .writer_identity = trace_dispatch.identity,
            .evaluation_identity = constraint_catalog.catalog_identity,
        },
    );
    var missing = std.ArrayList(MissingLowering).empty;
    errdefer missing.deinit(allocator);
    for (constraints, 0..) |constraint, index| {
        if (constraint.component != index)
            return error.CairoCudaConstraintOrderMismatch;
        const component = bundle.components[index];
        const planned = proof.findInstance(component.label, component.instance) orelse
            return error.MissingCompositionComponent;
        const base_entry = base_catalog.find(planned.name, planned.instance);
        if (base_entry == null or
            base_entry.?.component_index != index or
            base_entry.?.writer != planned.writer or
            digestEmpty(base_entry.?.identity))
        {
            try missing.append(allocator, .{
                .kind = .base_writer,
                .component_index = @intCast(index),
                .component = planned.name,
                .component_instance = planned.instance,
                .ordinal = 0,
                .semantic = constraint.expression,
            });
        }
        if (!interaction_catalog.admits(@intCast(index), planned.*)) {
            try missing.append(allocator, .{
                .kind = .interaction,
                .component_index = @intCast(index),
                .component = planned.name,
                .component_instance = planned.instance,
                .ordinal = 0,
                .semantic = interactionIdentity(constraint.expression),
            });
        }
        for (component.parts, 0..) |part, part_index| {
            if (constraint_catalog.admits(
                component,
                @intCast(index),
                part,
                @intCast(part_index),
            )) continue;
            try missing.append(allocator, .{
                .kind = .constraint_part,
                .component_index = @intCast(index),
                .component = planned.name,
                .component_instance = planned.instance,
                .ordinal = @intCast(part_index),
                .semantic = constraintPartIdentity(
                    constraint.expression,
                    @intCast(part_index),
                    part,
                ),
            });
        }
    }
    const owned_missing = try missing.toOwnedSlice(allocator);
    const relation_plan = interaction_catalog.plan;
    interaction_catalog_live = false;
    return .{
        .missing = owned_missing,
        .identity = loweringClosureIdentity(
            base_catalog.identity,
            trace_dispatch.identity,
            interaction_catalog.catalog_identity,
            constraint_catalog.catalog_identity,
            owned_missing,
        ),
        .trace_dispatch = trace_dispatch,
        .relation_plan = relation_plan,
        .resident_ingress = ingress_geometry,
    };
}

fn loweringDigest(missing: []const MissingLowering) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo-zig/cairo/cuda/missing-aot-lowerings/v2\x00");
    hashInt(&hash, u64, missing.len);
    for (missing) |entry| {
        hashInt(&hash, u8, @intFromEnum(entry.kind));
        hashInt(&hash, u32, entry.component_index);
        hashInt(&hash, u32, entry.component_instance);
        hashInt(&hash, u32, entry.ordinal);
        hashInt(&hash, u64, entry.component.len);
        hash.update(entry.component);
        hash.update(&entry.semantic);
    }
    return hash.finalResult();
}

fn loweringClosureIdentity(
    base_catalog_identity: [32]u8,
    trace_schedule_identity: [32]u8,
    interaction_catalog_identity: [32]u8,
    constraint_catalog_identity: [32]u8,
    missing: []const MissingLowering,
) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo-zig/cairo/cuda/aot-lowering-closure/v1\x00");
    hash.update(&base_catalog_identity);
    hash.update(&trace_schedule_identity);
    hash.update(&interaction_catalog_identity);
    hash.update(&constraint_catalog_identity);
    hash.update(&loweringDigest(missing));
    return hash.finalResult();
}

fn interactionIdentity(component_program: [32]u8) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo-zig/cairo/cuda/interaction-lowering/v2\x00");
    hash.update(&component_program);
    return hash.finalResult();
}

fn constraintPartIdentity(
    expression: [32]u8,
    ordinal: u32,
    part: composition.Part,
) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo-zig/cairo/cuda/constraint-part-lowering/v2\x00");
    hash.update(&expression);
    hashInt(&hash, u32, ordinal);
    hashInt(&hash, u32, part.rc_base);
    hashInt(&hash, u64, part.semantic_hash);
    return hash.finalResult();
}

fn traceBytes(component: composition.Component, tree: u32, rows: u64) !u64 {
    const span = for (component.trace_spans) |candidate| {
        if (candidate.tree == tree) break candidate;
    } else return error.MissingCompositionTraceSpan;
    const width = std.math.sub(u32, span.end, span.start) catch
        return error.CairoCudaGeometryOverflow;
    if (width == 0) return error.MissingCompositionTraceSpan;
    return std.math.mul(
        u64,
        try std.math.mul(u64, width, rows),
        @sizeOf(u32),
    ) catch error.CairoCudaGeometryOverflow;
}

fn alignedBytes(bytes: usize) !u64 {
    const value = std.math.cast(u64, bytes) orelse return error.CairoCudaGeometryOverflow;
    return std.mem.alignForward(u64, value, 256);
}

fn pow2(log_rows: u32) !u64 {
    if (log_rows >= 63) return error.CairoCudaGeometryOverflow;
    return @as(u64, 1) << @intCast(log_rows);
}

fn findComponent(
    bundle: composition.Bundle,
    name: []const u8,
    instance: u32,
) ?*const composition.Component {
    for (bundle.components) |*component| {
        if (component.instance == instance and std.mem.eql(u8, component.label, name))
            return component;
    }
    return null;
}

fn hashInt(hash: *std.crypto.hash.sha2.Sha256, comptime T: type, value: T) void {
    var encoded: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &encoded, value, .little);
    hash.update(&encoded);
}

fn digestEmpty(value: [32]u8) bool {
    return std.mem.allEqual(u8, &value, 0);
}

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
        bundle,
        relations,
        &input,
        program.constraints,
        product_registry,
        (try adapted_file.stat()).size,
        adapted_digest,
        &bootstrap,
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
