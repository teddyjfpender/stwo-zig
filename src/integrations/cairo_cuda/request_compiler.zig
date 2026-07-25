//! Fail-closed Cairo request compilation into the resident CUDA plan.
//!
//! This seam deliberately stops before device execution. It binds the
//! authenticated Cairo input, proof-derived semantic pack, exact component
//! geometry, generic ProofProgram, and CUDA target into one receipt while
//! enumerating every component whose CUDA AOT lowering is still absent.

const std = @import("std");
const cuda_plan = @import("../../backends/cuda/runtime/execution_plan.zig");
const prover = @import("../../frontends/cairo/prover.zig");
const proof_plan = @import("../../frontends/cairo/proof_plan.zig");
const semantic_authority = @import("../../frontends/cairo/proof_plan/semantic_authority.zig");
const compact = @import("../../frontends/cairo/compact_verifier_interchange.zig");
const compact_geometry = @import("../../frontends/cairo/compact_protocol_geometry.zig");
const statement_bootstrap = @import("../../frontends/cairo/statement_bootstrap.zig");
const composition = @import("../../frontends/cairo/witness/composition_bundle.zig");
const feed_bundle = @import("../../frontends/cairo/witness/feed_bundle.zig");
const subject_program = @import("program.zig");
const subject_identity = @import("identity.zig");
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

pub const Blocker = enum(u8) {
    proof_derived_semantic_authority,
    component_aot_lowerings,
    resident_stage_hooks,
    terminal_proof_assembly,
};

pub const blockers = [_]Blocker{
    .proof_derived_semantic_authority,
    .component_aot_lowerings,
    .resident_stage_hooks,
    .terminal_proof_assembly,
};

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

pub const AdmissionReceipt = struct {
    adapted_input_sha256: [32]u8,
    statement: [32]u8,
    semantic_program: [32]u8,
    complete_program: [32]u8,
    cuda_plan_cache_key: [32]u8,
    missing_lowering_digest: [32]u8,
    component_count: u32,
    missing_lowering_count: u32,
    blockers: [blockers.len]Blocker = blockers,
    execution_admissible: bool = false,
    production_eligible: bool = false,

    pub fn validate(self: AdmissionReceipt) !void {
        if (self.component_count == 0 or self.missing_lowering_count == 0 or
            digestEmpty(self.adapted_input_sha256) or
            digestEmpty(self.statement) or
            digestEmpty(self.semantic_program) or
            digestEmpty(self.complete_program) or
            digestEmpty(self.cuda_plan_cache_key) or
            digestEmpty(self.missing_lowering_digest) or
            self.execution_admissible or self.production_eligible or
            !std.meta.eql(self.blockers, blockers))
            return error.InvalidCairoCudaAdmissionReceipt;
    }
};

pub const PreparedRequest = struct {
    allocator: std.mem.Allocator,
    proof: proof_plan.CairoProofPlan,
    buffers: []subject_program.BufferDescription,
    proof_program: @import("stwo_backend_contracts").proof_program.ProofProgram,
    plan: cuda_plan.CudaPlan,
    missing_lowerings: []MissingLowering,
    receipt: AdmissionReceipt,

    pub fn deinit(self: *PreparedRequest) void {
        self.allocator.free(self.missing_lowerings);
        self.plan.deinit(self.allocator);
        self.proof_program.deinit(self.allocator);
        self.allocator.free(self.buffers);
        self.proof.deinit();
        self.* = undefined;
    }
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
    var plan = try cuda_plan.CudaPlan.compile(allocator, proof_program, target);
    errdefer plan.deinit(allocator);

    const missing = try missingLowerings(
        allocator,
        &proof,
        prepared.artifacts.composition,
        proof_program.constraints,
    );
    errdefer allocator.free(missing);
    const receipt = AdmissionReceipt{
        .adapted_input_sha256 = prepared.input_sha256,
        .statement = proof_program.identity.statement,
        .semantic_program = proof_program.semantic_digest,
        .complete_program = proof_program.program_digest,
        .cuda_plan_cache_key = plan.cache_key,
        .missing_lowering_digest = loweringDigest(missing),
        .component_count = @intCast(proof.components.len),
        .missing_lowering_count = @intCast(missing.len),
    };
    try receipt.validate();
    try prepared.artifacts.assertUnchanged();
    return .{
        .allocator = allocator,
        .proof = proof,
        .buffers = buffers,
        .proof_program = proof_program,
        .plan = plan,
        .missing_lowerings = missing,
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

fn missingLowerings(
    allocator: std.mem.Allocator,
    proof: *const proof_plan.CairoProofPlan,
    bundle: composition.Bundle,
    constraints: []const @import("stwo_backend_contracts").proof_program.ConstraintProgram,
) ![]MissingLowering {
    if (constraints.len != proof.components.len or constraints.len != bundle.components.len)
        return error.CairoCudaConstraintCardinalityMismatch;
    var count = std.math.mul(usize, proof.components.len, 2) catch
        return error.CairoCudaGeometryOverflow;
    for (bundle.components) |component|
        count = std.math.add(usize, count, component.parts.len) catch
            return error.CairoCudaGeometryOverflow;
    const missing = try allocator.alloc(MissingLowering, count);
    var cursor: usize = 0;
    for (constraints, 0..) |constraint, index| {
        if (constraint.component != index)
            return error.CairoCudaConstraintOrderMismatch;
        const component = bundle.components[index];
        const planned = proof.findInstance(component.label, component.instance) orelse
            return error.MissingCompositionComponent;
        missing[cursor] = .{
            .kind = .base_writer,
            .component_index = @intCast(index),
            .component = planned.name,
            .component_instance = planned.instance,
            .ordinal = 0,
            .semantic = baseWriterIdentity(planned.*, constraint.expression),
        };
        cursor += 1;
        missing[cursor] = .{
            .kind = .interaction,
            .component_index = @intCast(index),
            .component = planned.name,
            .component_instance = planned.instance,
            .ordinal = 0,
            .semantic = interactionIdentity(constraint.expression),
        };
        cursor += 1;
        for (component.parts, 0..) |part, part_index| {
            missing[cursor] = .{
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
            };
            cursor += 1;
        }
    }
    std.debug.assert(cursor == missing.len);
    return missing;
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

fn baseWriterIdentity(
    component: proof_plan.Component,
    component_program: [32]u8,
) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo-zig/cairo/cuda/base-writer-lowering/v2\x00");
    hash.update(&component_program);
    hash.update(component.name);
    hashInt(&hash, u32, component.instance);
    hashInt(&hash, u8, @intFromEnum(component.writer));
    for (component.trace_parts) |part| {
        hashInt(&hash, u8, @intFromEnum(std.meta.activeTag(part.id)));
        hashInt(&hash, u32, part.rows.real_rows orelse std.math.maxInt(u32));
        hashInt(&hash, u32, part.rows.padded_rows);
    }
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

test "Cairo CUDA admission remains fail closed and binds every missing lowering" {
    const receipt = AdmissionReceipt{
        .adapted_input_sha256 = [_]u8{1} ** 32,
        .statement = [_]u8{2} ** 32,
        .semantic_program = [_]u8{3} ** 32,
        .complete_program = [_]u8{4} ** 32,
        .cuda_plan_cache_key = [_]u8{5} ** 32,
        .missing_lowering_digest = [_]u8{6} ** 32,
        .component_count = 58,
        .missing_lowering_count = 174,
    };
    try receipt.validate();
    var forged = receipt;
    forged.execution_admissible = true;
    try std.testing.expectError(error.InvalidCairoCudaAdmissionReceipt, forged.validate());
    try std.testing.expect(!production_ready);
}

test "Cairo CUDA proof plans preserve distinct memory instances" {
    const rows = [_]proof_plan.TracePart{.{ .id = .main, .rows = .{
        .real_rows = 16,
        .padded_rows = 16,
    } }};
    var components = [_]proof_plan.Component{
        .{
            .name = "memory_id_to_big",
            .instance = 0,
            .canonical_ordinal = 0,
            .writer = .memory_trace,
            .trace_parts = &rows,
            .producer_edges = &.{},
            .capacity_feeds = &.{},
        },
        .{
            .name = "memory_id_to_big",
            .instance = 1,
            .canonical_ordinal = 1,
            .writer = .memory_trace,
            .trace_parts = &rows,
            .producer_edges = &.{},
            .capacity_feeds = &.{},
        },
    };
    var plan = try proof_plan.CairoProofPlan.init(std.testing.allocator, &components);
    defer plan.deinit();
    try std.testing.expect(plan.findInstance("memory_id_to_big", 0) != null);
    try std.testing.expect(plan.findInstance("memory_id_to_big", 1) != null);

    components[1].instance = 0;
    try std.testing.expectError(
        proof_plan.Error.DuplicateComponent,
        proof_plan.CairoProofPlan.init(std.testing.allocator, &components),
    );
}

test "Cairo CUDA request buffers preserve component-local mixed heights" {
    const allocator = std.testing.allocator;
    const adapter = @import("../../frontends/cairo/adapter/mod.zig");
    const fixed_table_bundle = @import("../../frontends/cairo/witness/fixed_table_bundle.zig");
    const witness_bundle = @import("../../frontends/cairo/witness/bundle.zig");
    const adapted_path = std.process.getEnvVarOwned(
        allocator,
        "STWO_ZIG_TEST_SN2_ADAPTED_INPUT",
    ) catch return error.SkipZigTest;
    defer allocator.free(adapted_path);
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
    const descriptions = try buildBufferDescriptions(allocator, &proof, bundle, 4097);
    defer allocator.free(descriptions);

    try std.testing.expectEqual(1 + proof.components.len * 2, descriptions.len);
    try std.testing.expectEqual(@as(u64, 4352), descriptions[0].staged.size_bytes);
    for (proof.components, 0..) |component, index| {
        const captured = findComponent(bundle, component.name, component.instance) orelse
            return error.TestUnexpectedResult;
        const rows = @as(u64, 1) << @intCast(captured.trace_log_size);
        try std.testing.expectEqual(
            try traceBytes(captured.*, 1, rows),
            descriptions[1 + index * 2].staged.size_bytes,
        );
        try std.testing.expectEqual(
            try traceBytes(captured.*, 2, rows),
            descriptions[2 + index * 2].staged.size_bytes,
        );
    }
}

test "Cairo CUDA compiles the complete authenticated SN2 structure and only reports AOT gaps" {
    const allocator = std.testing.allocator;
    const adapter = @import("../../frontends/cairo/adapter/mod.zig");
    const fixed_table_bundle = @import("../../frontends/cairo/witness/fixed_table_bundle.zig");
    const witness_bundle = @import("../../frontends/cairo/witness/bundle.zig");
    const adapted_path = std.process.getEnvVarOwned(
        allocator,
        "STWO_ZIG_TEST_SN2_ADAPTED_INPUT",
    ) catch return error.SkipZigTest;
    defer allocator.free(adapted_path);
    const adapted_digest = try sha256File(adapted_path);
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
    const protocol = try sn2Protocol(&bundle, fixed_tables.preprocessed_identities.len);
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
        .pack = testPack(bundle, verifier_log),
        .composition = &bundle,
        .preprocessed_logs = preprocessed_logs,
        .compact_statement = statement,
        .protocol = protocol,
        .buffers = buffers,
    });
    defer program.deinit(allocator);
    var cuda = try cuda_plan.CudaPlan.compile(allocator, program, testTarget());
    defer cuda.deinit(allocator);
    const missing = try missingLowerings(
        allocator,
        &proof,
        bundle,
        program.constraints,
    );
    defer allocator.free(missing);

    var part_count: usize = 0;
    for (bundle.components) |component| part_count += component.parts.len;
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
    try std.testing.expectEqual(2 * bundle.components.len + part_count, missing.len);
    try std.testing.expectEqual(bundle.components.len, lowering_counts[@intFromEnum(LoweringKind.base_writer)]);
    try std.testing.expectEqual(bundle.components.len, lowering_counts[@intFromEnum(LoweringKind.interaction)]);
    try std.testing.expectEqual(part_count, lowering_counts[@intFromEnum(LoweringKind.constraint_part)]);
    try std.testing.expectEqual(program.nodes.len, cuda.schedule.len);
    try std.testing.expect(cuda.prediction.request_bytes > 0);

    var mutated_program = program.constraints[0].expression;
    mutated_program[0] ^= 1;
    const first = proof.components[0];
    try std.testing.expect(!std.mem.eql(
        u8,
        &baseWriterIdentity(first, program.constraints[0].expression),
        &baseWriterIdentity(first, mutated_program),
    ));
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

fn sn2Protocol(
    bundle: *const composition.Bundle,
    preprocessed_columns: usize,
) !compact.CompactProtocolV1 {
    const verifier_log = try bundle.verifierMaxLogDegreeBound();
    var geometry = compact_geometry.RuntimeProtocolGeometryV1.sn2();
    geometry.max_log_degree_bound = verifier_log;
    geometry.fri_tree_count = 1 + (verifier_log - 1) / geometry.fri_fold_step;
    geometry.decommitment_record_count =
        geometry.commitment_count + geometry.fri_tree_count;
    const capacity = try compact_geometry.minimumDecommitmentWords(
        geometry.decommitment_record_count,
        geometry.query_count,
    );
    return (compact.CompactProofLayoutV1{
        .interaction_claim_words = @intCast(bundle.components.len * 4),
        .sampled_value_words = 4,
        .decommitment_capacity_words = capacity,
    }).protocolRuntime(7, geometry, .{
        @intCast(preprocessed_columns),
        finalSpanEnd(bundle, 1),
        finalSpanEnd(bundle, 2),
        8,
    });
}

fn finalSpanEnd(bundle: *const composition.Bundle, tree: u32) u32 {
    var end: u32 = 0;
    for (bundle.components) |component| {
        for (component.trace_spans) |span| if (span.tree == tree) {
            end = @max(end, span.end);
        };
    }
    return end;
}

fn testPack(
    bundle: composition.Bundle,
    verifier_log: u32,
) subject_identity.PackIdentity {
    return .{
        .provenance = .proof_derived,
        .manifest = [_]u8{1} ** 32,
        .composition_projection = [_]u8{2} ** 32,
        .composition = [_]u8{3} ** 32,
        .witness_programs = [_]u8{4} ** 32,
        .multiplicity_feeds = [_]u8{5} ** 32,
        .relation_templates = [_]u8{6} ** 32,
        .fixed_tables = [_]u8{7} ** 32,
        .preprocessed_coefficients = [_]u8{8} ** 32,
        .verifier_max_log_degree_bound = verifier_log,
        .composition_plan_hash = bundle.plan_hash,
    };
}

fn testTarget() cuda_plan.CompileOptions {
    return .{
        .sm = 90,
        .device_uuid = [_]u8{0x42} ** 16,
        .driver_version = 12080,
        .runtime_version = 12080,
        .toolkit_version = 12080,
        .runtime_build_identity = proof_ir.identityDigest("cairo-cuda-runtime"),
        .host_toolchain_identity = proof_ir.identityDigest("zig-0.15.2"),
        .kernel_pack_identity = proof_ir.identityDigest("cairo-cuda-aot"),
        .lane_streams = 0,
        .enable_graphs = true,
    };
}

fn sha256File(path: []const u8) ![32]u8 {
    const file = try std.fs.cwd().openFile(path, .{});
    defer file.close();
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    var buffer: [1 << 20]u8 = undefined;
    while (true) {
        const count = try file.read(&buffer);
        if (count == 0) break;
        hash.update(buffer[0..count]);
    }
    return hash.finalResult();
}
