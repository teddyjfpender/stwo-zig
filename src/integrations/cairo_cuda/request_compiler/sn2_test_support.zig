//! SN PIE 2 request-compiler test fixtures kept outside production ownership.

const std = @import("std");
const cuda_plan = @import("../../../backends/cuda/runtime/execution_plan.zig");
const proof_plan = @import("../../../frontends/cairo/proof_plan.zig");
const compact = @import(
    "../../../frontends/cairo/compact_verifier_interchange.zig",
);
const compact_geometry = @import(
    "../../../frontends/cairo/compact_protocol_geometry.zig",
);
const composition = @import(
    "../../../frontends/cairo/witness/composition_bundle.zig",
);
const subject_identity = @import("../identity.zig");
const proof_ir = @import("stwo_backend_contracts").proof_program;

pub fn expectMixedHeightBuffers(
    build_buffers: anytype,
    find_component: anytype,
    trace_bytes: anytype,
) !void {
    const allocator = std.testing.allocator;
    const adapter = @import("../../../frontends/cairo/adapter/mod.zig");
    const fixed_table_bundle = @import(
        "../../../frontends/cairo/witness/fixed_table_bundle.zig",
    );
    const witness_bundle = @import(
        "../../../frontends/cairo/witness/bundle.zig",
    );
    const feed_bundle = @import(
        "../../../frontends/cairo/witness/feed_bundle.zig",
    );
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
    const descriptions = try build_buffers(allocator, &proof, bundle, 4097);
    defer allocator.free(descriptions);

    try std.testing.expectEqual(1 + proof.components.len * 2, descriptions.len);
    try std.testing.expectEqual(@as(u64, 4352), descriptions[0].staged.size_bytes);
    for (proof.components, 0..) |component, index| {
        const captured = find_component(
            bundle,
            component.name,
            component.instance,
        ) orelse return error.TestUnexpectedResult;
        const rows = @as(u64, 1) << @intCast(captured.trace_log_size);
        try std.testing.expectEqual(
            try trace_bytes(captured.*, 1, rows),
            descriptions[1 + index * 2].staged.size_bytes,
        );
        try std.testing.expectEqual(
            try trace_bytes(captured.*, 2, rows),
            descriptions[2 + index * 2].staged.size_bytes,
        );
    }
}

pub fn protocol(
    bundle: *const composition.Bundle,
    preprocessed_columns: usize,
) !compact.CompactProtocolV1 {
    const verifier_log = try bundle.verifierMaxLogDegreeBound();
    var geometry = compact_geometry.RuntimeProtocolGeometryV1.sn2();
    geometry.max_log_degree_bound = verifier_log;
    geometry.fri_tree_count = 1 + (verifier_log - 1) / geometry.fri_fold_step;
    geometry.decommitment_record_count =
        geometry.commitment_count + geometry.fri_tree_count;
    if (bundle.components.len * 4 != compact.sn2_interaction_claim_words)
        return error.InvalidProtocolGeometry;
    return compact.sn2ProofLayout().protocolRuntime(7, geometry, .{
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

pub fn pack(
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

pub fn target() cuda_plan.CompileOptions {
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

pub fn sha256File(path: []const u8) ![32]u8 {
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
