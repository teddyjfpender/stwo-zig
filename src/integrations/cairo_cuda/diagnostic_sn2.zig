//! Direct, content-addressed SN PIE 2 ingress for CUDA bring-up.
//!
//! This route exists only to reach an end-to-end diagnostic proof before the
//! source-derived Cairo semantic manifest is available. It authenticates every
//! staged file and retains proof-derived provenance throughout.

const std = @import("std");
const execution_plan = @import("../../backends/cuda/runtime/execution_plan.zig");
const adapter = @import("../../frontends/cairo/adapter/mod.zig");
const compact = @import(
    "../../frontends/cairo/compact_verifier_interchange.zig",
);
const geometry = @import(
    "../../frontends/cairo/compact_protocol_geometry.zig",
);
const semantic_authority = @import(
    "../../frontends/cairo/proof_plan/semantic_authority.zig",
);
const statement = @import("../../frontends/cairo/statement_bootstrap.zig");
const composition_bundle = @import(
    "../../frontends/cairo/witness/composition_bundle.zig",
);
const feed_bundle = @import(
    "../../frontends/cairo/witness/feed_bundle.zig",
);
const fixed_bundle = @import(
    "../../frontends/cairo/witness/fixed_table_bundle.zig",
);
const relation_bundle = @import(
    "../../frontends/cairo/witness/relation_bundle.zig",
);
const witness_bundle = @import("../../frontends/cairo/witness/bundle.zig");
const identity = @import("identity.zig");
const request_compiler = @import("request_compiler.zig");

pub const production_eligible = false;

pub const ArtifactPaths = struct {
    adapted_input: []const u8,
    composition: []const u8,
    witness_programs: []const u8,
    multiplicity_feeds: []const u8,
    relation_templates: []const u8,
    fixed_tables: []const u8,
    preprocessed_coefficients: []const u8,
};

pub const ArtifactDigests = struct {
    adapted_input: [32]u8,
    composition: [32]u8,
    witness_programs: [32]u8,
    multiplicity_feeds: [32]u8,
    relation_templates: [32]u8,
    fixed_tables: [32]u8,
    preprocessed_coefficients: [32]u8,
    direct_manifest: [32]u8,
    direct_projection: [32]u8,
};

pub const Prepared = struct {
    allocator: std.mem.Allocator,
    adapted_bytes: []align(64) u8,
    input: adapter.ProverInput,
    composition: composition_bundle.Bundle,
    witnesses: witness_bundle.Bundle,
    feeds: feed_bundle.Bundle,
    relations: relation_bundle.Bundle,
    fixed: fixed_bundle.Bundle,
    statement_bytes: []u8,
    preprocessed_logs: []u32,
    protocol: compact.CompactProtocolV1,
    digests: ArtifactDigests,
    request: request_compiler.PreparedRequest,

    pub fn deinit(self: *Prepared) void {
        self.request.deinit();
        self.allocator.free(self.preprocessed_logs);
        self.allocator.free(self.statement_bytes);
        self.fixed.deinit();
        self.relations.deinit();
        self.feeds.deinit();
        self.witnesses.deinit();
        self.composition.deinit();
        self.input.deinit(self.allocator);
        self.allocator.free(self.adapted_bytes);
        self.* = undefined;
    }
};

/// Builds the exact SN2 development request used by the structural compiler
/// gate, replacing test-only identities with hashes of the real staged files.
pub fn compileDiagnosticSn2(
    allocator: std.mem.Allocator,
    paths: ArtifactPaths,
    target: execution_plan.CompileOptions,
) !Prepared {
    try requireAbsolute(paths);
    const adapted_bytes = try readAdaptedInput(allocator, paths.adapted_input);
    errdefer allocator.free(adapted_bytes);
    const adapted_digest = sha256(adapted_bytes);
    try validateLockedInput(adapted_bytes.len, adapted_digest);

    var input = try adapter.adapted_input.readFile(
        allocator,
        paths.adapted_input,
    );
    errdefer input.deinit(allocator);
    var composition = try composition_bundle.Bundle.readFile(
        allocator,
        paths.composition,
    );
    errdefer composition.deinit();
    var witnesses = try witness_bundle.Bundle.readFile(
        allocator,
        paths.witness_programs,
    );
    errdefer witnesses.deinit();
    var feeds = try feed_bundle.Bundle.readFile(
        allocator,
        paths.multiplicity_feeds,
    );
    errdefer feeds.deinit();
    var relations = try relation_bundle.Bundle.readFile(
        allocator,
        paths.relation_templates,
    );
    errdefer relations.deinit();
    var fixed = try fixed_bundle.Bundle.readFile(
        allocator,
        paths.fixed_tables,
    );
    errdefer fixed.deinit();

    const digests = try measureArtifacts(paths, adapted_digest);
    const statement_bytes = try statement.encodeCompactStatementV1(
        allocator,
        &composition,
        &input,
    );
    errdefer allocator.free(statement_bytes);
    const preprocessed_logs = try semantic_authority.preprocessedLogs(
        allocator,
        fixed,
    );
    errdefer allocator.free(preprocessed_logs);
    const protocol = try sn2Protocol(
        &composition,
        fixed.preprocessed_identities.len,
    );
    const pack = identity.PackIdentity{
        .provenance = .proof_derived,
        .manifest = digests.direct_manifest,
        .composition_projection = digests.direct_projection,
        .composition = digests.composition,
        .witness_programs = digests.witness_programs,
        .multiplicity_feeds = digests.multiplicity_feeds,
        .relation_templates = digests.relation_templates,
        .fixed_tables = digests.fixed_tables,
        .preprocessed_coefficients = digests.preprocessed_coefficients,
        .verifier_max_log_degree_bound = protocol.max_log_degree_bound,
        .composition_plan_hash = composition.plan_hash,
    };
    var request = try request_compiler.compileProofDerivedDiagnostic(
        allocator,
        .{
            .adapted_input = &input,
            .adapted_input_bytes = @intCast(adapted_bytes.len),
            .adapted_input_identity = adapted_digest,
            .witnesses = witnesses,
            .multiplicity_feeds = feeds,
            .fixed_tables = fixed,
            .composition = composition,
            .relation_templates = relations,
            .compact_statement = statement_bytes,
            .preprocessed_logs = preprocessed_logs,
            .pack = pack,
        },
        protocol,
        target,
    );
    errdefer request.deinit();
    if (request.receipt.production_eligible or
        request.receipt.missing_lowering_count != 0)
    {
        return error.InvalidDiagnosticSn2Admission;
    }
    return .{
        .allocator = allocator,
        .adapted_bytes = adapted_bytes,
        .input = input,
        .composition = composition,
        .witnesses = witnesses,
        .feeds = feeds,
        .relations = relations,
        .fixed = fixed,
        .statement_bytes = statement_bytes,
        .preprocessed_logs = preprocessed_logs,
        .protocol = protocol,
        .digests = digests,
        .request = request,
    };
}

fn measureArtifacts(
    paths: ArtifactPaths,
    adapted_input: [32]u8,
) !ArtifactDigests {
    var result = ArtifactDigests{
        .adapted_input = adapted_input,
        .composition = try sha256File(paths.composition),
        .witness_programs = try sha256File(paths.witness_programs),
        .multiplicity_feeds = try sha256File(paths.multiplicity_feeds),
        .relation_templates = try sha256File(paths.relation_templates),
        .fixed_tables = try sha256File(paths.fixed_tables),
        .preprocessed_coefficients = try sha256File(
            paths.preprocessed_coefficients,
        ),
        .direct_manifest = undefined,
        .direct_projection = undefined,
    };
    result.direct_projection = digestClosure(
        "stwo-zig/cairo/cuda/direct-composition-projection/v1",
        &.{result.composition},
    );
    result.direct_manifest = digestClosure(
        "stwo-zig/cairo/cuda/direct-proof-derived-artifacts/v1",
        &.{
            result.adapted_input,
            result.composition,
            result.witness_programs,
            result.multiplicity_feeds,
            result.relation_templates,
            result.fixed_tables,
            result.preprocessed_coefficients,
            result.direct_projection,
        },
    );
    return result;
}

fn sn2Protocol(
    bundle: *const composition_bundle.Bundle,
    preprocessed_columns: usize,
) !compact.CompactProtocolV1 {
    const verifier_log = try bundle.verifierMaxLogDegreeBound();
    var runtime = geometry.RuntimeProtocolGeometryV1.sn2();
    runtime.max_log_degree_bound = verifier_log;
    runtime.fri_tree_count = 1 +
        (verifier_log - 1) / runtime.fri_fold_step;
    runtime.decommitment_record_count =
        runtime.commitment_count + runtime.fri_tree_count;
    if (bundle.components.len * 4 != compact.sn2_interaction_claim_words)
        return error.InvalidProtocolGeometry;
    return compact.sn2ProofLayout().protocolRuntime(7, runtime, .{
        @intCast(preprocessed_columns),
        finalSpanEnd(bundle, 1),
        finalSpanEnd(bundle, 2),
        8,
    });
}

fn finalSpanEnd(bundle: *const composition_bundle.Bundle, tree: u32) u32 {
    var end: u32 = 0;
    for (bundle.components) |component| {
        for (component.trace_spans) |span| {
            if (span.tree == tree) end = @max(end, span.end);
        }
    }
    return end;
}

fn requireAbsolute(paths: ArtifactPaths) !void {
    inline for (std.meta.fields(ArtifactPaths)) |field| {
        if (!std.fs.path.isAbsolute(@field(paths, field.name)))
            return error.DiagnosticArtifactPathNotAbsolute;
    }
}

fn readAdaptedInput(
    allocator: std.mem.Allocator,
    path: []const u8,
) ![]align(64) u8 {
    const file = try std.fs.openFileAbsolute(path, .{});
    defer file.close();
    const stat = try file.stat();
    if (stat.kind != .file or stat.size == 0 or stat.size > 512 * 1024 * 1024)
        return error.InvalidDiagnosticAdaptedInput;
    const bytes = try allocator.alignedAlloc(u8, .@"64", @intCast(stat.size));
    errdefer allocator.free(bytes);
    if (try file.readAll(bytes) != bytes.len)
        return error.InvalidDiagnosticAdaptedInput;
    return bytes;
}

fn validateLockedInput(bytes: usize, digest: [32]u8) !void {
    if (bytes != request_compiler.sn2_diagnostic_fixture.adapted_input_size_bytes)
        return error.DiagnosticSn2InputSizeMismatch;
    var expected: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(
        &expected,
        request_compiler.sn2_diagnostic_fixture.adapted_input_sha256,
    ) catch unreachable;
    if (!std.mem.eql(u8, &digest, &expected))
        return error.DiagnosticSn2InputDigestMismatch;
}

fn sha256(bytes: []const u8) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(bytes);
    return hash.finalResult();
}

fn sha256File(path: []const u8) ![32]u8 {
    const file = try std.fs.openFileAbsolute(path, .{});
    defer file.close();
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    var buffer: [1024 * 1024]u8 = undefined;
    while (true) {
        const count = try file.read(&buffer);
        if (count == 0) break;
        hash.update(buffer[0..count]);
    }
    return hash.finalResult();
}

fn digestClosure(
    domain: []const u8,
    values: []const [32]u8,
) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(domain);
    hash.update(&.{0});
    for (values) |value| hash.update(&value);
    return hash.finalResult();
}
