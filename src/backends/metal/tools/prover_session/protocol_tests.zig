//! Protocol, artifact-view, environment, and provenance invariants.

const std = @import("std");
const stwo = @import("stwo");
const artifact_store = stwo.metal_session.artifact_store;
const artifact_views = stwo.metal_session.artifact_views;
const cairo_adapted_input = stwo.frontends.cairo.adapter.adapted_input;
const cairo_opcodes = stwo.frontends.cairo.adapter.opcodes;
const one_shot = @import("one_shot");
const protocol = stwo.metal_session.protocol;
const state = @import("state.zig");
const preparation = @import("preparation.zig");
const verification = @import("verification.zig");
const test_support = @import("test_support.zig");

const persistent_report_schema_version = state.persistent_report_schema_version;
const in_process_runner_linkage = state.in_process_runner_linkage;
const ProofResult = state.ProofResult;
const RunnerArtifacts = state.RunnerArtifacts;
const ViewCache = state.ViewCache;
const adaptedGeometry = preparation.adaptedGeometry;
const cacheDelta = preparation.cacheDelta;
const authorizeCompositionProgram = preparation.authorizeCompositionProgram;
const compositionProgramPolicy = preparation.compositionProgramPolicy;
const immutableObject = preparation.immutableObject;
const isSessionScrubbedRunnerEnvironment = preparation.isSessionScrubbedRunnerEnvironment;
const requireWarmPipelineCache = preparation.requireWarmPipelineCache;
const referenceEnvironment = preparation.referenceEnvironment;
const writeVerifiedResultFrame = preparation.writeVerifiedResultFrame;
const cliProvenance = verification.cliProvenance;
const requireCanonicalCliProtocol = verification.requireCanonicalCliProtocol;
const testArtifactObjects = test_support.testArtifactObjects;

const TestBuiltinSpan = struct { begin: u64, stop: u64 };

const TestPerProofShape = struct {
    address_count: usize = 0,
    f252_count: usize = 0,
    small_count: usize = 0,
    public_count: usize = 0,
    ec_op_span: ?TestBuiltinSpan = null,
};

test "production composition policy pins an AOT metallib digest" {
    const digest = [_]u8{0xab} ** 32;
    const encoded = std.fmt.bytesToHex(digest, .lower);
    const production = try compositionProgramPolicy(&encoded);
    try authorizeCompositionProgram(production, .metallib, digest);

    var other = digest;
    other[0] ^= 1;
    try std.testing.expectError(
        error.UnapprovedCompositionMetallib,
        authorizeCompositionProgram(production, .metallib, other),
    );
    try std.testing.expectError(
        error.CompositionSourceForbidden,
        authorizeCompositionProgram(production, .metal, digest),
    );
    try authorizeCompositionProgram(.diagnostic, .metal, other);
}

test "production composition policy rejects noncanonical digests" {
    try std.testing.expectError(
        error.InvalidCompositionMetallibDigest,
        compositionProgramPolicy("ab"),
    );
    try std.testing.expectError(
        error.InvalidCompositionMetallibDigest,
        compositionProgramPolicy("ABABABABABABABABABABABABABABABABABABABABABABABABABABABABABAB"),
    );
    try std.testing.expectError(
        error.InvalidCompositionMetallibDigest,
        compositionProgramPolicy("zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"),
    );
}

test "session cache delta includes library preparation time" {
    const before = stwo.backends.metal.runtime.PipelineCacheStats.zero();
    var after = before;
    after.library_cache_misses = 1;
    after.library_preparation_seconds = 0.25;
    const delta = cacheDelta(after, before);
    try std.testing.expectEqual(@as(u64, 1), delta.library_cache_misses);
    try std.testing.expectEqual(@as(f64, 0.25), delta.library_preparation_seconds);
}

test "warm proof cache gate permits hits and timing only" {
    var warm = stwo.backends.metal.runtime.PipelineCacheStats.zero();
    warm.library_cache_hits = 1;
    warm.pipeline_cache_hits = 58;
    warm.pipeline_preparation_seconds = 0.25;
    warm.library_preparation_seconds = 0.125;
    try requireWarmPipelineCache(warm);

    inline for (.{
        .{ "library_cache_misses", error.UnexpectedLibraryCacheMiss },
        .{ "binary_archive_hits", error.UnexpectedBinaryArchiveHit },
        .{ "binary_archive_misses", error.UnexpectedBinaryArchiveMiss },
        .{ "direct_compiles", error.UnexpectedDirectCompile },
        .{ "archive_populations", error.UnexpectedArchivePopulation },
        .{ "archive_serializations", error.UnexpectedArchiveSerialization },
        .{ "library_cache_evictions", error.UnexpectedLibraryCacheEviction },
        .{ "library_cache_rejections", error.UnexpectedLibraryCacheRejection },
        .{ "pipeline_cache_evictions", error.UnexpectedPipelineCacheEviction },
        .{ "pipeline_cache_invalidations", error.UnexpectedPipelineCacheInvalidation },
        .{ "pipeline_cache_rejections", error.UnexpectedPipelineCacheRejection },
    }) |field| {
        var cold = warm;
        @field(cold, field[0]) = 1;
        try std.testing.expectError(
            field[1],
            requireWarmPipelineCache(cold),
        );
    }
}

fn testAdaptedInputBytes(
    allocator: std.mem.Allocator,
    opcode_counts: [cairo_opcodes.N_OPCODES]u64,
    builtin_spans: [4]?TestBuiltinSpan,
    pc_count: u64,
    irrelevant_seed: u8,
    per_proof: TestPerProofShape,
) ![]u8 {
    var state_count: u64 = 0;
    for (opcode_counts) |count| state_count += count;
    const memory_payload_bytes = per_proof.address_count * @sizeOf(u32) +
        per_proof.f252_count * 8 * @sizeOf(u32) +
        per_proof.small_count * @sizeOf(u128);
    const public_payload_bytes = per_proof.public_count * @sizeOf(u32);
    const file_bytes = 64 + cairo_opcodes.N_OPCODES * 8 + state_count * 12 +
        48 + memory_payload_bytes + 8 + public_payload_bytes + 9 * 24;
    const bytes = try allocator.alloc(u8, @intCast(file_bytes));
    @memset(bytes, 0);
    @memcpy(bytes[0..8], "STWZCPI\x00");
    std.mem.writeInt(u32, bytes[8..12], cairo_adapted_input.VERSION, .little);
    bytes[16] = irrelevant_seed;
    std.mem.writeInt(u64, bytes[40..48], pc_count, .little);
    std.mem.writeInt(u32, bytes[56..60], cairo_opcodes.N_OPCODES, .little);
    var offset: usize = 64;
    for (opcode_counts) |count| {
        std.mem.writeInt(u64, bytes[offset..][0..8], count, .little);
        offset += 8 + @as(usize, @intCast(count)) * 12;
    }
    bytes[offset] = irrelevant_seed;
    std.mem.writeInt(u64, bytes[offset + 24 ..][0..8], per_proof.address_count, .little);
    std.mem.writeInt(u64, bytes[offset + 32 ..][0..8], per_proof.f252_count, .little);
    std.mem.writeInt(u64, bytes[offset + 40 ..][0..8], per_proof.small_count, .little);
    offset += 48;
    offset += memory_payload_bytes;
    std.mem.writeInt(u64, bytes[offset..][0..8], per_proof.public_count, .little);
    offset += 8;
    offset += public_payload_bytes;
    const geometry_segment_indices = [_]usize{ 1, 4, 5, 7 };
    var geometry_index: usize = 0;
    for (0..9) |segment_index| {
        if (geometry_index < geometry_segment_indices.len and
            geometry_segment_indices[geometry_index] == segment_index)
        {
            if (builtin_spans[geometry_index]) |span| {
                bytes[offset] = 1;
                std.mem.writeInt(u64, bytes[offset + 8 ..][0..8], span.begin, .little);
                std.mem.writeInt(u64, bytes[offset + 16 ..][0..8], span.stop, .little);
            }
            geometry_index += 1;
        } else if (segment_index == 8) {
            if (per_proof.ec_op_span) |span| {
                bytes[offset] = 1;
                std.mem.writeInt(u64, bytes[offset + 8 ..][0..8], span.begin, .little);
                std.mem.writeInt(u64, bytes[offset + 16 ..][0..8], span.stop, .little);
            }
        }
        offset += 24;
    }
    std.debug.assert(offset == bytes.len);
    return bytes;
}

test "adapted geometry validates layout and fingerprints only compatible row extents" {
    var directory = std.testing.tmpDir(.{});
    defer directory.cleanup();
    var opcode_counts = [_]u64{0} ** cairo_opcodes.N_OPCODES;
    opcode_counts[2] = 3;
    opcode_counts[18] = 4;
    const spans_a = [4]?TestBuiltinSpan{
        .{ .begin = 100, .stop = 150 },
        .{ .begin = 200, .stop = 230 },
        .{ .begin = 300, .stop = 360 },
        .{ .begin = 400, .stop = 410 },
    };
    const spans_b = [4]?TestBuiltinSpan{
        .{ .begin = 1_000, .stop = 1_050 },
        .{ .begin = 2_000, .stop = 2_030 },
        .{ .begin = 3_000, .stop = 3_060 },
        .{ .begin = 4_000, .stop = 4_010 },
    };
    const bytes_a = try testAdaptedInputBytes(std.testing.allocator, opcode_counts, spans_a, 17, 0x11, .{});
    defer std.testing.allocator.free(bytes_a);
    const bytes_b = try testAdaptedInputBytes(std.testing.allocator, opcode_counts, spans_b, 19, 0x22, .{});
    defer std.testing.allocator.free(bytes_b);
    try directory.dir.writeFile(.{ .sub_path = "a.stwzcpi", .data = bytes_a });
    try directory.dir.writeFile(.{ .sub_path = "b.stwzcpi", .data = bytes_b });
    const path_a = try directory.dir.realpathAlloc(std.testing.allocator, "a.stwzcpi");
    defer std.testing.allocator.free(path_a);
    const path_b = try directory.dir.realpathAlloc(std.testing.allocator, "b.stwzcpi");
    defer std.testing.allocator.free(path_b);

    const geometry_a = try adaptedGeometry(path_a, bytes_a.len);
    const geometry_b = try adaptedGeometry(path_b, bytes_b.len);
    try std.testing.expectEqual(geometry_a.fingerprint, geometry_b.fingerprint);
    try std.testing.expectEqual(@as(u64, 7), geometry_a.counts.cycles);
    try std.testing.expectEqual(@as(u64, 17), geometry_a.counts.pc_count);
    try std.testing.expectEqual(@as(u64, 19), geometry_b.counts.pc_count);

    var changed_counts = opcode_counts;
    changed_counts[2] += 1;
    const incompatible = try testAdaptedInputBytes(std.testing.allocator, changed_counts, spans_a, 17, 0x11, .{});
    defer std.testing.allocator.free(incompatible);
    try directory.dir.writeFile(.{ .sub_path = "incompatible.stwzcpi", .data = incompatible });
    const incompatible_path = try directory.dir.realpathAlloc(std.testing.allocator, "incompatible.stwzcpi");
    defer std.testing.allocator.free(incompatible_path);
    const incompatible_geometry = try adaptedGeometry(incompatible_path, incompatible.len);
    try std.testing.expect(!std.mem.eql(
        u8,
        &geometry_a.fingerprint,
        &incompatible_geometry.fingerprint,
    ));

    var changed_spans = spans_a;
    changed_spans[0].?.stop += 5;
    const incompatible_builtin = try testAdaptedInputBytes(
        std.testing.allocator,
        opcode_counts,
        changed_spans,
        17,
        0x11,
        .{},
    );
    defer std.testing.allocator.free(incompatible_builtin);
    try directory.dir.writeFile(.{ .sub_path = "incompatible-builtin.stwzcpi", .data = incompatible_builtin });
    const incompatible_builtin_path = try directory.dir.realpathAlloc(
        std.testing.allocator,
        "incompatible-builtin.stwzcpi",
    );
    defer std.testing.allocator.free(incompatible_builtin_path);
    const incompatible_builtin_geometry = try adaptedGeometry(
        incompatible_builtin_path,
        incompatible_builtin.len,
    );
    try std.testing.expect(!std.mem.eql(
        u8,
        &geometry_a.fingerprint,
        &incompatible_builtin_geometry.fingerprint,
    ));

    const trailing = try std.testing.allocator.alloc(u8, bytes_a.len + 1);
    defer std.testing.allocator.free(trailing);
    @memcpy(trailing[0..bytes_a.len], bytes_a);
    trailing[bytes_a.len] = 0xff;
    try directory.dir.writeFile(.{ .sub_path = "trailing.stwzcpi", .data = trailing });
    const trailing_path = try directory.dir.realpathAlloc(std.testing.allocator, "trailing.stwzcpi");
    defer std.testing.allocator.free(trailing_path);
    try std.testing.expectError(
        error.InvalidAdaptedInput,
        adaptedGeometry(trailing_path, trailing.len),
    );

    try std.testing.expectError(
        error.InvalidAdaptedInput,
        adaptedGeometry(path_a, bytes_a.len + 1),
    );
}

test "adapted geometry excludes per-proof runtime payload from plan compatibility" {
    var directory = std.testing.tmpDir(.{});
    defer directory.cleanup();
    var opcode_counts = [_]u64{0} ** cairo_opcodes.N_OPCODES;
    opcode_counts[7] = 5;
    const spans = [4]?TestBuiltinSpan{
        .{ .begin = 100, .stop = 150 },
        .{ .begin = 200, .stop = 230 },
        .{ .begin = 300, .stop = 360 },
        .{ .begin = 400, .stop = 410 },
    };
    const baseline = try testAdaptedInputBytes(
        std.testing.allocator,
        opcode_counts,
        spans,
        9,
        0x11,
        .{},
    );
    defer std.testing.allocator.free(baseline);
    const runtime_changed = try testAdaptedInputBytes(
        std.testing.allocator,
        opcode_counts,
        spans,
        23,
        0x22,
        .{
            .address_count = 7,
            .f252_count = 2,
            .small_count = 3,
            .public_count = 4,
            .ec_op_span = .{ .begin = 5_000, .stop = 5_700 },
        },
    );
    defer std.testing.allocator.free(runtime_changed);
    try directory.dir.writeFile(.{ .sub_path = "baseline.stwzcpi", .data = baseline });
    try directory.dir.writeFile(.{ .sub_path = "runtime-changed.stwzcpi", .data = runtime_changed });
    const baseline_path = try directory.dir.realpathAlloc(std.testing.allocator, "baseline.stwzcpi");
    defer std.testing.allocator.free(baseline_path);
    const runtime_path = try directory.dir.realpathAlloc(std.testing.allocator, "runtime-changed.stwzcpi");
    defer std.testing.allocator.free(runtime_path);

    const baseline_geometry = try adaptedGeometry(baseline_path, baseline.len);
    const runtime_geometry = try adaptedGeometry(runtime_path, runtime_changed.len);
    try std.testing.expectEqual(baseline_geometry.fingerprint, runtime_geometry.fingerprint);
    try std.testing.expectEqual(@as(u64, 9), baseline_geometry.counts.pc_count);
    try std.testing.expectEqual(@as(u64, 23), runtime_geometry.counts.pc_count);
}

test "persistent report uses schema version 3" {
    try std.testing.expectEqual(@as(u32, 3), persistent_report_schema_version);
}

test "persistent view cache reuses exact objects without changing store identity" {
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    try temporary.dir.writeFile(.{ .sub_path = "evaluations.bin", .data = "evaluations" });
    try temporary.dir.writeFile(.{ .sub_path = "composition.bin", .data = "composition" });
    try temporary.dir.writeFile(.{ .sub_path = "composition.metallib", .data = "metallib" });
    var tree_bytes: [60]u8 = [_]u8{0} ** 60;
    @memcpy(tree_bytes[0..8], "STWZMRK\x00");
    std.mem.writeInt(u32, tree_bytes[8..12], 1, .little);
    std.mem.writeInt(u32, tree_bytes[12..16], 0, .little);
    std.mem.writeInt(u32, tree_bytes[16..20], 1, .little);
    std.mem.writeInt(u64, tree_bytes[20..28], 32, .little);
    for (tree_bytes[28..], 0..) |*byte, index| byte.* = @intCast(index);
    try temporary.dir.writeFile(.{ .sub_path = "tree.bin", .data = &tree_bytes });

    const parent = try temporary.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(parent);
    const store_root = try std.fs.path.join(std.testing.allocator, &.{ parent, "store" });
    defer std.testing.allocator.free(store_root);
    var store = try artifact_store.Store.initNew(std.testing.allocator, store_root, true);
    defer store.deinit();
    const names = [_][]const u8{ "evaluations.bin", "tree.bin", "composition.bin", "composition.metallib" };
    var snapshots: [names.len]artifact_store.Snapshot = undefined;
    var initialized: usize = 0;
    defer for (snapshots[0..initialized]) |*snapshot| snapshot.deinit(std.testing.allocator);
    while (initialized < names.len) : (initialized += 1) {
        const source = try temporary.dir.realpathAlloc(std.testing.allocator, names[initialized]);
        defer std.testing.allocator.free(source);
        snapshots[initialized] = try store.ingestPathWithPolicy(source, .byte_copy);
    }

    var expected_root: [32]u8 = undefined;
    for (&expected_root, 0..) |*byte, index| byte.* = @intCast(index);
    const inputs = artifact_views.Inputs{
        .preprocessed_evaluations = immutableObject(&snapshots[0]),
        .preprocessed_tree0_merkle = immutableObject(&snapshots[1]),
        .composition = immutableObject(&snapshots[2]),
        .composition_program = .{ .metallib = immutableObject(&snapshots[3]) },
        .expected_tree0_root = expected_root,
    };
    var views = ViewCache.init(std.testing.allocator);
    const first = try views.getOrCreate(store.root_path, "first", inputs);
    const first_directory = try std.testing.allocator.dupe(u8, first.directory);
    defer std.testing.allocator.free(first_directory);
    const second = try views.getOrCreate(store.root_path, "second", inputs);
    try std.testing.expectEqual(@as(usize, 1), views.views.count());
    try std.testing.expectEqualStrings(first_directory, second.directory);
    views.deinit();

    for (&snapshots) |*snapshot| {
        var resolved = try store.resolveRef(snapshot.ref());
        resolved.deinit(std.testing.allocator);
    }
}

test "reference environment preserves diagnostics and omits absent references" {
    const base = RunnerArtifacts{
        .adapted_input = "/a",
        .schedule = "/b",
        .witness_programs = "/c",
        .multiplicity_feeds = "/d",
        .relation_templates = "/e",
        .fixed_tables = "/f",
        .composition = "/g",
        .composition_program = "/g.metallib",
        .preprocessed_evaluations = "/h",
        .preprocessed_tree0_merkle = "/h.tree0-merkle",
        .preprocessed_coefficients = "/i",
        .transcript_reference = null,
        .quotient_reference = null,
    };
    const absent = referenceEnvironment(base);
    try std.testing.expectEqual(null, absent[0]);
    try std.testing.expectEqual(null, absent[1]);
    try std.testing.expectEqual(null, absent[2]);

    var diagnostic = base;
    diagnostic.transcript_reference = "/transcript.json";
    diagnostic.quotient_reference = "/quotient.bin";
    const present = referenceEnvironment(diagnostic);
    try std.testing.expectEqualStrings("STWO_ZIG_SN2_TRANSCRIPT_REFERENCE", present[0].?.name);
    try std.testing.expectEqualStrings("/transcript.json", present[0].?.value);
    try std.testing.expectEqualStrings("STWO_ZIG_SN2_QUOTIENT_REFERENCE", present[1].?.name);
    try std.testing.expectEqualStrings("/quotient.bin", present[1].?.value);
    try std.testing.expectEqualStrings("STWO_ZIG_SN2_REPLAY_TRANSCRIPT_AFTER_TREE2", present[2].?.name);
    try std.testing.expectEqualStrings("1", present[2].?.value);
}

test "reference-free session scrubs every hidden transcript control" {
    const forbidden = [_][]const u8{
        "STWO_ZIG_SN2_TRANSCRIPT_REFERENCE",
        "STWO_ZIG_SN2_QUOTIENT_REFERENCE",
        "STWO_ZIG_SN2_REPLAY_TRANSCRIPT_AFTER_TREE2",
        "STWO_ZIG_SN2_TRANSCRIPT_BOOTSTRAP",
        "STWO_ZIG_SN2_RESTORE_REFERENCE_RELATION_CHALLENGES",
    };
    for (forbidden) |name|
        try std.testing.expect(isSessionScrubbedRunnerEnvironment(name));

    try std.testing.expect(!isSessionScrubbedRunnerEnvironment(
        "STWO_ZIG_METAL_REPLAY_RETAINED_LOOKUPS",
    ));
    try std.testing.expect(!isSessionScrubbedRunnerEnvironment("PATH"));
}

test "CLI provenance promotes complete authoritative runner evidence" {
    const encoded =
        \\{"self_contained":false,"parity_fixture_used":false,"proof_derived_artifact_used":true,"statement_self_derived":true,"artifact_manifest_digest":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}
    ;
    var parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, encoded, .{});
    defer parsed.deinit();

    const evidence = cliProvenance(parsed.value.object);
    try std.testing.expect(!evidence.self_contained);
    try std.testing.expect(!evidence.parity_fixture_used);
    try std.testing.expect(evidence.proof_derived_artifact_used);
    try std.testing.expect(evidence.statement_self_derived);
    try std.testing.expect(evidence.provenance_complete);
    try std.testing.expectEqualStrings(
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        &evidence.artifact_manifest_digest.?,
    );
}

test "CLI provenance preserves execution evidence while withholding completeness" {
    const encoded =
        \\{"self_contained":false,"parity_fixture_used":false,"proof_derived_artifact_used":true,"statement_self_derived":true}
    ;
    var parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, encoded, .{});
    defer parsed.deinit();

    const evidence = cliProvenance(parsed.value.object);
    try std.testing.expect(!evidence.self_contained);
    try std.testing.expect(!evidence.parity_fixture_used);
    try std.testing.expect(evidence.proof_derived_artifact_used);
    try std.testing.expect(evidence.statement_self_derived);
    try std.testing.expectEqual(null, evidence.artifact_manifest_digest);
    try std.testing.expect(!evidence.provenance_complete);
}

test "CLI provenance fails closed on absent malformed or contradictory booleans" {
    const cases = [_][]const u8{
        "{\"self_contained\":false,\"parity_fixture_used\":false,\"proof_derived_artifact_used\":true}",
        "{\"self_contained\":false,\"parity_fixture_used\":\"false\",\"proof_derived_artifact_used\":true,\"statement_self_derived\":true}",
        "{\"self_contained\":true,\"parity_fixture_used\":true,\"proof_derived_artifact_used\":false,\"statement_self_derived\":true}",
        "{\"self_contained\":true,\"parity_fixture_used\":false,\"proof_derived_artifact_used\":true,\"statement_self_derived\":true}",
        "{\"self_contained\":true,\"parity_fixture_used\":false,\"proof_derived_artifact_used\":false,\"statement_self_derived\":false}",
    };
    for (cases) |encoded| {
        var parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, encoded, .{});
        defer parsed.deinit();
        const evidence = cliProvenance(parsed.value.object);
        try std.testing.expect(!evidence.self_contained);
        try std.testing.expect(evidence.parity_fixture_used);
        try std.testing.expect(evidence.proof_derived_artifact_used);
        try std.testing.expect(!evidence.statement_self_derived);
        try std.testing.expectEqual(null, evidence.artifact_manifest_digest);
        try std.testing.expect(!evidence.provenance_complete);
    }
}

test "CLI provenance rejects a malformed digest while preserving statement evidence" {
    const encoded =
        \\{"self_contained":false,"parity_fixture_used":false,"proof_derived_artifact_used":true,"statement_self_derived":true,"artifact_manifest_digest":"0123456789ABCDEF0123456789abcdef0123456789abcdef0123456789abcdef"}
    ;
    var parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, encoded, .{});
    defer parsed.deinit();

    const evidence = cliProvenance(parsed.value.object);
    try std.testing.expect(!evidence.self_contained);
    try std.testing.expect(!evidence.parity_fixture_used);
    try std.testing.expect(evidence.proof_derived_artifact_used);
    try std.testing.expect(evidence.statement_self_derived);
    try std.testing.expectEqual(null, evidence.artifact_manifest_digest);
    try std.testing.expect(!evidence.provenance_complete);
}

test "CLI protocol evidence is exact and fail closed" {
    const valid =
        \\{"protocol_complete":true,"protocol":{"channel":"blake2s","channel_salt":0,"log_blowup_factor":1,"n_queries":70,"interaction_pow_bits":24,"query_pow_bits":26,"fri_fold_step":3,"fri_lifting":null,"fri_log_last_layer_degree_bound":0}}
    ;
    var parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, valid, .{});
    defer parsed.deinit();
    try requireCanonicalCliProtocol(parsed.value.object);

    const invalid = [_][]const u8{
        "{\"protocol_complete\":false,\"protocol\":{\"channel\":\"blake2s\",\"channel_salt\":0,\"log_blowup_factor\":1,\"n_queries\":70,\"interaction_pow_bits\":24,\"query_pow_bits\":26,\"fri_fold_step\":3,\"fri_lifting\":null,\"fri_log_last_layer_degree_bound\":0}}",
        "{\"protocol_complete\":true,\"protocol\":{\"channel\":\"blake2s\",\"channel_salt\":0,\"log_blowup_factor\":1,\"n_queries\":70,\"interaction_pow_bits\":24,\"query_pow_bits\":25,\"fri_fold_step\":3,\"fri_lifting\":null,\"fri_log_last_layer_degree_bound\":0}}",
        "{\"protocol_complete\":true}",
    };
    for (invalid) |document| {
        var candidate = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, document, .{});
        defer candidate.deinit();
        try std.testing.expectError(
            error.InvalidCliProtocol,
            requireCanonicalCliProtocol(candidate.value.object),
        );
    }
}

test "verified result frame promotes normalized provenance" {
    const request = protocol.Request{
        .sequence = 7,
        .request_id = "sn-7",
        .artifacts = .{
            .adapted_input = .{ .path = "/a" },
            .schedule = .{ .path = "/b" },
            .witness_programs = .{ .path = "/c" },
            .multiplicity_feeds = .{ .path = "/d" },
            .relation_templates = .{ .path = "/e" },
            .fixed_tables = .{ .path = "/f" },
            .composition = .{ .path = "/g" },
            .composition_program = .{ .path = "/g.metallib" },
            .preprocessed_evaluations = .{ .path = "/h" },
            .preprocessed_tree0_merkle = .{ .path = "/h.tree0-merkle" },
            .preprocessed_coefficients = .{ .path = "/i" },
            .transcript_reference = null,
            .quotient_reference = null,
        },
        .proof_output = "/tmp/proof",
        .report_output = "/tmp/report",
        .budget_gib = "24",
        .expected_tree0_root_hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    };
    var result = ProofResult{
        .adapted_cycles = 8_000_000,
        .adapted_input_sha256 = [_]u8{'a'} ** 64,
        .prove_wall_s = 2,
        .prove_mhz = 4,
        .session_block_wall_s = 3,
        .proof_bytes = 1024,
        .proof_sha256 = [_]u8{'b'} ** 64,
        .pipeline_cache_delta = .zero(),
        .provenance = .{
            .self_contained = false,
            .parity_fixture_used = false,
            .proof_derived_artifact_used = true,
            .statement_self_derived = true,
            .artifact_manifest_digest = [_]u8{'c'} ** 64,
            .provenance_complete = true,
        },
        .executable_identity = .{
            .daemon_executable_sha256 = [_]u8{'d'} ** 64,
            .runner_executable_sha256 = [_]u8{'d'} ** 64,
        },
        .rust_verifier = .{
            .protocol_digest = [_]u8{'e'} ** 64,
            .statement_digest = [_]u8{'f'} ** 64,
            .proof_digest = [_]u8{'b'} ** 64,
            .provenance_digest = [_]u8{'1'} ** 64,
            .executable_sha256 = [_]u8{'2'} ** 64,
            .wall_time_ns = 70_000_000,
            .service_wall_time_ns = 75_000_000,
            .result_sha256 = [_]u8{'3'} ** 64,
        },
        .artifact_objects = testArtifactObjects(),
        .prepared_state_cache_hit = false,
    };
    result.pipeline_cache_delta.library_preparation_seconds = 0.25;
    var encoded: [8192]u8 = undefined;
    var writer = std.Io.Writer.fixed(&encoded);
    try writeVerifiedResultFrame(&writer, request, result);

    var parsed = try std.json.parseFromSlice(
        std.json.Value,
        std.testing.allocator,
        writer.buffered(),
        .{},
    );
    defer parsed.deinit();
    const object = parsed.value.object;
    try std.testing.expectEqualStrings("result", object.get("type").?.string);
    try std.testing.expect(!object.get("self_contained").?.bool);
    try std.testing.expect(!object.get("parity_fixture_used").?.bool);
    try std.testing.expect(object.get("proof_derived_artifact_used").?.bool);
    try std.testing.expect(object.get("statement_self_derived").?.bool);
    try std.testing.expectEqualStrings(
        "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
        object.get("artifact_manifest_digest").?.string,
    );
    try std.testing.expect(object.get("provenance_complete").?.bool);
    try std.testing.expect(object.get("protocol_complete").?.bool);
    try std.testing.expect(one_shot.protocolObjectIsCanonical(object.get("proof_protocol")));
    try std.testing.expectEqualStrings(
        "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
        object.get("daemon_executable_sha256").?.string,
    );
    try std.testing.expectEqualStrings(
        object.get("daemon_executable_sha256").?.string,
        object.get("runner_executable_sha256").?.string,
    );
    try std.testing.expectEqualStrings(
        in_process_runner_linkage,
        object.get("runner_linkage").?.string,
    );
    try std.testing.expect(!object.get("reuse").?.object.get("resident_arena").?.bool);
    try std.testing.expect(!object.get("reuse").?.object.get("preprocessed_state").?.bool);
    try std.testing.expectEqual(
        @as(f64, 0.25),
        object.get("pipeline_cache_delta").?.object.get("library_preparation_seconds").?.float,
    );
    try std.testing.expectEqualStrings(
        "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
        object.get("artifact_objects").?.object.get("adapted_input").?.object.get("object_id").?.string,
    );

    result.prepared_state_cache_hit = true;
    var reused_encoded: [8192]u8 = undefined;
    var reused_writer = std.Io.Writer.fixed(&reused_encoded);
    try writeVerifiedResultFrame(&reused_writer, request, result);
    var reused = try std.json.parseFromSlice(
        std.json.Value,
        std.testing.allocator,
        reused_writer.buffered(),
        .{},
    );
    defer reused.deinit();
    try std.testing.expect(reused.value.object.get("reuse").?.object.get("resident_arena").?.bool);
    try std.testing.expect(reused.value.object.get("reuse").?.object.get("preprocessed_state").?.bool);
}
