//! One source-authenticated Cairo request, without a captured-proof dependency.
const std = @import("std");
const cairo = @import("stwo_cairo_frontend");
const cuda = @import("stwo_cuda_backend");
const geometry_mod = @import("canonical_geometry.zig");
const feeds_mod = @import("canonical_feeds.zig");
const request_mod = @import("request_compiler.zig");
const parametric = @import("parametric_eval.zig");
const identities = @import("identity.zig");

pub const Paths = struct {
    input: []const u8,
    variant: cairo.preprocessed.trace.Variant = .canonical_small,
    automatic_variant: bool = true,
    library: []const u8 = "vectors/cairo/official/air_template_library_v1.json",
    witnesses: []const u8 = "vectors/cairo/official/witness_programs_v1.bin",
    topology: []const u8 = "vectors/cairo/official/witness_feed_topology_v1.json",
    fixed: []const u8 = "vectors/cairo/cairo_fixed_tables.bin",
    relations: []const u8 = "vectors/cairo/cairo_relation_templates.bin",
};

pub const Prepared = struct {
    allocator: std.mem.Allocator,
    arena: *std.heap.ArenaAllocator,
    adapted_bytes: []align(64) u8,
    input: cairo.adapter.ProverInput,
    input_file_sha256: [32]u8,
    input_sha256: [32]u8,
    variant: cairo.preprocessed.trace.Variant,
    claim: cairo.claim_generator.OwnedClaimGeometry,
    geometry: geometry_mod.Geometry,
    composition: cairo.witness.composition_bundle.Bundle,
    witnesses: cairo.witness.bundle.Bundle,
    feeds: cairo.witness.feed_bundle.Bundle,
    relations: cairo.witness.relation_bundle.Bundle,
    fixed: cairo.witness.fixed_table_bundle.Bundle,
    statement_bytes: []u8,
    preprocessed_logs: []u32,
    protocol: cairo.compact_verifier_interchange.CompactProtocolV1,
    request: request_mod.PreparedRequest,

    pub fn deinit(self: *Prepared) void {
        self.arena.deinit();
        self.allocator.destroy(self.arena);
        self.* = undefined;
    }
};

pub fn prepare(parent: std.mem.Allocator, paths: Paths, target: cuda.runtime.execution_plan.CompileOptions) !Prepared {
    const arena = try parent.create(std.heap.ArenaAllocator);
    errdefer parent.destroy(arena);
    arena.* = std.heap.ArenaAllocator.init(parent);
    errdefer arena.deinit();
    const allocator = arena.allocator();
    const witness_sha = try authenticate(paths.witnesses, "b2108615463b3c7003b07df20e800a42c4c7625344a681ed22e78e57238c90a6");
    const fixed_sha = try authenticate(paths.fixed, "ed8dd7b470d1837bd2db254f08ee30f3ed180099f8ed78653db008f195713890");
    const relation_sha = try authenticate(paths.relations, "2a692328b5e761b7129c82052542ba03221d228089fe1583f2d8043e6b3d231f");
    const input_file_sha = try fileSha(paths.input);
    var input = try cairo.adapter.input.readFile(allocator, paths.input);
    const encoded = try cairo.adapter.compact_writer.encode(allocator, &input);
    const input_sha = sha(encoded);
    const witnesses = try cairo.witness.bundle.Bundle.readFile(allocator, paths.witnesses);
    const topology = try cairo.witness.feed_topology.readOfficial(allocator, paths.topology);
    const fixed_source = try cairo.witness.fixed_table_bundle.Bundle.readFile(allocator, paths.fixed);
    const relations = try cairo.witness.relation_bundle.Bundle.readFile(allocator, paths.relations);
    const library = try @import("canonical_eval_aot.zig").loadLibrary(allocator, paths.library);
    var claim = try cairo.claim_generator.deriveFromProverInput(allocator, &input, .{ .preprocessed_variant = @enumFromInt(@intFromEnum(paths.variant)) });
    const variant = try cairo.air.preprocessed_admission.select(allocator, &claim, library, paths.variant, paths.automatic_variant);
    if (variant != paths.variant) {
        claim.deinit();
        claim = try cairo.claim_generator.deriveFromProverInput(allocator, &input, .{ .preprocessed_variant = @enumFromInt(@intFromEnum(variant)) });
    }
    const spec = try cairo.preprocessed.trace.Spec.init(allocator, variant);
    const fixed = try @import("canonical_fixed.zig").project(allocator, fixed_source, spec);
    const logs = try spec.logs(allocator);
    const geometry = try geometry_mod.resolve(allocator, &input, &claim, topology);
    const bundle = try library.instantiate(allocator, &claim, variant, input.builtin_segments);
    const feeds = try feeds_mod.compile(allocator, &input, &claim, geometry, topology, fixed);
    const statement = try cairo.statement_bootstrap.encodeCompactStatementV1(allocator, &bundle, &input);
    const protocol = try @import("canonical_protocol.zig").derive(allocator, bundle, logs);
    var composition_sha = std.crypto.hash.sha2.Sha256.init(.{});
    composition_sha.update(&parametric.source_authority);
    for (bundle.components) |component| composition_sha.update(&identities.componentProgramDigest(parametric.source_authority, component));
    var pp_sha = std.crypto.hash.sha2.Sha256.init(.{});
    for (spec.columns) |column| {
        pp_sha.update(column.identity);
        var word: [4]u8 = undefined;
        std.mem.writeInt(u32, &word, column.log_size, .little);
        pp_sha.update(&word);
    }
    const active = try allocator.alloc(u32, geometry.extents.len);
    for (geometry.extents, active) |extent, *rows| rows.* = extent.active_rows;
    const request = try request_mod.compileCanonicalSource(allocator, .{
        .adapted_input = &input,
        .adapted_input_bytes = encoded.len,
        .adapted_input_identity = input_sha,
        .witnesses = witnesses,
        .multiplicity_feeds = feeds.bundle,
        .fixed_tables = fixed,
        .composition = bundle,
        .relation_templates = relations,
        .compact_statement = statement,
        .preprocessed_logs = logs,
        .pack = .{
            .provenance = .source_derived,
            .manifest = parametric.source_authority,
            .composition_projection = topology.sha256,
            .composition = composition_sha.finalResult(),
            .witness_programs = witness_sha,
            .multiplicity_feeds = feeds.identity,
            .relation_templates = relation_sha,
            .fixed_tables = fixed_sha,
            .preprocessed_coefficients = pp_sha.finalResult(),
            .verifier_max_log_degree_bound = protocol.max_log_degree_bound,
            .composition_plan_hash = bundle.plan_hash,
        },
    }, &claim, active, topology, protocol, target);
    if (request.missing_lowerings.len != 0) return error.IncompleteCanonicalCudaLowering;
    try @import("executor/ingress/writer_preactions.zig").validateGatherGeometry(&request.proof);
    // Detect file mutation across parsing without retaining an extra copy.
    if (!std.mem.eql(u8, &input_file_sha, &try fileSha(paths.input))) return error.CanonicalInputChanged;
    _ = try authenticate(paths.witnesses, "b2108615463b3c7003b07df20e800a42c4c7625344a681ed22e78e57238c90a6");
    _ = try authenticate(paths.fixed, "ed8dd7b470d1837bd2db254f08ee30f3ed180099f8ed78653db008f195713890");
    _ = try authenticate(paths.relations, "2a692328b5e761b7129c82052542ba03221d228089fe1583f2d8043e6b3d231f");
    return .{ .allocator = parent, .arena = arena, .adapted_bytes = encoded, .input = input, .input_file_sha256 = input_file_sha, .input_sha256 = input_sha, .variant = variant, .claim = claim, .geometry = geometry, .composition = bundle, .witnesses = witnesses, .feeds = feeds.bundle, .relations = relations, .fixed = fixed, .statement_bytes = statement, .preprocessed_logs = logs, .protocol = protocol, .request = request };
}

fn sha(bytes: []const u8) [32]u8 {
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &digest, .{});
    return digest;
}

fn fileSha(path: []const u8) ![32]u8 {
    const file = try std.fs.cwd().openFile(path, .{});
    defer file.close();
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    var buffer: [64 * 1024]u8 = undefined;
    while (true) {
        const count = try file.read(&buffer);
        if (count == 0) break;
        hash.update(buffer[0..count]);
    }
    return hash.finalResult();
}

fn authenticate(path: []const u8, expected: []const u8) ![32]u8 {
    const digest = try fileSha(path);
    const encoded = std.fmt.bytesToHex(digest, .lower);
    if (!std.mem.eql(u8, &encoded, expected)) return error.CanonicalSourceAuthorityMismatch;
    return digest;
}

test "canonical CUDA complete source requests prepare controllers locally" {
    for ([_]struct { name: []const u8, variant: cairo.preprocessed.trace.Variant }{
        .{ .name = "all_opcodes", .variant = .canonical_small },
        .{ .name = "all_builtins", .variant = .canonical },
        .{ .name = "all_builtins", .variant = .canonical_small },
    }) |case| {
        const path = try std.fmt.allocPrint(std.testing.allocator, "vectors/cairo/official/{s}.prover_input.json", .{case.name});
        defer std.testing.allocator.free(path);
        var prepared = try prepare(std.testing.allocator, .{ .input = path, .variant = case.variant }, @import("request_compiler/sn2_test_support.zig").target());
        defer prepared.deinit();
        try std.testing.expectEqual(@as(usize, 0), prepared.request.missing_lowerings.len);
        try std.testing.expectEqual(@as(u32, 2), prepared.request.resident.evaluation_codegen_version);
        try std.testing.expectEqual(@as(u32, 70), prepared.protocol.query_count);
        try std.testing.expectEqual(@as(u32, 26), prepared.protocol.query_pow_bits);
        try std.testing.expectEqual(@as(u32, 1), prepared.protocol.fri_fold_step);
        var controllers = try @import("executor/ingress/controller_bundle.zig").Prepared.init(std.testing.allocator, &prepared.request, prepared.protocol, prepared.composition, prepared.preprocessed_logs);
        defer controllers.deinit();
        try std.testing.expect(controllers.evaluation.constants.?.len > 0);
    }
}

test "canonical CUDA SN PIE suite host admission" {
    const directory = std.process.getEnvVarOwned(std.testing.allocator, "STWO_CAIRO_CUDA_LOCAL_INPUT_DIR") catch return error.SkipZigTest;
    defer std.testing.allocator.free(directory);
    for (1..5) |number| {
        const path = try std.fmt.allocPrint(std.testing.allocator, "{s}/sn-pie-{}.cpi", .{ directory, number });
        defer std.testing.allocator.free(path);
        const started = try std.time.Instant.now();
        var prepared = try prepare(std.testing.allocator, .{ .input = path }, @import("request_compiler/sn2_test_support.zig").target());
        defer prepared.deinit();
        var controllers = try @import("executor/ingress/controller_bundle.zig").Prepared.init(std.testing.allocator, &prepared.request, prepared.protocol, prepared.composition, prepared.preprocessed_logs);
        defer controllers.deinit();
        std.debug.print("canonical_host_admission SN_PIE_{} components={} witness_launches={} air_placements={} planned_arena_bytes={} planning_ns={} proof_verified=false\n", .{
            number,                                         prepared.composition.components.len,                 prepared.request.trace_dispatch.entries.len,
            controllers.evaluation.topology.placements.len, controllers.resident.combined_arena.total_words * 4, (try std.time.Instant.now()).since(started),
        });
        if (std.process.hasEnvVarConstant("STWO_CAIRO_CUDA_DUMP_PLAN")) {
            for (prepared.request.resident.slots) |slot| {
                if (slot.words < 1 << 26) continue;
                const placement = try controllers.resident.combined_arena.placement(slot.id);
                std.debug.print("canonical_host_slot SN_PIE_{} kind={s} ordinal={} bytes={} offset={} lifetime={s}..{s}\n", .{
                    number,                     @tagName(slot.kind),      slot.ordinal,                slot.words * 4,
                    placement.offset_words * 4, @tagName(slot.live_from), @tagName(slot.live_through),
                });
            }
            std.debug.print("canonical_host_peak SN_PIE_{} live_bytes={}\n", .{ number, prepared.request.resident.summary.peak_live_words * 4 });
        }
        try std.testing.expectEqual(@as(usize, 0), prepared.request.missing_lowerings.len);
    }
}
