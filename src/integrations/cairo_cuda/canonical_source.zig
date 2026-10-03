//! One source-authenticated Cairo request, without a captured-proof dependency.
const std = @import("std");
const cairo = @import("stwo_cairo_frontend");
const cuda = @import("stwo_cuda_backend");
const geometry_mod = @import("canonical_geometry.zig");
const feeds_mod = @import("canonical_feeds.zig");
const request_mod = @import("request_compiler.zig");
const parametric = @import("parametric_eval.zig");
const identities = @import("identity.zig");

pub const InputTimings = @import("canonical_input.zig").Timings;

pub const Paths = struct {
    input: []const u8,
    expected_input_sha256: ?[32]u8 = null,
    /// When set, prove the pinned circuit leaf protocol under this registry
    /// lane. The variant and memory padding come from the lane, not CLI hints.
    leaf_lane: ?cairo.proving.leaf_lane.Lane = null,
    variant: cairo.preprocessed.trace.Variant = .canonical_small,
    automatic_variant: bool = true,
    library: []const u8 = "vectors/cairo/official/air_template_library_v1.json",
    witnesses: []const u8 = "vectors/cairo/official/witness_programs_v1.bin",
    topology: []const u8 = "vectors/cairo/official/witness_feed_topology_v1.json",
    fixed: []const u8 = "vectors/cairo/cairo_fixed_tables.bin",
    relations: []const u8 = "vectors/cairo/cairo_relation_templates.bin",
};

/// Source-authority artifacts that do not depend on an adapted PIE. A batch
/// retains these authenticated, parsed objects across distinct proofs while
/// each `Prepared` still owns its input, claim, geometry, feeds and request.
pub const Assets = struct {
    allocator: std.mem.Allocator,
    arena: *std.heap.ArenaAllocator,
    witness_path: []const u8,
    fixed_path: []const u8,
    relation_path: []const u8,
    library_path: []const u8,
    topology_path: []const u8,
    witness_sha: [32]u8,
    fixed_sha: [32]u8,
    relation_sha: [32]u8,
    witnesses: cairo.witness.bundle.Bundle,
    topology: cairo.witness.feed_topology.Loaded,
    fixed_source: cairo.witness.fixed_table_bundle.Bundle,
    relations: cairo.witness.relation_bundle.Bundle,
    library: cairo.air.template_library.Library,

    pub fn load(parent: std.mem.Allocator, paths: Paths) !Assets {
        const arena = try parent.create(std.heap.ArenaAllocator);
        errdefer parent.destroy(arena);
        arena.* = std.heap.ArenaAllocator.init(parent);
        errdefer arena.deinit();
        const allocator = arena.allocator();
        const witness_sha = try authenticate(paths.witnesses, "b2108615463b3c7003b07df20e800a42c4c7625344a681ed22e78e57238c90a6");
        const fixed_sha = try authenticate(paths.fixed, "ed8dd7b470d1837bd2db254f08ee30f3ed180099f8ed78653db008f195713890");
        const relation_sha = try authenticate(paths.relations, "2a692328b5e761b7129c82052542ba03221d228089fe1583f2d8043e6b3d231f");
        return .{
            .allocator = parent,
            .arena = arena,
            .witness_path = try allocator.dupe(u8, paths.witnesses),
            .fixed_path = try allocator.dupe(u8, paths.fixed),
            .relation_path = try allocator.dupe(u8, paths.relations),
            .library_path = try allocator.dupe(u8, paths.library),
            .topology_path = try allocator.dupe(u8, paths.topology),
            .witness_sha = witness_sha,
            .fixed_sha = fixed_sha,
            .relation_sha = relation_sha,
            .witnesses = try cairo.witness.bundle.Bundle.readFile(allocator, paths.witnesses),
            .topology = try cairo.witness.feed_topology.readOfficial(allocator, paths.topology),
            .fixed_source = try cairo.witness.fixed_table_bundle.Bundle.readFile(allocator, paths.fixed),
            .relations = try cairo.witness.relation_bundle.Bundle.readFile(allocator, paths.relations),
            .library = try @import("canonical_eval_aot.zig").loadLibrary(allocator, paths.library),
        };
    }

    pub fn deinit(self: *Assets) void {
        self.arena.deinit();
        self.allocator.destroy(self.arena);
        self.* = undefined;
    }

    fn checkPaths(self: *const Assets, paths: Paths) !void {
        if (!std.mem.eql(u8, self.witness_path, paths.witnesses) or
            !std.mem.eql(u8, self.fixed_path, paths.fixed) or
            !std.mem.eql(u8, self.relation_path, paths.relations) or
            !std.mem.eql(u8, self.library_path, paths.library) or
            !std.mem.eql(u8, self.topology_path, paths.topology)) return error.CanonicalAssetPathMismatch;
    }
};

pub const Prepared = struct {
    allocator: std.mem.Allocator,
    arena: *std.heap.ArenaAllocator,
    adapted_bytes: []align(64) u8,
    input: cairo.adapter.ProverInput,
    input_file_sha256: [32]u8,
    input_capture_timings: InputTimings,
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
    return prepareWithAssets(parent, paths, target, null);
}

/// Prepare one dynamic PIE request while borrowing previously authenticated
/// source artifacts. The caller retains `assets` until the proof finishes.
pub fn prepareWithAssets(parent: std.mem.Allocator, paths: Paths, target: cuda.runtime.execution_plan.CompileOptions, assets: ?*const Assets) !Prepared {
    var profile = SourceProfile.init();
    const arena = try parent.create(std.heap.ArenaAllocator);
    errdefer parent.destroy(arena);
    arena.* = std.heap.ArenaAllocator.init(parent);
    errdefer arena.deinit();
    const allocator = arena.allocator();
    if (assets) |shared| try shared.checkPaths(paths);
    const witness_sha = if (assets) |shared| shared.witness_sha else try authenticate(paths.witnesses, "b2108615463b3c7003b07df20e800a42c4c7625344a681ed22e78e57238c90a6");
    const fixed_sha = if (assets) |shared| shared.fixed_sha else try authenticate(paths.fixed, "ed8dd7b470d1837bd2db254f08ee30f3ed180099f8ed78653db008f195713890");
    const relation_sha = if (assets) |shared| shared.relation_sha else try authenticate(paths.relations, "2a692328b5e761b7129c82052542ba03221d228089fe1583f2d8043e6b3d231f");
    profile.mark("asset_authentication");
    const captured = try @import("canonical_input.zig").readExpected(allocator, paths.input, paths.expected_input_sha256);
    var input = captured.input;
    const encoded = captured.encoded;
    const input_file_sha = captured.file_sha256;
    const input_sha = captured.encoded_sha256;
    profile.mark("input_read");
    const witnesses = if (assets) |shared| shared.witnesses else try cairo.witness.bundle.Bundle.readFile(allocator, paths.witnesses);
    const topology = if (assets) |shared| shared.topology else try cairo.witness.feed_topology.readOfficial(allocator, paths.topology);
    const fixed_source = if (assets) |shared| shared.fixed_source else try cairo.witness.fixed_table_bundle.Bundle.readFile(allocator, paths.fixed);
    const relations = if (assets) |shared| shared.relations else try cairo.witness.relation_bundle.Bundle.readFile(allocator, paths.relations);
    const library = if (assets) |shared| shared.library else try @import("canonical_eval_aot.zig").loadLibrary(allocator, paths.library);
    profile.mark("asset_decode");
    const preferred_variant: cairo.preprocessed.trace.Variant = if (paths.leaf_lane) |lane|
        @enumFromInt(@intFromEnum(lane.variant))
    else
        paths.variant;
    const memory_components: ?usize = if (paths.leaf_lane) |lane| lane.memory_id_to_big_components else null;
    var claim = try cairo.claim_generator.deriveFromProverInput(allocator, &input, .{
        .preprocessed_variant = @enumFromInt(@intFromEnum(preferred_variant)),
        .memory_id_to_big_components = memory_components,
    });
    const variant = try cairo.air.preprocessed_admission.select(allocator, &claim, library, preferred_variant, paths.leaf_lane == null and paths.automatic_variant);
    if (variant != preferred_variant) {
        claim.deinit();
        claim = try cairo.claim_generator.deriveFromProverInput(allocator, &input, .{
            .preprocessed_variant = @enumFromInt(@intFromEnum(variant)),
            .memory_id_to_big_components = memory_components,
        });
    }
    profile.mark("claim_and_variant");
    const spec = try cairo.preprocessed.trace.Spec.init(allocator, variant);
    const fixed = try @import("canonical_fixed.zig").project(allocator, fixed_source, spec);
    const logs = try spec.logs(allocator);
    profile.mark("fixed_projection");
    const geometry = try geometry_mod.resolve(allocator, &input, &claim, topology);
    const bundle = try library.instantiate(allocator, &claim, variant, input.builtin_segments);
    profile.mark("geometry_and_air");
    const feeds = try feeds_mod.compile(allocator, &input, &claim, geometry, topology, fixed);
    profile.mark("multiplicity_feeds");
    const statement = try cairo.statement_bootstrap.encodeCompactStatementV1(allocator, &bundle, &input);
    const protocol = if (paths.leaf_lane) |lane|
        try @import("canonical_protocol.zig").deriveLeaf(allocator, bundle, logs, lane)
    else
        try @import("canonical_protocol.zig").derive(allocator, bundle, logs);
    profile.mark("statement_and_protocol");
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
    profile.mark("request_compile");
    if (request.missing_lowerings.len != 0) return error.IncompleteCanonicalCudaLowering;
    try @import("executor/ingress/writer_preactions.zig").validateGatherGeometry(&request.proof);
    // The request binds the owned input capture, not a later read of its path.
    if (assets == null) {
        _ = try authenticate(paths.witnesses, "b2108615463b3c7003b07df20e800a42c4c7625344a681ed22e78e57238c90a6");
        _ = try authenticate(paths.fixed, "ed8dd7b470d1837bd2db254f08ee30f3ed180099f8ed78653db008f195713890");
        _ = try authenticate(paths.relations, "2a692328b5e761b7129c82052542ba03221d228089fe1583f2d8043e6b3d231f");
    }
    profile.mark("final_admission");
    return .{ .allocator = parent, .arena = arena, .adapted_bytes = encoded, .input = input, .input_file_sha256 = input_file_sha, .input_capture_timings = captured.timings, .input_sha256 = input_sha, .variant = variant, .claim = claim, .geometry = geometry, .composition = bundle, .witnesses = witnesses, .feeds = feeds.bundle, .relations = relations, .fixed = fixed, .statement_bytes = statement, .preprocessed_logs = logs, .protocol = protocol, .request = request };
}

const SourceProfile = struct {
    timer: ?std.time.Timer,

    fn init() SourceProfile {
        if (!std.process.hasEnvVarConstant("STWO_CAIRO_SOURCE_STAGE_PROFILE")) return .{ .timer = null };
        return .{ .timer = std.time.Timer.start() catch null };
    }

    fn mark(self: *SourceProfile, name: []const u8) void {
        if (self.timer) |*timer| std.debug.print("cairo-cuda source-stage name={s} elapsed_ns={}\n", .{ name, timer.lap() });
    }
};

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
        try std.testing.expectEqual(@as(u64, 0), prepared.request.resident.summary.decommit_terminal_shortfall_words);
        for (prepared.request.proof_program.fri_layers) |layer|
            try std.testing.expectEqual(layer.evaluation_log_rows, layer.log_rows_per_leaf);
        try std.testing.expectEqual(@as(u32, 2), prepared.request.resident.evaluation_codegen_version);
        try std.testing.expectEqual(@as(u32, 70), prepared.protocol.query_count);
        try std.testing.expectEqual(@as(u32, 26), prepared.protocol.query_pow_bits);
        try std.testing.expectEqual(@as(u32, 1), prepared.protocol.fri_fold_step);
        var controllers = try @import("executor/ingress/controller_bundle.zig").Prepared.init(std.testing.allocator, &prepared.request, prepared.protocol, prepared.composition, prepared.preprocessed_logs);
        defer controllers.deinit();
        try std.testing.expect(controllers.evaluation.constants.?.len > 0);
    }
}

test "canonical CUDA shared authenticated assets preserve the dynamic request" {
    const paths: Paths = .{
        .input = "vectors/cairo/official/all_builtins.prover_input.json",
        .variant = .canonical,
    };
    const target = @import("request_compiler/sn2_test_support.zig").target();
    var assets = try Assets.load(std.testing.allocator, paths);
    defer assets.deinit();
    var fresh = try prepare(std.testing.allocator, paths, target);
    defer fresh.deinit();
    var reused = try prepareWithAssets(std.testing.allocator, paths, target, &assets);
    defer reused.deinit();
    try std.testing.expectEqual(fresh.input_sha256, reused.input_sha256);
    try std.testing.expectEqual(fresh.request.plan.cache_key, reused.request.plan.cache_key);
    try std.testing.expectEqual(fresh.composition.plan_hash, reused.composition.plan_hash);
    try std.testing.expectEqual(fresh.feeds.feeds.len, reused.feeds.feeds.len);
    try std.testing.expectEqual(fresh.protocol.query_count, reused.protocol.query_count);
    try std.testing.expectError(error.CanonicalAssetPathMismatch, prepareWithAssets(
        std.testing.allocator,
        .{ .input = paths.input, .fixed = "another-fixed-file.bin" },
        target,
        &assets,
    ));
}

test "concurrent canonical source preparation borrows immutable authenticated assets" {
    const target = @import("request_compiler/sn2_test_support.zig").target();
    const compact: Paths = .{ .input = "vectors/cairo/official/all_opcodes.prover_input.cpi" };
    const json: Paths = .{ .input = "vectors/cairo/official/all_builtins.prover_input.json" };
    var assets = try Assets.load(std.testing.allocator, compact);
    defer assets.deinit();
    const Worker = struct {
        assets: *const Assets,
        target: cuda.runtime.execution_plan.CompileOptions,
        prepared: ?Prepared = null,
        failure: ?anyerror = null,

        fn run(self: *@This()) void {
            self.prepared = prepareWithAssets(std.heap.smp_allocator, compact, self.target, self.assets) catch |err| {
                self.failure = err;
                return;
            };
        }
    };
    var worker = Worker{ .assets = &assets, .target = target };
    defer if (worker.prepared) |*prepared| prepared.deinit();
    const thread = try std.Thread.spawn(.{}, Worker.run, .{&worker});
    var other = prepareWithAssets(std.heap.smp_allocator, json, target, &assets) catch |err| {
        thread.join();
        return err;
    };
    defer other.deinit();
    thread.join();
    if (worker.failure) |err| return err;
    var ahead = worker.prepared orelse return error.MissingPreparedCairoSource;
    worker.prepared = null;
    defer ahead.deinit();
    var serial = try prepareWithAssets(std.heap.smp_allocator, compact, target, &assets);
    defer serial.deinit();
    try std.testing.expectEqual(serial.input_sha256, ahead.input_sha256);
    try std.testing.expectEqual(serial.request.plan.cache_key, ahead.request.plan.cache_key);
    try std.testing.expectEqual(serial.composition.plan_hash, ahead.composition.plan_hash);
    try std.testing.expectEqual(serial.geometry.extents.len, ahead.geometry.extents.len);
    try std.testing.expectEqual(serial.feeds.feeds.len, ahead.feeds.feeds.len);
    for (serial.feeds.feeds, ahead.feeds.feeds) |expected, actual| {
        try std.testing.expectEqualSlices(u8, expected.producer, actual.producer);
        try std.testing.expectEqualSlices(u32, expected.descriptors, actual.descriptors);
    }
}

test "canonical CUDA circuit leaf prepares lifted M31 source geometry" {
    const params = cairo.proving.leaf_lane.ProverParameters{
        .channel_hash = .blake2s,
        .channel_salt = 0,
        .fri_config = .{
            .pow_bits = 26,
            .log_blowup_factor = 1,
            .log_last_layer_degree_bound = 0,
            .n_queries = 70,
            .fold_step = 1,
        },
        .preprocessed_trace = .canonical,
        .store_polynomials_coefficients = false,
        .include_all_preprocessed_columns = true,
        .opt_n_id_to_big_components = 16,
        .lifting_size_policy = .at_least_preprocessed,
    };
    const lane = try cairo.proving.leaf_lane.Lane.fromParameters(params);
    var prepared = try prepare(std.testing.allocator, .{
        .input = "vectors/cairo/official/all_builtins.prover_input.json",
        .leaf_lane = lane,
    }, @import("request_compiler/sn2_test_support.zig").target());
    defer prepared.deinit();
    try std.testing.expectEqual(.blake2s_m31, prepared.protocol.channel_profile);
    try std.testing.expect(prepared.protocol.include_all_preprocessed_columns);
    try std.testing.expect(prepared.protocol.fri_lifting_log_size != null);
    try std.testing.expectEqual(@as(u32, 1), prepared.protocol.fri_fold_step);
    try std.testing.expectEqual(@as(usize, 0), prepared.request.missing_lowerings.len);
    var bootstrap = try @import("executor/statement_ingress.zig").derive(
        std.testing.allocator,
        prepared.protocol,
        &prepared.composition,
        &prepared.input,
    );
    defer bootstrap.deinit();
    const config_words = bootstrap.words(2).?;
    try std.testing.expectEqualSlices(u32, &.{ 26, 1, 70, 0, 1, 0, 0, 0 }, config_words);
    var controllers = try @import("executor/ingress/controller_bundle.zig").Prepared.init(
        std.testing.allocator,
        &prepared.request,
        prepared.protocol,
        prepared.composition,
        prepared.preprocessed_logs,
    );
    defer controllers.deinit();
    const lifting_log = prepared.protocol.fri_lifting_log_size.?;
    for (prepared.request.proof_program.commitments) |tree|
        try std.testing.expectEqual(lifting_log, tree.evaluation_log_rows);
    for (controllers.main_commit.cohorts) |cohort|
        try std.testing.expectEqual(cohort.trace_log_rows + params.fri_config.log_blowup_factor, cohort.evaluation_log_rows);
    try std.testing.expectEqual(@as(u32, 1) << @intCast(lifting_log), controllers.main_commit.tree_size);
    var quotient_topology = try @import("executor/quotient/topology.zig").derive(
        std.testing.allocator,
        prepared.composition,
        prepared.request.proof_program,
        prepared.protocol,
    );
    defer quotient_topology.deinit();
    const shape = try cairo.witness.resident_geometry.sampleShapeWithPolicy(
        std.testing.allocator,
        prepared.composition,
        .{ prepared.protocol.trace_columns[0], prepared.protocol.trace_columns[1], prepared.protocol.trace_columns[2] },
        true,
    );
    defer cairo.witness.resident_geometry.freeSampleShape(std.testing.allocator, shape);
    var sample_count: usize = 0;
    var periodic_count: usize = 0;
    for (shape) |tree| for (tree) |count| {
        sample_count += count;
        periodic_count += @intFromBool(count == 2);
    };
    try std.testing.expectEqual(sample_count, quotient_topology.sampled_value_count);
    try std.testing.expectEqual(sample_count + periodic_count, quotient_topology.termCount());
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
        try std.testing.expectEqual(@as(u64, 0), prepared.request.resident.summary.decommit_terminal_shortfall_words);
        for (prepared.request.proof_program.fri_layers) |layer|
            try std.testing.expectEqual(layer.evaluation_log_rows, layer.log_rows_per_leaf);
    }
}
