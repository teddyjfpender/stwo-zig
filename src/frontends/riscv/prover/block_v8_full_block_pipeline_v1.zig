//! Complete bounded execution-to-root driver. All wide witnesses are proved
//! once and released. Reduction reloads thin metadata and serialized proofs;
//! it never retains the full set of recursive witnesses or producer keys.
const std = @import("std");
const E = @import("stwo_prover_engine");
const Source = @import("block_v8_endpoint_mixed_execution_v1.zig");
const Mixed = @import("block_v8_endpoint_mixed_pipeline_v1.zig");
const Native = @import("block_v8_endpoint_local_execution_mode_v1.zig").For(true);
const Boundary = @import("block_v8_full_boundary_policy_v1.zig");
const Capture = @import("block_v7_real_window_capture_v1.zig");
const NativeSaved = @import("../recursion/block_v8_window_root_saved_v1.zig");
const MixedSaved = @import("../recursion/block_v8_endpoint_mixed_join_saved_v1.zig");
const Upper = @import("../recursion/block_v8_window_root_receiver_v1.zig");
const Fold = @import("../recursion/block_v8_window_root_fold_v1.zig");
const Profile = @import("../recursion/block_v8_window_root_profile_v1.zig");
const Parent = @import("../recursion/blake3_execution_parent_proof.zig");
const Wire = @import("../recursion/block_v8_window_root_wire_v1.zig");
const AdmissionCache = @import("../recursion/block_v8_window_root_admission_cache_v1.zig");
pub const production_active = false;
pub const Job = struct { kind: enum { native, mixed }, request: Source.Request };
/// Requests borrow immutable snapshots/ELF for the duration of run. Adjacent
/// jobs should share snapshot storage; the driver does not duplicate it.
pub const Input = struct { elf: []const u8, private_input: []const u8, trusted: Boundary.Trusted, jobs: []const Job };
pub const Options = struct {
    native: Native.Options = .{ .cohort_cycles = 1 << 23, .max_cohort_cycles = 1 << 23 },
    mixed: Mixed.Options = .{},
    max_jobs: u32 = 2048,
    max_artifact_bytes: usize = 128 << 20,
    /// Reuse is conditional on fresh proof/key verification, never file presence.
    resume_saved: bool = false,
    /// Opt-in only. Final receiving always rebuilds the complete tree uncached.
    immutable_admission_cache: bool = false,
    admission_cache_limits: AdmissionCache.Limits = .{},
};
pub const Summary = struct {
    schema: []const u8 = "stwo-b8-complete-execution-root-v1",
    proof_verified: bool = false,
    cycles: u64,
    elf_sha256: [32]u8,
    input_sha256: [32]u8,
    expected_output_sha256: [32]u8,
    windows: u32,
    folds: u32 = 0,
    root_bytes: usize = 0,
    root_sha256: [64]u8 = @splat(0),
    initial_policy_id: [32]u8,
    terminal_policy_id: [32]u8,
    preparation_ns: u64 = 0,
    originals_ns: u64 = 0,
    window_roots_ns: u64 = 0,
    folds_ns: u64 = 0,
    final_verification_ns: u64 = 0,
    whole_ns: u64 = 0,
    charged_peak_bytes: usize = 0,
    resumed_windows: u32 = 0,
    resumed_folds: u32 = 0,
    resume_fold_verification_ns: u64 = 0,
    resumed_original_bundles: u32 = 0,
    resume_verification_ns: u64 = 0,
    admission_cache_setup_ns: u64 = 0,
    admission_cache_leaf_verification_ns: u64 = 0,
    admission_cache: ?AdmissionCache.Stats = null,
    fresh_complete_run: bool = true,
    timing_scope: []const u8 = "fresh execution-to-root invocation",
};
pub const Catalog = struct {
    schema: []const u8 = "stwo-b8-root-metadata-catalog-v1",
    window_count: u32,
    root_index: u32,
    nodes: []const Wire.NodeRecord,
    pub fn validate(self: @This(), a: std.mem.Allocator, jobs: []const Job) !void {
        if (!std.mem.eql(u8, self.schema, "stwo-b8-root-metadata-catalog-v1") or jobs.len == 0 or jobs.len > 2048 or self.window_count != jobs.len or self.nodes.len != 2 * jobs.len - 1 or self.root_index >= self.nodes.len or self.root_index + 1 != self.nodes.len) return error.InvalidFullRootCatalog;
        const uses = try a.alloc(u32, self.nodes.len);
        defer a.free(uses);
        @memset(uses, 0);
        for (self.nodes, 0..) |node, i| {
            try node.validate();
            if (node.index != i) return error.InvalidFullRootCatalog;
            if (i < jobs.len) {
                if (node.kind != @intFromEnum(jobs[i].kind)) return error.InvalidFullRootCatalog;
            } else if (node.kind != 2 or node.children.len != 2) return error.InvalidFullRootCatalog;
            for (node.children) |child| uses[child] = try std.math.add(u32, uses[child], 1);
        }
        for (uses, 0..) |count, i| if (count != @as(u32, @intFromBool(i != self.root_index))) return error.ReusedOrOrphanFullRootNode;
    }
};

fn writeJson(a: std.mem.Allocator, dir: std.fs.Dir, name: []const u8, value: anytype) !void {
    const bytes = try std.json.Stringify.valueAlloc(a, value, .{ .whitespace = .indent_2 });
    defer a.free(bytes);
    try dir.writeFile(.{ .sub_path = name, .data = bytes });
}
fn nodeName(buffer: []u8, index: u32, extension: []const u8) ![]const u8 {
    return std.fmt.bufPrint(buffer, "node-{d}.{s}", .{ index, extension });
}
fn exists(directory: std.fs.Dir, name: []const u8) !bool {
    directory.access(name, .{}) catch |err| switch (err) {
        error.FileNotFound => return false,
        else => return err,
    };
    return true;
}
fn archiveFinal(directory: std.fs.Dir) !void {
    if (!try exists(directory, "report.json") and !try exists(directory, "catalog.json") and !try exists(directory, "root.proof")) return;
    var attempt: u32 = 0;
    var buffer: [96]u8 = undefined;
    const path = while (attempt < 1024) : (attempt += 1) {
        const candidate = try std.fmt.bufPrint(&buffer, "previous-final-{d}", .{attempt});
        directory.makeDir(candidate) catch |err| switch (err) {
            error.PathAlreadyExists => continue,
            else => return err,
        };
        break candidate;
    } else return error.FullBlockArchiveLimit;
    for ([_][]const u8{ "report.json", "catalog.json", "root.proof" }) |name| {
        var target_buffer: [128]u8 = undefined;
        const target = try std.fmt.bufPrint(&target_buffer, "{s}/{s}", .{ path, name });
        directory.rename(name, target) catch |err| switch (err) {
            error.FileNotFound => {},
            else => return err,
        };
    }
}
fn external(job: Job, boundary: *const Boundary.Owned) !Upper.External {
    const r = job.request;
    return .{ .elf = r.elf, .incoming = r.incoming, .outgoing = r.outgoing, .trusted = r.trusted_window, .config = r.config, .boundary = try boundary.windowOptions(r.trusted_window.window.skip_cycles, r.trusted_window.window.cycles) };
}
fn validateInputs(input: Input, options: Options) !void {
    if (input.jobs.len == 0 or input.jobs.len > @min(options.max_jobs, 2048) or options.max_artifact_bytes == 0) return error.InvalidFullBlockJobs;
    if (options.immutable_admission_cache) {
        const required_nodes = try std.math.sub(usize, try std.math.mul(usize, input.jobs.len, 2), 1);
        var depth: usize = 0;
        var leaves: usize = 1;
        while (leaves < input.jobs.len) : (depth += 1) leaves *= 2;
        if (required_nodes > options.admission_cache_limits.max_nodes or depth > options.admission_cache_limits.max_depth) return error.UnsupportedFullAdmissionCacheGeometry;
    }
    var cursor: u64 = 0;
    for (input.jobs, 0..) |job, i| {
        const r = job.request;
        const window = r.trusted_window.window;
        if (window.cycles == 0 or window.cycles > 1 << 24 or window.skip_cycles != cursor or !std.meta.eql(r.elf_sha256, input.trusted.elf_sha256) or !std.meta.eql(r.trusted_window.elf_sha256, input.trusted.elf_sha256) or !std.meta.eql(r.config, input.trusted.config)) return error.InvalidFullBlockCoverage;
        if (job.kind == .native) {
            const cohort = @min(options.native.cohort_cycles, options.native.max_cohort_cycles);
            if (cohort == 0 or try std.math.divCeil(u32, window.cycles, cohort) > @min(options.native.max_cohorts, 62)) return error.UnsupportedFullNativeGeometry;
        } else if (window.cycles > options.mixed.source.max_cycles) return error.UnsupportedFullMixedGeometry;
        if (i != 0 and (!std.meta.eql(input.jobs[i - 1].request.trusted_window.outgoing_sha256, r.trusted_window.incoming_sha256) or !std.meta.eql(input.jobs[i - 1].request.outgoing.cpu, r.incoming.cpu))) return error.NonAdjacentFullBlockInputs;
        cursor = try std.math.add(u64, cursor, window.cycles);
    }
    if (cursor != input.trusted.total_cycles) return error.IncompleteFullBlockCoverage;
}

/// Each reconstructed subtree has one explicit temporary allocator lifetime.
/// There are no complete RAM snapshots inside the durable metadata packet.
fn loadTree(t: std.mem.Allocator, directory: std.fs.Dir, records: []const Wire.NodeRecord, index: u32, jobs: []const Job, boundary: *const Boundary.Owned, maximum: usize, depth: usize) anyerror!Upper.Tree {
    if (index >= records.len or depth > 16) return error.InvalidFullRootCatalog;
    const node = records[index];
    try node.validate();
    if (node.kind == 2) {
        const children = try t.alloc(Upper.Tree, node.children.len);
        for (children, node.children) |*child, id| child.* = try loadTree(t, directory, records, id, jobs, boundary, maximum, depth + 1);
        return .{ .branch = .{ .children = children, .main_root = node.main_root } };
    }
    if (index >= jobs.len or node.kind != @intFromEnum(jobs[index].kind)) return error.InvalidFullRootCatalog;
    var buffer: [80]u8 = undefined;
    const bytes = try directory.readFileAlloc(t, try nodeName(&buffer, index, "public"), maximum);
    const ext = try external(jobs[index], boundary);
    if (node.kind == 0) {
        const leaf = try Wire.decodeNativeLeafLeaky(t, bytes, .{ .max_bytes = maximum });
        if (!std.meta.eql(leaf.main_root, node.main_root)) return error.UntrustedFullRootMainCommitment;
        return .{ .leaf = .{ .external = ext, .input = leaf } };
    }
    const leaf = try Wire.decodeMixedLeafLeaky(t, bytes, .{ .max_bytes = maximum });
    if (!std.meta.eql(leaf.main_root, node.main_root)) return error.UntrustedFullRootMainCommitment;
    return .{ .mixed_leaf = .{ .external = ext, .input = leaf.input, .main_root = leaf.main_root, .global_g_repartition = leaf.global_g_repartition } };
}

fn wrapWindow(a: std.mem.Allocator, directory: std.fs.Dir, output: std.fs.Dir, index: u32, job: Job, boundary: *const Boundary.Owned) !Wire.NodeRecord {
    const ext = try external(job, boundary);
    var name: [80]u8 = undefined;
    var main_root: [32]u8 = undefined;
    if (job.kind == .native) {
        var saved = try NativeSaved.produce(a, directory, ext);
        defer saved.deinit();
        const leaf = saved.metadata.leaf.input;
        const metadata = try Wire.encodeNativeLeaf(a, leaf);
        defer a.free(metadata);
        try output.writeFile(.{ .sub_path = try nodeName(&name, index, "public"), .data = metadata });
        try output.writeFile(.{ .sub_path = try nodeName(&name, index, "proof"), .data = saved.root.bytes });
        try writeJson(a, output, try nodeName(&name, index, "recursion.json"), saved.root.stats);
        main_root = leaf.main_root;
    } else {
        var saved = try MixedSaved.produce(a, directory, ext, .{ .source_workers = 1, .global_g_repartition = true });
        defer saved.deinit();
        var fresh = try saved.verify(a, ext);
        defer fresh.deinit();
        main_root = fresh.capture.commitments[1];
        const metadata = try Wire.encodeMixedLeaf(a, .{ .main_root = main_root, .global_g_repartition = true, .input = .{ .root = &.{}, .global_g_repartition = true, .physical_claims = saved.claims, .mixed_metadata = saved.metadata, .global_roots = saved.data.memory_roots, .cohort_policy = saved.data.cohort_policy, .selected_addresses = saved.data.selected_initial_addresses } });
        defer a.free(metadata);
        try output.writeFile(.{ .sub_path = try nodeName(&name, index, "public"), .data = metadata });
        try output.writeFile(.{ .sub_path = try nodeName(&name, index, "proof"), .data = saved.root.bytes });
        try writeJson(a, output, try nodeName(&name, index, "recursion.json"), saved.root.stats);
    }
    return .{ .kind = @intFromEnum(job.kind), .index = index, .children = &.{}, .main_root = main_root };
}

fn receiveSavedWindow(a: std.mem.Allocator, output: std.fs.Dir, index: u32, job: Job, boundary: *const Boundary.Owned, maximum: usize) !?Wire.NodeRecord {
    var name: [80]u8 = undefined;
    const has_metadata = try exists(output, try nodeName(&name, index, "public"));
    const has_proof = try exists(output, try nodeName(&name, index, "proof"));
    if (has_metadata != has_proof) return error.IncompleteSavedWindowRoot;
    if (!has_metadata) return null;
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const t = arena.allocator();
    const bytes = try output.readFileAlloc(t, try nodeName(&name, index, "public"), maximum);
    const ext = try external(job, boundary);
    const tree: Upper.Tree = if (job.kind == .native) .{ .leaf = .{ .external = ext, .input = try Wire.decodeNativeLeafLeaky(t, bytes, .{ .max_bytes = maximum }) } } else blk: {
        const leaf = try Wire.decodeMixedLeafLeaky(t, bytes, .{ .max_bytes = maximum });
        break :blk .{ .mixed_leaf = .{ .external = ext, .input = leaf.input, .main_root = leaf.main_root, .global_g_repartition = leaf.global_g_repartition } };
    };
    const profile = try tree.derive(a);
    defer profile.deinit();
    const window = job.request.trusted_window.window;
    const span = profile.span;
    const initial_id: ?[32]u8 = if (ext.boundary.initial) |first| first.policy_id else null;
    const terminal_id: ?[32]u8 = if (ext.boundary.terminal) |last| last.policy_id else null;
    if (span.first_cycle != window.skip_cycles + 1 or span.cycles != window.cycles or !std.meta.eql(span.elf_sha256, ext.trusted.elf_sha256) or !std.meta.eql(span.config, ext.config) or !std.meta.eql(span.incoming_snapshot_id, ext.trusted.incoming_sha256) or !std.meta.eql(span.outgoing_snapshot_id, ext.trusted.outgoing_sha256) or !std.meta.eql(span.initial_cpu, ext.incoming.cpu) or !std.meta.eql(span.final_cpu, ext.outgoing.cpu) or !std.meta.eql(span.initial_policy_id, initial_id) or !std.meta.eql(span.terminal_policy_id, terminal_id)) return error.UntrustedSavedWindowCoverage;
    const proof = try output.readFileAlloc(t, try nodeName(&name, index, "proof"), maximum);
    var decoded = try Parent.codec.decode(a, proof, &profile.admission);
    var verified = try Parent.verify(&decoded, &profile.admission);
    defer verified.deinit();
    const capture = Profile.Capture.borrow(&verified);
    try profile.requireCapture(&capture);
    return .{ .kind = @intFromEnum(job.kind), .index = index, .children = &.{}, .main_root = verified.capture.commitments[1] };
}

fn foldPair(a: std.mem.Allocator, directory: std.fs.Dir, records: []const Wire.NodeRecord, pair: [2]u32, jobs: []const Job, boundary: *const Boundary.Owned, maximum: usize) ![32]u8 {
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const t = arena.allocator();
    var profiles: [2]*Profile.Owned = undefined;
    var verified: [2]Upper.Verified = undefined;
    var profile_count: usize = 0;
    var verified_count: usize = 0;
    defer for (profiles[0..profile_count]) |profile| profile.deinit();
    defer for (verified[0..verified_count]) |*proof| proof.deinit();
    var captures: [2]Profile.Capture = undefined;
    var pointers: [2]*const Profile.Capture = undefined;
    var name: [80]u8 = undefined;
    for (pair, 0..) |index, i| {
        const tree = try loadTree(t, directory, records, index, jobs, boundary, maximum, 0);
        profiles[i] = try tree.derive(a);
        profile_count += 1;
        const bytes = try directory.readFileAlloc(t, try nodeName(&name, index, "proof"), maximum);
        var decoded = try Parent.codec.decode(a, bytes, &profiles[i].admission);
        verified[i] = try Parent.verify(&decoded, &profiles[i].admission);
        verified_count += 1;
        captures[i] = Profile.Capture.borrow(&verified[i]);
        try profiles[i].requireCapture(&captures[i]);
        pointers[i] = &captures[i];
    }
    var root = try Fold.produce(a, &.{ profiles[0], profiles[1] }, &pointers);
    defer root.deinit();
    try writeJson(a, directory, try nodeName(&name, @intCast(records.len), "proving.json"), root.stats);
    var fresh = try Fold.verify(a, root.bytes, &.{ profiles[0], profiles[1] }, root.span);
    defer fresh.deinit();
    try directory.writeFile(.{ .sub_path = try nodeName(&name, @intCast(records.len), "proof"), .data = root.bytes });
    return fresh.capture.commitments[1];
}

/// File presence produces only a candidate; no verified progress or admission
/// is granted until the independent frozen cache and proof verification below.
fn savedWindowCandidate(a: std.mem.Allocator, directory: std.fs.Dir, index: u32, job: Job, maximum: usize) !?Wire.NodeRecord {
    var name: [80]u8 = undefined;
    const has_metadata = try exists(directory, try nodeName(&name, index, "public"));
    const has_proof = try exists(directory, try nodeName(&name, index, "proof"));
    if (has_metadata != has_proof) return error.IncompleteSavedWindowRoot;
    if (!has_metadata) return null;
    const bytes = try directory.readFileAlloc(a, try nodeName(&name, index, "public"), maximum);
    defer a.free(bytes);
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const main_root = if (job.kind == .native)
        (try Wire.decodeNativeLeafLeaky(arena.allocator(), bytes, .{ .max_bytes = maximum })).main_root
    else
        (try Wire.decodeMixedLeafLeaky(arena.allocator(), bytes, .{ .max_bytes = maximum })).main_root;
    return .{ .kind = @intFromEnum(job.kind), .index = index, .children = &.{}, .main_root = main_root };
}
fn freezeAdmissions(a: std.mem.Allocator, directory: std.fs.Dir, records: []const Wire.NodeRecord, input: Input, boundary: *const Boundary.Owned, options: Options) !*AdmissionCache.Cache {
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const t = arena.allocator();
    const forest = try t.alloc(Upper.Tree, input.jobs.len);
    for (forest, 0..) |*tree, i| tree.* = try loadTree(t, directory, records, @intCast(i), input.jobs, boundary, options.max_artifact_bytes, 0);
    const frozen = try AdmissionCache.Frozen.clone(a, .{ .elf = input.elf, .private_input = input.private_input, .trusted = input.trusted }, forest, options.admission_cache_limits);
    defer frozen.deinit();
    return try AdmissionCache.Cache.create(a, frozen);
}
fn verifyCachedBytes(a: std.mem.Allocator, bytes: []const u8, cache: *const AdmissionCache.Cache, node: AdmissionCache.Node) !Upper.Verified {
    const profile = try cache.profile(node);
    var decoded = try Parent.codec.decode(a, bytes, &profile.admission);
    var verified = try Parent.verify(&decoded, &profile.admission);
    errdefer verified.deinit();
    const capture = Profile.Capture.borrow(&verified);
    try profile.requireCapture(&capture);
    return verified;
}
fn verifyCachedWindow(a: std.mem.Allocator, directory: std.fs.Dir, index: u32, job: Job, boundary: *const Boundary.Owned, cache: *const AdmissionCache.Cache, node: AdmissionCache.Node, maximum: usize) !void {
    const profile = try cache.profile(node);
    const ext = try external(job, boundary);
    const window = job.request.trusted_window.window;
    const span = profile.span;
    const initial_id: ?[32]u8 = if (ext.boundary.initial) |first| first.policy_id else null;
    const terminal_id: ?[32]u8 = if (ext.boundary.terminal) |last| last.policy_id else null;
    if (span.first_cycle != window.skip_cycles + 1 or span.cycles != window.cycles or !std.meta.eql(span.elf_sha256, ext.trusted.elf_sha256) or !std.meta.eql(span.config, ext.config) or !std.meta.eql(span.incoming_snapshot_id, ext.trusted.incoming_sha256) or !std.meta.eql(span.outgoing_snapshot_id, ext.trusted.outgoing_sha256) or !std.meta.eql(span.initial_cpu, ext.incoming.cpu) or !std.meta.eql(span.final_cpu, ext.outgoing.cpu) or !std.meta.eql(span.initial_policy_id, initial_id) or !std.meta.eql(span.terminal_policy_id, terminal_id)) return error.UntrustedSavedWindowCoverage;
    var name: [80]u8 = undefined;
    const bytes = try directory.readFileAlloc(a, try nodeName(&name, index, "proof"), maximum);
    defer a.free(bytes);
    var verified = try verifyCachedBytes(a, bytes, cache, node);
    verified.deinit();
}
const CachedFold = struct { main_root: [32]u8, node: AdmissionCache.Node, resumed: bool = false, verification_ns: u64 = 0 };
const SavedFoldTiming = struct { fold_ns: u64, children: [2]u32, index: u32 };
fn receiveSavedFold(a: std.mem.Allocator, directory: std.fs.Dir, pair: [2]u32, handles: [2]AdmissionCache.Node, cache: *AdmissionCache.Cache, index: u32, maximum: usize) !?CachedFold {
    var timer = try std.time.Timer.start();
    var name: [80]u8 = undefined;
    const has_proof = try exists(directory, try nodeName(&name, index, "proof"));
    const has_timing = try exists(directory, try nodeName(&name, index, "timing.json"));
    const has_proving = try exists(directory, try nodeName(&name, index, "proving.json"));
    if (!has_proof and !has_timing and !has_proving) return null;
    if (!has_proof or !has_timing or !has_proving) return error.IncompleteSavedFoldRoot;
    const timing_bytes = try directory.readFileAlloc(a, try nodeName(&name, index, "timing.json"), @min(maximum, 1 << 20));
    defer a.free(timing_bytes);
    const timing = try std.json.parseFromSlice(SavedFoldTiming, a, timing_bytes, .{});
    defer timing.deinit();
    if (timing.value.index != index or !std.meta.eql(timing.value.children, pair)) return error.UntrustedSavedFoldRoster;
    const proving_bytes = try directory.readFileAlloc(a, try nodeName(&name, index, "proving.json"), @min(maximum, 1 << 20));
    defer a.free(proving_bytes);
    const proving = try std.json.parseFromSlice(Fold.Stats, a, proving_bytes, .{});
    defer proving.deinit();
    const bytes = try directory.readFileAlloc(a, try nodeName(&name, index, "proof"), maximum);
    defer a.free(bytes);
    const temporary = try cache.deriveUnboundFoldForVerification(&handles);
    var temporary_live = true;
    defer if (temporary_live) temporary.deinit();
    const expected_id = temporary.admission.expected_id;
    const public_id = temporary.admission.public_id;
    const admission_seal = temporary.admission.seal;
    const fixed_root = temporary.fixed_root;
    // Own MAIN enters Profile.fromCompiled only after key/admission derivation.
    // We verify the bytes under this independently derived admission, not under
    // any header-supplied expected key or previous successful receiving receipt.
    var decoded = try Parent.codec.decode(a, bytes, &temporary.admission);
    var verified = try Parent.verify(&decoded, &temporary.admission);
    defer verified.deinit();
    const main_root = verified.capture.commitments[1];
    temporary.deinit();
    temporary_live = false;
    const node = try cache.appendFold(&handles, main_root);
    const final_profile = try cache.profile(node);
    // Fail closed if a future factory ever makes its own MAIN affect admission.
    if (!std.meta.eql(expected_id, final_profile.admission.expected_id) or !std.meta.eql(public_id, final_profile.admission.public_id) or !std.meta.eql(admission_seal, final_profile.admission.seal) or !std.meta.eql(fixed_root, final_profile.fixed_root)) return error.UntrustedSavedFoldAdmission;
    const capture = Profile.Capture.borrow(&verified);
    try final_profile.requireCapture(&capture);
    return .{ .main_root = main_root, .node = node, .resumed = true, .verification_ns = timer.read() };
}
fn foldPairCached(a: std.mem.Allocator, directory: std.fs.Dir, pair: [2]u32, nodes: []const AdmissionCache.Node, cache: *AdmissionCache.Cache, next_index: u32, maximum: usize, resume_saved: bool) !CachedFold {
    var profiles: [2]*const Profile.Owned = undefined;
    var verified: [2]Upper.Verified = undefined;
    var verified_count: usize = 0;
    defer for (verified[0..verified_count]) |*proof| proof.deinit();
    var captures: [2]Profile.Capture = undefined;
    var pointers: [2]*const Profile.Capture = undefined;
    var handles: [2]AdmissionCache.Node = undefined;
    var name: [80]u8 = undefined;
    for (pair, 0..) |index, i| {
        if (index >= nodes.len) return error.InvalidFullRootCatalog;
        handles[i] = nodes[index];
        profiles[i] = try cache.profile(handles[i]);
    }
    if (resume_saved) if (try receiveSavedFold(a, directory, pair, handles, cache, next_index, maximum)) |saved| return saved;
    for (pair, 0..) |index, i| {
        const bytes = try directory.readFileAlloc(a, try nodeName(&name, index, "proof"), maximum);
        defer a.free(bytes);
        verified[i] = try verifyCachedBytes(a, bytes, cache, handles[i]);
        verified_count += 1;
        captures[i] = Profile.Capture.borrow(&verified[i]);
        pointers[i] = &captures[i];
    }
    var root = try Fold.produce(a, &profiles, &pointers);
    defer root.deinit();
    const node = try cache.appendFold(&handles, root.main_root);
    // The producer's MAIN root is only a nomination. This independently
    // derived admission must verify the proof and bind both commitments.
    var fresh = try verifyCachedBytes(a, root.bytes, cache, node);
    defer fresh.deinit();
    try writeJson(a, directory, try nodeName(&name, next_index, "proving.json"), root.stats);
    try directory.writeFile(.{ .sub_path = try nodeName(&name, next_index, "proof"), .data = root.bytes });
    return .{ .main_root = fresh.capture.commitments[1], .node = node };
}

pub fn run(budget: *E.host_budget_allocator.SharedHostBudget, pool: *E.work_pool.WorkPool, output: std.fs.Dir, input: Input, options: Options) !Summary {
    try validateInputs(input, options);
    var iterator = output.iterate();
    if (try iterator.next() != null and !options.resume_saved) return error.NonemptyFullBlockOutput;
    const a = budget.allocator();
    var whole = try std.time.Timer.start();
    var phase = try std.time.Timer.start();
    var boundary = try Boundary.Owned.derive(a, input.elf, input.private_input, input.trusted, .{});
    defer boundary.deinit();
    try boundary.requireInitial(input.jobs[0].request.incoming, 1);
    if (options.resume_saved) try archiveFinal(output);
    var summary = Summary{ .cycles = input.trusted.total_cycles, .elf_sha256 = input.trusted.elf_sha256, .input_sha256 = input.trusted.input_sha256, .expected_output_sha256 = Capture.sha(&input.trusted.expected_output), .windows = @intCast(input.jobs.len), .initial_policy_id = boundary.initial_policy.policy_id, .terminal_policy_id = boundary.terminal_policy.policy_id, .preparation_ns = phase.lap() };
    var public_arena = std.heap.ArenaAllocator.init(a);
    defer public_arena.deinit();
    const public = public_arena.allocator();
    var records: std.ArrayList(Wire.NodeRecord) = .empty;
    defer records.deinit(a);
    var frontier: std.ArrayList(u32) = .empty;
    defer frontier.deinit(a);
    var following: std.ArrayList(u32) = .empty;
    defer following.deinit(a);
    var admission_cache: ?*AdmissionCache.Cache = null;
    defer if (admission_cache) |cache| cache.deinit();
    var cached_nodes: std.ArrayList(AdmissionCache.Node) = .empty;
    defer cached_nodes.deinit(a);
    const saved_candidates: []bool = if (options.immutable_admission_cache) try a.alloc(bool, input.jobs.len) else &.{};
    defer if (options.immutable_admission_cache) a.free(saved_candidates);
    @memset(saved_candidates, false);
    for (input.jobs, 0..) |job, i| {
        phase.reset();
        if (options.resume_saved) {
            var binding = try E.work_pool.ScopedPoolBinding.init(pool);
            defer binding.deinit();
            const saved = if (options.immutable_admission_cache)
                try savedWindowCandidate(a, output, @intCast(i), job, options.max_artifact_bytes)
            else
                try receiveSavedWindow(a, output, @intCast(i), job, &boundary, options.max_artifact_bytes);
            if (saved) |record| {
                try records.append(a, record);
                try frontier.append(a, @intCast(i));
                if (options.immutable_admission_cache) saved_candidates[i] = true else summary.resumed_windows += 1;
                summary.resume_verification_ns += phase.lap();
                summary.fresh_complete_run = false;
                summary.timing_scope = "resume invocation; previously completed proving excluded";
                try writeJson(a, output, "progress.json", .{ .phase = if (options.immutable_admission_cache) "unverified_saved_window_candidates" else "reverified_window_roots", .completed = i + 1, .required = input.jobs.len, .proof_verified = false, .summary = summary });
                continue;
            }
        }
        var name: [80]u8 = undefined;
        const path = try std.fmt.bufPrint(&name, "window-{d}", .{i});
        var retained_originals = false;
        output.makeDir(path) catch |err| switch (err) {
            error.PathAlreadyExists => {
                if (!options.resume_saved) return err;
                retained_originals = true;
            },
            else => return err,
        };
        var directory = try output.openDir(path, .{ .iterate = true });
        defer directory.close();
        phase.reset();
        const ports = try boundary.windowOptions(job.request.trusted_window.window.skip_cycles, job.request.trusted_window.window.cycles);
        if (retained_originals) {
            // wrapWindow must freshly verify every saved original. A partial
            // directory fails closed; it is never repaired by mixing attempts.
            summary.resumed_original_bundles += 1;
            summary.fresh_complete_run = false;
            summary.timing_scope = "resume invocation; previously completed proving excluded";
        } else if (job.kind == .native) {
            var config = options.native;
            config.boundary = ports;
            config.program_flavor = .sparse_elf;
            config.native_profile = .direct_ram_clock_v3_wide;
            config.cohort_cycles = @min(@min(config.cohort_cycles, config.max_cohort_cycles), job.request.trusted_window.window.cycles);
            config.max_cohort_cycles = config.cohort_cycles;
            config.bundle.max_cohort_cycles = config.cohort_cycles;
            const result = try Native.run(budget, pool, directory, job.request, config);
            defer result.deinit();
            try writeJson(a, output, try std.fmt.bufPrint(&name, "window-{d}-original.json", .{i}), result.stats);
        } else {
            var config = options.mixed;
            config.source.boundary = ports;
            config.source.native_wide_shards = true;
            config.source.max_cycles = job.request.trusted_window.window.cycles;
            config.receiver.bundle.max_cohort_cycles = config.source.max_cycles;
            var binding = try E.work_pool.ScopedPoolBinding.init(pool);
            defer binding.deinit();
            const result = try Mixed.produceDirectory(a, job.request, directory, config);
            try writeJson(a, output, try std.fmt.bufPrint(&name, "window-{d}-original.json", .{i}), result.stats);
        }
        summary.originals_ns += phase.lap();
        var binding = try E.work_pool.ScopedPoolBinding.init(pool);
        defer binding.deinit();
        const record = try wrapWindow(a, directory, output, @intCast(i), job, &boundary);
        summary.window_roots_ns += phase.lap();
        try records.append(a, record);
        try frontier.append(a, @intCast(i));
        try writeJson(a, output, "progress.json", .{ .phase = "window_roots", .completed = i + 1, .required = input.jobs.len, .proof_verified = false, .summary = summary });
    }
    if (options.immutable_admission_cache) {
        phase.reset();
        var binding = try E.work_pool.ScopedPoolBinding.init(pool);
        defer binding.deinit();
        admission_cache = try freezeAdmissions(a, output, records.items, input, &boundary, options);
        summary.admission_cache_setup_ns = phase.lap();
        // No saved candidate is counted as resumed until proof/capture checks
        // succeed against its independently derived, frozen-context admission.
        for (input.jobs, 0..) |job, i| {
            const node = try admission_cache.?.root(i);
            try verifyCachedWindow(a, output, @intCast(i), job, &boundary, admission_cache.?, node, options.max_artifact_bytes);
            try cached_nodes.append(a, node);
            const elapsed = phase.lap();
            summary.admission_cache_leaf_verification_ns += elapsed;
            if (saved_candidates[i]) {
                summary.resumed_windows += 1;
                summary.resume_verification_ns += elapsed;
            }
        }
        summary.admission_cache = admission_cache.?.stats();
        try writeJson(a, output, "progress.json", .{ .phase = "cache_reverified_window_roots", .completed = input.jobs.len, .required = input.jobs.len, .proof_verified = false, .summary = summary });
    }
    while (frontier.items.len > 1) {
        following.clearRetainingCapacity();
        var i: usize = 0;
        while (i < frontier.items.len) : (i += 2) {
            if (i + 1 == frontier.items.len) {
                try following.append(a, frontier.items[i]);
                continue;
            }
            phase.reset();
            const pair = [2]u32{ frontier.items[i], frontier.items[i + 1] };
            var binding = try E.work_pool.ScopedPoolBinding.init(pool);
            defer binding.deinit();
            const index: u32 = @intCast(records.items.len);
            var resumed_fold = false;
            const main_root = if (admission_cache) |cache| blk: {
                const folded = try foldPairCached(a, output, pair, cached_nodes.items, cache, index, options.max_artifact_bytes, options.resume_saved);
                resumed_fold = folded.resumed;
                if (folded.resumed) {
                    summary.resumed_folds += 1;
                    summary.resume_fold_verification_ns += folded.verification_ns;
                    summary.fresh_complete_run = false;
                    summary.timing_scope = "resume invocation; previously completed proving excluded";
                }
                try cached_nodes.append(a, folded.node);
                summary.admission_cache = cache.stats();
                break :blk folded.main_root;
            } else try foldPair(a, output, records.items, pair, input.jobs, &boundary, options.max_artifact_bytes);
            try records.append(a, .{ .kind = 2, .index = index, .children = try public.dupe(u32, &pair), .main_root = main_root });
            try following.append(a, index);
            summary.folds += 1;
            const elapsed = phase.lap();
            summary.folds_ns += elapsed;
            var name: [80]u8 = undefined;
            if (resumed_fold) {
                // Preserve the historical proof/proving/timing files verbatim.
                try writeJson(a, output, try nodeName(&name, index, "resume.json"), .{ .verification_ns = elapsed, .children = pair, .index = index, .prior_proving_excluded = true });
            } else try writeJson(a, output, try nodeName(&name, index, "timing.json"), .{ .fold_ns = elapsed, .children = pair, .index = index });
            try writeJson(a, output, "progress.json", .{ .phase = "folds", .completed = summary.folds, .required = input.jobs.len - 1, .proof_verified = false, .summary = summary });
        }
        std.mem.swap(std.ArrayList(u32), &frontier, &following);
    }
    const catalog = Catalog{ .window_count = @intCast(input.jobs.len), .root_index = frontier.items[0], .nodes = records.items };
    try catalog.validate(a, input.jobs);
    try writeJson(a, output, "catalog.json", catalog);
    // Drop every cached profile and owned frozen input before fresh receiving.
    if (admission_cache) |cache| {
        summary.admission_cache = cache.stats();
        cache.deinit();
        admission_cache = null;
    }
    // The final receiver uses serialized catalog/root bytes and a newly derived
    // full policy. All window/fold captures, profiles and producer keys are gone.
    phase.reset();
    const catalog_bytes = try output.readFileAlloc(a, "catalog.json", 16 << 20);
    defer a.free(catalog_bytes);
    var fresh_arena = std.heap.ArenaAllocator.init(a);
    defer fresh_arena.deinit();
    const fresh_catalog = try std.json.parseFromSliceLeaky(Catalog, fresh_arena.allocator(), catalog_bytes, .{});
    try fresh_catalog.validate(a, input.jobs);
    var fresh_boundary = try Boundary.Owned.derive(a, input.elf, input.private_input, input.trusted, .{});
    defer fresh_boundary.deinit();
    const tree = try loadTree(fresh_arena.allocator(), output, fresh_catalog.nodes, fresh_catalog.root_index, input.jobs, &fresh_boundary, options.max_artifact_bytes, 0);
    var name: [80]u8 = undefined;
    const root = try output.readFileAlloc(a, try nodeName(&name, fresh_catalog.root_index, "proof"), options.max_artifact_bytes);
    defer a.free(root);
    var binding = try E.work_pool.ScopedPoolBinding.init(pool);
    defer binding.deinit();
    var verified = try Upper.verifyFull(a, root, tree, &fresh_boundary);
    defer verified.deinit();
    summary.final_verification_ns = phase.lap();
    try output.writeFile(.{ .sub_path = "root.proof", .data = root });
    summary.root_bytes = root.len;
    summary.root_sha256 = std.fmt.bytesToHex(Capture.sha(root), .lower);
    summary.proof_verified = true;
    summary.whole_ns = whole.read();
    summary.charged_peak_bytes = budget.snapshot().peak_live_bytes;
    try writeJson(a, output, "report.json", summary);
    return summary;
}
