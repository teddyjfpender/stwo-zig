//! Fresh root-only reception. It loads pinned source declarations/public cells,
//! not native-op.bin; reconstructs all source verifier classes from bounded
//! shape advice; checks exactly one final physical root plus global admission.
const std = @import("std");
const Runtime = @import("../pure_p2_op_runtime.zig");
const V = @import("../../rv64_recursion/om31_poseidon/mod.zig");
const C = V.common;
const Topology = @import("topology.zig");
const Receiver = @import("../pure_p2_op_root_receiver.zig");
const Sidecar = @import("../pure_p2_root_sidecar.zig");
const Templates = @import("../pure_p2_gkr_templates_wire.zig");
const Gkr = @import("../pure_p2_gkr_template.zig");
const Skeleton = @import("../pure_p2_trace_skeleton.zig");
const CPU = @import("../pure_p2_cpu_leaf_test.zig");
const Catalog = @import("../pure_p2_truth_leaf_test.zig");
const Miller = @import("../pure_p2_tower_leaf_test.zig");
const LocalCatalog = @import("../truth_local_gkr/leaf_test.zig");
const LocalMiller = @import("../miller_local_gkr/leaf_test.zig");
pub const Limits = struct { proof_bytes: usize = 2 << 20, sidecar_bytes: usize = 64 << 20, miller_cache_bytes: usize = 0 };
pub const CacheReport = struct { classes: usize, hits: usize, misses: usize, peak_requested_bytes: usize, borrowed_leaves: usize, fallbacks: usize };
pub const Verified = struct { members: usize, root_bytes: usize, source_ns: u64, root_verify_ns: u64, total_ns: u64, miller_cache: ?CacheReport = null };
fn cacheCapacityError(err: anyerror) bool {
    return err == error.OutOfMemory or err == error.MillerOuterCacheEntryLimit;
}
const SourceWalk = @import("../pure_p2_root_source_walk.zig");
const Views = @import("../pure_p2_root_source_view.zig");
const SourceLeaves = struct {
    leaves: []Topology.SourceLeaf,
    made: usize = 0,
    cache: ?*@import("../miller_local_gkr/outer_key_cache.zig").Cache,
    fallbacks: *usize,
    cached: *usize,
    fn accept(raw: ?*anyopaque, a: std.mem.Allocator, ordinal: usize, view: Views.View) !void {
        const self: *@This() = @ptrCast(@alignCast(raw orelse return error.MissingOpRootSession));
        if (ordinal != self.made or ordinal >= self.leaves.len) return error.OpRootLeafCoverage;
        self.leaves[self.made] = switch (view) {
            .cpu => |v| try Topology.SourceLeaf.initCpu(a, v),
            .catalog => |v| try Topology.SourceLeaf.initCatalog(a, v),
            .local_catalog => |v| try Topology.SourceLeaf.initLocalCatalog(a, v),
            .miller => |v| try Topology.SourceLeaf.initMiller(a, v),
            .local_miller => |v| if (self.cache) |cache| Topology.SourceLeaf.initLocalMillerCachedForVerification(a, v, cache) catch |err| blk: {
                if (!cacheCapacityError(err)) return err;
                self.fallbacks.* += 1;
                break :blk try Topology.SourceLeaf.initLocalMiller(a, v);
            } else try Topology.SourceLeaf.initLocalMiller(a, v),
        };
        if (self.leaves[self.made].borrowed != null) self.cached.* += 1;
        self.leaves[self.made].retireProverData();
        self.made += 1;
    }
};
const Context = struct {
    profile: @import("../op_profile.zig").Profile,
    metadata: Receiver.Metadata,
    templates: []const u8,
    root: []const u8,
    verified: ?Verified = null,
    qualification: bool = false,
    qualification_miller: bool = false,
    miller_cache_bytes: usize = 0,
    timer: std.time.Timer,
    fn receive(raw: ?*anyopaque, a: std.mem.Allocator, source: Runtime.SourceDirectory) !void {
        const self: *@This() = @ptrCast(@alignCast(raw orelse return error.MissingOpRootSession));
        if (self.verified != null) return error.DuplicateOpRootSourceCallback;
        var plan = try Receiver.prepare(a, .{ .source_suite = source.source_suite, .image = source.image, .output = .{ .address = source.output_address, .bytes = source.output }, .profile = self.profile, .setups = source.setups, .requests = source.requests, .spans = source.metadata.spans, .cpu_keys = source.cpu_keys, .truths = source.truths, .truth_keys = source.truth_keys, .truth_local_keys = source.inventory.truth_local_keys, .miller = source.miller, .expected = source.expected }, self.metadata);
        defer plan.deinit();
        var templates = try SourceWalk.decodeTemplates(a, source, &plan, self.templates);
        defer templates.deinit(a);
        // Declared child cap is charged to the surrounding request budget. A
        // cache allocation refusal is an optimization miss, never new admission.
        var miller_cache: ?@import("../miller_local_gkr/outer_key_cache.zig").Cache = null;
        if (self.miller_cache_bytes != 0) miller_cache = @import("../miller_local_gkr/outer_key_cache.zig").Cache.initForVerification(a, self.miller_cache_bytes, 256) catch |err| switch (err) {
            error.OutOfMemory => null,
            else => return err,
        };
        defer if (miller_cache) |*cache| cache.deinit() catch unreachable;
        var cache_fallbacks: usize = 0;
        var cached_leaves: usize = 0;
        const leaves = try a.alloc(Topology.SourceLeaf, plan.inventory.workers.len);
        var built = SourceLeaves{ .leaves = leaves, .cache = if (miller_cache) |*cache| cache else null, .fallbacks = &cache_fallbacks, .cached = &cached_leaves };
        defer {
            for (leaves[0..built.made]) |*leaf| leaf.deinit();
            a.free(leaves);
        }
        try SourceWalk.visit(a, source, self.profile, &plan, self.metadata, &templates, .{ .context = &built, .accept = SourceLeaves.accept });
        var topology = try Topology.Topology.initForVerification(a, self.profile, plan.inventory.execution, leaves);
        defer topology.deinit();
        const source_ns = self.timer.read();
        try @import("receiver.zig").verifyPlan(a, &plan, &topology, self.root);
        if (comptime @import("builtin").is_test) {
            if (self.qualification) try @import("qualification.zig").run(a, source, self.metadata, &plan, &topology, self.root);
            if (self.qualification_miller) try @import("qualification.zig").runMiller(a, source, self.metadata, &plan, &topology, self.root);
        }
        const cache_report: ?CacheReport = if (miller_cache) |*cache| blk: {
            const snap = cache.snapshot();
            break :blk .{ .classes = snap.classes, .hits = snap.hits, .misses = snap.misses, .peak_requested_bytes = snap.bytes.peak_live_bytes, .borrowed_leaves = cached_leaves, .fallbacks = cache_fallbacks };
        } else null;
        self.verified = .{ .miller_cache = cache_report, .members = leaves.len, .root_bytes = self.root.len, .source_ns = source_ns, .root_verify_ns = self.timer.read() - source_ns, .total_ns = self.timer.read() };
        std.debug.print("OP_P2_ROOT_ONLY accepted=true complete=true members={} bytes={} source_ns={} root_verify_ns={} native_PCS_GKR_verified=false security_qualified=false\n", .{ leaves.len, self.root.len, source_ns, self.timer.read() - source_ns });
    }
};
fn validateLimits(limits: Limits) !void {
    if (limits.miller_cache_bytes > 8 << 30) return error.OpRootInputBudget;
    if (limits.proof_bytes == 0 or limits.proof_bytes > 2 << 20 or limits.sidecar_bytes == 0 or limits.sidecar_bytes > 64 << 20) return error.OpRootInputBudget;
}
pub fn verifyBytes(a: std.mem.Allocator, config: @import("../../rv64_ethereum_request.zig").Config, source_directory: []const u8, profile: @import("../op_profile.zig").Profile, resources: Runtime.Resources, limits: Limits, root: []const u8, sidecar: []const u8, templates: []const u8) !Verified {
    return verifyBytesMode(a, config, source_directory, profile, resources, .{}, limits, root, sidecar, templates, false);
}
pub fn verifyBytesWithOptions(a: std.mem.Allocator, config: @import("../../rv64_ethereum_request.zig").Config, source_directory: []const u8, profile: @import("../op_profile.zig").Profile, resources: Runtime.Resources, options: Runtime.Options, limits: Limits, root: []const u8, sidecar: []const u8, templates: []const u8) !Verified {
    return verifyBytesMode(a, config, source_directory, profile, resources, options, limits, root, sidecar, templates, false);
}
fn verifyBytesMode(a: std.mem.Allocator, config: @import("../../rv64_ethereum_request.zig").Config, source_directory: []const u8, profile: @import("../op_profile.zig").Profile, resources: Runtime.Resources, options: Runtime.Options, limits: Limits, root: []const u8, sidecar: []const u8, templates: []const u8, qualification: bool) !Verified {
    try validateLimits(limits);
    if (root.len == 0 or root.len > limits.proof_bytes or templates.len > Templates.MAX_BYTES) return error.OpRootInputBudget;
    _ = try Templates.preflight(templates);
    var metadata = try Sidecar.decode(a, sidecar, .{ .bytes = limits.sidecar_bytes });
    defer metadata.deinit(a);
    var context = Context{ .profile = profile, .metadata = metadata.metadata, .root = root, .templates = templates, .timer = try std.time.Timer.start(), .qualification = qualification, .miller_cache_bytes = limits.miller_cache_bytes };
    try Runtime.withSourceDirectoryWithOptions(a, config, source_directory, profile, resources, options, &context, Context.receive);
    return context.verified orelse error.OpRootSourceIncomplete;
}
/// Test-only adapter for an independently rebuilt synthetic program image.
/// Reuses the production source-only receiver; never reads native proof bytes.
pub fn verifyFixtureSource(a: std.mem.Allocator, source: Runtime.SourceDirectory, root: []const u8, sidecar: []const u8, templates: []const u8, qualify_miller: bool) !Verified {
    return verifyFixtureSourceWithLimits(a, source, root, sidecar, templates, qualify_miller, .{});
}
pub fn verifyFixtureSourceWithLimits(a: std.mem.Allocator, source: Runtime.SourceDirectory, root: []const u8, sidecar: []const u8, templates: []const u8, qualify_miller: bool, limits: Limits) !Verified {
    if (!@import("builtin").is_test) return error.OpRootFixtureOnly;
    try validateLimits(limits);
    if (root.len == 0 or root.len > limits.proof_bytes or sidecar.len > limits.sidecar_bytes or templates.len > Templates.MAX_BYTES) return error.OpRootInputBudget;
    _ = try Templates.preflight(templates);
    var metadata = try Sidecar.decode(a, sidecar, .{ .bytes = limits.sidecar_bytes });
    defer metadata.deinit(a);
    var context = Context{ .profile = source.metadata.profile, .metadata = metadata.metadata, .root = root, .templates = templates, .timer = try std.time.Timer.start(), .qualification_miller = qualify_miller, .miller_cache_bytes = limits.miller_cache_bytes };
    try Context.receive(&context, a, source);
    return context.verified orelse error.OpRootSourceIncomplete;
}
pub fn verifyDirectory(a: std.mem.Allocator, config: @import("../../rv64_ethereum_request.zig").Config, source_directory: []const u8, root_directory: []const u8, profile: @import("../op_profile.zig").Profile, resources: Runtime.Resources, limits: Limits) !Verified {
    return verifyDirectoryMode(a, config, source_directory, root_directory, profile, resources, .{}, limits, false);
}
pub fn qualifyDirectory(a: std.mem.Allocator, config: @import("../../rv64_ethereum_request.zig").Config, source_directory: []const u8, root_directory: []const u8, profile: @import("../op_profile.zig").Profile, resources: Runtime.Resources, limits: Limits) !Verified {
    if (!@import("builtin").is_test) return error.OpRootQualificationIsTestOnly;
    return verifyDirectoryMode(a, config, source_directory, root_directory, profile, resources, .{}, limits, true);
}
pub fn verifyDirectoryWithOptions(a: std.mem.Allocator, config: @import("../../rv64_ethereum_request.zig").Config, source_directory: []const u8, root_directory: []const u8, profile: @import("../op_profile.zig").Profile, resources: Runtime.Resources, options: Runtime.Options, limits: Limits) !Verified {
    return verifyDirectoryMode(a, config, source_directory, root_directory, profile, resources, options, limits, false);
}
pub fn qualifyDirectoryWithOptions(a: std.mem.Allocator, config: @import("../../rv64_ethereum_request.zig").Config, source_directory: []const u8, root_directory: []const u8, profile: @import("../op_profile.zig").Profile, resources: Runtime.Resources, options: Runtime.Options, limits: Limits) !Verified {
    if (!@import("builtin").is_test) return error.OpRootQualificationIsTestOnly;
    return verifyDirectoryMode(a, config, source_directory, root_directory, profile, resources, options, limits, true);
}
fn verifyDirectoryMode(a: std.mem.Allocator, config: @import("../../rv64_ethereum_request.zig").Config, source_directory: []const u8, root_directory: []const u8, profile: @import("../op_profile.zig").Profile, resources: Runtime.Resources, options: Runtime.Options, limits: Limits, qualification: bool) !Verified {
    try validateLimits(limits);
    var dir = try std.fs.cwd().openDir(root_directory, .{});
    defer dir.close();
    const proof = try dir.readFileAlloc(a, "root.bin", limits.proof_bytes);
    defer a.free(proof);
    const sidecar = try dir.readFileAlloc(a, "root-sidecar.bin", limits.sidecar_bytes);
    defer a.free(sidecar);
    const templates = try dir.readFileAlloc(a, "root-gkr-shapes.bin", Templates.MAX_BYTES);
    defer a.free(templates);
    return verifyBytesMode(a, config, source_directory, profile, resources, options, limits, proof, sidecar, templates, qualification);
}

test "OP pure P2 root reader rejects invalid caps before filesystem access" {
    const Request = @import("../../rv64_ethereum_request.zig");
    const Symbols = @import("stwo_riscv_frontend").rv64.ethereum_contract.Symbols;
    const config = Request.Config{ .elf = "", .input = "", .elf_sha256 = "", .input_sha256 = "", .expected_output = "", .symbols = std.mem.zeroes(Symbols), .output_directory = "", .terminal_pc = 0 };
    try std.testing.expectError(error.OpRootInputBudget, verifyDirectory(std.testing.allocator, config, "missing-source", "missing-root", .op_target_b4_q72_p0_fold4_v1, .{}, .{ .proof_bytes = (2 << 20) + 1 }));
    try std.testing.expectError(error.OpRootInputBudget, verifyDirectory(std.testing.allocator, config, "missing-source", "missing-root", .op_target_b4_q72_p0_fold4_v1, .{}, .{ .sidecar_bytes = (64 << 20) + 1 }));
}

test "R6 Miller verifier cache fallback is restricted to capacity and defaults off" {
    try std.testing.expectEqual(@as(usize, 0), (Limits{}).miller_cache_bytes);
    try std.testing.expect(cacheCapacityError(error.OutOfMemory));
    try std.testing.expect(cacheCapacityError(error.MillerOuterCacheEntryLimit));
    for ([_]anyerror{ error.MillerOuterCacheClassMismatch, error.MillerOuterCacheRequestMismatch, error.MillerOuterCacheVerificationOnly, error.OpRootLeafCapVariant, error.InvalidOpGkrTemplateDegree, error.OpRootLeafSourceAuthority }) |err| try std.testing.expect(!cacheCapacityError(err));
    try std.testing.expectError(error.OpRootInputBudget, validateLimits(.{ .miller_cache_bytes = (8 << 30) + 1 }));
}
