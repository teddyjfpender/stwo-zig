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
pub const Limits = struct { proof_bytes: usize = 2 << 20, sidecar_bytes: usize = 64 << 20 };
pub const Verified = struct { members: usize, root_bytes: usize, source_ns: u64, root_verify_ns: u64, total_ns: u64 };
const Context = struct {
    profile: @import("../op_profile.zig").Profile,
    metadata: Receiver.Metadata,
    templates: []const u8,
    root: []const u8,
    verified: ?Verified = null,
    qualification: bool = false,
    timer: std.time.Timer,
    fn receive(raw: ?*anyopaque, a: std.mem.Allocator, source: Runtime.SourceDirectory) !void {
        const self: *@This() = @ptrCast(@alignCast(raw orelse return error.MissingOpRootSession));
        if (self.verified != null) return error.DuplicateOpRootSourceCallback;
        var plan = try Receiver.prepare(a, .{ .image = source.image, .output = .{ .address = source.output_address, .bytes = source.output }, .profile = self.profile, .setups = source.setups, .requests = source.requests, .spans = source.metadata.spans, .cpu_keys = source.cpu_keys, .truths = source.truths, .truth_keys = source.truth_keys, .truth_local_keys = source.inventory.truth_local_keys, .miller = source.miller, .expected = source.expected }, self.metadata);
        defer plan.deinit();
        var local_count: usize = 0;
        for (source.inventory.truth_local_keys) |key| {
            if (key != null) local_count += 1;
        }
        var templates = try Templates.decode(a, self.templates, source.setups.len + local_count);
        defer templates.deinit(a);
        const leaves = try a.alloc(Topology.SourceLeaf, plan.inventory.workers.len);
        var made: usize = 0;
        defer {
            for (leaves[0..made]) |*leaf| leaf.deinit();
            a.free(leaves);
        }
        for (source.setups, source.requests, source.metadata.spans, source.cpu_keys, templates.shapes[0..source.setups.len], 0..) |setup, request, span, key, shape_advice, i| {
            var arena = std.heap.ArenaAllocator.init(a);
            defer arena.deinit();
            const expected = plan.inventory.workers[i];
            const instances = expected.local_instances orelse return error.MissingOpRootLocalAuthority;
            // Only coefficient-vector lengths vary. Every other dimension is
            // independently derived from this exact trusted instance roster.
            const local = try Gkr.skeleton(arena.allocator(), instances, shape_advice);
            const shape = try @import("../../rv64_recursion/om31_native/cpu_capture.zig").geometryForOp(arena.allocator(), setup, self.profile.config());
            const values = try Skeleton.init(arena.allocator(), &shape);
            const metadata = self.metadata.leaves[i];
            const view = CPU.ShapeView{ .op_span = span, .setup = setup, .request = request, .first = plan.inventory.first_ids[i], .expected = expected, .key = key, .manifest = plan.manifest, .main = metadata.main, .receipt = metadata.receipt orelse return error.MissingOpRootLocalAuthority, .claims = metadata.claims, .child = &local, .shape = &shape, .values = &values };
            leaves[made] = try Topology.SourceLeaf.initCpu(a, view);
            @import("verifier_key.zig").retireProverData(&leaves[made].authority);
            made += 1;
        }
        var template_index = source.setups.len;
        for (source.truths, source.truth_keys, 0..) |truth, key, j| {
            const i = source.setups.len + j;
            var arena = std.heap.ArenaAllocator.init(a);
            defer arena.deinit();
            if (if (source.inventory.truth_local_keys.len == 0) null else source.inventory.truth_local_keys[j]) |local_key| {
                const shapes = try @import("../truth_local_gkr/authority.zig").shapes(truth);
                const instances = @import("../truth_local_gkr/native.zig").instances(shapes);
                const local = try Gkr.Truth.skeleton(arena.allocator(), &instances, templates.shapes[template_index]);
                template_index += 1;
                const shape = try @import("../truth_local_gkr/statement.zig").geometry(arena.allocator(), local_key, truth);
                const values = try Skeleton.init(arena.allocator(), &shape);
                const metadata = self.metadata.leaves[i];
                if (metadata.claims.len != 2) return error.OpRootTruthClaims;
                const view = LocalCatalog.View{ .key = local_key, .truth = truth, .expected = plan.inventory.workers[i], .manifest = plan.manifest, .main = metadata.main, .receipt = metadata.receipt orelse return error.MissingOpRootLocalAuthority, .claims = metadata.claims[0..2].*, .local = &local, .shape = &shape, .values = &values };
                leaves[made] = try Topology.SourceLeaf.initLocalCatalog(a, view);
                @import("verifier_key.zig").retireProverData(&leaves[made].authority);
                made += 1;
                continue;
            }
            const shape = try @import("../pure_p2_truth_statement.zig").geometry(arena.allocator(), key, truth);
            const values = try Skeleton.init(arena.allocator(), &shape);
            const metadata = self.metadata.leaves[i];
            const view = Catalog.View{ .key = key, .truth = truth, .expected = plan.inventory.workers[i], .manifest = plan.manifest, .main = metadata.main, .claims = metadata.claims, .shape = &shape, .values = &values };
            leaves[made] = try Topology.SourceLeaf.initCatalog(a, view);
            @import("verifier_key.zig").retireProverData(&leaves[made].authority);
            made += 1;
        }
        for (source.miller, 0..) |miller, j| {
            const i = source.setups.len + source.truths.len + j;
            var arena = std.heap.ArenaAllocator.init(a);
            defer arena.deinit();
            const shape = try @import("../pure_p2_tower_statement.zig").geometry(arena.allocator(), miller.key);
            const values = try Skeleton.init(arena.allocator(), &shape);
            const metadata = self.metadata.leaves[i];
            if (metadata.claims.len != 4) return error.OpRootTruthClaims;
            const view = Miller.View{ .key = miller.key, .span = miller.span, .expected = plan.inventory.workers[i], .manifest = plan.manifest, .main = metadata.main, .claims = metadata.claims[0..4].*, .shape = &shape, .values = &values };
            leaves[made] = try Topology.SourceLeaf.initMiller(a, view);
            @import("verifier_key.zig").retireProverData(&leaves[made].authority);
            made += 1;
        }
        var topology = try Topology.Topology.initForVerification(a, self.profile, plan.inventory.execution, leaves);
        defer topology.deinit();
        const source_ns = self.timer.read();
        try @import("receiver.zig").verifyPlan(a, &plan, &topology, self.root);
        if (comptime @import("builtin").is_test) {
            if (self.qualification) try @import("qualification.zig").run(a, source, self.metadata, &plan, &topology, self.root);
        }
        self.verified = .{ .members = leaves.len, .root_bytes = self.root.len, .source_ns = source_ns, .root_verify_ns = self.timer.read() - source_ns, .total_ns = self.timer.read() };
        std.debug.print("OP_P2_ROOT_ONLY accepted=true complete=true members={} bytes={} source_ns={} root_verify_ns={} native_PCS_GKR_verified=false security_qualified=false\n", .{ leaves.len, self.root.len, source_ns, self.timer.read() - source_ns });
    }
};
fn validateLimits(limits: Limits) !void {
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
    var context = Context{ .profile = profile, .metadata = metadata.metadata, .root = root, .templates = templates, .timer = try std.time.Timer.start(), .qualification = qualification };
    try Runtime.withSourceDirectoryWithOptions(a, config, source_directory, profile, resources, options, &context, Context.receive);
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
