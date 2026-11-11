//! Fresh R7 root-only reception. Native proof bytes are never opened; only
//! pinned source declarations/public cells, bounded shape advice and one root.
const std = @import("std");
const E = @import("stwo_prover_engine");
const Runtime = @import("../pure_p2_op_runtime.zig");
const Receiver = @import("../pure_p2_op_root_receiver.zig");
const Sidecar = @import("../pure_p2_root_sidecar.zig");
const Templates = @import("../pure_p2_gkr_templates_wire.zig");
const Walk = @import("../pure_p2_root_source_walk.zig");
const Views = @import("../pure_p2_root_source_view.zig");
const S = @import("execution_source.zig");
const Topology = @import("execution_topology.zig").Topology;
pub const Limits = struct { proof_bytes: usize = 2 << 20, sidecar_bytes: usize = 64 << 20 };
pub const Verified = struct { members: usize, root_bytes: usize, source_ns: u64, root_verify_ns: u64 };
const Leaves = struct {
    values: []S.Leaf,
    made: usize = 0,
    fn accept(raw: ?*anyopaque, a: std.mem.Allocator, ordinal: usize, view: Views.View) !void {
        const self: *@This() = @ptrCast(@alignCast(raw orelse return error.MissingR7Session));
        if (ordinal != self.made or ordinal >= self.values.len) return error.R7LeafCoverage;
        self.values[self.made] = try S.Leaf.init(a, view);
        const key = try self.values[self.made].key();
        std.debug.print("OP_R7_FRESH_SOURCE ordinal={} format={s} identity={s}\n", .{ ordinal, @tagName(key), std.fmt.bytesToHex(key.identity(), .lower) });
        self.values[self.made].retire();
        self.made += 1;
    }
};
const Context = struct {
    profile: @import("../op_profile.zig").Profile,
    metadata: Receiver.Metadata,
    root: []const u8,
    templates: []const u8,
    verified: ?Verified = null,
    timer: std.time.Timer,
    qualify: bool = false,
    fn receive(raw: ?*anyopaque, a: std.mem.Allocator, source: Runtime.SourceDirectory) !void {
        const self: *@This() = @ptrCast(@alignCast(raw orelse return error.MissingR7Session));
        if (self.verified != null) return error.R7DuplicateReception;
        var plan = try Receiver.prepare(a, .{ .source_suite = source.source_suite, .image = source.image, .output = .{ .address = source.output_address, .bytes = source.output }, .profile = self.profile, .setups = source.setups, .requests = source.requests, .spans = source.metadata.spans, .cpu_keys = source.cpu_keys, .truths = source.truths, .truth_keys = source.truth_keys, .truth_local_keys = source.inventory.truth_local_keys, .miller = source.miller, .expected = source.expected }, self.metadata);
        defer plan.deinit();
        var shapes = try Walk.decodeTemplates(a, source, &plan, self.templates);
        defer shapes.deinit(a);
        const leaves = try a.alloc(S.Leaf, plan.inventory.workers.len);
        var built = Leaves{ .values = leaves };
        defer {
            for (leaves[0..built.made]) |*leaf| leaf.deinit();
            a.free(leaves);
        }
        try Walk.visit(a, source, self.profile, &plan, self.metadata, &shapes, .{ .context = &built, .accept = Leaves.accept });
        var topology = try Topology.init(a, self.profile, plan.inventory.execution, leaves, true);
        defer topology.deinit();
        const source_ns = self.timer.read();
        @import("execution_receiver.zig").verifyPlan(a, &plan, &topology, self.root) catch |err| {
            std.debug.print("OP_R7_ROOT_VERIFY_ERROR {s}\n", .{@errorName(err)});
            return err;
        };
        if (comptime @import("builtin").is_test) if (self.qualify) @import("execution_qualification.zig").run(a, source, self.metadata, &plan, &topology, self.root) catch |err| {
            std.debug.print("OP_R7_ROOT_QUALIFICATION_ERROR {s}\n", .{@errorName(err)});
            return err;
        };
        self.verified = .{ .members = leaves.len, .root_bytes = self.root.len, .source_ns = source_ns, .root_verify_ns = self.timer.read() - source_ns };
        std.debug.print("OP_R7_ROOT_ONLY accepted=true complete=true members={} bytes={} source_ns={} root_verify_ns={} native_PCS_GKR_verified=false security_qualified=false\n", .{ leaves.len, self.root.len, source_ns, self.timer.read() - source_ns });
    }
};
fn validate(a: std.mem.Allocator, limits: Limits) !void {
    if (limits.proof_bytes == 0 or limits.proof_bytes > 2 << 20 or limits.sidecar_bytes == 0 or limits.sidecar_bytes > 64 << 20) return error.R7InputBudget;
    if (!E.host_budget_allocator.SharedHostBudget.isAllocator(a)) return error.R7HostBudgetRequired;
}
pub fn verifyBytes(a: std.mem.Allocator, config: @import("../../rv64_ethereum_request.zig").Config, source_directory: []const u8, profile: @import("../op_profile.zig").Profile, resources: Runtime.Resources, options: Runtime.Options, limits: Limits, root: []const u8, sidecar: []const u8, templates: []const u8) !Verified {
    return verifyBytesMode(a, config, source_directory, profile, resources, options, limits, root, sidecar, templates, false);
}
fn verifyBytesMode(a: std.mem.Allocator, config: @import("../../rv64_ethereum_request.zig").Config, source_directory: []const u8, profile: @import("../op_profile.zig").Profile, resources: Runtime.Resources, options: Runtime.Options, limits: Limits, root: []const u8, sidecar: []const u8, templates: []const u8, qualify: bool) !Verified {
    try validate(a, limits);
    if (root.len == 0 or root.len > limits.proof_bytes or templates.len > Templates.MAX_BYTES) return error.R7InputBudget;
    _ = try Templates.preflight(templates);
    var metadata = try Sidecar.decode(a, sidecar, .{ .bytes = limits.sidecar_bytes });
    defer metadata.deinit(a);
    var context = Context{ .profile = profile, .metadata = metadata.metadata, .root = root, .templates = templates, .timer = try std.time.Timer.start(), .qualify = qualify };
    try Runtime.withSourceDirectoryWithOptions(a, config, source_directory, profile, resources, options, &context, Context.receive);
    return context.verified orelse error.R7Incomplete;
}
pub fn qualifyDirectory(a: std.mem.Allocator, config: @import("../../rv64_ethereum_request.zig").Config, source_directory: []const u8, root_directory: []const u8, profile: @import("../op_profile.zig").Profile, resources: Runtime.Resources, options: Runtime.Options, limits: Limits) !Verified {
    if (!@import("builtin").is_test) return error.R7QualificationOnly;
    return directoryMode(a, config, source_directory, root_directory, profile, resources, options, limits, true);
}
pub fn verifyDirectory(a: std.mem.Allocator, config: @import("../../rv64_ethereum_request.zig").Config, source_directory: []const u8, root_directory: []const u8, profile: @import("../op_profile.zig").Profile, resources: Runtime.Resources, options: Runtime.Options, limits: Limits) !Verified {
    return directoryMode(a, config, source_directory, root_directory, profile, resources, options, limits, false);
}
fn directoryMode(a: std.mem.Allocator, config: @import("../../rv64_ethereum_request.zig").Config, source_directory: []const u8, root_directory: []const u8, profile: @import("../op_profile.zig").Profile, resources: Runtime.Resources, options: Runtime.Options, limits: Limits, qualify: bool) !Verified {
    try validate(a, limits);
    var dir = try std.fs.cwd().openDir(root_directory, .{});
    defer dir.close();
    const root = try dir.readFileAlloc(a, "root.bin", limits.proof_bytes);
    defer a.free(root);
    const sidecar = try dir.readFileAlloc(a, "root-sidecar.bin", limits.sidecar_bytes);
    defer a.free(sidecar);
    const templates = try dir.readFileAlloc(a, "root-gkr-shapes.bin", Templates.MAX_BYTES);
    defer a.free(templates);
    return verifyBytesMode(a, config, source_directory, profile, resources, options, limits, root, sidecar, templates, qualify);
}
