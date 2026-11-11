//! Native fresh reception -> known mixed leaves -> R7 physical parents.
//! Acceptance is published only after the complete independent native plan
//! and the final root proof agree on every admitted leaf frame.
const std = @import("std");
const E = @import("stwo_prover_engine");
const Runtime = @import("../pure_p2_op_runtime.zig");
const Views = @import("../pure_p2_root_source_view.zig");
const Hooks = @import("../pure_p2_native_source_hooks.zig");
const Receiver = @import("../pure_p2_op_root_receiver.zig");
const Sidecar = @import("../pure_p2_root_sidecar.zig");
const Templates = @import("../pure_p2_gkr_templates_wire.zig");
const S = @import("execution_source.zig");
const Keys = @import("execution_keys.zig");
const Topology = @import("execution_topology.zig").Topology;
const Fold = @import("fold.zig");
const P = @import("outer_proof.zig");
pub const Limits = struct {
    members: usize = 256,
    proof_bytes: usize = 2 << 20,
    sidecar_bytes: usize = 64 << 20,
    artifact_directory: ?[]const u8 = null,
    /// Test/qualification only. Verified against independently compiled source
    /// and the exact native callback's expected frame; never transplanted.
    retained_cpu_leaf: ?[]const u8 = null,
};
pub const Result = struct {
    allocator: std.mem.Allocator,
    proof: []u8,
    sidecar: []u8,
    templates: []u8,
    members: usize,
    reductions: usize,
    retained_leaves: usize,
    total_ns: u64,
    pub fn deinit(self: *@This()) void {
        self.allocator.free(self.proof);
        self.allocator.free(self.sidecar);
        self.allocator.free(self.templates);
        self.* = undefined;
    }
};
const Node = struct {
    key: Keys.Ref,
    verified: Keys.Captured,
    bytes: []u8,
    output: Fold.Digest,
    fn deinit(self: *Node, a: std.mem.Allocator) void {
        self.verified.deinit(a);
        a.free(self.bytes);
        self.* = undefined;
    }
};
const Session = struct {
    allocator: std.mem.Allocator,
    profile: @import("../op_profile.zig").Profile,
    limits: Limits,
    nodes: std.ArrayList(Node) = .empty,
    sources: std.ArrayList(S.Leaf) = .empty,
    metadata: std.ArrayList(Receiver.Leaf) = .empty,
    templates: std.ArrayList([]const u8) = .empty,
    directory: ?std.fs.Dir = null,
    result: ?Result = null,
    retained_leaves: usize = 0,
    produced: usize = 0,
    timer: std.time.Timer,
    fn deinit(self: *Session) void {
        for (self.nodes.items) |*node| node.deinit(self.allocator);
        self.nodes.deinit(self.allocator);
        for (self.sources.items) |*source| source.deinit();
        self.sources.deinit(self.allocator);
        for (self.metadata.items) |leaf| self.allocator.free(leaf.claims);
        self.metadata.deinit(self.allocator);
        for (self.templates.items) |shape| self.allocator.free(shape);
        self.templates.deinit(self.allocator);
        if (self.directory) |*dir| dir.close();
        if (self.result) |*result| result.deinit();
    }
    fn from(raw: ?*anyopaque) !*Session {
        return @ptrCast(@alignCast(raw orelse return error.MissingR7Session));
    }
    fn publish(self: *Session, key: Keys.Ref, output: Fold.Digest, bytes: []const u8, recorder: *E.stage_profile.Recorder, retained: bool) !void {
        if (self.directory) |dir| {
            const write = @import("../../rv64_ethereum_batch_receipt.zig").writeExclusive;
            const name = try std.fmt.allocPrint(self.allocator, "node-{d:0>6}.bin", .{self.produced});
            defer self.allocator.free(name);
            try write(dir, name, bytes);
            var stages = try recorder.snapshot(self.allocator);
            defer stages.deinit(self.allocator);
            const json = try std.json.Stringify.valueAlloc(self.allocator, .{ .schema = "op-r7-pending-node-v2", .identity = std.fmt.bytesToHex(key.identity(), .lower), .format = @tagName(key), .output = output, .retained_verified_leaf = retained, .stages = stages, .complete_execution = false }, .{});
            defer self.allocator.free(json);
            const info = try std.fmt.allocPrint(self.allocator, "node-{d:0>6}.json", .{self.produced});
            defer self.allocator.free(info);
            try write(dir, info, json);
        }
        self.produced += 1;
    }
    fn finishNode(self: *Session, key: Keys.Ref, output: Fold.Digest, bytes: []u8, recorder: *E.stage_profile.Recorder, retained: bool) !Node {
        errdefer self.allocator.free(bytes);
        if (bytes.len > self.limits.proof_bytes) return error.R7ProofBudget;
        var capture = try key.verifyCaptured(self.allocator, &output, bytes);
        errdefer capture.deinit(self.allocator);
        try self.publish(key, output, bytes, recorder, retained);
        return .{ .key = key, .verified = capture, .bytes = bytes, .output = output };
    }
    fn makeLeaf(self: *Session, key: Keys.Ref, pending: Views.Pending) !Node {
        const a = self.allocator;
        var recorder = E.stage_profile.Recorder.initWithOptions(a, "cpu", pending.kind, .{ .capture_tasks = false, .capture_process_usage = true });
        defer recorder.deinit();
        const output = try S.output(a, pending.view);
        if (pending.view == .cpu and pending.ordinal == 0) if (self.limits.retained_cpu_leaf) |path| {
            const bytes = try std.fs.cwd().readFileAlloc(a, path, self.limits.proof_bytes);
            const node = try self.finishNode(key, output, bytes, &recorder, true);
            self.retained_leaves += 1;
            return node;
        };
        const bytes = blk: {
            var owner = try S.build(a, pending.view);
            defer owner.deinit();
            break :blk try key.prove(a, &owner, &output, &recorder);
        };
        return self.finishNode(key, output, bytes, &recorder, false);
    }
    fn accept(raw: ?*anyopaque, a: std.mem.Allocator, pending: Views.Pending) !void {
        const self = try from(raw);
        if (pending.ordinal != self.nodes.items.len or pending.ordinal >= self.limits.members) return error.R7LeafCoverage;
        if (pending.template.bytes != null) try self.templates.ensureUnusedCapacity(a, 1);
        var source = try S.Leaf.init(a, pending.view);
        var installed = false;
        errdefer if (!installed) source.deinit();
        self.sources.appendAssumeCapacity(source);
        installed = true;
        errdefer {
            self.sources.items[self.sources.items.len - 1].deinit();
            self.sources.items.len -= 1;
        }
        const owned = &self.sources.items[self.sources.items.len - 1];
        var node = try self.makeLeaf(try owned.key(), pending);
        errdefer node.deinit(a);
        owned.retire();
        const claims = try a.dupe(@import("stwo_core").fields.om31.OM31, pending.claims);
        errdefer a.free(claims);
        try self.nodes.ensureUnusedCapacity(a, 1);
        try self.metadata.ensureUnusedCapacity(a, 1);
        self.nodes.appendAssumeCapacity(node);
        self.metadata.appendAssumeCapacity(.{ .ordinal = @intCast(pending.ordinal), .main = pending.main, .receipt = pending.receipt, .claims = claims });
        if (pending.template.take()) |bytes| self.templates.appendAssumeCapacity(bytes);
    }
    fn parent(self: *Session, key: Keys.Ref, left: *const Node, right: *const Node) !Node {
        const a = self.allocator;
        const pair = Fold.Source{ .children = .{ .{ .key = left.key, .verified = left.verified.borrow(), .output = left.output }, .{ .key = right.key, .verified = right.verified.borrow(), .output = right.output } } };
        const output = try pair.expectedOutput();
        var recorder = E.stage_profile.Recorder.initWithOptions(a, "cpu", "R7 fold", .{ .capture_tasks = false, .capture_process_usage = true });
        defer recorder.deinit();
        const bytes = blk: {
            var owner = try pair.buildForProving(a);
            defer owner.deinit();
            break :blk try key.prove(a, &owner, &output, &recorder);
        };
        return self.finishNode(key, output, bytes, &recorder, false);
    }
    fn complete(raw: ?*anyopaque, a: std.mem.Allocator, v: Runtime.CompleteVerified) !void {
        const self = try from(raw);
        if (self.result != null or self.nodes.items.len != v.inventory.workers.len) return error.R7LeafCoverage;
        const metadata = Receiver.Metadata{ .execution = v.inventory.execution, .manifest = v.native.manifest.digest, .leaves = self.metadata.items };
        var plan = try Receiver.prepare(a, .{ .source_suite = v.source_suite, .image = v.image, .profile = self.profile, .setups = v.setups, .requests = v.requests, .spans = v.metadata.spans, .cpu_keys = v.cpu_keys, .truths = v.truths, .truth_keys = v.truth_keys, .truth_local_keys = v.inventory.truth_local_keys, .miller = v.miller, .expected = v.expected, .output = .{ .address = v.output_address, .bytes = v.output } }, metadata);
        defer plan.deinit();
        const expected = try plan.expectedLeaves(a);
        defer a.free(expected);
        for (expected, self.nodes.items) |frame, node| if (!std.meta.eql(frame, node.output)) return error.R7LeafFrame;
        var topology = try Topology.init(a, self.profile, plan.inventory.execution, self.sources.items, false);
        defer topology.deinit();
        const members = self.nodes.items.len;
        var reductions: usize = 0;
        while (self.nodes.items.len > 1) {
            var next: std.ArrayList(Node) = .empty;
            errdefer {
                for (next.items) |*node| node.deinit(a);
                next.deinit(a);
            }
            try next.ensureTotalCapacity(a, (self.nodes.items.len + 1) / 2);
            var i: usize = 0;
            while (i + 1 < self.nodes.items.len) : (i += 2) {
                const key = topology.parents.items[reductions];
                next.appendAssumeCapacity(try self.parent(.{ .r7 = key }, &self.nodes.items[i], &self.nodes.items[i + 1]));
                @import("../native_omul/verifier_key.zig").retireProverData(&key.core);
                reductions += 1;
            }
            if (i < self.nodes.items.len) next.appendAssumeCapacity(self.nodes.items[i]);
            for (self.nodes.items[0..i]) |*node| node.deinit(a);
            self.nodes.deinit(a);
            self.nodes = next;
        }
        const root = &self.nodes.items[0];
        try @import("execution_receiver.zig").verifyPlan(a, &plan, &topology, root.bytes);
        const sidecar = try Sidecar.encode(a, metadata, .{ .bytes = self.limits.sidecar_bytes });
        errdefer a.free(sidecar);
        const templates = try Templates.encode(a, self.templates.items);
        errdefer a.free(templates);
        const proof = try a.dupe(u8, root.bytes);
        errdefer a.free(proof);
        if (self.directory) |dir| {
            const write = @import("../../rv64_ethereum_batch_receipt.zig").writeExclusive;
            try write(dir, "root.bin", proof);
            try write(dir, "root-sidecar.bin", sidecar);
            try write(dir, "root-gkr-shapes.bin", templates);
            const json = try std.json.Stringify.valueAlloc(a, .{ .schema = "op-r7-complete-execution-root-v2", .members = members, .reductions = reductions, .retained_verified_leaves = self.retained_leaves, .total_ns = self.timer.read(), .security_qualified = false, .full_fresh_production_latency = self.retained_leaves == 0 }, .{});
            defer a.free(json);
            try write(dir, "root.json", json);
            try std.posix.fsync(dir.fd);
        }
        self.result = .{ .allocator = a, .proof = proof, .sidecar = sidecar, .templates = templates, .members = members, .reductions = reductions, .retained_leaves = self.retained_leaves, .total_ns = self.timer.read() };
        std.debug.print("OP_R7_RECURSIVE_ROOT accepted=true complete=true members={} reductions={} bytes={} retained_leaves={} total_ns={} security_qualified=false\n", .{ members, reductions, proof.len, self.retained_leaves, self.timer.read() });
    }
};
pub fn proveDirectory(a: std.mem.Allocator, config: @import("../../rv64_ethereum_request.zig").Config, native_directory: []const u8, profile: @import("../op_profile.zig").Profile, resources: Runtime.Resources, options: Runtime.Options, limits: Limits) !Result {
    if (limits.members == 0 or limits.members > 256 or limits.proof_bytes == 0 or limits.proof_bytes > 2 << 20 or limits.sidecar_bytes == 0 or limits.sidecar_bytes > 64 << 20) return error.R7InputBudget;
    if (limits.retained_cpu_leaf != null and !@import("builtin").is_test) return error.R7RetainedQualificationOnly;
    var session = Session{ .allocator = a, .profile = profile, .limits = limits, .timer = try std.time.Timer.start() };
    defer session.deinit();
    try session.sources.ensureTotalCapacity(a, limits.members);
    if (limits.artifact_directory) |path| {
        try std.fs.cwd().makeDir(path);
        session.directory = try std.fs.cwd().openDir(path, .{});
    }
    var sink = Views.Sink{ .context = &session, .accept = Session.accept };
    try Runtime.verifyDirectoryWithOptions(a, config, native_directory, profile, resources, options, .{ .context = &session, .complete = Session.complete, .fragments = Hooks.hooks(&sink) });
    const result = session.result orelse return error.R7Incomplete;
    session.result = null;
    return result;
}
