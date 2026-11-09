//! Bounded sequential reference: freshly verified native OP fragments -> actual
//! source-owned algebraic leaves -> canonical physical fold tree -> independent
//! execution receiver. No fragment callback can accept a complete execution.
const std = @import("std");
const Core = @import("stwo_core");
const V = @import("../../rv64_recursion/om31_poseidon/mod.zig");
const C = V.common;
const Runtime = @import("../pure_p2_op_runtime.zig");
const Bundle = @import("../pure_p2_op_bundle.zig");
const CPU = @import("../pure_p2_cpu_leaf_test.zig");
const Catalog = @import("../pure_p2_truth_leaf_test.zig");
const Miller = @import("../pure_p2_tower_leaf_test.zig");
const LocalCatalog = @import("../truth_local_gkr/leaf_test.zig");
const Protocol = @import("../pure_p2_worker_protocol.zig");
const Authority = @import("authority.zig").Key;
const Proof = @import("proof.zig");
const Fold = @import("fold.zig");
const Topology = @import("topology.zig");
const GkrTemplate = @import("../pure_p2_gkr_template.zig");
const TemplateWire = @import("../pure_p2_gkr_templates_wire.zig");
const Sidecar = @import("../pure_p2_root_sidecar.zig");
const Receiver = @import("../pure_p2_op_root_receiver.zig");
const Node = struct {
    /// Borrowed from source_leaves or the independently rebuilt Topology.
    key: *const Authority,
    verified: Proof.Captured,
    encoded: []u8,
    output: Fold.Digest,
    fn deinit(self: *Node, a: std.mem.Allocator) void {
        self.verified.deinit(a);
        a.free(self.encoded);
        self.* = undefined;
    }
};
const CpuSource = struct {
    view: CPU.ShapeView,
    pub fn sourceLeaf(self: @This(), a: std.mem.Allocator) !Topology.SourceLeaf {
        return Topology.SourceLeaf.initCpu(a, self.view);
    }
    pub fn buildForProving(self: @This(), a: std.mem.Allocator) !C.PoseidonContext {
        var scope = @import("scope.zig").begin();
        defer scope.deinit();
        return self.view.buildForProving(a);
    }
    pub fn trace(self: @This(), a: std.mem.Allocator) !C.PoseidonContext {
        return self.view.build(a, true, null);
    }
    pub fn expectedOutput(self: @This(), a: std.mem.Allocator) !Fold.Digest {
        return self.view.expectedOutput(a);
    }
};
fn ViewSource(comptime View: type) type {
    return struct {
        view: View,
        pub fn sourceLeaf(self: @This(), a: std.mem.Allocator) !Topology.SourceLeaf {
            return if (View == Catalog.View) Topology.SourceLeaf.initCatalog(a, self.view) else if (View == LocalCatalog.View) Topology.SourceLeaf.initLocalCatalog(a, self.view) else Topology.SourceLeaf.initMiller(a, self.view);
        }
        pub fn buildForProving(self: @This(), a: std.mem.Allocator) !C.PoseidonContext {
            var scope = @import("scope.zig").begin();
            defer scope.deinit();
            return self.view.buildForProving(a);
        }
        pub fn trace(self: @This(), a: std.mem.Allocator) !C.PoseidonContext {
            return self.view.build(a, true);
        }
        pub fn expectedOutput(self: @This(), a: std.mem.Allocator) !Fold.Digest {
            return self.view.expectedOutput(a);
        }
    };
}
const FoldSource = struct {
    view: Fold.Source,
    pub fn buildForProving(self: @This(), a: std.mem.Allocator) !C.PoseidonContext {
        var scope = @import("scope.zig").begin();
        defer scope.deinit();
        return self.view.buildForProving(a);
    }
    pub fn trace(self: @This(), a: std.mem.Allocator) !C.PoseidonContext {
        return (Fold.TraceSource{ .keys = .{ self.view.children[0].key, self.view.children[1].key } }).build(a);
    }
    pub fn expectedOutput(self: @This(), _: std.mem.Allocator) !Fold.Digest {
        return self.view.expectedOutput();
    }
};
pub const Limits = struct { members: usize = 256, proof_bytes: usize = 2 << 20, sidecar_bytes: usize = 64 << 20, artifact_directory: ?[]const u8 = null };
pub const Result = struct {
    allocator: std.mem.Allocator,
    proof: []u8,
    root: Fold.Digest,
    sidecar: []u8,
    templates: []u8,
    members: usize,
    reductions: usize,
    total_ns: u64,
    pub fn deinit(self: *Result) void {
        self.allocator.free(self.proof);
        self.allocator.free(self.sidecar);
        self.allocator.free(self.templates);
        self.* = undefined;
    }
};
const Session = struct {
    allocator: std.mem.Allocator,
    profile: Protocol.Profile,
    limits: Limits,
    nodes: std.ArrayList(Node) = .empty,
    leaves: std.ArrayList(Receiver.Leaf) = .empty,
    claims: std.ArrayList([]C.O) = .empty,
    source_leaves: std.ArrayList(Topology.SourceLeaf) = .empty,
    templates: std.ArrayList([]const u8) = .empty,
    result: ?Result = null,
    started: std.time.Timer,
    directory: ?std.fs.Dir = null,
    produced_nodes: usize = 0,
    fn deinit(self: *Session) void {
        if (self.directory) |*dir| dir.close();
        for (self.nodes.items) |*node| node.deinit(self.allocator);
        for (self.templates.items) |shape| self.allocator.free(shape);
        self.templates.deinit(self.allocator);
        for (self.source_leaves.items) |*source| source.deinit();
        self.source_leaves.deinit(self.allocator);
        for (self.claims.items) |claims| self.allocator.free(claims);
        self.nodes.deinit(self.allocator);
        self.leaves.deinit(self.allocator);
        self.claims.deinit(self.allocator);
        if (self.result) |*result| result.deinit();
    }
    fn from(context: ?*anyopaque) !*Session {
        return @ptrCast(@alignCast(context orelse return error.MissingOpRecursionSession));
    }
    fn prove(self: *Session, source: anytype, kind: []const u8, key: *const Authority) !Node {
        const a = self.allocator;
        var timer = try std.time.Timer.start();
        var owner = try source.buildForProving(a);
        var live = true;
        defer if (live) owner.deinit();
        const output = try source.expectedOutput(a);
        // Immutable setup was independently built once from the trace-only
        // source compiler, separate from this request's actual assignment.
        var recorder = @import("stwo_prover_engine").stage_profile.Recorder.initWithOptions(a, "cpu", kind, .{ .capture_tasks = false, .capture_process_usage = true });
        defer recorder.deinit();
        const encoded = try Proof.proveProfiled(a, &owner, key, &output, &recorder);
        errdefer a.free(encoded);
        if (encoded.len > self.limits.proof_bytes) return error.OpRecursiveProofBudget;
        owner.deinit();
        live = false;
        const prove_ns = timer.lap();
        var verified = try Proof.verifyCaptured(a, key, &output, encoded);
        errdefer verified.deinit(a);
        std.debug.print("OP_P2_RECURSIVE_NODE kind={s} bytes={} source_prove_ns={} native_receive_ns={}\n", .{ kind, encoded.len, prove_ns, timer.lap() });
        if (self.directory) |dir| {
            const write = @import("../../rv64_ethereum_batch_receipt.zig").writeExclusive;
            const name = try std.fmt.allocPrint(a, "node-{d:0>6}.bin", .{self.produced_nodes});
            defer a.free(name);
            try write(dir, name, encoded);
            var output_words: [9]u32 = undefined;
            for (output, &output_words) |value, *word| {
                const fields = value.toM31Array();
                for (fields[1..]) |extra| if (!extra.isZero()) return error.NonBaseFoldDigest;
                word.* = fields[0].v;
            }
            var sha: [32]u8 = undefined;
            std.crypto.hash.sha2.Sha256.hash(encoded, &sha, .{});
            const record = try std.json.Stringify.valueAlloc(a, .{ .schema = "op-p2-r6-pending-node/v1", .kind = kind, .ordinal = self.produced_nodes, .source_identity = std.fmt.bytesToHex(key.base.identity, .lower), .profile = self.profile, .output = output_words, .proof_sha256 = std.fmt.bytesToHex(sha, .lower), .complete_execution = false }, .{});
            defer a.free(record);
            const record_name = try std.fmt.allocPrint(a, "node-{d:0>6}.json", .{self.produced_nodes});
            defer a.free(record_name);
            try write(dir, record_name, record);
            var stages = try recorder.snapshot(a);
            defer stages.deinit(a);
            const stage_json = try std.json.Stringify.valueAlloc(a, stages, .{});
            defer a.free(stage_json);
            const stage_name = try std.fmt.allocPrint(a, "node-{d:0>6}.stages.json", .{self.produced_nodes});
            defer a.free(stage_name);
            try write(dir, stage_name, stage_json);
            try std.posix.fsync(dir.fd);
        }
        self.produced_nodes += 1;
        return .{ .key = key, .verified = verified, .encoded = encoded, .output = output };
    }
    fn append(self: *Session, ordinal: usize, main: [36]u8, receipt: ?[36]u8, claims: []const C.O, source: anytype, kind: []const u8) !void {
        if (ordinal != self.leaves.items.len or ordinal >= self.limits.members) return error.OpRecursiveLeafCoverage;
        var source_leaf = try source.sourceLeaf(self.allocator);
        var installed = false;
        errdefer if (!installed) source_leaf.deinit();
        self.source_leaves.appendAssumeCapacity(source_leaf);
        installed = true;
        errdefer {
            self.source_leaves.items[self.source_leaves.items.len - 1].deinit();
            self.source_leaves.items.len -= 1;
        }
        const key = &self.source_leaves.items[self.source_leaves.items.len - 1].authority;
        var node = try self.prove(source, kind, key);
        errdefer node.deinit(self.allocator);
        const owned_claims = try self.allocator.dupe(C.O, claims);
        errdefer self.allocator.free(owned_claims);
        try self.nodes.ensureUnusedCapacity(self.allocator, 1);
        try self.leaves.ensureUnusedCapacity(self.allocator, 1);
        try self.claims.ensureUnusedCapacity(self.allocator, 1);
        self.nodes.appendAssumeCapacity(node);
        self.leaves.appendAssumeCapacity(.{ .ordinal = @intCast(ordinal), .main = main, .receipt = receipt, .claims = owned_claims });
        self.claims.appendAssumeCapacity(owned_claims);
    }
    fn cpu(context: ?*anyopaque, a: std.mem.Allocator, v: Bundle.CpuVerified) !void {
        const self = try from(context);
        var native = try Protocol.W.Wire.decodeProofBytesBinary(a, v.encoded.bytes);
        defer native.deinit(a);
        var arena = std.heap.ArenaAllocator.init(a);
        defer arena.deinit();
        const shape = try @import("../../rv64_recursion/om31_native/cpu_capture.zig").geometryForOp(arena.allocator(), v.setup, v.key.profile.config());
        const values = try V.proof.fromNative(arena.allocator(), &native, v.capture, &shape);
        const main = native.commitment_scheme_proof.commitments.items[1];
        const local = v.stage_one.local orelse return error.MissingOpRecursiveReceipt;
        const source = CpuSource{ .view = .{ .op_span = v.span, .setup = v.setup, .request = v.request, .first = v.first_ids, .expected = v.expected, .key = v.key, .manifest = v.manifest.digest, .main = main, .receipt = local.receipt, .claims = v.encoded.claims, .child = local.proof, .shape = &shape, .values = &values } };
        const template = try GkrTemplate.fromProof(a, v.expected.local_instances orelse return error.MissingOpRecursiveReceipt, local.proof);
        errdefer a.free(template);
        try self.append(v.ordinal, main, local.receipt, v.encoded.claims, source, "CPU");
        try self.templates.append(a, template);
    }
    fn truth(context: ?*anyopaque, a: std.mem.Allocator, v: Bundle.TruthVerified) !void {
        const self = try from(context);
        var native = try Protocol.W.Wire.decodeProofBytesBinary(a, v.encoded.bytes);
        defer native.deinit(a);
        var arena = std.heap.ArenaAllocator.init(a);
        defer arena.deinit();
        const shape = try @import("../pure_p2_truth_statement.zig").geometry(arena.allocator(), v.key, v.truth);
        const values = try V.proof.fromNative(arena.allocator(), &native, v.capture, &shape);
        const main = native.commitment_scheme_proof.commitments.items[1];
        const source = ViewSource(Catalog.View){ .view = .{ .key = v.key, .truth = v.truth, .expected = v.expected, .manifest = v.manifest.digest, .main = main, .claims = v.encoded.claims, .shape = &shape, .values = &values } };
        try self.append(v.ordinal, main, null, v.encoded.claims, source, @tagName(v.truth.family()));
    }
    fn localTruth(context: ?*anyopaque, a: std.mem.Allocator, v: Bundle.LocalTruthVerified) !void {
        const self = try from(context);
        var native = try Protocol.W.Wire.decodeProofBytesBinary(a, v.encoded.bytes);
        defer native.deinit(a);
        const shapes = try @import("../truth_local_gkr/authority.zig").shapes(v.truth);
        var local = try @import("../truth_local_gkr/native.zig").decode(a, shapes, v.encoded.local);
        defer local.deinit();
        var arena = std.heap.ArenaAllocator.init(a);
        defer arena.deinit();
        const shape = try @import("../truth_local_gkr/statement.zig").geometry(arena.allocator(), v.key, v.truth);
        const values = try V.proof.fromNative(arena.allocator(), &native, v.capture, &shape);
        const main = native.commitment_scheme_proof.commitments.items[1];
        const source = ViewSource(LocalCatalog.View){ .view = .{ .key = v.key, .truth = v.truth, .expected = v.expected, .manifest = v.manifest.digest, .main = main, .receipt = v.encoded.receipt, .claims = v.encoded.claims, .local = &local.proof, .shape = &shape, .values = &values } };
        const instances = @import("../truth_local_gkr/native.zig").instances(shapes);
        const template = try GkrTemplate.Truth.fromProof(a, &instances, &local.proof);
        errdefer a.free(template);
        try self.append(v.ordinal, main, v.encoded.receipt, &v.encoded.claims, source, @tagName(v.truth.family()));
        try self.templates.append(a, template);
    }
    fn miller(context: ?*anyopaque, a: std.mem.Allocator, v: Bundle.MillerVerified) !void {
        const self = try from(context);
        var native = try Protocol.W.Wire.decodeProofBytesBinary(a, v.encoded.bytes);
        defer native.deinit(a);
        var arena = std.heap.ArenaAllocator.init(a);
        defer arena.deinit();
        const shape = try @import("../pure_p2_tower_statement.zig").geometry(arena.allocator(), v.key);
        const values = try V.proof.fromNative(arena.allocator(), &native, v.capture, &shape);
        const main = native.commitment_scheme_proof.commitments.items[1];
        const source = ViewSource(Miller.View){ .view = .{ .key = v.key, .span = v.span, .expected = v.expected, .manifest = v.manifest.digest, .main = main, .claims = v.encoded.claims, .shape = &shape, .values = &values } };
        try self.append(v.ordinal, main, null, &v.encoded.claims, source, "Miller");
    }
    fn complete(context: ?*anyopaque, a: std.mem.Allocator, v: Runtime.CompleteVerified) !void {
        const self = try from(context);
        if (self.result != null or self.nodes.items.len != v.inventory.workers.len) return error.OpRecursiveLeafCoverage;
        const metadata = Receiver.Metadata{ .execution = v.inventory.execution, .manifest = v.native.manifest.digest, .leaves = self.leaves.items };
        var plan = try Receiver.prepare(a, .{ .image = v.image, .profile = self.profile, .setups = v.setups, .requests = v.requests, .spans = v.metadata.spans, .cpu_keys = v.cpu_keys, .truths = v.truths, .truth_keys = v.truth_keys, .truth_local_keys = v.inventory.truth_local_keys, .miller = v.miller, .expected = v.expected, .output = .{ .address = v.output_address, .bytes = v.output } }, metadata);
        defer plan.deinit();
        for (plan.expected_outputs, self.nodes.items) |expected, node| {
            const fields = try Core.crypto.poseidon2_m31_sponge.decode(expected);
            for (fields, node.output) |field, actual| if (!actual.eql(C.Q.fromBase(field))) return error.OpRecursiveLeafFrameMismatch;
        }
        var topology = try Topology.Topology.init(a, self.profile, plan.inventory.execution, self.source_leaves.items);
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
                const left = &self.nodes.items[i];
                const right = &self.nodes.items[i + 1];
                const source = FoldSource{ .view = .{ .children = .{ .{ .key = left.key, .verified = &left.verified, .output = left.output }, .{ .key = right.key, .verified = &right.verified, .output = right.output } } } };
                const parent = try self.prove(source, "fold", topology.owned.items[reductions]);
                next.appendAssumeCapacity(parent);
                reductions += 1;
            }
            // Transfer the unpaired last node, never duplicate an execution leaf.
            const paired = i;
            if (i < self.nodes.items.len) next.appendAssumeCapacity(self.nodes.items[i]);
            for (self.nodes.items[0..paired]) |*node| node.deinit(a);
            self.nodes.deinit(a);
            self.nodes = next;
        }
        const root = &self.nodes.items[0];
        try @import("receiver.zig").verifyPlan(a, &plan, &topology, root.encoded);
        const encoded_sidecar = try Sidecar.encode(a, metadata, .{ .bytes = self.limits.sidecar_bytes });
        errdefer a.free(encoded_sidecar);
        const encoded_templates = try TemplateWire.encode(a, self.templates.items);
        errdefer a.free(encoded_templates);
        if (self.directory) |dir| {
            const write = @import("../../rv64_ethereum_batch_receipt.zig").writeExclusive;
            try write(dir, "root.bin", root.encoded);
            try write(dir, "root-sidecar.bin", encoded_sidecar);
            try write(dir, "root-gkr-shapes.bin", encoded_templates);
            const completion = try std.json.Stringify.valueAlloc(a, .{ .schema = "op-p2-r6-complete-root/v1", .members = members, .reductions = reductions, .bytes = root.encoded.len, .profile = self.profile, .security_qualified = false, .total_ns = self.started.read() }, .{});
            defer a.free(completion);
            // Completion marker is synced LAST; receivers still establish completion
            // from the source inventory and root proof, never from this marker.
            try write(dir, "root.json", completion);
            try std.posix.fsync(dir.fd);
        }
        self.result = .{ .allocator = a, .proof = try a.dupe(u8, root.encoded), .root = root.output, .sidecar = encoded_sidecar, .templates = encoded_templates, .members = members, .reductions = reductions, .total_ns = self.started.read() };
        std.debug.print("OP_P2_RECURSIVE_ROOT accepted=true complete=true members={} reductions={} root_bytes={} total_ns={} security_qualified=false production_admitted=false\n", .{ members, reductions, root.encoded.len, self.started.read() });
        root.deinit(a);
        self.nodes.clearRetainingCapacity();
    }
};
pub fn proveDirectory(a: std.mem.Allocator, config: @import("../../rv64_ethereum_request.zig").Config, native_directory: []const u8, profile: Protocol.Profile, resources: Runtime.Resources, limits: Limits) !Result {
    if (limits.members == 0 or limits.members > 256 or limits.proof_bytes == 0 or limits.sidecar_bytes == 0 or limits.sidecar_bytes > 64 << 20) return error.InvalidOpRecursionLimits;
    var session = Session{ .allocator = a, .profile = profile, .limits = limits, .started = try std.time.Timer.start() };
    defer session.deinit();
    if (limits.artifact_directory) |path| {
        try std.fs.cwd().makeDir(path);
        session.directory = try std.fs.cwd().openDir(path, .{});
    }
    // Keys are borrowed by pending nodes: pin the SourceLeaf array before any callback.
    try session.source_leaves.ensureTotalCapacity(a, limits.members);
    try Runtime.verifyDirectoryWithHooks(a, config, native_directory, profile, resources, .{ .context = &session, .complete = Session.complete, .fragments = .{ .context = &session, .cpu = Session.cpu, .truth = Session.truth, .truth_local = Session.localTruth, .miller = Session.miller } });
    const result = session.result orelse return error.OpRecursiveExecutionIncomplete;
    session.result = null;
    return result;
}
