//! Wrapped proof/cache custody and fold-class retention.
const std = @import("std");
const core = @import("stwo_core");
const O = core.fields.om31.OM31;
const Outer = @import("outer_wrap.zig");
const Bridge = @import("../om31_outer.zig");
const Prove = @import("stwo_circuit_cpu_integration").om31.prove;
const Wire = @import("stwo_circuit_cpu_integration").om31.wire;
const context_owner = @import("execution_wrap_context.zig");
const requireReceiverTrace = context_owner.requireReceiverTrace;
const main_owner = @import("execution_wrap.zig");
const Node = main_owner.Node;

pub const Pending = struct {
    proof: *Outer.Wrapped,
    node: usize,
    pub fn deinit(self: Pending, a: std.mem.Allocator) void {
        self.proof.deinit();
        a.destroy(self.proof);
    }
};
pub fn child(p: Pending) Bridge.Child {
    return p.proof.asChild();
}
pub fn hybridChildren(kids: []const Bridge.Child) bool {
    for (kids) |kid| if (kid.hybrid != null) return true;
    return false;
}
pub fn freeMarginals(a: std.mem.Allocator, values: []const []const O) void {
    for (values) |pair| a.free(pair);
    a.free(values);
}
pub fn copyMarginals(a: std.mem.Allocator, values: []const []const O) ![]const []const O {
    const out = try a.alloc([]const O, values.len);
    errdefer a.free(out);
    var count: usize = 0;
    errdefer for (out[0..count]) |pair| a.free(pair);
    for (out, values) |*pair, value| {
        pair.* = try a.dupe(O, value);
        count += 1;
    }
    return out;
}
pub fn cached(a: std.mem.Allocator, dir: std.fs.Dir, name: []const u8, allow_resume: bool) !?[]u8 {
    if (!allow_resume) return null;
    return dir.readFileAlloc(a, name, Wire.MAX_BYTES) catch |err| switch (err) {
        error.FileNotFound => null,
        else => return err,
    };
}
pub fn save(a: std.mem.Allocator, dir: std.fs.Dir, name: []const u8, proof: *const Outer.Wrapped) !void {
    const bytes = try proof.serialize(a);
    defer a.free(bytes);
    try dir.writeFile(.{ .sub_path = name, .data = bytes });
}
pub const Fold = struct { pending: Pending, restored: bool, retired_preprocessed_bytes: usize };
/// Receiver-only, in-process fold v2 class authorities. Each entry was built by
/// THIS process from an honest trace-only fold graph; a later fold of the same
/// geometry class (Bridge.classKey) reuses its retired PP + verifier Authority
/// and skips graph/PP/FIXED construction. Never persisted, never producer-fed.
/// STWO_RV64_FOLD_CLASS_CACHE=0 disables; =check rebuilds and compares.
pub const FoldClasses = struct {
    const PPT = @import("stwo_circuit_frontend").common.preprocessed.PreprocessedCircuit;
    const Entry = struct { key: [32]u8, pp: *PPT, authority: *Prove.Authority };
    allocator: std.mem.Allocator,
    entries: std.ArrayList(Entry) = .empty,
    check: bool = false,
    hits: usize = 0,
    misses: usize = 0,
    checked: usize = 0,
    pub fn fromEnv(a: std.mem.Allocator) ?FoldClasses {
        const value = std.posix.getenv("STWO_RV64_FOLD_CLASS_CACHE") orelse "1";
        if (std.mem.eql(u8, value, "0")) return null;
        return .{ .allocator = a, .check = std.mem.eql(u8, value, "check") };
    }
    pub fn deinit(self: *FoldClasses) void {
        for (self.entries.items) |entry| {
            entry.authority.deinit();
            self.allocator.destroy(entry.authority);
            entry.pp.deinit(self.allocator);
            self.allocator.destroy(entry.pp);
        }
        self.entries.deinit(self.allocator);
    }
    pub fn find(self: *const FoldClasses, key: [32]u8) ?Entry {
        for (self.entries.items) |entry| if (std.mem.eql(u8, &entry.key, &key)) return entry;
        return null;
    }
    /// Takes ownership of a freshly verified, retired fold's PP/Authority.
    pub fn adopt(self: *FoldClasses, key: [32]u8, proof: *Outer.Wrapped) !void {
        if (proof.borrowed or !proof.authority.retired) return error.FoldClassAdoptRequiresRetiredOwner;
        try self.entries.append(self.allocator, .{ .key = key, .pp = proof.pp, .authority = proof.authority });
        proof.borrowed = true;
    }
};
/// Borrows children throughout construction. The caller releases them ONLY
/// after the new parent has a complete proof, fresh capture and durable bytes.
pub fn combine(a: std.mem.Allocator, left: Pending, right: Pending, nodes: *std.ArrayList(Node), dir: std.fs.Dir, allow_resume: bool, factory: ?Outer.Device.Factory, existing_only: bool, classes: ?*FoldClasses) !Fold {
    const l = nodes.items[left.node];
    const r = nodes.items[right.node];
    if (l.first_leaf + l.leaf_count != r.first_leaf) return error.RecursiveLeafAdjacency;
    std.log.info("rv64 OM31 recursion fold: [{d},{d}) + [{d},{d})", .{ l.first_leaf, l.first_leaf + l.leaf_count, r.first_leaf, r.first_leaf + r.leaf_count });
    const children = [2]Bridge.Child{ child(left), child(right) };
    const digest = try Bridge.expectedDigest(&children);
    const class_key = try Bridge.classKey(&children);
    const hit: ?FoldClasses.Entry = if (!existing_only) null else if (classes) |cache| cache.find(class_key) else null;
    if (hit) |entry| if (!classes.?.check) {
        var timer = try std.time.Timer.start();
        var name_buffer: [64]u8 = undefined;
        const name = try std.fmt.bufPrint(&name_buffer, "fold-{d:0>6}.proof", .{nodes.items.len});
        const encoded = (try cached(a, dir, name, allow_resume)) orelse return error.MissingRecursiveNodeProof;
        defer a.free(encoded);
        const proof = try a.create(Outer.Wrapped);
        errdefer a.destroy(proof);
        proof.* = try Outer.restoreWithAuthority(a, entry.pp, entry.authority, digest, encoded);
        classes.?.hits += 1;
        std.log.info("rv64 OM31 recursion fold accepted (class cache hit): class={x} restore_ns={d} verify_ns={d} total_ns={d}", .{ class_key[0..8], proof.timings.restore_ns, proof.timings.verify_ns, timer.read() });
        const node = nodes.items.len;
        nodes.appendAssumeCapacity(.{ .first_leaf = l.first_leaf, .leaf_count = l.leaf_count + r.leaf_count, .left = left.node, .right = right.node, .authority = proof.effectiveIdentity(), .digest = digest });
        return .{ .pending = .{ .proof = proof, .node = node }, .restored = true, .retired_preprocessed_bytes = 0 };
    };
    const build_fold = if (existing_only or (factory != null and factory.?.prepare_from_circuit != null)) &Bridge.buildFoldTraceOnly else &Bridge.buildFold;
    var graph = try build_fold(a, &children);
    defer graph.deinit();
    if (existing_only) try requireReceiverTrace(&graph.ctx);
    if (!std.mem.eql(u8, &digest, &graph.output_digest)) return error.RecursiveFoldDigest;
    var name_buffer: [64]u8 = undefined;
    const name = try std.fmt.bufPrint(&name_buffer, "fold-{d:0>6}.proof", .{nodes.items.len});
    const encoded = try cached(a, dir, name, allow_resume);
    if (existing_only and encoded == null) return error.MissingRecursiveNodeProof;
    defer if (encoded) |bytes| a.free(bytes);
    const proof = try a.create(Outer.Wrapped);
    errdefer a.destroy(proof);
    proof.* = try Outer.wrapGraphOrLoadWithFactory(a, &graph.ctx, digest, encoded, @intCast(nodes.items.len), factory);
    std.log.info("rv64 OM31 recursion fold accepted: preprocess_ns={d} prove_ns={d} restore_ns={d} verify_ns={d}", .{ proof.timings.preprocess_ns, proof.timings.prove_ns, proof.timings.restore_ns, proof.timings.verify_ns });
    errdefer proof.deinit();
    // rootverify derive hook (no-op unless derive-vk-tables runs).
    @import("../root_verify.zig").recordFold(children, class_key, digest, proof.authority);
    if (!existing_only) try save(a, dir, name, proof);
    const retired_bytes = proof.retireProverData();
    if (hit) |entry| {
        // check mode: the class authority must equal the freshly rebuilt one.
        if (!std.mem.eql(u8, &entry.authority.identity, &proof.authority.identity)) return error.FoldClassAuthorityMismatch;
        classes.?.checked += 1;
        std.log.info("rv64 OM31 recursion fold class check ok: class={x}", .{class_key[0..8]});
    } else if (existing_only) if (classes) |cache| {
        try cache.adopt(class_key, proof);
        cache.misses += 1;
        std.log.info("rv64 OM31 recursion fold class adopted: class={x} identity={x}", .{ class_key[0..8], proof.authority.identity[0..8] });
    };
    const node = nodes.items.len;
    nodes.appendAssumeCapacity(.{ .first_leaf = l.first_leaf, .leaf_count = l.leaf_count + r.leaf_count, .left = left.node, .right = right.node, .authority = proof.effectiveIdentity(), .digest = digest });
    return .{ .pending = .{ .proof = proof, .node = node }, .restored = encoded != null, .retired_preprocessed_bytes = retired_bytes };
}
