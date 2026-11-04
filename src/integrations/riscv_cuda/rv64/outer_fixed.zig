//! Default-off trusted GPU FIXED precommit. Never used by CPU reception.
const std = @import("std");
const S = @import("outer_source.zig");
const O = @import("stwo_circuit_cpu_integration").om31;
const Dev = O.device_prove;
const Circuit = @import("stwo_circuit_frontend");
const PP = Circuit.common.preprocessed.PreprocessedCircuit;
const D = @import("stwo_prover_api").device_pcs;
const SC = @import("session_context.zig");
const Id = @import("pcs_scope.zig");
pub const Owner = struct {
    allocator: std.mem.Allocator,
    backend: *S.Context,
    pp: *const PP,
    scope: D.Scope,
    raw: @import("outer_fixed_ingress.zig").Raw = .{},
    inputs: [45]D.TraceColumn = undefined,
    tree: D.Tree = undefined,
    failure: ?anyerror = null,
    pub fn promote(self: *Owner, next: D.Scope) !void {
        if (!std.mem.eql(u8, &next.fixed, &self.tree.root) or next.ordinal != self.scope.ordinal or std.mem.allEqual(u8, &next.main, 0)) return error.InvalidFixedScopePromotion;
        var job = Promotion{ .owner = self, .next = next };
        const status = self.backend.service.submit(self.backend.service.session, Promotion.run, &job);
        if (job.failure) |err| return err;
        try S.checked(status);
        self.scope = next;
    }
    const Promotion = struct {
        owner: *Owner,
        next: D.Scope,
        failure: ?anyerror = null,
        fn run(_: *anyopaque, _: u64, data: ?*anyopaque) callconv(.c) c_int {
            const self: *@This() = @ptrCast(@alignCast(data.?));
            self.owner.backend.service.promoteSingleRetained(Id.identity(self.owner.scope), Id.identity(self.next), self.owner.backend.trace_commit.rebind) catch |err| {
                self.failure = err;
                return 1;
            };
            return 0;
        }
    };
    fn upload(raw: *anyopaque, token: u64, data: ?*anyopaque) callconv(.c) c_int {
        const self: *Owner = @ptrCast(@alignCast(data.?));
        self.uploadImpl(raw, token) catch |err| {
            self.failure = err;
            return 1;
        };
        return 0;
    }
    fn uploadImpl(self: *Owner, raw: *anyopaque, token: u64) !void {
        var ctx = SC.Context{ .session = self.backend.service.session, .native_context = raw, .token = token, .scope = Id.identity(self.scope), .api = &self.backend.api };
        defer ctx.active = false;
        var count: usize = 0;
        for (self.pp.columns) |column| count = try std.math.add(usize, count, column.values.len);
        self.raw = .{ .lease = try ctx.allocate(count, 0), .scope = ctx.scope };
        var at: usize = 0;
        for (self.pp.columns, &self.inputs) |column, *out| {
            if (column.values.len == 0 or !std.math.isPowerOfTwo(column.values.len)) return error.InvalidOuterFixedGeometry;
            const words: []const u32 = @ptrCast(column.values);
            try S.checked(self.backend.api.upload(raw, self.raw.lease.words.? + at, words.ptr, words.len * 4));
            out.* = .{ .log_size = column.logSize(), .encoding = .evaluations, .device = .{ .words = self.raw.lease.words.? + at, .count = words.len, .context_token = self.raw.lease.context_token, .generation = self.raw.lease.generation } };
            at += words.len;
        }
        try ctx.join();
    }
    fn dropRaw(_: *anyopaque, _: u64, data: ?*anyopaque) callconv(.c) c_int {
        const self: *Owner = @ptrCast(@alignCast(data.?));
        self.raw.release(self.rawOps()) catch return 1;
        self.inputs = @splat(.{ .log_size = 0, .encoding = .evaluations });
        return 0;
    }
    pub fn rawOps(self: *Owner) @import("outer_fixed_ingress.zig").Ops {
        return .{ .session = self.backend.service.session, .validate = self.backend.service.lease_validate, .rebind = self.backend.trace_commit.rebind, .release = self.backend.service.lease_release };
    }
    fn prepare(raw: *anyopaque, a: std.mem.Allocator, key: *const O.prove.Authority, graph: *const Circuit.builder.Context(O.protocol.Q), scope: D.Scope) !Dev.Source {
        const self: *Owner = @ptrCast(@alignCast(raw));
        if (key.pp != self.pp or !key.device_fixed or !std.mem.eql(u8, &key.fixedRoot(), &self.tree.root) or scope.ordinal != self.scope.ordinal) return error.InvalidOuterFixedAuthority;
        try Dev.validateTree(&key.fixed_logs, self.tree);
        return S.Context.prepareImpl(self.backend, a, key, &.{}, scope, graph, self);
    }
    fn release(raw: *anyopaque) void {
        const self: *Owner = @ptrCast(@alignCast(raw));
        const b = self.backend;
        const release_status = b.service.submit(b.service.session, dropRaw, self);
        b.service.finishProofScope(self.scope);
        b.mutex.lock();
        std.debug.assert(b.fixed_pending == self);
        if (release_status != 0) b.cleanup_failed = true;
        b.fixed_pending = null;
        b.mutex.unlock();
        self.allocator.destroy(self);
    }
};
pub fn precommit(raw: *anyopaque, a: std.mem.Allocator, pp: *const PP, ordinal: u32) !Dev.PrecommittedFixed {
    const b: *S.Context = @ptrCast(@alignCast(raw));
    b.mutex.lock();
    var locked = true;
    defer if (locked) b.mutex.unlock();
    try b.requireHealthyLocked();
    if (b.active != null or b.fixed_pending != null) return error.OuterProofAlreadyActive;
    b.fixed_nonce = try std.math.add(u64, b.fixed_nonce, 1);
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("circuit/om31/provisional-fixed-owner/v1\x00");
    var word: [8]u8 = undefined;
    std.mem.writeInt(u64, &word, b.fixed_nonce, .little);
    hash.update(&word);
    const scope = D.Scope{ .statement = hash.finalResult(), .fixed = @splat(0), .main = @splat(0), .ordinal = ordinal };
    const self = try a.create(Owner);
    self.* = .{ .allocator = a, .backend = b, .pp = pp, .scope = scope };
    b.fixed_pending = self;
    b.mutex.unlock();
    locked = false;
    errdefer Owner.release(self);
    const status = b.service.submit(b.service.session, Owner.upload, self);
    if (self.failure) |err| return err;
    try S.checked(status);
    self.tree = try b.trace_commit.commitFixed(a, .{ .scope = scope, .config = try O.protocol.targetConfig(), .tree_index = 0, .columns = &self.inputs });
    // Retain original evaluations for MAIN/INTER; Source takes exact custody.
    var logs: [45]u32 = undefined;
    for (pp.columns, &logs) |column, *log| log.* = column.logSize();
    try Dev.validateTree(&logs, self.tree);
    return .{ .context = self, .tree = self.tree, .scope = scope, .prepare_from_circuit = Owner.prepare, .release = Owner.release };
}
