//! Owning verified tree nodes. Received artifacts require an independently
//! admitted key; neither the artifact nor its Span may select verification keys.
const std = @import("std");
const protocol = @import("blake3_execution_parent_protocol.zig");
const verifier = @import("blake3_native_parent_verifier.zig");
const artifact = @import("blake3_native_parent_artifact.zig");
const parent = @import("blake3_execution_parent_preparation.zig");
const aggregate = @import("blake3_execution_aggregate.zig");
const spans = @import("span_statement_blake3.zig");
pub const Node = struct {
    admission: protocol.Admission,
    statement: spans.SpanStatement,
    verified: verifier.Verified,
    /// Consumes the artifact on every path. Output owns the capture and borrows
    /// neither the artifact nor the caller's admission/statement storage.
    pub fn verifyOwned(received: *artifact.Owned, admission: protocol.Admission, expected: [32]u8, statement: spans.SpanStatement) !Node {
        defer received.deinit();
        try admitStatement(&admission, expected, statement);
        return .{ .admission = admission, .statement = statement, .verified = try verifier.verify(received, &admission) };
    }
    pub fn validate(self: *const Node) !void {
        try admitStatement(&self.admission, self.admission.expected_id, self.statement);
        try self.verified.validate(&self.admission, self.admission.expected_id);
    }
    pub fn root(self: *const Node) !spans.RootStatement {
        try self.validate();
        return spans.RootStatement.init(self.statement);
    }
    pub fn deinit(self: *Node) void {
        self.verified.deinit();
        self.* = undefined;
    }
};
fn admitStatement(admission: *const protocol.Admission, expected: [32]u8, statement: spans.SpanStatement) !void {
    try admission.validate();
    if (!std.mem.eql(u8, &admission.expected_id, &expected)) return error.UntrustedBlake3ParentKey;
    const context = admission.key.context;
    if (context.statement_identity == null or context.span_binding_id == null) return error.MissingTreeSpan;
    const id = (try spans.identity.hash(&try statement.canonicalWords(), .statement)).bytes;
    if (!std.mem.eql(u8, &id, &context.statement_identity.?)) return error.UntrustedTreeSpan;
}
/// Borrows both nodes on every path. At most two child preparations and their
/// direct joined columns are live; no earlier tree witnesses are retained.
/// The result still requires proving under a caller-admitted parent key.
pub fn preparePair(a: std.mem.Allocator, left: *const Node, right: *const Node, capacity: u32) !aggregate.Fold {
    return preparePairWithPool(a, left, right, capacity, null);
}
/// Reuses a caller-owned pool, admitting at most one helper plus the coordinator.
/// The allocator must support concurrent access and enforce the caller's shared
/// preparation budget. Pool stacks belong to its separate caller reservation.
/// Both borrowed nodes survive failure; all partial witnesses are destroyed.
pub fn preparePairWithPool(a: std.mem.Allocator, left: *const Node, right: *const Node, capacity: u32, pool: ?*@import("stwo_prover_engine").work_pool.WorkPool) !aggregate.Fold {
    if (left == right) return error.AliasedAggregateChildren;
    try left.validate();
    try right.validate();
    _ = try spans.SpanStatement.fold(left.statement, right.statement);
    var jobs = [2]Preparation{
        .{ .a = a, .node = left, .capacity = capacity },
        .{ .a = a, .node = right, .capacity = capacity },
    };
    defer for (&jobs) |*job| {
        if (job.owned) |*owned| owned.deinit();
        if (job.planned) |*planned| planned.deinit();
    };
    // Complete both authenticated layouts before either child allocates its
    // final hash columns. Both waves reuse the same bounded pool policy.
    try runWave(&jobs, pool);
    var shared = try @import("blake3_native_hash_columns.zig").Shared.init(a, .{ jobs[0].planned.?.layout, jobs[1].planned.?.layout });
    defer shared.deinit();
    for (&jobs, 0..) |*job, i| {
        job.hash_columns = try shared.partition(i);
        job.emitting = true;
    }
    try runWave(&jobs, pool);
    var l = jobs[0].owned.?;
    var r = jobs[1].owned.?;
    jobs[0].owned = null;
    jobs[1].owned = null;
    return aggregate.prepareShared(a, &l, &r, .{ left.statement, right.statement }, &shared.owner);
}
fn runWave(jobs: *[2]Preparation, pool: ?*@import("stwo_prover_engine").work_pool.WorkPool) !void {
    if (pool) |workers| {
        const pools = @import("stwo_prover_engine").work_pool;
        var lease = try workers.acquire(try pools.WorkerBudget.init(@min(2, workers.workerCount())));
        defer lease.deinit();
        if (lease.helperCount() != 0) {
            var done: std.Thread.WaitGroup = .{};
            try lease.spawnWg(&done, Preparation.run, .{&jobs[0]});
            jobs[1].run();
            // Join even when either child failed, before reading helper results
            // or releasing its lease, borrowed captures, allocator or witnesses.
            done.wait();
            lease.completeWave();
        } else for (jobs) |*job| job.run();
    } else for (jobs) |*job| job.run();
    for (jobs) |job| if (job.failure) |err| return err;
}
const Preparation = struct {
    a: std.mem.Allocator,
    node: *const Node,
    capacity: u32,
    owned: ?parent.PartitionPrepared = null,
    hash_columns: ?@import("blake3_native_hash_columns.zig").Owner = null,
    planned: ?parent.Planned = null,
    emitting: bool = false,
    failure: ?anyerror = null,
    fn run(self: *Preparation) void {
        if (!self.emitting) {
            self.planned = parent.State.plan(self.a, &self.node.admission, &self.node.verified, self.node.admission.expected_id, self.capacity) catch |err| {
                self.failure = err;
                return;
            };
            return;
        }
        const state = self.planned.?.emitPartition(self.hash_columns.?) catch |err| {
            self.failure = err;
            return;
        };
        defer state.deinit();
        self.owned = state.finishPartition() catch |err| {
            self.failure = err;
            return;
        };
    }
};
