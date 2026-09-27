//! One recursive proof over every real dyadic member of an exact-count forest.
//! The outer proof contains one independently admitted child verifier per member;
//! no dummy execution proof or invalid intermediate prefix Span is introduced.
const std = @import("std");
const core = @import("stwo_core");
const spans = @import("span_statement_blake3.zig");
const forest = @import("blake3_exact_forest_protocol.zig");
const tree = @import("blake3_execution_tree.zig");
const artifact = @import("blake3_native_parent_artifact.zig");
const codec = @import("blake3_native_parent_codec.zig");
const parent = @import("blake3_execution_parent_preparation.zig");
const protocol = @import("blake3_execution_parent_protocol.zig");
const rebase = @import("air/blake3_parent_rebase.zig");
const join = @import("air/blake3_parent_join.zig");
const mixDigest = @import("../prover/blake3_execution_protocol.zig").mixDigest;
const Budget = @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget;

pub const VERSION: u32 = 2;
pub const Fold = struct {
    prepared: parent.Prepared,
    statement: spans.RootStatement,
    roster_digest: [32]u8,

    pub fn deinit(self: *Fold) void {
        self.prepared.deinit();
        self.* = undefined;
    }
};
pub const Bounded = struct {
    fold: Fold,
    budget: *Budget,

    pub fn deinit(self: *Bounded) void {
        self.fold.deinit();
        self.budget.destroy();
        self.* = undefined;
    }
};

pub fn prepareBounded(
    allocator: std.mem.Allocator,
    job: spans.JobContext,
    nodes: []const *const tree.Node,
    trusted_roster_digest: [32]u8,
    capacity: u32,
    byte_limit: usize,
) !Bounded {
    const budget = try Budget.create(allocator, byte_limit);
    errdefer budget.destroy();
    var fold = prepare(
        budget.allocator(),
        job,
        nodes,
        trusted_roster_digest,
        capacity,
    ) catch |err| {
        if (err == error.OutOfMemory and budget.snapshot().exceeded)
            return error.PreparationHostBudgetExceeded;
        return err;
    };
    errdefer fold.deinit();
    try fold.prepared.rows.partitionHashRows();
    return .{ .fold = fold, .budget = budget };
}

/// Receiver-owned expected root statement, derived solely from the admitted
/// complete job. It cannot be replaced by a statement carried in proof bytes.
pub fn expectedRoot(job: spans.JobContext) !spans.RootStatement {
    try job.validate();
    const complete = job.complete;
    const executed = try spans.ExecutedSpan.init(
        0,
        job.segment_count,
        0,
        complete.total_cycles,
        complete.initial_state,
        complete.final_state,
        try spans.EdgeClaim.present(complete.public_input),
        try spans.EdgeClaim.present(complete.public_output),
    );
    return spans.RootStatement.init(try spans.SpanStatement.init(
        job,
        try spans.SlotSpan.init(0, job.slot_height),
        .{ .executed = executed },
    ));
}

/// Fresh receiver for the single outer proof. The root key ID and roster
/// digest are both independent policy inputs; proof metadata grants neither.
pub fn verifyBytes(
    allocator: std.mem.Allocator,
    bytes: []const u8,
    admission: protocol.Admission,
    job: spans.JobContext,
    trusted_roster_digest: [32]u8,
) !tree.Node {
    return verifyProfile(allocator, bytes, admission, job, trusted_roster_digest, .csp_q70_pow26);
}

/// Explicit development-only receiver. Never substitutes for canonical block
/// security, even when its statement and roster are otherwise valid.
pub fn verifyDiagnosticBytes(
    allocator: std.mem.Allocator,
    bytes: []const u8,
    admission: protocol.Admission,
    job: spans.JobContext,
    trusted_roster_digest: [32]u8,
) !tree.Node {
    return verifyProfile(allocator, bytes, admission, job, trusted_roster_digest, .diagnostic_q8_pow0);
}

fn verifyProfile(
    allocator: std.mem.Allocator,
    bytes: []const u8,
    admission: protocol.Admission,
    job: spans.JobContext,
    trusted_roster_digest: [32]u8,
    expected_profile: protocol.Profile,
) !tree.Node {
    try admission.validate();
    if (admission.key.profile != expected_profile)
        return error.ExpectedCanonicalBlockSecurity;
    const exact = admission.key.context.exact_aggregation orelse
        return error.MissingExactRootBinding;
    if (exact.child_count != @popCount(job.segment_count) or
        !std.mem.eql(u8, &exact.binding_digest, &admission.key.context.span_binding_id.?))
        return error.InvalidExactRootBinding;
    if (!std.mem.eql(u8, &exact.roster_digest, &trusted_roster_digest))
        return error.UntrustedExactForestRoster;
    const root = try expectedRoot(job);
    var received: artifact.Owned = try codec.decode(allocator, bytes, admission);
    var node = try tree.Node.verifyOwned(
        &received,
        admission,
        admission.expected_id,
        root.statement,
    );
    errdefer node.deinit();
    _ = try node.root();
    return node;
}

/// The trusted roster digest must come from independent verifier policy.
/// `nodes` own fresh-verified child captures and remain borrowed throughout.
/// Each child is prepared and drained before the next child is retained.
pub fn prepare(
    allocator: std.mem.Allocator,
    job: spans.JobContext,
    nodes: []const *const tree.Node,
    trusted_roster_digest: [32]u8,
    capacity: u32,
) !Fold {
    return prepareProfile(allocator, job, nodes, trusted_roster_digest, capacity, .csp_q70_pow26);
}

/// Explicit development-only composition of diagnostic child proofs.
pub fn prepareDiagnostic(
    allocator: std.mem.Allocator,
    job: spans.JobContext,
    nodes: []const *const tree.Node,
    trusted_roster_digest: [32]u8,
    capacity: u32,
) !Fold {
    return prepareProfile(allocator, job, nodes, trusted_roster_digest, capacity, .diagnostic_q8_pow0);
}

fn prepareProfile(
    allocator: std.mem.Allocator,
    job: spans.JobContext,
    nodes: []const *const tree.Node,
    trusted_roster_digest: [32]u8,
    capacity: u32,
    expected_profile: protocol.Profile,
) !Fold {
    if (nodes.len == 0 or nodes.len > spans.MAX_SLOT_HEIGHT + 1)
        return error.InvalidExactRootCount;
    var entries: [spans.MAX_SLOT_HEIGHT + 1]forest.Entry = undefined;
    for (nodes, 0..) |node, index| {
        try node.validate();
        if (node.admission.key.profile != expected_profile)
            return error.ExpectedCanonicalBlockSecurity;
        entries[index] = .{
            .statement = node.statement,
            .expected_key_id = node.admission.expected_id,
        };
    }
    const roster = try forest.digest(job, entries[0..nodes.len]);
    if (!std.mem.eql(u8, &roster, &trusted_roster_digest))
        return error.UntrustedExactForestRoster;
    const executed = try forest.validate(job, entries[0..nodes.len]);
    const statement = try expectedRoot(job);
    if (!std.meta.eql(executed, statement.statement.body.executed))
        return error.InvalidExactRootExecution;
    const statement_id = (try spans.identity.hash(
        &try statement.statement.canonicalWords(),
        .statement,
    )).bytes;

    var binding = core.channel.blake3.Channel{};
    binding.mixU32s(&.{ 0x4233_5852, VERSION, @intCast(nodes.len) });
    mixDigest(&binding, roster);
    mixDigest(&binding, statement_id);
    var next_namespace: u32 = 1;
    var accumulated: ?parent.Prepared = null;
    errdefer if (accumulated) |*owned| owned.deinit();
    for (nodes, 0..) |node, index| {
        var child = try parent.prepare(
            allocator,
            &node.admission,
            &node.verified,
            node.admission.expected_id,
            capacity,
        );
        var moved = false;
        defer if (!moved) child.deinit();
        var namespace = try rebase.prepare(allocator, &child.rows, next_namespace);
        defer namespace.deinit();
        next_namespace = try namespace.end();
        const namespace_id = try namespace.identity();
        try rebase.apply(&child.rows, &namespace, namespace_id);
        binding.mixU32s(&.{@intCast(index)});
        mixDigest(&binding, try protocol.contextIdentity(child.context));
        mixDigest(&binding, namespace_id);
        if (accumulated) |*previous| {
            const joined = try join.joinDraining(
                allocator,
                &previous.rows,
                &child.rows,
                .{
                    .{ .first = 1, .end = namespace.first },
                    .{ .first = namespace.first, .end = next_namespace },
                },
            );
            previous.rows.deinit();
            child.rows.deinit();
            previous.rows = joined;
            moved = true;
        } else {
            accumulated = child;
            moved = true;
        }
    }
    var result = accumulated.?;
    accumulated = null;
    errdefer result.deinit();
    result.context.statement_identity = statement_id;
    result.context.span_binding_id = binding.digestBytes();
    result.context.aggregation = null;
    result.context.exact_aggregation = .{
        .roster_digest = roster,
        .binding_digest = result.context.span_binding_id.?,
        .child_count = @intCast(nodes.len),
    };
    result.context.quad_aggregation = null;
    _ = try protocol.contextIdentity(result.context);
    return .{ .prepared = result, .statement = statement, .roster_digest = roster };
}
