//! Persistent, budgeted proving context for the verified streaming frontier.
const std = @import("std");
const engine = @import("stwo_prover_engine");
const api = @import("blake3_execution_parent_proof.zig");
const worker_mod = @import("blake3_native_parent_worker.zig");

const codec = @import("blake3_native_parent_codec.zig");
const spans = @import("span_statement_blake3.zig");

/// Deliverable bytes and statement, with no proof-selected verification key.
/// Verification still requires the receiver's independently pinned admission.
pub const RootArtifact = struct {
    allocator: std.mem.Allocator,
    bytes: []u8,
    statement: spans.SpanStatement,
    expected_key_id: [32]u8,
    pub fn deinit(self: *RootArtifact) void {
        self.allocator.free(self.bytes);
        self.* = undefined;
    }
    pub fn verify(self: *const RootArtifact, a: std.mem.Allocator, admission: api.protocol.Admission, expected: [32]u8) !api.tree.Node {
        if (!std.mem.eql(u8, &self.expected_key_id, &expected) or !std.mem.eql(u8, &admission.expected_id, &expected)) return error.UntrustedBlake3ParentKey;
        _ = try spans.RootStatement.init(self.statement);
        var decoded = try codec.decode(a, self.bytes, admission);
        return api.tree.Node.verifyOwned(&decoded, admission, expected, self.statement);
    }
};

pub fn ForBackend(comptime Backend: type) type {
    return struct {
        allocator: std.mem.Allocator,
        pool: *engine.work_pool.WorkPool,
        preparation_limit: usize,
        worker_options: worker_mod.Options,
        profile: api.protocol.Profile = .csp_q70_pow26,
        worker: ?*api.pipeline.ForBackend(Backend).Worker = null,
        retain_root_artifact: bool = false,
        /// Retain one canonical artifact per dyadic forest member. A V2
        /// exact-count receiver must verify every retained proof separately.
        retain_exact_forest_artifacts: bool = false,
        root_artifact: ?RootArtifact = null,

        const Self = @This();
        pub fn deinit(self: *Self) void {
            if (self.root_artifact) |*artifact| artifact.deinit();
            if (self.worker) |worker| worker.deinit();
            self.* = undefined;
        }
        pub fn takeRootArtifact(self: *Self) !RootArtifact {
            const artifact = self.root_artifact orelse return error.NoCompletedRootArtifact;
            self.root_artifact = null;
            return artifact;
        }
        /// Borrows both children on every path. A persistent worker rebinds its
        /// admitted plan for each geometry; no received artifact selects keys.
        pub fn fold(self: *Self, left: *const api.tree.Node, right: *const api.tree.Node) !api.tree.Node {
            try left.validate();
            try right.validate();
            if (left.admission.key.profile != self.profile or right.admission.key.profile != self.profile)
                return error.StreamSecurityProfileMismatch;
            const Budget = engine.host_budget_allocator.SharedHostBudget;
            const budget = try Budget.create(self.allocator, self.preparation_limit);
            defer budget.destroy();
            var folded = try api.tree.preparePairWithPool(budget.allocator(), left, right, 2, self.pool);
            defer folded.deinit();
            return self.provePrepared(&folded.prepared, folded.statement);
        }
        /// Prove either an admitted execution-leaf preparation or an aggregate.
        /// Consumes its rows on all paths; the independently verified node and
        /// optional root bytes own their storage after preparation is released.
        pub fn provePrepared(self: *Self, prepared: *api.preparation.Prepared, statement: spans.SpanStatement) !api.tree.Node {
            defer prepared.rows.releaseRows();
            // Independent key derivation itself commits fixed columns. Drop a
            // structurally obsolete cached plan before that temporary commitment
            // is constructed, not merely before the replacement worker is built.
            if (self.worker) |worker| {
                const matching_rows = blk: {
                    var lease = try worker.acquire();
                    defer lease.deinit();
                    worker.plan.validateRows(&prepared.rows) catch |err| switch (err) {
                        error.InvalidBlake3ParentRows => break :blk false,
                        else => return err,
                    };
                    break :blk true;
                };
                if (!matching_rows) {
                    self.worker = null;
                    worker.deinit();
                }
            }
            const key = try api.ForBackend(Backend).deriveKeyWithProfileAndPool(
                prepared.rows.allocator,
                prepared,
                self.profile,
                self.pool,
            );
            const expected = try key.identity();
            const admission = try api.protocol.Admission.init(key, expected);
            // The frontier owns independently verified nodes, not this cached
            // proving plan. Reuse matching structure; otherwise evict before
            // building a replacement so two large fixed commitments never overlap.
            // On allocation failure the frontier remains retryable with no worker.
            if (self.worker) |worker| {
                const reusable = blk: {
                    var lease = try worker.acquire();
                    defer lease.deinit();
                    break :blk try worker.plan.tryRebindAdmission(&prepared.rows, admission);
                };
                if (!reusable) {
                    self.worker = null;
                    worker.deinit();
                }
            }
            if (self.worker == null) self.worker = try api.pipeline.ForBackend(Backend).Worker.init(
                self.allocator,
                &prepared.rows,
                admission,
                self.worker_options,
            );
            var proof = try self.worker.?.proveAdmittedConsuming(&prepared.rows, admission);
            defer proof.deinit();
            var encoded: ?[]u8 = null;
            errdefer if (encoded) |bytes| self.allocator.free(bytes);
            var forest_encoded: ?[]u8 = null;
            errdefer if (forest_encoded) |bytes| self.allocator.free(bytes);
            if (self.retain_root_artifact and statement.slots.first == 0 and statement.slots.height == statement.job.slot_height) {
                _ = try spans.RootStatement.init(statement);
                encoded = try codec.encode(self.allocator, &proof, admission);
            }
            if (self.retain_exact_forest_artifacts)
                forest_encoded = try codec.encode(self.allocator, &proof, admission);
            // Publish transport bytes only after independent proof verification.
            var node = try api.tree.Node.verifyOwned(&proof, admission, expected, statement);
            if (forest_encoded) |bytes| {
                node.transport_bytes = bytes;
                node.transport_allocator = self.allocator;
                forest_encoded = null;
            }
            if (encoded) |bytes| {
                if (self.root_artifact) |*old| old.deinit();
                self.root_artifact = .{ .allocator = self.allocator, .bytes = bytes, .statement = statement, .expected_key_id = expected };
            }
            return node;
        }
    };
}
