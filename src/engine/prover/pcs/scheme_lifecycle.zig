//! PCS setup, revision configuration, storage policy and teardown ownership.
const std = @import("std");
const core = @import("stwo_core");
const Revision = core.protocol_revision.Revision;
const PcsConfig = core.pcs.PcsConfig;
const PREPROCESSED_TRACE_IDX = core.verifier_types.PREPROCESSED_TRACE_IDX;
const revision_lifting = @import("revision_lifting.zig");
const TwiddleSource = @import("../poly/twiddle_source.zig").TwiddleSource;
const M31TwiddleTower = @import("../poly/twiddle_tower.zig").M31TwiddleTower;
const CoefficientRetentionPolicy = @import("columns/storage.zig").CoefficientRetentionPolicy;
const work_profile = @import("stwo_prover_api").work_profile;
const deferred_commit = @import("deferred_commit.zig");
pub fn Lifecycle(comptime B: type, comptime H: type, comptime MC: type, comptime Self: type, comptime CommitmentSchemeError: type) type {
    _ = MC;
    const revision = Self.revision;
    const BackendCommitmentTree = Self.CommittedTree;
    return struct {
        pub fn init(allocator: std.mem.Allocator, config: PcsConfig) !Self {
            return initWithTwiddleSource(config, TwiddleSource.initOwned(allocator));
        }
        /// A `proving_5a7c5ed` scheme whose heights are known up front.
        pub fn initRevision(allocator: std.mem.Allocator, config: revision_lifting.PcsConfigV2) !Self {
            var scheme = try init(allocator, Revision.proving_5a7c5ed.legacyView(config));
            errdefer scheme.deinit(allocator);
            try scheme.setRevisionConfig(config);
            return scheme;
        }
        /// `initRevision` with twiddles borrowed from a long-lived tower, so
        /// consecutive proofs share one precompute. Twiddles are canonical,
        /// so the proof is unchanged.
        pub fn initRevisionWithTwiddleTower(config: revision_lifting.PcsConfigV2, tower: *const M31TwiddleTower) !Self {
            var scheme = initWithTwiddleTower(Revision.proving_5a7c5ed.legacyView(config), tower);
            try scheme.setRevisionConfig(config);
            return scheme;
        }
        pub fn initWithTwiddleTower(config: PcsConfig, tower: *const M31TwiddleTower) Self {
            return initWithTwiddleSource(config, TwiddleSource.initBorrowed(tower));
        }
        fn initWithTwiddleSource(config: PcsConfig, twiddle_source: TwiddleSource) Self {
            return .{
                .trees = .{},
                .config = config,
                .coefficient_retention_policy = .always,
                .twiddle_source = twiddle_source,
                .pending_commit = null,
                .shell_preopening_audit = .{},
            };
        }

        /// Arms the cold shell audit before the first profiled commitment.
        /// Starting after a tree exists (or is pending) remains observable and
        /// makes final publication fail closed.
        pub fn beginShellWorkProfile(self: *Self, work_recorder: ?*work_profile.Recorder(true)) void {
            const active = work_recorder orelse return;
            self.shell_preopening_audit.begin(
                self.trees.items.len,
                self.pending_commit != null,
            );
            if (!self.shell_preopening_audit.complete) active.markIncomplete();
        }

        pub fn observePreOpeningRootMix(self: *Self, ordinal: usize, root: []const u8) void {
            self.shell_preopening_audit.observeRootMixed(ordinal, root);
        }

        pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
            deferred_commit.discard(self, allocator);
            for (self.trees.items) |*tree| tree.deinit(allocator);
            self.trees.deinit(allocator);
            self.twiddle_source.deinit(allocator);
            self.* = undefined;
        }

        /// Sets the `proving_5a7c5ed` configuration: FRI and PoW run from
        /// `config.fri_config` and tree `i` is committed at
        /// `config.liftingLogSize(i)`. Must precede the first commitment, as
        /// the heights shape every root; the caller mixes the configuration
        /// (`Revision.proving_5a7c5ed.mixConfig`). Only a Merkle channel of
        /// that revision (a channel profile) takes one.
        pub fn setRevisionConfig(
            self: *Self,
            config: revision_lifting.PcsConfigV2,
        ) error{ RevisionAfterCommit, RevisionRequiresChannelProfile }!void {
            if (comptime revision != .proving_5a7c5ed) return error.RevisionRequiresChannelProfile;
            if (self.trees.items.len != 0 or self.pending_commit != null) return error.RevisionAfterCommit;
            self.config = Revision.proving_5a7c5ed.legacyView(config);
            self.revision_config = config;
        }

        /// The height choke point every commit path appends through. A
        /// `proving_5a7c5ed` scheme without its configuration fails closed
        /// instead of committing at the largest column.
        pub fn liftCommittedTree(self: *Self, allocator: std.mem.Allocator, tree: *BackendCommitmentTree) !void {
            if (comptime revision != .proving_5a7c5ed) return;
            const config = self.revision_config orelse return error.MissingRevisionConfig;
            try revision_lifting.liftCommittedTree(B, H, config, allocator, tree, self.trees.items.len);
        }

        /// `max_log_degree_bound` of upstream `prove_ex` for a revision
        /// scheme; null for the existing lanes, whose bound follows the
        /// composition split.
        pub fn revisionMaskLogSize(self: Self, include_all_preprocessed_columns: bool) !?u32 {
            const config = self.revision_config orelse return null;
            if (self.trees.items.len <= PREPROCESSED_TRACE_IDX) return CommitmentSchemeError.InvalidPreprocessedTree;
            return try revision_lifting.maskLogSize(
                config,
                try self.proofLiftingLogSize(),
                self.trees.items[PREPROCESSED_TRACE_IDX].commitment.maxLogSize(),
                include_all_preprocessed_columns,
            );
        }

        pub fn setCompactPolynomialStorage(self: *Self, minimum_log_size: u32) void {
            self.compact_polynomial_min_log_size = @max(1, minimum_log_size);
            self.compact_polynomial_storage = true;
            self.coefficient_retention_policy = .always;
        }

        pub fn setStorePolynomialsCoefficients(self: *Self) void {
            self.coefficient_retention_policy = .always;
        }

        /// Selects whether committed evaluation columns retain a second,
        /// coefficient-form copy until the opening phase.
        ///
        /// `.never` bounds commitment residency at the cost of evaluating
        /// sampled values from the committed extended-domain columns. This
        /// does not change commitments, Fiat-Shamir inputs, or proof bytes.
        pub fn setCoefficientRetentionPolicy(
            self: *Self,
            policy: CoefficientRetentionPolicy,
        ) void {
            self.coefficient_retention_policy = policy;
        }

        /// Execution-only storage selection. The default allocation and protocol
        /// are unchanged. Selected storage currently requires `.never` coefficients.
        pub fn setRetainedColumnAllocator(self: *Self, allocator: ?std.mem.Allocator) void {
            self.retained_column_allocator = allocator;
        }

        /// Execution-only opt-in; no commitment or transcript parameter changes.
        pub fn setQuotientValuesAllocator(self: *Self, allocator: ?std.mem.Allocator) void {
            self.quotient_values_allocator = allocator;
        }
    };
}
