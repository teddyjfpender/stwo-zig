//! Candidate four-root/two-track Gate transcript with private mutable custody.
//!
//! This wraps the proposed event plan and admitted line-root cache in one
//! stable allocation. The selected verifier still needs sealed-key derivation,
//! checked wire geometry, a complete PCS/FRI verifier, and a security proof.
//! No production proof selector constructs this type.
const std = @import("std");
const framed = @import("../channel/framed_bcs_v2.zig");
const plan_mod = @import("../channel/paired_gate_event_plan_v2.zig");
const uniform = @import("../queries/uniform_v1.zig");
const m31 = @import("../fields/m31.zig");
const qm31 = @import("../fields/qm31.zig");
const circle = @import("../circle.zig");
const canonic = @import("../poly/circle/canonic.zig");
const core_utils = @import("../utils.zig");
const source_merkle = @import("blake2s_personalized_source_v2.zig");
const lifted_verifier = @import("verifier.zig");
const row_context = @import("../pcs/paired_row_context_v2.zig");
const descriptor = @import("line_descriptor_v2.zig");
const admission = @import("line_admission_v2.zig");

pub const Digest32 = framed.Digest32;
pub const Error = error{
    InvalidQueryGeometry,
    ZeroQueries,
    InvalidLineRowWidth,
    InvalidLinePath,
    InvalidSourceRoster,
    SourceStatementMismatch,
    SourceNotAdmitted,
    SourceContextMissing,
    SourceAlreadyVerified,
    NonCanonicalSourceRow,
    InvalidSourcePairShape,
    ManifestPlanMismatch,
    InvalidQueryIndex,
    QueriesNotDrawn,
} || plan_mod.Error || admission.Error || uniform.Error || row_context.Error ||
    lifted_verifier.MerkleVerificationError || lifted_verifier.TreeHeightError ||
    qm31.QM31.Error;

pub const source_tree_count: usize = 4;
pub const max_source_columns: usize = 256;
pub const source_roster_magic = "S31SRC2V";
pub const source_root_events = [source_tree_count]u64{ 1, 4, 10, 12 };
pub const SourceRosterV2 = struct {
    column_log_sizes: [source_tree_count][]const u32,
    column_descriptors: [source_tree_count][]const Digest32,
};

const OwnedSourceRoster = struct {
    logs: [source_tree_count][max_source_columns]u32,
    counts: [source_tree_count]usize,
    total: usize,

    fn init(statement: framed.StatementBinding, query_log: u32, roster: SourceRosterV2) Error!OwnedSourceRoster {
        var out: OwnedSourceRoster = undefined;
        out.total = 0;
        for (roster.column_log_sizes, 0..) |logs, tree| {
            const identities = roster.column_descriptors[tree];
            if (logs.len == 0 or logs.len > max_source_columns or
                (tree == 3 and logs.len != 8) or
                identities.len != logs.len or
                logs.len > max_source_columns - out.total)
                return error.InvalidSourceRoster;
            for (logs) |log| if (log != query_log) return error.InvalidSourceRoster;
            const digest = try sourceRosterDigest(statement.key_digest, query_log, tree, logs, identities);
            if (!std.mem.eql(u8, &digest, &statement.source_tree_descriptors[tree]))
                return error.SourceStatementMismatch;
            out.counts[tree] = logs.len;
            @memcpy(out.logs[tree][0..logs.len], logs);
            out.total += logs.len;
        }
        return out;
    }
};

/// Candidate source descriptor: role-framed version, key digest, fixed root
/// event, lifting log, and ordered full-width column identities/logs. The selected key
/// must own these bytes; equality to a caller-built statement alone is not a
/// sealed-key theorem. The source, production-plain, and line Merkle profiles
/// remain separate.
pub fn sourceRosterDigest(
    key_digest: Digest32,
    query_log: u32,
    tree: usize,
    logs: []const u32,
    identities: []const Digest32,
) Error!Digest32 {
    if (tree >= source_tree_count or logs.len == 0 or logs.len > max_source_columns or
        identities.len != logs.len or query_log < 2 or query_log > 30)
        return error.InvalidSourceRoster;
    for (identities, 0..) |identity, i| {
        for (identities[0..i]) |earlier| {
            if (std.mem.eql(u8, &identity, &earlier)) return error.InvalidSourceRoster;
        }
    }
    var bytes: [8 + source_merkle.profile_id.len + 8 + 8 + 32 + 1 + 8 + 4 + 4 + 36 * max_source_columns]u8 = undefined;
    var at: usize = 0;
    @memcpy(bytes[at..][0..8], source_roster_magic);
    at += 8;
    @memcpy(bytes[at..][0..source_merkle.profile_id.len], source_merkle.profile_id);
    at += source_merkle.profile_id.len;
    @memcpy(bytes[at..][0..8], &source_merkle.leaf_context);
    at += 8;
    @memcpy(bytes[at..][0..8], &source_merkle.parent_context);
    at += 8;
    @memcpy(bytes[at..][0..32], &key_digest);
    at += 32;
    bytes[at] = @intCast(tree);
    at += 1;
    std.mem.writeInt(u64, bytes[at..][0..8], source_root_events[tree], .little);
    at += 8;
    std.mem.writeInt(u32, bytes[at..][0..4], query_log, .little);
    at += 4;
    std.mem.writeInt(u32, bytes[at..][0..4], @intCast(logs.len), .little);
    at += 4;
    for (logs, identities) |log, identity| {
        if (log != query_log) return error.InvalidSourceRoster;
        std.mem.writeInt(u32, bytes[at..][0..4], log, .little);
        at += 4;
        @memcpy(bytes[at..][0..32], &identity);
        at += 32;
    }
    return framed.hashFrameParts(.tree_context, 0, &.{bytes[0..at]});
}

pub const SourceTreePairOpeningV2 = struct {
    /// One pair per key-owned column, in its exact source descriptor order.
    columns: []const [2]m31.M31,
    hash_witness: []Digest32,
};

pub const SourcePairWordsV2 = [2][2]qm31.QM31;

fn qm31FromLimbs(limbs: [4]u32) qm31.QM31 {
    var coordinates: [4]m31.M31 = undefined;
    for (limbs, &coordinates) |limb, *coordinate| coordinate.* = m31.M31.fromCanonical(limb);
    return qm31.QM31.fromM31Array(coordinates);
}

const State = struct {
    allocator: std.mem.Allocator,
    plan: plan_mod.PairedGateEventPlanV2,
    admitted: *admission.AdmittedLineManifestV2,
    query_log_size: u32,
    queries: ?uniform.SampledQueriesV1 = null,
    source_roster: ?OwnedSourceRoster = null,
    source_roots: [source_tree_count]?Digest32 = [_]?Digest32{null} ** source_tree_count,
    ood_point: ?circle.CirclePointQM31 = null,
    source_claims: [max_source_columns]qm31.QM31 = undefined,
    source_claim_count: usize = 0,
    source_context: ?row_context.RowContextV2 = null,
    source_insertions: ?[]?SourcePairWordsV2 = null,
};

/// Four canonical M31 coordinates for one QM31 line value, with the Merkle
/// path at an index derived privately from a sampled query. No index field is
/// accepted from the proof or caller.
pub const LineRowOpeningV2 = struct {
    row: [4]u32,
    siblings: []const Digest32,
};

/// Opaque custody for the candidate S31NAT9F schedule. A caller receives no
/// channel, plan, cache, or mutable query slice. The caller must derive the
/// statement and manifest from one sealed verification key; this API checks
/// their equality but cannot establish the external derivation premise.
pub const OwnedPairedGateVerifierV2 = opaque {
    const Self = @This();

    pub fn init(
        allocator: std.mem.Allocator,
        manifest: descriptor.LineTreeManifestV2,
        statement: framed.StatementBinding,
    ) Error!*Self {
        return initInternal(allocator, manifest, statement, null);
    }

    /// H1 candidate only: each source column is present at the first raw
    /// query height. The roster digests must match the statement before any
    /// transcript event. Lower-height sparse Gate columns fail closed.
    pub fn initWithSourceRoster(
        allocator: std.mem.Allocator,
        manifest: descriptor.LineTreeManifestV2,
        statement: framed.StatementBinding,
        roster: SourceRosterV2,
    ) Error!*Self {
        return initInternal(allocator, manifest, statement, roster);
    }

    fn initInternal(
        allocator: std.mem.Allocator,
        manifest: descriptor.LineTreeManifestV2,
        statement: framed.StatementBinding,
        roster: ?SourceRosterV2,
    ) Error!*Self {
        // A one-bit FRI fold at each committed height has a line tree at the
        // next height. The raw query is sampled over the first fold height.
        // This is checked geometry, not a sealed-key derivation.
        try manifest.validate();
        const query_log_size = manifest.fold_heights[0];
        if (query_log_size < 2 or query_log_size > 30) return error.InvalidQueryGeometry;
        for (manifest.fold_heights[1..], 1..) |height, i| {
            if (height + 1 != manifest.fold_heights[i - 1]) return error.InvalidQueryGeometry;
        }
        for (manifest.trees, 0..) |tree, i| {
            const fold_height = manifest.fold_heights[i / 2];
            if (fold_height < 2 or tree.tree_log_size != fold_height - 1)
                return error.InvalidQueryGeometry;
        }
        const owned_roster = if (roster) |input|
            try OwnedSourceRoster.init(statement, query_log_size, input)
        else
            null;
        const state = try allocator.create(State);
        errdefer allocator.destroy(state);
        state.allocator = allocator;
        state.plan = try plan_mod.PairedGateEventPlanV2.init(statement, manifest.fold_heights);
        state.admitted = try admission.AdmittedLineManifestV2.init(
            allocator,
            manifest,
            statement,
            &state.plan.channel,
        );
        state.query_log_size = query_log_size;
        state.queries = null;
        state.source_roster = owned_roster;
        state.source_roots = [_]?Digest32{null} ** source_tree_count;
        state.ood_point = null;
        state.source_claim_count = 0;
        state.source_context = null;
        state.source_insertions = null;
        return @ptrCast(state);
    }

    fn privateState(self: *Self) *State {
        return @ptrCast(@alignCast(self));
    }

    fn stateConst(self: *const Self) *const State {
        return @ptrCast(@alignCast(self));
    }

    pub fn deinit(self: *Self) void {
        const state = self.privateState();
        if (state.source_insertions) |insertions| state.allocator.free(insertions);
        if (state.source_context) |*context| context.deinit();
        if (state.queries) |*queries| queries.deinit(state.allocator);
        state.admitted.deinit();
        state.allocator.destroy(state);
    }

    pub fn statementDigest(self: *const Self) Digest32 {
        return self.stateConst().admitted.statementDigest();
    }

    pub fn manifestDigest(self: *const Self) Digest32 {
        return self.stateConst().admitted.manifestDigest();
    }

    pub fn transcriptDigest(self: *const Self) Digest32 {
        return self.stateConst().plan.channel.digest;
    }

    pub fn nextEvent(self: *const Self) u64 {
        return self.stateConst().plan.channel.next_event;
    }

    pub fn mixFixedRoot(self: *Self, root: Digest32) Error!void {
        const state = self.privateState();
        if (state.source_roster != null and state.plan.channel.next_event != source_root_events[0])
            return error.SourceStatementMismatch;
        try state.plan.mixFixedRoot(root);
        state.source_roots[0] = root;
    }

    pub fn mixCircuitIdentity(self: *Self, identity: Digest32) Error!void {
        try self.privateState().plan.mixCircuitIdentity(identity);
    }

    pub fn mixPublicValues(self: *Self, limbs: []const u32) Error!void {
        try self.privateState().plan.mixPublicValues(limbs);
    }

    pub fn mixMainRoot(self: *Self, root: Digest32) Error!void {
        const state = self.privateState();
        if (state.source_roster != null and state.plan.channel.next_event != source_root_events[1])
            return error.SourceStatementMismatch;
        try state.plan.mixMainRoot(root);
        state.source_roots[1] = root;
    }

    pub fn beginInteractionPow(self: *Self, difficulty: u32) Error!framed.PowBarrier {
        return self.privateState().plan.beginInteractionPow(difficulty);
    }

    pub fn acceptInteractionNonce(self: *Self, nonce: u64) Error!void {
        try self.privateState().plan.acceptInteractionNonce(nonce);
    }

    pub fn drawLookupPair(self: *Self) Error![8]u32 {
        return self.privateState().plan.drawLookupPair();
    }

    pub fn mixInteractionClaim(self: *Self, limbs: []const u32) Error!void {
        try self.privateState().plan.mixInteractionClaim(limbs);
    }

    pub fn mixInteractionRoot(self: *Self, root: Digest32) Error!void {
        const state = self.privateState();
        if (state.source_roster != null and state.plan.channel.next_event != source_root_events[2])
            return error.SourceStatementMismatch;
        try state.plan.mixInteractionRoot(root);
        state.source_roots[2] = root;
    }

    pub fn drawCompositionGamma(self: *Self) Error![4]u32 {
        return self.privateState().plan.drawCompositionGamma();
    }

    pub fn mixCompositionRoot(self: *Self, root: Digest32) Error!void {
        const state = self.privateState();
        if (state.source_roster != null and state.plan.channel.next_event != source_root_events[3])
            return error.SourceStatementMismatch;
        try state.plan.mixCompositionRoot(root);
        state.source_roots[3] = root;
    }

    pub fn drawOodsSeed(self: *Self) Error![4]u32 {
        const state = self.privateState();
        const limbs = try state.plan.drawOodsSeed();
        if (state.source_roster != null)
            state.ood_point = try circle.secureFieldPointFromRandomSeedChecked(qm31FromLimbs(limbs));
        return limbs;
    }

    pub fn mixSampledValues(self: *Self, limbs: []const u32) Error!void {
        const state = self.privateState();
        if (state.source_roster) |roster| {
            if (state.ood_point == null or limbs.len != roster.total * 4)
                return error.InvalidSourcePairShape;
        }
        try state.plan.mixSampledValues(limbs);
        if (state.source_roster) |roster| {
            for (0..roster.total) |i| state.source_claims[i] = qm31FromLimbs(limbs[4 * i ..][0..4].*);
            state.source_claim_count = roster.total;
        }
    }

    pub fn drawBatchLambda(self: *Self) Error![4]u32 {
        const state = self.privateState();
        const limbs = try state.plan.drawBatchLambda();
        if (state.source_roster) |roster| {
            if (state.source_claim_count != roster.total) return error.SourceContextMissing;
            const point = state.ood_point orelse return error.SourceContextMissing;
            state.source_context = try row_context.RowContextV2.init(
                state.allocator,
                point,
                state.source_claims[0..roster.total],
                qm31FromLimbs(limbs),
            );
        }
        return limbs;
    }

    pub fn drawFoldAlpha(self: *Self) Error![4]u32 {
        return self.privateState().plan.drawFoldAlpha();
    }

    /// The admitted cache absorbs and retains the root. The plan stage only
    /// advances after that exact absorption succeeds, so there is no second
    /// root mix and no independently supplied root for later opening checks.
    pub fn captureOriginalLineRoot(self: *Self, root: Digest32) Error!void {
        const state = self.privateState();
        if (state.plan.stage != .original_line_root) return error.UnexpectedStage;
        const tree_index = 2 * state.plan.fold_index;
        const shape = try state.admitted.openingShape(tree_index);
        if (shape.track != .original or shape.fold_height != try state.plan.currentFoldHeight())
            return error.ManifestPlanMismatch;
        try state.admitted.captureRootAtNamedEvent(tree_index, root);
        state.plan.stage = .own_quotient_line_root;
    }

    pub fn captureOwnQuotientLineRoot(self: *Self, root: Digest32) Error!void {
        const state = self.privateState();
        if (state.plan.stage != .own_quotient_line_root) return error.UnexpectedStage;
        const tree_index = 2 * state.plan.fold_index + 1;
        const shape = try state.admitted.openingShape(tree_index);
        if (shape.track != .own_quotient or shape.fold_height != try state.plan.currentFoldHeight())
            return error.ManifestPlanMismatch;
        try state.admitted.captureRootAtNamedEvent(tree_index, root);
        state.plan.fold_index += 1;
        state.plan.stage = .fold_alpha;
    }

    pub fn mixOriginalTerminalCoefficients(self: *Self, limbs: []const u32) Error!void {
        try self.privateState().plan.mixOriginalTerminalCoefficients(limbs);
    }

    pub fn mixOwnQuotientTerminalCoefficients(self: *Self, limbs: []const u32) Error!void {
        try self.privateState().plan.mixOwnQuotientTerminalCoefficients(limbs);
    }

    pub fn beginFriPow(self: *Self, difficulty: u32) Error!framed.PowBarrier {
        return self.privateState().plan.beginFriPow(difficulty);
    }

    pub fn acceptFriNonce(self: *Self, nonce: u64) Error!void {
        try self.privateState().plan.acceptFriNonce(nonce);
    }

    /// The raw query channel and position slice remain private. The selected
    /// verifier must additionally prove one sampled query is projected
    /// consistently through every FRI fold and opening geometry.
    pub fn drawQueries(
        self: *Self,
        n_queries: usize,
        max_blocks: u64,
    ) Error!void {
        const state = self.privateState();
        if (n_queries == 0) return error.ZeroQueries;
        if (!state.admitted.allRootsCaptured()) return error.RootNotCaptured;
        var query_channel = try state.plan.beginQueries();
        var queries = try uniform.drawUniformQueriesV1(
            &query_channel,
            state.allocator,
            state.query_log_size,
            n_queries,
            max_blocks,
        );
        errdefer queries.deinit(state.allocator);
        if (state.source_roster != null) {
            const insertions = try state.allocator.alloc(?SourcePairWordsV2, n_queries);
            @memset(insertions, null);
            state.source_insertions = insertions;
        }
        state.queries = queries;
    }

    pub fn queryCount(self: *const Self) Error!usize {
        const queries = self.stateConst().queries orelse return error.QueriesNotDrawn;
        return queries.raw.len;
    }

    pub fn queryPosition(self: *const Self, index: usize) Error!usize {
        const queries = self.stateConst().queries orelse return error.QueriesNotDrawn;
        if (index >= queries.raw.len) return error.InvalidQueryIndex;
        return queries.raw[index];
    }

    /// Authenticate all four source trees at the pair fixed by one sampled
    /// query, then derive CAS09's original/own-quotient inserted values from
    /// the privately retained OOD point, claims, and batch challenge. The
    /// caller supplies only row values and Merkle witnesses, never roots,
    /// positions, a RowContext, or precomputed insertion values.
    pub fn verifyAndKeepSourcePair(
        self: *Self,
        query_ordinal: usize,
        openings: [source_tree_count]SourceTreePairOpeningV2,
    ) Error!void {
        const state = self.privateState();
        const roster = if (state.source_roster) |*value| value else return error.SourceNotAdmitted;
        const queries = state.queries orelse return error.QueriesNotDrawn;
        if (query_ordinal >= queries.raw.len) return error.InvalidQueryIndex;
        const insertions = state.source_insertions orelse return error.SourceContextMissing;
        if (insertions[query_ordinal] != null) return error.SourceAlreadyVerified;
        const context = state.source_context orelse return error.SourceContextMissing;
        const raw = queries.raw[query_ordinal];
        if (raw >= (@as(usize, 1) << @intCast(state.query_log_size)))
            return error.InvalidQueryGeometry;
        const base = raw & ~@as(usize, 1);
        const positions = [2]usize{ base, base + 1 };
        for (openings, 0..) |opened, tree| {
            const root = state.source_roots[tree] orelse return error.RootNotCaptured;
            if (opened.columns.len != roster.counts[tree]) return error.InvalidSourcePairShape;
            var columns: [max_source_columns][]const m31.M31 = undefined;
            for (opened.columns, 0..) |*pair, i| {
                for (pair) |value| if (value.v >= m31.Modulus) return error.NonCanonicalSourceRow;
                columns[i] = pair[0..];
            }
            // The admitted roster already checked every log equals the tree
            // height, so this borrow avoids four shape-copy allocations per
            // sampled query. The lifted verifier reads but never mutates it.
            const verifier = lifted_verifier.MerkleVerifierLifted(source_merkle.SourceMerkleHasherV2){
                .root = root,
                .column_log_sizes = roster.logs[tree][0..roster.counts[tree]],
                .height = state.query_log_size,
            };
            try verifier.verify(
                state.allocator,
                &positions,
                columns[0..opened.columns.len],
                .{ .hash_witness = opened.hash_witness },
            );
        }
        const domain = canonic.CanonicCoset.new(state.query_log_size).circleDomain();
        var inserted: SourcePairWordsV2 = undefined;
        for (0..2) |side| {
            var row: [max_source_columns]m31.M31 = undefined;
            var at: usize = 0;
            for (openings) |opened| {
                for (opened.columns) |column| {
                    row[at] = column[side];
                    at += 1;
                }
            }
            if (at != roster.total) return error.InvalidSourcePairShape;
            const point = domain.at(core_utils.bitReverseIndex(base + side, state.query_log_size));
            inserted[side] = try context.openedValues(row[0..at], point);
        }
        insertions[query_ordinal] = inserted;
    }

    /// Read-only diagnostic access. Later fold verification must use the
    /// privately stored value, never accept this returned copy as input.
    pub fn sourceInsertionAt(self: *const Self, query_ordinal: usize) Error!SourcePairWordsV2 {
        const state = self.stateConst();
        const insertions = state.source_insertions orelse return error.SourceContextMissing;
        if (query_ordinal >= insertions.len) return error.InvalidQueryIndex;
        return insertions[query_ordinal] orelse error.SourceContextMissing;
    }

    fn projectedLineRow(self: *const Self, tree_index: usize, query_ordinal: usize) Error!u64 {
        const state = self.stateConst();
        const queries = state.queries orelse return error.QueriesNotDrawn;
        if (query_ordinal >= queries.raw.len) return error.InvalidQueryIndex;
        const shape = try state.admitted.openingShape(tree_index);
        const fold_index = tree_index / 2;
        if (fold_index >= state.plan.fold_count or
            shape.fold_height != state.plan.fold_heights[fold_index] or
            shape.tree_log_size + 1 != shape.fold_height or
            shape.tree_log_size >= state.query_log_size)
            return error.InvalidQueryGeometry;
        const raw = queries.raw[query_ordinal];
        if (raw >= (@as(usize, 1) << @intCast(state.query_log_size)))
            return error.InvalidQueryGeometry;
        const shift = state.query_log_size - shape.tree_log_size;
        return @intCast(raw >> @intCast(shift));
    }

    /// Checks an opening at the line row selected by a previously sampled
    /// raw query. A fold from height h to h-1 removes one high-order bit in
    /// bit-reversed query order: `line_row = raw >> (query_log - tree_log)`.
    /// This authenticates only one selected row, not the adjacent pair needed
    /// for a complete FRI relation or a proof-acceptance decision.
    pub fn verifyCapturedLineOpening(
        self: *const Self,
        tree_index: usize,
        query_ordinal: usize,
        row: []const u32,
        siblings: []const Digest32,
    ) Error!bool {
        const leaf_index = try self.projectedLineRow(tree_index, query_ordinal);
        return self.stateConst().admitted.verifyCapturedOpening(tree_index, row, leaf_index, siblings);
    }

    /// Authenticate both adjacent rows under one captured line-tree root.
    /// CAS09's pair base is `(selected_line_row & ~1)`. Both path indices are
    /// derived here from the same sampled raw query; neither can be supplied
    /// or reordered by the caller. The result is local authenticated line
    /// data only; no source insertion or FRI fold equation is checked here.
    pub fn verifyAndReadLinePair(
        self: *const Self,
        tree_index: usize,
        query_ordinal: usize,
        openings: [2]LineRowOpeningV2,
    ) Error![2]qm31.QM31 {
        const selected = try self.projectedLineRow(tree_index, query_ordinal);
        const shape = try self.stateConst().admitted.openingShape(tree_index);
        if (shape.column_count != 4 or shape.tree_log_size == 0)
            return error.InvalidLineRowWidth;
        const base = selected & ~@as(u64, 1);
        var out: [2]qm31.QM31 = undefined;
        for (openings, 0..) |opening, side| {
            const index = base + @as(u64, @intCast(side));
            if (!try self.stateConst().admitted.verifyCapturedOpening(
                tree_index,
                &opening.row,
                index,
                opening.siblings,
            )) return error.InvalidLinePath;
            var coordinates: [4]m31.M31 = undefined;
            for (opening.row, 0..) |word, coordinate|
                coordinates[coordinate] = m31.M31.fromCanonical(word);
            out[side] = qm31.QM31.fromM31Array(coordinates);
        }
        return out;
    }

    /// Check both independent tracks for one fold and one sampled query.
    /// No partial result escapes if either track fails authentication.
    pub fn verifyAndReadBothTrackPairs(
        self: *const Self,
        fold_index: usize,
        query_ordinal: usize,
        openings: [2][2]LineRowOpeningV2,
    ) Error![2][2]qm31.QM31 {
        if (fold_index >= self.stateConst().plan.fold_count - 1)
            return error.InvalidTreeIndex;
        return .{
            try self.verifyAndReadLinePair(2 * fold_index, query_ordinal, openings[0]),
            try self.verifyAndReadLinePair(2 * fold_index + 1, query_ordinal, openings[1]),
        };
    }
};

fn testStatement(manifest: descriptor.LineTreeManifestV2, allocator: std.mem.Allocator) !framed.StatementBinding {
    const zero = [_]u8{0} ** 32;
    return .{
        .key_digest = zero,
        .circuit_digest = zero,
        .fri_config_digest = zero,
        .source_tree_descriptors = [_]Digest32{zero} ** 4,
        .line_profile_digest = try manifest.digest(allocator),
    };
}

test "opaque paired verifier owns channel, cached roots and query positions" {
    const allocator = std.testing.allocator;
    const zero = [_]u8{0} ** 32;
    const profile = descriptor.lineHashProfileDigest();
    const columns = [_]Digest32{zero};
    var trees = [_]descriptor.LineTreeDescriptorV2{
        .{ .key_digest = zero, .profile_digest = profile, .track = .original, .fold_height = 2, .tree_log_size = 1, .root_event = 17, .column_descriptors = &columns },
        .{ .key_digest = zero, .profile_digest = profile, .track = .own_quotient, .fold_height = 2, .tree_log_size = 1, .root_event = 18, .column_descriptors = &columns },
    };
    var fold_heights = [_]u32{ 2, 1 };
    const manifest = descriptor.LineTreeManifestV2{ .key_digest = zero, .fold_heights = &fold_heights, .trees = &trees };
    const statement = try testStatement(manifest, allocator);
    const verifier = try OwnedPairedGateVerifierV2.init(allocator, manifest, statement);
    defer verifier.deinit();
    try std.testing.expectEqual(@as(u64, 1), verifier.nextEvent());
    try std.testing.expectError(error.UnexpectedStage, verifier.mixMainRoot(zero));
    try std.testing.expectError(error.UnexpectedStage, verifier.captureOriginalLineRoot(zero));
    try std.testing.expectError(error.QueriesNotDrawn, verifier.queryCount());
    const leaf0 = try @import("blake2s_personalized_line_v2.zig").hashCanonicalRow(&.{0});
    const leaf1 = try @import("blake2s_personalized_line_v2.zig").hashCanonicalRow(&.{1});
    const root = @import("blake2s_personalized_line_v2.zig").LineMerkleHasherV2.hashChildren(.{ .left = leaf0, .right = leaf1 });
    try verifier.mixFixedRoot(zero);
    try verifier.mixCircuitIdentity(zero);
    try verifier.mixPublicValues(&.{ 0, 1, 2, 3 });
    try verifier.mixMainRoot(zero);
    _ = try verifier.beginInteractionPow(0);
    try verifier.acceptInteractionNonce(0);
    _ = try verifier.drawLookupPair();
    try verifier.mixInteractionClaim(&.{ 0, 1, 2, 3 });
    try verifier.mixInteractionRoot(zero);
    _ = try verifier.drawCompositionGamma();
    try verifier.mixCompositionRoot(zero);
    _ = try verifier.drawOodsSeed();
    try verifier.mixSampledValues(&.{ 0, 1, 2, 3 });
    _ = try verifier.drawBatchLambda();
    _ = try verifier.drawFoldAlpha();
    try std.testing.expectEqual(@as(u64, 17), verifier.nextEvent());
    try std.testing.expectError(error.RootNotCaptured, verifier.drawQueries(8, 1));
    const before_root = verifier.transcriptDigest();
    try verifier.captureOriginalLineRoot(root);
    try std.testing.expectEqual(@as(u64, 18), verifier.nextEvent());
    try std.testing.expectEqualDeep(framed.hashRoot(before_root, 17, root), verifier.transcriptDigest());
    try std.testing.expectError(error.UnexpectedStage, verifier.captureOriginalLineRoot(root));
    try verifier.captureOwnQuotientLineRoot(root);
    try std.testing.expectEqual(@as(u64, 19), verifier.nextEvent());
    // The cache copied shapes before this caller-owned descriptor changed.
    trees[0].tree_log_size = 0;
    trees[0].root_event = 99;
    fold_heights[0] = 99;
    _ = try verifier.drawFoldAlpha();
    try verifier.mixOriginalTerminalCoefficients(&.{ 0, 1, 2, 3 });
    try verifier.mixOwnQuotientTerminalCoefficients(&.{ 0, 1, 2, 3 });
    _ = try verifier.beginFriPow(0);
    try verifier.acceptFriNonce(0);
    try verifier.drawQueries(8, 1);
    try std.testing.expectEqual(@as(usize, 8), try verifier.queryCount());
    var seen = [2]bool{ false, false };
    for (0..8) |ordinal| {
        const raw = try verifier.queryPosition(ordinal);
        try std.testing.expect(raw < 4);
        const projected = raw >> 1;
        seen[projected] = true;
        const good_row: u32 = @intCast(projected);
        const good_sibling = if (projected == 0) leaf1 else leaf0;
        try std.testing.expect(try verifier.verifyCapturedLineOpening(0, ordinal, &.{good_row}, &.{good_sibling}));
        try std.testing.expect(try verifier.verifyCapturedLineOpening(1, ordinal, &.{good_row}, &.{good_sibling}));
        // A valid path for the other leaf cannot be replayed at this sampled
        // query ordinal, even though both paths share the captured root.
        const wrong_row: u32 = @intCast(1 - projected);
        const wrong_sibling = if (projected == 0) leaf0 else leaf1;
        try std.testing.expect(!(try verifier.verifyCapturedLineOpening(0, ordinal, &.{wrong_row}, &.{wrong_sibling})));
    }
    try std.testing.expect(seen[0] and seen[1]);
    try std.testing.expectError(error.InvalidQueryIndex, verifier.queryPosition(8));
    try std.testing.expectError(error.InvalidQueryIndex, verifier.verifyCapturedLineOpening(0, 8, &.{0}, &.{leaf1}));
    try std.testing.expectError(error.RowWidthMismatch, verifier.verifyCapturedLineOpening(0, 0, &.{ 0, 1 }, &.{leaf1}));
    try std.testing.expectError(error.InvalidLineRowWidth, verifier.verifyAndReadLinePair(0, 0, .{
        .{ .row = .{ 0, 1, 2, 3 }, .siblings = &.{leaf1} },
        .{ .row = .{ 4, 5, 6, 7 }, .siblings = &.{leaf0} },
    }));
    try std.testing.expectError(error.UnexpectedStage, verifier.drawQueries(8, 1));
}

test "both adjacent line rows use private sampled pair indices on both tracks" {
    const allocator = std.testing.allocator;
    const zero = [_]u8{0} ** 32;
    const profile = descriptor.lineHashProfileDigest();
    const columns = [_]Digest32{ zero, [_]u8{1} ** 32, [_]u8{2} ** 32, [_]u8{3} ** 32 };
    const trees = [_]descriptor.LineTreeDescriptorV2{
        .{ .key_digest = zero, .profile_digest = profile, .track = .original, .fold_height = 3, .tree_log_size = 2, .root_event = 17, .column_descriptors = &columns },
        .{ .key_digest = zero, .profile_digest = profile, .track = .own_quotient, .fold_height = 3, .tree_log_size = 2, .root_event = 18, .column_descriptors = &columns },
    };
    const manifest = descriptor.LineTreeManifestV2{ .key_digest = zero, .fold_heights = &.{ 3, 2 }, .trees = &trees };
    const verifier = try OwnedPairedGateVerifierV2.init(allocator, manifest, try testStatement(manifest, allocator));
    defer verifier.deinit();
    const line_hash = @import("blake2s_personalized_line_v2.zig");
    const rows = [4][4]u32{
        .{ 0, 1, 2, 3 }, .{ 4, 5, 6, 7 }, .{ 8, 9, 10, 11 }, .{ 12, 13, 14, 15 },
    };
    var leaves: [4]Digest32 = undefined;
    for (rows, &leaves) |row, *leaf| leaf.* = try line_hash.hashCanonicalRow(&row);
    const parent01 = line_hash.LineMerkleHasherV2.hashChildren(.{ .left = leaves[0], .right = leaves[1] });
    const parent23 = line_hash.LineMerkleHasherV2.hashChildren(.{ .left = leaves[2], .right = leaves[3] });
    const root = line_hash.LineMerkleHasherV2.hashChildren(.{ .left = parent01, .right = parent23 });
    const paths = [4][2]Digest32{
        .{ leaves[1], parent23 }, .{ leaves[0], parent23 },
        .{ leaves[3], parent01 }, .{ leaves[2], parent01 },
    };
    try verifier.mixFixedRoot(zero);
    try verifier.mixCircuitIdentity(zero);
    try verifier.mixPublicValues(&.{ 0, 1, 2, 3 });
    try verifier.mixMainRoot(zero);
    _ = try verifier.beginInteractionPow(0);
    try verifier.acceptInteractionNonce(0);
    _ = try verifier.drawLookupPair();
    try verifier.mixInteractionClaim(&.{ 0, 1, 2, 3 });
    try verifier.mixInteractionRoot(zero);
    _ = try verifier.drawCompositionGamma();
    try verifier.mixCompositionRoot(zero);
    _ = try verifier.drawOodsSeed();
    try verifier.mixSampledValues(&.{ 0, 1, 2, 3 });
    _ = try verifier.drawBatchLambda();
    _ = try verifier.drawFoldAlpha();
    try verifier.captureOriginalLineRoot(root);
    try verifier.captureOwnQuotientLineRoot(root);
    _ = try verifier.drawFoldAlpha();
    try verifier.mixOriginalTerminalCoefficients(&.{ 0, 1, 2, 3 });
    try verifier.mixOwnQuotientTerminalCoefficients(&.{ 0, 1, 2, 3 });
    _ = try verifier.beginFriPow(0);
    try verifier.acceptFriNonce(0);
    try verifier.drawQueries(8, 1);
    var seen = [2]bool{ false, false };
    for (0..8) |ordinal| {
        const raw = try verifier.queryPosition(ordinal);
        try std.testing.expect(raw < 8);
        const base = (raw >> 1) & ~@as(usize, 1);
        seen[base / 2] = true;
        const openings = [2]LineRowOpeningV2{
            .{ .row = rows[base], .siblings = &paths[base] },
            .{ .row = rows[base + 1], .siblings = &paths[base + 1] },
        };
        const both = try verifier.verifyAndReadBothTrackPairs(0, ordinal, .{ openings, openings });
        for (0..2) |track| {
            const pair = both[track];
            for (0..2) |side| {
                const coordinates = pair[side].toM31Array();
                for (0..4) |coordinate|
                    try std.testing.expectEqual(rows[base + side][coordinate], coordinates[coordinate].v);
            }
            // Replaying the first path as its neighbor cannot authenticate.
            const wrong_neighbor = [2]LineRowOpeningV2{ openings[0], openings[0] };
            try std.testing.expectError(error.InvalidLinePath, verifier.verifyAndReadLinePair(track, ordinal, wrong_neighbor));
        }
        const wrong_neighbor = [2]LineRowOpeningV2{ openings[0], openings[0] };
        try std.testing.expectError(error.InvalidLinePath, verifier.verifyAndReadBothTrackPairs(0, ordinal, .{ openings, wrong_neighbor }));
        var noncanonical = openings;
        noncanonical[1].row[0] = m31.Modulus;
        try std.testing.expectError(error.NonCanonicalRow, verifier.verifyAndReadLinePair(0, ordinal, noncanonical));
    }
    try std.testing.expect(seen[0] and seen[1]);
    try std.testing.expectError(error.InvalidQueryIndex, verifier.verifyAndReadLinePair(0, 8, .{
        .{ .row = rows[0], .siblings = &paths[0] },
        .{ .row = rows[1], .siblings = &paths[1] },
    }));
    try std.testing.expectError(error.InvalidTreeIndex, verifier.verifyAndReadBothTrackPairs(1, 0, .{
        .{ .{ .row = rows[0], .siblings = &paths[0] }, .{ .row = rows[1], .siblings = &paths[1] } },
        .{ .{ .row = rows[0], .siblings = &paths[0] }, .{ .row = rows[1], .siblings = &paths[1] } },
    }));
}

test "owned verifier rejects mismatched statement before transcript events" {
    const allocator = std.testing.allocator;
    const zero = [_]u8{0} ** 32;
    const manifest = descriptor.LineTreeManifestV2{ .key_digest = zero, .fold_heights = &.{17}, .trees = &.{} };
    var statement = try testStatement(manifest, allocator);
    statement.line_profile_digest = zero;
    try std.testing.expectError(error.StatementMismatch, OwnedPairedGateVerifierV2.init(allocator, manifest, statement));
}

test "owned verifier rejects inconsistent fold and line-tree geometry" {
    const allocator = std.testing.allocator;
    const zero = [_]u8{0} ** 32;
    const profile = descriptor.lineHashProfileDigest();
    const columns = [_]Digest32{zero};
    var trees = [_]descriptor.LineTreeDescriptorV2{
        .{ .key_digest = zero, .profile_digest = profile, .track = .original, .fold_height = 3, .tree_log_size = 2, .root_event = 17, .column_descriptors = &columns },
        .{ .key_digest = zero, .profile_digest = profile, .track = .own_quotient, .fold_height = 3, .tree_log_size = 2, .root_event = 18, .column_descriptors = &columns },
    };
    var heights = [_]u32{ 3, 1 };
    const manifest = descriptor.LineTreeManifestV2{ .key_digest = zero, .fold_heights = &heights, .trees = &trees };
    try std.testing.expectError(error.InvalidQueryGeometry, OwnedPairedGateVerifierV2.init(
        allocator,
        manifest,
        try testStatement(manifest, allocator),
    ));
    heights[1] = 2;
    trees[0].tree_log_size = 1;
    try std.testing.expectError(error.InvalidQueryGeometry, OwnedPairedGateVerifierV2.init(
        allocator,
        manifest,
        try testStatement(manifest, allocator),
    ));
}

test "zero queries are rejected and failed query sampling is terminal" {
    const allocator = std.testing.allocator;
    const zero = [_]u8{0} ** 32;
    const manifest = descriptor.LineTreeManifestV2{ .key_digest = zero, .fold_heights = &.{2}, .trees = &.{} };
    const verifier = try OwnedPairedGateVerifierV2.init(allocator, manifest, try testStatement(manifest, allocator));
    defer verifier.deinit();
    try verifier.mixFixedRoot(zero);
    try verifier.mixCircuitIdentity(zero);
    try verifier.mixPublicValues(&.{ 0, 1, 2, 3 });
    try verifier.mixMainRoot(zero);
    _ = try verifier.beginInteractionPow(0);
    try verifier.acceptInteractionNonce(0);
    _ = try verifier.drawLookupPair();
    try verifier.mixInteractionClaim(&.{ 0, 1, 2, 3 });
    try verifier.mixInteractionRoot(zero);
    _ = try verifier.drawCompositionGamma();
    try verifier.mixCompositionRoot(zero);
    _ = try verifier.drawOodsSeed();
    try verifier.mixSampledValues(&.{ 0, 1, 2, 3 });
    _ = try verifier.drawBatchLambda();
    _ = try verifier.drawFoldAlpha();
    try verifier.mixOriginalTerminalCoefficients(&.{ 0, 1, 2, 3 });
    try verifier.mixOwnQuotientTerminalCoefficients(&.{ 0, 1, 2, 3 });
    _ = try verifier.beginFriPow(0);
    try verifier.acceptFriNonce(0);
    const before = verifier.nextEvent();
    try std.testing.expectError(error.ZeroQueries, verifier.drawQueries(0, 0));
    try std.testing.expectEqual(before, verifier.nextEvent());
    // Beginning terminal queries commits the plan to completion. A sampler
    // budget failure cannot be retried with a more favorable configuration.
    try std.testing.expectError(error.InsufficientBlockBudget, verifier.drawQueries(1, 0));
    try std.testing.expectEqual(before + 1, verifier.nextEvent());
    try std.testing.expectError(error.QueriesNotDrawn, verifier.queryCount());
    try std.testing.expectError(error.UnexpectedStage, verifier.drawQueries(1, 1));
}

const TestSourceTree = struct {
    count: usize,
    values: [8][4]m31.M31,
    parents: [2]Digest32,
    root: Digest32,

    fn init(count: usize, offset: u32) TestSourceTree {
        var self: TestSourceTree = undefined;
        self.count = count;
        for (0..count) |column| for (0..4) |row| {
            self.values[column][row] = m31.M31.fromCanonical(offset + @as(u32, @intCast(4 * column + row)));
        };
        var leaves: [4]Digest32 = undefined;
        for (&leaves, 0..) |*leaf, row| {
            var hasher = source_merkle.SourceMerkleHasherV2.defaultWithInitialState();
            for (0..count) |column| hasher.updateLeaf(self.values[column][row .. row + 1]);
            leaf.* = hasher.finalize();
        }
        self.parents[0] = source_merkle.SourceMerkleHasherV2.hashChildren(.{ .left = leaves[0], .right = leaves[1] });
        self.parents[1] = source_merkle.SourceMerkleHasherV2.hashChildren(.{ .left = leaves[2], .right = leaves[3] });
        self.root = source_merkle.SourceMerkleHasherV2.hashChildren(.{ .left = self.parents[0], .right = self.parents[1] });
        return self;
    }

    fn opening(
        self: *const TestSourceTree,
        base: usize,
        columns: *[8][2]m31.M31,
        witness: *[1]Digest32,
    ) SourceTreePairOpeningV2 {
        for (columns[0..self.count], 0..) |*pair, column| {
            pair.* = .{ self.values[column][base], self.values[column][base + 1] };
        }
        witness[0] = self.parents[1 - base / 2];
        return .{ .columns = columns[0..self.count], .hash_witness = witness };
    }
};

fn h1SourceRoster() SourceRosterV2 {
    const one = &[_]u32{2};
    const eight = &[_]u32{2} ** 8;
    const first = &[_]Digest32{[_]u8{0x11} ** 32};
    const second = &[_]Digest32{[_]u8{0x22} ** 32};
    const third = &[_]Digest32{[_]u8{0x33} ** 32};
    const fourth = &[_]Digest32{
        [_]u8{0x40} ** 32, [_]u8{0x41} ** 32, [_]u8{0x42} ** 32, [_]u8{0x43} ** 32,
        [_]u8{0x44} ** 32, [_]u8{0x45} ** 32, [_]u8{0x46} ** 32, [_]u8{0x47} ** 32,
    };
    return .{
        .column_log_sizes = .{ one, one, one, eight },
        .column_descriptors = .{ first, second, third, fourth },
    };
}

fn h1SourceStatement(manifest: descriptor.LineTreeManifestV2, allocator: std.mem.Allocator) !framed.StatementBinding {
    var statement = try testStatement(manifest, allocator);
    const roster = h1SourceRoster();
    for (&statement.source_tree_descriptors, 0..) |*digest, tree|
        digest.* = try sourceRosterDigest(
            statement.key_digest,
            2,
            tree,
            roster.column_log_sizes[tree],
            roster.column_descriptors[tree],
        );
    return statement;
}

test "source descriptor bytes match independent Python and bind ordered identities" {
    const zero = [_]u8{0} ** 32;
    const id_a = [_]u8{0x11} ** 32;
    const id_b = [_]u8{0x22} ** 32;
    var expected: Digest32 = undefined;
    _ = try std.fmt.hexToBytes(&expected, "c240d76f253dc370bb3f2b7e44241b2ab032bc657b806a7bd632963825ac6027");
    try std.testing.expectEqualDeep(expected, try sourceRosterDigest(zero, 2, 0, &.{2}, &.{id_a}));
    _ = try std.fmt.hexToBytes(&expected, "4094bee38e32da96e5527a489338f3adcb84706636592b677805c4ae89c019cc");
    try std.testing.expectEqualDeep(expected, try sourceRosterDigest(zero, 2, 1, &.{2}, &.{id_b}));
    const ordered = try sourceRosterDigest(zero, 2, 0, &.{ 2, 2 }, &.{ id_a, id_b });
    const swapped = try sourceRosterDigest(zero, 2, 0, &.{ 2, 2 }, &.{ id_b, id_a });
    try std.testing.expect(!std.mem.eql(u8, &ordered, &swapped));
    try std.testing.expectError(error.InvalidSourceRoster, sourceRosterDigest(zero, 2, 0, &.{ 2, 2 }, &.{ id_a, id_a }));
    try std.testing.expectError(error.InvalidSourceRoster, sourceRosterDigest(zero, 2, 0, &.{2}, &.{}));
}

fn advanceH1Source(
    allocator: std.mem.Allocator,
    manifest: descriptor.LineTreeManifestV2,
    statement: framed.StatementBinding,
    roots: [4]Digest32,
    claims: []const u32,
) !*OwnedPairedGateVerifierV2 {
    const verifier = try OwnedPairedGateVerifierV2.initWithSourceRoster(allocator, manifest, statement, h1SourceRoster());
    errdefer verifier.deinit();
    try verifier.mixFixedRoot(roots[0]);
    try verifier.mixCircuitIdentity([_]u8{0} ** 32);
    try verifier.mixPublicValues(&.{ 0, 1, 2, 3 });
    try verifier.mixMainRoot(roots[1]);
    _ = try verifier.beginInteractionPow(0);
    try verifier.acceptInteractionNonce(0);
    _ = try verifier.drawLookupPair();
    try verifier.mixInteractionClaim(&.{ 0, 1, 2, 3 });
    try verifier.mixInteractionRoot(roots[2]);
    _ = try verifier.drawCompositionGamma();
    try verifier.mixCompositionRoot(roots[3]);
    _ = try verifier.drawOodsSeed();
    try verifier.mixSampledValues(claims);
    _ = try verifier.drawBatchLambda();
    _ = try verifier.drawFoldAlpha();
    try verifier.mixOriginalTerminalCoefficients(&.{ 0, 1, 2, 3 });
    try verifier.mixOwnQuotientTerminalCoefficients(&.{ 0, 1, 2, 3 });
    _ = try verifier.beginFriPow(0);
    try verifier.acceptFriNonce(0);
    try verifier.drawQueries(1, 1);
    return verifier;
}

test "owned H1 source pair authenticates four roots and derives OOD insertions" {
    const allocator = std.testing.allocator;
    const zero = [_]u8{0} ** 32;
    const manifest = descriptor.LineTreeManifestV2{ .key_digest = zero, .fold_heights = &.{2}, .trees = &.{} };
    const statement = try h1SourceStatement(manifest, allocator);
    const trees = [4]TestSourceTree{
        TestSourceTree.init(1, 1),  TestSourceTree.init(1, 10),
        TestSourceTree.init(1, 20), TestSourceTree.init(8, 30),
    };
    const roots = [4]Digest32{ trees[0].root, trees[1].root, trees[2].root, trees[3].root };
    const claims = [_]u32{0} ** (4 * 11);
    const verifier = try advanceH1Source(allocator, manifest, statement, roots, &claims);
    defer verifier.deinit();
    try std.testing.expectError(error.SourceContextMissing, verifier.sourceInsertionAt(0));
    const raw = try verifier.queryPosition(0);
    const base = raw & ~@as(usize, 1);
    var columns: [4][8][2]m31.M31 = undefined;
    var witnesses: [4][1]Digest32 = undefined;
    var openings: [4]SourceTreePairOpeningV2 = undefined;
    for (&openings, &trees, &columns, &witnesses) |*opening, *tree, *cols, *witness|
        opening.* = tree.opening(base, cols, witness);
    try verifier.verifyAndKeepSourcePair(0, openings);
    const inserted = try verifier.sourceInsertionAt(0);
    try std.testing.expect(!inserted[0][0].isZero());
    try std.testing.expectError(error.SourceAlreadyVerified, verifier.verifyAndKeepSourcePair(0, openings));
    try std.testing.expectError(error.InvalidQueryIndex, verifier.verifyAndKeepSourcePair(1, openings));

    // A complete honest path for the other source pair cannot be replayed at
    // this sampled query ordinal. The caller has no leaf-index parameter.
    const wrong_base = 2 - base;
    for (&openings, &trees, &columns, &witnesses) |*opening, *tree, *cols, *witness|
        opening.* = tree.opening(wrong_base, cols, witness);
    const wrong_index = try advanceH1Source(allocator, manifest, statement, roots, &claims);
    defer wrong_index.deinit();
    try std.testing.expectError(error.RootMismatch, wrong_index.verifyAndKeepSourcePair(0, openings));

    for (&openings, &trees, &columns, &witnesses) |*opening, *tree, *cols, *witness|
        opening.* = tree.opening(base, cols, witness);

    var altered = openings;
    var changed_columns = columns[0];
    changed_columns[0][0] = m31.M31.fromCanonical(999);
    altered[0].columns = changed_columns[0..1];
    const fresh = try advanceH1Source(allocator, manifest, statement, roots, &claims);
    defer fresh.deinit();
    try std.testing.expectError(error.RootMismatch, fresh.verifyAndKeepSourcePair(0, altered));

    var wrong_roots = roots;
    wrong_roots[0][0] ^= 1;
    const wrong_root = try advanceH1Source(allocator, manifest, statement, wrong_roots, &claims);
    defer wrong_root.deinit();
    // Its transcript may select a different raw pair; rebuild honest rows
    // for that position while keeping the original authenticated tree root.
    const wrong_root_base = (try wrong_root.queryPosition(0)) & ~@as(usize, 1);
    for (&openings, &trees, &columns, &witnesses) |*opening, *tree, *cols, *witness|
        opening.* = tree.opening(wrong_root_base, cols, witness);
    try std.testing.expectError(error.RootMismatch, wrong_root.verifyAndKeepSourcePair(0, openings));

    // A canonical but false OOD claim is bound to a different transcript
    // and changes the inserted quotient. Local source paths alone cannot
    // reject it; the later fold/degree equation must do that.
    var changed_claims = claims;
    changed_claims[0] = 1;
    const changed_claim = try advanceH1Source(allocator, manifest, statement, roots, &changed_claims);
    defer changed_claim.deinit();
    const changed_base = (try changed_claim.queryPosition(0)) & ~@as(usize, 1);
    for (&openings, &trees, &columns, &witnesses) |*opening, *tree, *cols, *witness|
        opening.* = tree.opening(changed_base, cols, witness);
    try changed_claim.verifyAndKeepSourcePair(0, openings);
    try std.testing.expect(!std.mem.eql(u8, &changed_claim.transcriptDigest(), &verifier.transcriptDigest()));
}

test "H1 source admission rejects unbound roster, lower height and wrong claim shape" {
    const allocator = std.testing.allocator;
    const zero = [_]u8{0} ** 32;
    const manifest = descriptor.LineTreeManifestV2{ .key_digest = zero, .fold_heights = &.{2}, .trees = &.{} };
    const statement = try h1SourceStatement(manifest, allocator);
    var wrong_statement = statement;
    wrong_statement.source_tree_descriptors[0][0] ^= 1;
    try std.testing.expectError(error.SourceStatementMismatch, OwnedPairedGateVerifierV2.initWithSourceRoster(
        allocator,
        manifest,
        wrong_statement,
        h1SourceRoster(),
    ));
    var lower = h1SourceRoster();
    lower.column_log_sizes[0] = &.{1};
    try std.testing.expectError(error.InvalidSourceRoster, OwnedPairedGateVerifierV2.initWithSourceRoster(
        allocator,
        manifest,
        statement,
        lower,
    ));

    const verifier = try OwnedPairedGateVerifierV2.initWithSourceRoster(allocator, manifest, statement, h1SourceRoster());
    defer verifier.deinit();
    try verifier.mixFixedRoot(zero);
    try verifier.mixCircuitIdentity(zero);
    try verifier.mixPublicValues(&.{ 0, 1, 2, 3 });
    try verifier.mixMainRoot(zero);
    _ = try verifier.beginInteractionPow(0);
    try verifier.acceptInteractionNonce(0);
    _ = try verifier.drawLookupPair();
    try verifier.mixInteractionClaim(&.{ 0, 1, 2, 3 });
    try verifier.mixInteractionRoot(zero);
    _ = try verifier.drawCompositionGamma();
    try verifier.mixCompositionRoot(zero);
    _ = try verifier.drawOodsSeed();
    const before = verifier.nextEvent();
    try std.testing.expectError(error.InvalidSourcePairShape, verifier.mixSampledValues(&.{ 0, 1, 2, 3 }));
    try std.testing.expectEqual(before, verifier.nextEvent());
    var noncanonical = [_]u32{0} ** (4 * 11);
    noncanonical[0] = m31.Modulus;
    try std.testing.expectError(error.InvalidFieldLimbs, verifier.mixSampledValues(&noncanonical));
    try std.testing.expectEqual(before, verifier.nextEvent());
}
