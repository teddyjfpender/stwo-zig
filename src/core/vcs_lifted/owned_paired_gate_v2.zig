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
const line = @import("../poly/line.zig");
const core_utils = @import("../utils.zig");
const source_merkle = @import("blake2s_personalized_source_v2.zig");
const lifted_verifier = @import("verifier.zig");
const row_context = @import("../pcs/paired_row_context_v2.zig");
const paired_claim_rows = @import("../pcs/paired_claim_rows_v2.zig");
const paired_claim_batch = @import("../pcs/paired_claim_batch_v2.zig");
const h3_projection = @import("sparse_h3_source_projection_v2.zig");
const quotients = @import("../pcs/quotients.zig");
const pcs_utils = @import("../pcs/utils.zig");
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
    UnsupportedH1FoldProfile,
    InvalidTerminalShape,
    FoldContextMissing,
    InvalidQueryProjection,
    OriginalIntermediateFoldMismatch,
    QuotientIntermediateFoldMismatch,
    OriginalTerminalFoldMismatch,
    QuotientTerminalFoldMismatch,
    UnsupportedSparseH3Profile,
    SparseSourceAlreadyVerified,
    InvalidSparseClaimLayout,
    SourceEnsembleNotAdmitted,
    CommittedFoldsNotChecked,
} || plan_mod.Error || admission.Error || uniform.Error || row_context.Error ||
    lifted_verifier.MerkleVerificationError || lifted_verifier.TreeHeightError ||
    qm31.QM31.Error || m31.M31.Error || h3_projection.Error;

pub const source_tree_count: usize = 4;
pub const max_source_columns: usize = 256;
pub const source_roster_magic = "S31SRC2V";
pub const source_root_events = [source_tree_count]u64{ 1, 4, 10, 12 };
pub const SourceRosterV2 = struct {
    column_log_sizes: [source_tree_count][]const u32,
    column_descriptors: [source_tree_count][]const Digest32,
};

/// One or two key-derived mask offsets for a source column. For accepted
/// sparse Gate, exactly twelve interaction columns have two samples.
pub const SparseH3MaskOffsetsV2 = struct {
    count: u8,
    values: [2]i32,
};

pub const SparseH3SourceRosterV2 = struct {
    column_log_sizes: [source_tree_count][]const u32,
    column_descriptors: [source_tree_count][]const Digest32,
    mask_offsets: [source_tree_count][]const SparseH3MaskOffsetsV2,
    mask_log: u32,
};

/// Local candidate occupancy receipt. These counts are not a paper batch
/// width: the native quotient evaluator inserts one extra periodicity sample
/// for each two-sample column, while the original track uses one source value
/// per column. Therefore the current two tracks do not implement Protocol 4
/// Eq. (77)'s matching per-claim original/quotient ensemble.
pub const SparseH3TermCountsV2 = struct {
    original_by_height: [3]usize,
    explicit_claims_by_height: [3]usize,
    periodic_by_height: [3]usize,
    quotient_by_height: [3]usize,
};

const SourceMode = enum { h1, sparse_h3 };

const OwnedSourceRoster = struct {
    logs: [source_tree_count][max_source_columns]u32,
    offsets: [source_tree_count][max_source_columns]SparseH3MaskOffsetsV2,
    counts: [source_tree_count]usize,
    total: usize,
    claim_total: usize,
    term_counts: SparseH3TermCountsV2,
    mask_log: u32,
    mode: SourceMode,

    fn init(statement: framed.StatementBinding, query_log: u32, roster: SourceRosterV2) Error!OwnedSourceRoster {
        var out: OwnedSourceRoster = undefined;
        out.total = 0;
        out.claim_total = 0;
        out.term_counts = .{
            .original_by_height = .{ 0, 0, 0 },
            .explicit_claims_by_height = .{ 0, 0, 0 },
            .periodic_by_height = .{ 0, 0, 0 },
            .quotient_by_height = .{ 0, 0, 0 },
        };
        out.mask_log = 0;
        out.mode = .h1;
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
            out.claim_total += logs.len;
        }
        return out;
    }

    fn initSparseH3(statement: framed.StatementBinding, query_log: u32, roster: SparseH3SourceRosterV2) Error!OwnedSourceRoster {
        if (query_log != 17 or roster.mask_log != 16) return error.UnsupportedSparseH3Profile;
        try h3_projection.validateAcceptedH3Logs(roster.column_log_sizes);
        var out: OwnedSourceRoster = undefined;
        out.total = 0;
        out.claim_total = 0;
        out.term_counts = .{
            .original_by_height = .{ 0, 0, 0 },
            .explicit_claims_by_height = .{ 0, 0, 0 },
            .periodic_by_height = .{ 0, 0, 0 },
            .quotient_by_height = .{ 0, 0, 0 },
        };
        out.mask_log = roster.mask_log;
        out.mode = .sparse_h3;
        for (roster.column_log_sizes, 0..) |logs, tree| {
            const identities = roster.column_descriptors[tree];
            const offsets = roster.mask_offsets[tree];
            if (identities.len != logs.len or offsets.len != logs.len or
                logs.len > max_source_columns - out.total)
                return error.InvalidSparseClaimLayout;
            for (offsets, 0..) |entry, col| {
                const has_two = tree == 2 and ((col >= 4 and col <= 7) or col >= 16);
                if (entry.count != @as(u8, if (has_two) 2 else 1) or
                    (entry.count == 1 and entry.values[1] != 0))
                    return error.InvalidSparseClaimLayout;
                const slot: usize = switch (logs[col]) {
                    17 => 0,
                    11 => 1,
                    5 => 2,
                    else => return error.InvalidSparseClaimLayout,
                };
                out.term_counts.original_by_height[slot] += 1;
                out.term_counts.explicit_claims_by_height[slot] += entry.count;
                out.term_counts.periodic_by_height[slot] += @intFromBool(has_two);
                out.term_counts.quotient_by_height[slot] += entry.count + @as(usize, @intFromBool(has_two));
                out.claim_total += entry.count;
            }
            const digest = try sparseH3SourceRosterDigest(
                statement.key_digest,
                query_log,
                roster.mask_log,
                tree,
                logs,
                identities,
                offsets,
            );
            if (!std.mem.eql(u8, &digest, &statement.source_tree_descriptors[tree]))
                return error.SourceStatementMismatch;
            out.counts[tree] = logs.len;
            @memcpy(out.logs[tree][0..logs.len], logs);
            @memcpy(out.offsets[tree][0..logs.len], offsets);
            out.total += logs.len;
        }
        if (out.total != 61 or out.claim_total != 73 or
            !std.mem.eql(usize, &out.term_counts.original_by_height, &.{ 14, 28, 19 }) or
            !std.mem.eql(usize, &out.term_counts.explicit_claims_by_height, &.{ 18, 32, 23 }) or
            !std.mem.eql(usize, &out.term_counts.periodic_by_height, &.{ 4, 4, 4 }) or
            !std.mem.eql(usize, &out.term_counts.quotient_by_height, &.{ 22, 36, 27 }))
            return error.InvalidSparseClaimLayout;
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

pub const sparse_h3_roster_magic = "S31SRC3V";

/// Versioned source descriptor for the accepted sparse H3 shape. Its mask
/// offsets are *instructions*, not proof-supplied sample points. A selected
/// S31 adapter must derive every identity, log and offset from its sealed key.
pub fn sparseH3SourceRosterDigest(
    key_digest: Digest32,
    query_log: u32,
    mask_log: u32,
    tree: usize,
    logs: []const u32,
    identities: []const Digest32,
    offsets: []const SparseH3MaskOffsetsV2,
) Error!Digest32 {
    if (tree >= source_tree_count or query_log != 17 or mask_log != 16 or
        logs.len == 0 or logs.len > max_source_columns or
        identities.len != logs.len or offsets.len != logs.len)
        return error.InvalidSparseClaimLayout;
    for (identities, 0..) |identity, i| {
        for (identities[0..i]) |earlier|
            if (std.mem.eql(u8, &identity, &earlier)) return error.InvalidSparseClaimLayout;
    }
    var bytes: [8 + source_merkle.profile_id.len + 8 + 8 + 32 + 1 + 8 + 4 + 4 + 4 + 45 * max_source_columns]u8 = undefined;
    var at: usize = 0;
    @memcpy(bytes[at..][0..8], sparse_h3_roster_magic);
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
    std.mem.writeInt(u32, bytes[at..][0..4], mask_log, .little);
    at += 4;
    std.mem.writeInt(u32, bytes[at..][0..4], @intCast(logs.len), .little);
    at += 4;
    for (logs, identities, offsets, 0..) |log, identity, offset, col| {
        const has_two = tree == 2 and ((col >= 4 and col <= 7) or col >= 16);
        if ((log != 17 and log != 11 and log != 5) or
            offset.count != @as(u8, if (has_two) 2 else 1) or
            (offset.count == 1 and offset.values[1] != 0))
            return error.InvalidSparseClaimLayout;
        std.mem.writeInt(u32, bytes[at..][0..4], log, .little);
        at += 4;
        @memcpy(bytes[at..][0..32], &identity);
        at += 32;
        bytes[at] = offset.count;
        at += 1;
        for (offset.values) |value| {
            std.mem.writeInt(i32, bytes[at..][0..4], value, .little);
            at += 4;
        }
    }
    return framed.hashFrameParts(.tree_context, 0, &.{bytes[0..at]});
}

pub const SourceTreePairOpeningV2 = struct {
    /// One pair per key-owned column, in its exact source descriptor order.
    columns: []const [2]m31.M31,
    hash_witness: []Digest32,
};

pub const SourcePairWordsV2 = [2][2]qm31.QM31;
pub const SparseH3PairWordsV2 = [3]SourcePairWordsV2;

/// One literal `(f, own quotient)` pair for each explicit OOD claim. Double-
/// sample columns repeat the *same authenticated source value* under distinct
/// claim indices. This does not include legacy periodicity contributions.
pub const SparseH3LiteralClaimV2 = paired_claim_batch.ClaimRecord;

const SparseH3LiteralClaimRowsV2 = [73]SparseH3LiteralClaimV2;

fn qm31FromLimbs(limbs: [4]u32) qm31.QM31 {
    var coordinates: [4]m31.M31 = undefined;
    for (limbs, &coordinates) |limb, *coordinate| coordinate.* = m31.M31.fromCanonical(limb);
    return qm31.QM31.fromM31Array(coordinates);
}

fn foldPair(even: qm31.QM31, odd: qm31.QM31, coordinate: m31.M31, alpha: qm31.QM31) Error!qm31.QM31 {
    return even.add(odd).add(alpha.mul(even.sub(odd).mulM31(try coordinate.inv())));
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
    sparse_h3_insertions: ?[]?SparseH3PairWordsV2 = null,
    literal_h3_claim_rows: ?[]?*SparseH3LiteralClaimRowsV2 = null,
    // Eq. (66) arithmetic receipt only. It cannot admit the fold ensemble.
    weighted_h3_diagnostics: ?[]?SparseH3PairWordsV2 = null,
    // Separate from the 61/85 diagnostic rows. No public constructor fills
    // this until a matched, authenticated per-claim ensemble is specified.
    paired_h3_insertions: ?[]?SparseH3PairWordsV2 = null,
    h3_fold_checked: ?[]u16 = null,
    batch_lambda: ?qm31.QM31 = null,
    fold_alphas: [plan_mod.max_fold_heights]qm31.QM31 = undefined,
    fold_alpha_count: usize = 0,
    terminal_coefficients: [2]?qm31.QM31 = .{ null, null },
    h3_terminal_coefficients: [2]?[2]qm31.QM31 = .{ null, null },
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
        return initInternal(allocator, manifest, statement, null, null);
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
        return initInternal(allocator, manifest, statement, roster, null);
    }

    /// Accepted sparse Gate H3 *shape* candidate. The external S31 adapter
    /// still must derive this roster and its mask offsets from a sealed key.
    /// Production plain roots cannot be reused under the personalized source
    /// profile named in these descriptors.
    pub fn initWithSparseH3SourceRoster(
        allocator: std.mem.Allocator,
        manifest: descriptor.LineTreeManifestV2,
        statement: framed.StatementBinding,
        roster: SparseH3SourceRosterV2,
    ) Error!*Self {
        return initInternal(allocator, manifest, statement, null, roster);
    }

    fn initInternal(
        allocator: std.mem.Allocator,
        manifest: descriptor.LineTreeManifestV2,
        statement: framed.StatementBinding,
        roster: ?SourceRosterV2,
        sparse_roster: ?SparseH3SourceRosterV2,
    ) Error!*Self {
        if (roster != null and sparse_roster != null) return error.InvalidSourceRoster;
        // A one-bit FRI fold at each committed height has a line tree at the
        // next height. The raw query is sampled over the first fold height.
        // This is checked geometry, not a sealed-key derivation.
        try manifest.validate();
        const query_log_size = manifest.fold_heights[0];
        if (query_log_size < 2 or query_log_size > 30) return error.InvalidQueryGeometry;
        for (manifest.fold_heights[1..], 1..) |height, i| {
            if (height + 1 != manifest.fold_heights[i - 1]) return error.InvalidQueryGeometry;
        }
        if (sparse_roster != null and
            (query_log_size != 17 or manifest.fold_heights.len < 14 or
                manifest.fold_heights[12] != 5 or manifest.fold_heights[13] != 4))
            return error.UnsupportedSparseH3Profile;
        for (manifest.trees, 0..) |tree, i| {
            const fold_height = manifest.fold_heights[i / 2];
            if (fold_height < 2 or tree.tree_log_size != fold_height - 1)
                return error.InvalidQueryGeometry;
        }
        const owned_roster = if (roster) |input|
            try OwnedSourceRoster.init(statement, query_log_size, input)
        else if (sparse_roster) |input|
            try OwnedSourceRoster.initSparseH3(statement, query_log_size, input)
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
        state.sparse_h3_insertions = null;
        state.literal_h3_claim_rows = null;
        state.weighted_h3_diagnostics = null;
        state.paired_h3_insertions = null;
        state.h3_fold_checked = null;
        state.batch_lambda = null;
        state.fold_alpha_count = 0;
        state.terminal_coefficients = .{ null, null };
        state.h3_terminal_coefficients = .{ null, null };
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
        if (state.sparse_h3_insertions) |insertions| state.allocator.free(insertions);
        if (state.literal_h3_claim_rows) |rows| {
            for (rows) |maybe_row| if (maybe_row) |row| state.allocator.destroy(row);
            state.allocator.free(rows);
        }
        if (state.weighted_h3_diagnostics) |rows| state.allocator.free(rows);
        if (state.paired_h3_insertions) |insertions| state.allocator.free(insertions);
        if (state.h3_fold_checked) |checked| state.allocator.free(checked);
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
            if (state.ood_point == null or limbs.len != roster.claim_total * 4)
                return error.InvalidSourcePairShape;
        }
        try state.plan.mixSampledValues(limbs);
        if (state.source_roster) |roster| {
            for (0..roster.claim_total) |i| state.source_claims[i] = qm31FromLimbs(limbs[4 * i ..][0..4].*);
            state.source_claim_count = roster.claim_total;
        }
    }

    pub fn drawBatchLambda(self: *Self) Error![4]u32 {
        const state = self.privateState();
        const limbs = try state.plan.drawBatchLambda();
        if (state.source_roster) |roster| {
            if (state.source_claim_count != roster.claim_total) return error.SourceContextMissing;
            const point = state.ood_point orelse return error.SourceContextMissing;
            const batch = qm31FromLimbs(limbs);
            state.batch_lambda = batch;
            if (roster.mode == .h1) {
                state.source_context = try row_context.RowContextV2.init(
                    state.allocator,
                    point,
                    state.source_claims[0..roster.total],
                    batch,
                );
            }
        }
        return limbs;
    }

    pub fn drawFoldAlpha(self: *Self) Error![4]u32 {
        const state = self.privateState();
        const fold_index = state.plan.fold_index;
        const limbs = try state.plan.drawFoldAlpha();
        state.fold_alphas[fold_index] = qm31FromLimbs(limbs);
        state.fold_alpha_count = @max(state.fold_alpha_count, fold_index + 1);
        return limbs;
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
        const state = self.privateState();
        if (state.source_roster != null and state.plan.fold_count == 2 and limbs.len != 4)
            return error.InvalidTerminalShape;
        if (state.source_roster) |roster| {
            if (roster.mode == .sparse_h3 and (state.plan.fold_count != 14 or limbs.len != 8))
                return error.InvalidTerminalShape;
        }
        try state.plan.mixOriginalTerminalCoefficients(limbs);
        if (state.source_roster != null and state.plan.fold_count == 2)
            state.terminal_coefficients[0] = qm31FromLimbs(limbs[0..4].*);
        if (state.source_roster) |roster| {
            if (roster.mode == .sparse_h3)
                state.h3_terminal_coefficients[0] = .{ qm31FromLimbs(limbs[0..4].*), qm31FromLimbs(limbs[4..8].*) };
        }
    }

    pub fn mixOwnQuotientTerminalCoefficients(self: *Self, limbs: []const u32) Error!void {
        const state = self.privateState();
        if (state.source_roster != null and state.plan.fold_count == 2 and limbs.len != 4)
            return error.InvalidTerminalShape;
        if (state.source_roster) |roster| {
            if (roster.mode == .sparse_h3 and (state.plan.fold_count != 14 or limbs.len != 8))
                return error.InvalidTerminalShape;
        }
        try state.plan.mixOwnQuotientTerminalCoefficients(limbs);
        if (state.source_roster != null and state.plan.fold_count == 2)
            state.terminal_coefficients[1] = qm31FromLimbs(limbs[0..4].*);
        if (state.source_roster) |roster| {
            if (roster.mode == .sparse_h3)
                state.h3_terminal_coefficients[1] = .{ qm31FromLimbs(limbs[0..4].*), qm31FromLimbs(limbs[4..8].*) };
        }
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
        if (state.source_roster) |roster| {
            if (roster.mode == .h1) {
                const insertions = try state.allocator.alloc(?SourcePairWordsV2, n_queries);
                @memset(insertions, null);
                state.source_insertions = insertions;
            } else {
                const insertions = try state.allocator.alloc(?SparseH3PairWordsV2, n_queries);
                errdefer state.allocator.free(insertions);
                @memset(insertions, null);
                const literal_rows = try state.allocator.alloc(?*SparseH3LiteralClaimRowsV2, n_queries);
                errdefer state.allocator.free(literal_rows);
                @memset(literal_rows, null);
                const checked = try state.allocator.alloc(u16, n_queries);
                errdefer state.allocator.free(checked);
                @memset(checked, 0);
                const weighted = try state.allocator.alloc(?SparseH3PairWordsV2, n_queries);
                @memset(weighted, null);
                state.sparse_h3_insertions = insertions;
                state.literal_h3_claim_rows = literal_rows;
                state.h3_fold_checked = checked;
                state.weighted_h3_diagnostics = weighted;
            }
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
        if (roster.mode != .h1) return error.UnsupportedH1FoldProfile;
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

    /// Authenticate the top-height lifted source pair in all four captured
    /// roots, then privately compute a diagnostic original/native-quotient
    /// pair at each populated sparse height. This is not yet a degree-correct
    /// Eq. (77) insertion: the original uses 61 column terms while native
    /// friAnswers inserts periodic samples and uses 85 quotient terms.
    /// The lower circle row is derived by
    /// `((raw >> (k-h+1)) << 1) | (raw&1)`, and each claim point is doubled
    /// `k-h` times before its quotient denominator is evaluated at height h.
    /// This is a candidate local row join; it does not check FRI line equations
    /// or establish a native-to-paper batch-width mapping.
    pub fn verifyAndKeepSparseH3SourcePair(
        self: *Self,
        query_ordinal: usize,
        openings: [source_tree_count]SourceTreePairOpeningV2,
    ) Error!void {
        return self.verifyAndKeepSparseH3SourcePairInternal(query_ordinal, openings, .with_diagnostic);
    }

    /// Authenticate the same four source roots and retain only the literal
    /// 73 explicit-claim pairs. This skips the unrelated legacy periodic
    /// quotient computation. It still does not admit a fold ensemble.
    pub fn verifyAndKeepSparseH3LiteralClaimPairs(
        self: *Self,
        query_ordinal: usize,
        openings: [source_tree_count]SourceTreePairOpeningV2,
    ) Error!void {
        return self.verifyAndKeepSparseH3SourcePairInternal(query_ordinal, openings, .literal_only);
    }

    const SparseH3DerivationMode = enum { literal_only, with_diagnostic };

    fn verifyAndKeepSparseH3SourcePairInternal(
        self: *Self,
        query_ordinal: usize,
        openings: [source_tree_count]SourceTreePairOpeningV2,
        mode: SparseH3DerivationMode,
    ) Error!void {
        const state = self.privateState();
        const roster = if (state.source_roster) |*value| value else return error.SourceNotAdmitted;
        if (roster.mode != .sparse_h3 or state.query_log_size != 17)
            return error.UnsupportedSparseH3Profile;
        const queries = state.queries orelse return error.QueriesNotDrawn;
        if (query_ordinal >= queries.raw.len) return error.InvalidQueryIndex;
        const insertions = state.sparse_h3_insertions orelse return error.SourceContextMissing;
        const literal_slots = state.literal_h3_claim_rows orelse return error.SourceContextMissing;
        const weighted_slots = state.weighted_h3_diagnostics orelse return error.SourceContextMissing;
        if (insertions[query_ordinal] != null) return error.SparseSourceAlreadyVerified;
        if (literal_slots[query_ordinal] != null) return error.SparseSourceAlreadyVerified;
        if (weighted_slots[query_ordinal] != null) return error.SparseSourceAlreadyVerified;
        const sampled_point = state.ood_point orelse return error.SourceContextMissing;
        const lambda = state.batch_lambda orelse return error.SourceContextMissing;
        if (state.source_claim_count != roster.claim_total) return error.SourceContextMissing;
        const raw = queries.raw[query_ordinal];
        if (raw >= (@as(usize, 1) << 17)) return error.InvalidQueryGeometry;
        const base = raw & ~@as(usize, 1);
        const positions = [2]usize{ base, base + 1 };

        // These are native lifted leaves: every lower-height column is
        // included at the top raw leaf via the sign-preserving projection.
        // Merkle row width/order come from the admitted descriptor, not wire.
        for (openings, 0..) |opened, tree| {
            const root = state.source_roots[tree] orelse return error.RootNotCaptured;
            if (opened.columns.len != roster.counts[tree]) return error.InvalidSourcePairShape;
            var columns: [max_source_columns][]const m31.M31 = undefined;
            for (opened.columns, 0..) |*pair, col| {
                for (pair) |value| if (value.v >= m31.Modulus) return error.NonCanonicalSourceRow;
                columns[col] = pair[0..];
            }
            const verifier = lifted_verifier.MerkleVerifierLifted(source_merkle.SourceMerkleHasherV2){
                .root = root,
                .column_log_sizes = roster.logs[tree][0..roster.counts[tree]],
                .height = state.query_log_size,
            };
            try verifier.verify(state.allocator, &positions, columns[0..opened.columns.len], .{ .hash_witness = opened.hash_witness });
        }

        // A local arena bounds temporary per-height sample/quotient shapes.
        // The selected verifier should precompute and reuse quotient constants
        // before admitting this path; no performance claim is made here.
        var arena = std.heap.ArenaAllocator.init(state.allocator);
        defer arena.deinit();
        const a = arena.allocator();
        var claim_starts: [source_tree_count][max_source_columns]usize = undefined;
        var claim_at: usize = 0;
        for (0..source_tree_count) |tree| for (0..roster.counts[tree]) |col| {
            claim_starts[tree][col] = claim_at;
            claim_at += roster.offsets[tree][col].count;
        };
        if (claim_at != roster.claim_total) return error.InvalidSparseClaimLayout;

        // Literal explicit-claim pairs keep each source identity attached to
        // each of its one or two OOD claims. No native periodic sample enters
        // this array. It is a source-bound candidate receipt, not yet the
        // matched/batched fold ensemble required by Protocol 4.
        const literal = try state.allocator.create(SparseH3LiteralClaimRowsV2);
        errdefer state.allocator.destroy(literal);
        var claim_inputs: [73]paired_claim_rows.ClaimInput = undefined;
        var source_rows: [3][2]circle.CirclePointM31 = undefined;
        for (h3_projection.accepted_h3_logs, 0..) |height, slot| {
            const projected = try h3_projection.projectCirclePair(raw, 17, height);
            const domain = canonic.CanonicCoset.new(height).circleDomain();
            for (projected, 0..) |index, side|
                source_rows[slot][side] = domain.at(core_utils.bitReverseIndex(index, height));
        }
        const mask_step = canonic.CanonicCoset.new(roster.mask_log).step();
        for (0..source_tree_count) |tree| for (0..roster.counts[tree]) |col| {
            const height = roster.logs[tree][col];
            const slot: usize = switch (height) {
                17 => 0,
                11 => 1,
                5 => 2,
                else => return error.InvalidSparseClaimLayout,
            };
            const sample = roster.offsets[tree][col];
            for (0..sample.count) |j| {
                const index = claim_starts[tree][col] + j;
                const shift = mask_step.mulSigned(sample.values[j]);
                const top_point = sampled_point.add(.{
                    .x = qm31.QM31.fromBase(shift.x),
                    .y = qm31.QM31.fromBase(shift.y),
                });
                claim_inputs[index] = .{
                    .point = top_point.repeatedDouble(17 - height),
                    .claimed_value = state.source_claims[index],
                    .source_rows = source_rows[slot],
                    .source_values = openings[tree].columns[col],
                };
                literal[index] = .{
                    .root_index = @intCast(tree),
                    .column_index = @intCast(col),
                    .claim_index = @intCast(index),
                    .height = @intCast(height),
                    .words = undefined,
                };
            }
        };
        var literal_words: [73]paired_claim_rows.PairWords = undefined;
        paired_claim_rows.derive(&claim_inputs, &literal_words) catch return error.InvalidSparseClaimLayout;
        for (&literal_words, literal) |words, *record| record.words = words;
        const weighted = paired_claim_batch.deriveCandidate(literal, lambda) catch return error.InvalidSparseClaimLayout;
        if (mode == .literal_only) {
            literal_slots[query_ordinal] = literal;
            weighted_slots[query_ordinal] = weighted;
            return;
        }

        var derived: SparseH3PairWordsV2 = undefined;
        for (h3_projection.accepted_h3_logs, 0..) |height, slot| {
            const projected = try h3_projection.projectCirclePair(raw, 17, height);
            try h3_projection.checkCircleProjection(base, 17, height);
            try h3_projection.checkCircleProjection(base + 1, 17, height);
            var log_trees: [source_tree_count][]u32 = undefined;
            var point_trees: [source_tree_count][][]circle.CirclePointQM31 = undefined;
            var claim_trees: [source_tree_count][][]qm31.QM31 = undefined;
            var value_trees: [source_tree_count][][]m31.M31 = undefined;
            var original = [2]qm31.QM31{ qm31.QM31.zero(), qm31.QM31.zero() };
            var power = qm31.QM31.one();
            for (0..source_tree_count) |tree| {
                var count: usize = 0;
                for (roster.logs[tree][0..roster.counts[tree]]) |log|
                    if (log == height) {
                        count += 1;
                    };
                log_trees[tree] = try a.alloc(u32, count);
                point_trees[tree] = try a.alloc([]circle.CirclePointQM31, count);
                claim_trees[tree] = try a.alloc([]qm31.QM31, count);
                value_trees[tree] = try a.alloc([]m31.M31, count);
                var at: usize = 0;
                for (roster.logs[tree][0..roster.counts[tree]], 0..) |log, col| {
                    if (log != height) continue;
                    const sample = roster.offsets[tree][col];
                    log_trees[tree][at] = height;
                    point_trees[tree][at] = try a.alloc(circle.CirclePointQM31, sample.count);
                    claim_trees[tree][at] = try a.alloc(qm31.QM31, sample.count);
                    value_trees[tree][at] = try a.alloc(m31.M31, 2);
                    for (0..2) |side| {
                        const value = openings[tree].columns[col][side];
                        value_trees[tree][at][side] = value;
                        original[side] = original[side].add(power.mul(qm31.QM31.fromBase(value)));
                    }
                    power = power.mul(lambda);
                    for (0..sample.count) |j| {
                        const offset_point = canonic.CanonicCoset.new(roster.mask_log).step()
                            .mulSigned(sample.values[j]);
                        const point = sampled_point.add(.{
                            .x = qm31.QM31.fromBase(offset_point.x),
                            .y = qm31.QM31.fromBase(offset_point.y),
                        });
                        point_trees[tree][at][j] = point.repeatedDouble(17 - height);
                        claim_trees[tree][at][j] = state.source_claims[claim_starts[tree][col] + j];
                    }
                    at += 1;
                }
            }
            const answers = quotients.friAnswers(
                a,
                pcs_utils.TreeVec([]u32).initOwned(log_trees[0..]),
                pcs_utils.TreeVec([][]circle.CirclePointQM31).initOwned(point_trees[0..]),
                pcs_utils.TreeVec([][]qm31.QM31).initOwned(claim_trees[0..]),
                lambda,
                &projected,
                pcs_utils.TreeVec([][]m31.M31).initOwned(value_trees[0..]),
                height,
            ) catch |err| switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
                else => return error.InvalidSparseClaimLayout,
            };
            if (answers.len != 2) return error.InvalidSparseClaimLayout;
            for (0..2) |side| derived[slot][side] = .{ original[side], answers[side] };
        }
        literal_slots[query_ordinal] = literal;
        weighted_slots[query_ordinal] = weighted;
        insertions[query_ordinal] = derived;
    }

    /// A copy for diagnostics only. Fold verification must read the retained
    /// private insertion directly and check every configured query ordinal.
    pub fn sparseH3InsertionAt(self: *const Self, query_ordinal: usize) Error!SparseH3PairWordsV2 {
        const insertions = self.stateConst().sparse_h3_insertions orelse return error.SourceContextMissing;
        if (query_ordinal >= insertions.len) return error.InvalidQueryIndex;
        return insertions[query_ordinal] orelse error.SourceContextMissing;
    }

    /// One copied explicit-claim receipt. Claim order is root, column, then
    /// offset-instruction order. It is not a batched or degree-tested oracle.
    pub fn sparseH3LiteralClaimAt(self: *const Self, query_ordinal: usize, claim_index: usize) Error!SparseH3LiteralClaimV2 {
        const rows = self.stateConst().literal_h3_claim_rows orelse return error.SourceContextMissing;
        if (query_ordinal >= rows.len or claim_index >= 73) return error.InvalidQueryIndex;
        const stored = rows[query_ordinal] orelse return error.SourceContextMissing;
        return stored[claim_index];
    }

    /// Diagnostic Eq. (66) arithmetic, not fold admission. Each height's
    /// explicit-claim list is `(f_j,q_j)` with powers λ^(2j), λ^(2j+1);
    /// repeated originals retain distinct positions. The selected multi-Q
    /// theorem and same-source extraction are still missing, so this value
    /// never fills `paired_h3_insertions`.
    pub fn sparseH3CandidateWeightedAt(self: *const Self, query_ordinal: usize) Error!SparseH3PairWordsV2 {
        const rows = self.stateConst().weighted_h3_diagnostics orelse return error.SourceContextMissing;
        if (query_ordinal >= rows.len) return error.InvalidQueryIndex;
        return rows[query_ordinal] orelse error.SourceContextMissing;
    }

    /// Read-only occupancy receipt for this admitted candidate roster. It
    /// deliberately exposes the 61-versus-85 term mismatch to callers.
    pub fn sparseH3TermCounts(self: *const Self) Error!SparseH3TermCountsV2 {
        const roster = self.stateConst().source_roster orelse return error.SourceNotAdmitted;
        if (roster.mode != .sparse_h3) return error.UnsupportedSparseH3Profile;
        return roster.term_counts;
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

    /// Exact CAS09 two-step H1 relation for one sampled raw query, restricted
    /// to a degree-zero terminal on each independent track. Step zero folds
    /// the privately retained source insertion into the selected authenticated
    /// line row. Step one folds the authenticated adjacent line pair into the
    /// transcript-absorbed terminal coefficient. The only caller input is the
    /// two tracks' line row/path wire; no alpha, position, root, or insertion
    /// value enters through this API. A full verifier must check every query.
    pub fn verifyH1OneStepAtQuery(
        self: *const Self,
        query_ordinal: usize,
        openings: [2][2]LineRowOpeningV2,
    ) Error!void {
        const state = self.stateConst();
        if (state.source_roster == null or state.plan.fold_count != 2 or state.query_log_size < 3)
            return error.UnsupportedH1FoldProfile;
        if (state.fold_alpha_count != 2 or
            state.terminal_coefficients[0] == null or state.terminal_coefficients[1] == null)
            return error.FoldContextMissing;
        const queries = state.queries orelse return error.QueriesNotDrawn;
        if (query_ordinal >= queries.raw.len) return error.InvalidQueryIndex;
        const insertions = state.source_insertions orelse return error.SourceContextMissing;
        const inserted = insertions[query_ordinal] orelse return error.SourceContextMissing;
        const raw = queries.raw[query_ordinal];
        const k = state.query_log_size;
        if (raw >= (@as(usize, 1) << @intCast(k))) return error.InvalidQueryGeometry;
        const line_pairs = try self.verifyAndReadBothTrackPairs(0, query_ordinal, openings);

        const source_domain = canonic.CanonicCoset.new(k).circleDomain();
        const source_base = raw & ~@as(usize, 1);
        const source_p0 = source_domain.at(core_utils.bitReverseIndex(source_base, k));
        const projected = source_domain.at(core_utils.bitReverseIndex(raw, k)).double();
        const next_circle_domain = canonic.CanonicCoset.new(k - 1).circleDomain();
        const projected_row = ((raw >> 2) << 1) | (raw & 1);
        const expected_projected = next_circle_domain.at(core_utils.bitReverseIndex(projected_row, k - 1));
        if (!projected.eql(expected_projected)) return error.InvalidQueryProjection;

        const line_base = (raw >> 1) & ~@as(usize, 1);
        const line_x = line.LineDomain.fromCircleDomain(source_domain)
            .at(core_utils.bitReverseIndex(line_base, k - 1));
        const terminal_domain = line.LineDomain.fromCircleDomain(next_circle_domain);
        const terminal_row = raw >> 2;
        const terminal_x = terminal_domain.at(core_utils.bitReverseIndex(terminal_row, k - 2));
        const selected_side = (raw >> 1) & 1;
        for (0..2) |track| {
            const first = try foldPair(inserted[0][track], inserted[1][track], source_p0.y, state.fold_alphas[0]);
            if (!first.eql(line_pairs[track][selected_side]))
                return if (track == 0) error.OriginalIntermediateFoldMismatch else error.QuotientIntermediateFoldMismatch;
            const second = try foldPair(line_pairs[track][0], line_pairs[track][1], line_x, state.fold_alphas[1]);
            // H1 has no source insertion at the second height; CAS09's
            // alpha^2 times the fold of a zero pair is exactly zero.
            var coefficient = [1]qm31.QM31{state.terminal_coefficients[track].?};
            const terminal = line.LinePoly.fromOrderedCoefficients(&coefficient);
            const expected = try terminal.evalAtPoint(state.allocator, qm31.QM31.fromBase(terminal_x));
            if (!second.eql(expected))
                return if (track == 0) error.OriginalTerminalFoldMismatch else error.QuotientTerminalFoldMismatch;
        }
    }

    /// Check one committed H3 cascade step at one privately sampled query.
    /// Both line tracks and both adjacent rows are authenticated under roots
    /// already captured by this owner. Source values come from a separate
    /// privately admitted matched per-claim ensemble at heights 17, 11, or
    /// 5. No public admission path exists yet, so real calls fail closed.
    /// The 61/85 diagnostic rows from verifyAndKeepSparseH3SourcePair never
    /// enter this relation. This checks Eq. (68) pointwise only after a future
    /// ensemble admission establishes the source values' origin and meaning.
    /// A successful call records this step for this query. The final h=4
    /// check requires all thirteen committed steps to have passed.
    pub fn verifySparseH3CommittedStepAtQuery(
        self: *Self,
        fold_index: usize,
        query_ordinal: usize,
        previous_openings: ?[2][2]LineRowOpeningV2,
        next_openings: [2][2]LineRowOpeningV2,
    ) Error!void {
        const state = self.stateConst();
        const roster = state.source_roster orelse return error.SourceNotAdmitted;
        if (roster.mode != .sparse_h3 or state.query_log_size != 17 or
            state.plan.fold_count != 14)
            return error.UnsupportedSparseH3Profile;
        if (fold_index >= 13) return error.InvalidTreeIndex;
        const height: u32 = @intCast(17 - fold_index);
        if (state.plan.fold_heights[fold_index] != height or
            state.fold_alpha_count <= fold_index)
            return error.FoldContextMissing;
        if ((fold_index == 0) != (previous_openings == null))
            return error.InvalidSourcePairShape;
        const queries = state.queries orelse return error.QueriesNotDrawn;
        if (query_ordinal >= queries.raw.len) return error.InvalidQueryIndex;
        const insertions = state.paired_h3_insertions orelse return error.SourceEnsembleNotAdmitted;
        const inserted = insertions[query_ordinal] orelse return error.SourceContextMissing;
        const raw = queries.raw[query_ordinal];
        if (raw >= (@as(usize, 1) << 17)) return error.InvalidQueryGeometry;
        const alpha = state.fold_alphas[fold_index];
        const next = try self.verifyAndReadBothTrackPairs(fold_index, query_ordinal, next_openings);
        const previous = if (previous_openings) |openings|
            try self.verifyAndReadBothTrackPairs(fold_index - 1, query_ordinal, openings)
        else
            null;
        const selected_side = (raw >> @intCast(fold_index + 1)) & 1;
        const source_slot: ?usize = switch (height) {
            17 => 0,
            11 => 1,
            5 => 2,
            else => null,
        };
        var source_y: m31.M31 = undefined;
        if (source_slot != null) {
            const source_pair = try h3_projection.projectCirclePair(raw, 17, height);
            const source_domain = canonic.CanonicCoset.new(height).circleDomain();
            source_y = source_domain.at(core_utils.bitReverseIndex(source_pair[0], height)).y;
        }
        var line_x: m31.M31 = undefined;
        if (previous != null) {
            const base = (raw >> @intCast(fold_index)) & ~@as(usize, 1);
            const line_domain = line.LineDomain.fromCircleDomain(canonic.CanonicCoset.new(height + 1).circleDomain());
            if (!line_domain.double().coset().eql(canonic.CanonicCoset.new(height).circleDomain().half_coset))
                return error.InvalidQueryProjection;
            line_x = line_domain.at(core_utils.bitReverseIndex(base, height));
        }
        for (0..2) |track| {
            var expected = qm31.QM31.zero();
            if (previous) |pair|
                expected = try foldPair(pair[track][0], pair[track][1], line_x, alpha);
            if (source_slot) |slot| {
                const source_fold = try foldPair(inserted[slot][0][track], inserted[slot][1][track], source_y, alpha);
                expected = expected.add(if (fold_index == 0) source_fold else alpha.square().mul(source_fold));
            }
            if (!expected.eql(next[track][selected_side]))
                return if (track == 0) error.OriginalIntermediateFoldMismatch else error.QuotientIntermediateFoldMismatch;
        }
        const checked = state.h3_fold_checked orelse return error.SourceContextMissing;
        checked[query_ordinal] |= @as(u16, 1) << @intCast(fold_index);
    }

    /// Candidate last one-bit fold, h=4 -> terminal log 3, for one sampled
    /// query. Both h=4 line pairs are authenticated at privately derived
    /// adjacent indices, then folded with retained alpha[13] into the two
    /// transcript-bound degree<2 terminal polynomials. It admits no source
    /// values: the separate paired-ensemble slot must already be populated,
    /// and all thirteen committed steps must have passed for this query.
    /// No public path populates that slot or selects this verifier.
    pub fn verifySparseH3TerminalAtQuery(
        self: *const Self,
        query_ordinal: usize,
        previous_openings: [2][2]LineRowOpeningV2,
    ) Error!void {
        const state = self.stateConst();
        const roster = state.source_roster orelse return error.SourceNotAdmitted;
        if (roster.mode != .sparse_h3 or state.query_log_size != 17 or
            state.plan.fold_count != 14 or state.plan.fold_heights[13] != 4)
            return error.UnsupportedSparseH3Profile;
        if (state.fold_alpha_count != 14 or state.h3_terminal_coefficients[0] == null or
            state.h3_terminal_coefficients[1] == null)
            return error.FoldContextMissing;
        const queries = state.queries orelse return error.QueriesNotDrawn;
        if (query_ordinal >= queries.raw.len) return error.InvalidQueryIndex;
        const insertions = state.paired_h3_insertions orelse return error.SourceEnsembleNotAdmitted;
        if (insertions[query_ordinal] == null) return error.SourceContextMissing;
        const checked = state.h3_fold_checked orelse return error.SourceContextMissing;
        if (checked[query_ordinal] != 0x1fff) return error.CommittedFoldsNotChecked;
        const raw = queries.raw[query_ordinal];
        if (raw >= (@as(usize, 1) << 17)) return error.InvalidQueryGeometry;
        const previous = try self.verifyAndReadBothTrackPairs(12, query_ordinal, previous_openings);
        const previous_domain = line.LineDomain.fromCircleDomain(canonic.CanonicCoset.new(5).circleDomain());
        const terminal_domain = line.LineDomain.fromCircleDomain(canonic.CanonicCoset.new(4).circleDomain());
        if (!previous_domain.double().coset().eql(canonic.CanonicCoset.new(4).circleDomain().half_coset))
            return error.InvalidQueryProjection;
        const previous_base = (raw >> 13) & ~@as(usize, 1);
        const previous_x = previous_domain.at(core_utils.bitReverseIndex(previous_base, 4));
        const terminal_row = raw >> 14;
        const terminal_x = terminal_domain.at(core_utils.bitReverseIndex(terminal_row, 3));
        const alpha = state.fold_alphas[13];
        for (0..2) |track| {
            const actual = try foldPair(previous[track][0], previous[track][1], previous_x, alpha);
            var coefficients = state.h3_terminal_coefficients[track].?;
            const terminal = line.LinePoly.fromOrderedCoefficients(&coefficients);
            const expected = try terminal.evalAtPoint(state.allocator, qm31.QM31.fromBase(terminal_x));
            if (!actual.eql(expected))
                return if (track == 0) error.OriginalTerminalFoldMismatch else error.QuotientTerminalFoldMismatch;
        }
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

const SparseH3TestRoster = struct {
    logs: [4][max_source_columns]u32 = undefined,
    ids: [4][max_source_columns]Digest32 = undefined,
    offsets: [4][max_source_columns]SparseH3MaskOffsetsV2 = undefined,

    fn init() SparseH3TestRoster {
        var out: SparseH3TestRoster = .{};
        const counts = h3_projection.accepted_h3_counts;
        const patterns = [4][]const u32{
            &.{ 5, 5, 5, 11, 11, 11, 11, 11, 11, 11, 11, 17 },
            &.{ 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 5, 5, 5, 5, 17 },
            &.{ 11, 11, 11, 11, 11, 11, 11, 11, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 17, 17, 17, 17 },
            &([_]u32{17} ** 8),
        };
        for (0..4) |tree| {
            for (patterns[tree], 0..) |height, at| {
                out.logs[tree][at] = height;
                out.ids[tree][at] = [_]u8{@intCast(32 * tree + at + 1)} ** 32;
                const has_two = tree == 2 and ((at >= 4 and at <= 7) or at >= 16);
                out.offsets[tree][at] = if (has_two)
                    .{ .count = 2, .values = .{ -1, 0 } }
                else
                    .{ .count = 1, .values = .{ 0, 0 } };
            }
            std.debug.assert(patterns[tree].len == counts[tree]);
        }
        return out;
    }

    fn slices(self: *const SparseH3TestRoster) SparseH3SourceRosterV2 {
        var out: SparseH3SourceRosterV2 = undefined;
        out.mask_log = 16;
        for (h3_projection.accepted_h3_counts, 0..) |count, tree| {
            out.column_log_sizes[tree] = self.logs[tree][0..count];
            out.column_descriptors[tree] = self.ids[tree][0..count];
            out.mask_offsets[tree] = self.offsets[tree][0..count];
        }
        return out;
    }
};

const SparseH3TestManifest = struct {
    heights: [14]u32 = undefined,
    trees: [26]descriptor.LineTreeDescriptorV2 = undefined,
    columns: [4]Digest32 = .{
        [_]u8{0xE1} ** 32,
        [_]u8{0xE2} ** 32,
        [_]u8{0xE3} ** 32,
        [_]u8{0xE4} ** 32,
    },

    fn init(self: *SparseH3TestManifest) void {
        const zero = [_]u8{0} ** 32;
        const profile = descriptor.lineHashProfileDigest();
        for (&self.heights, 0..) |*height, i| height.* = @intCast(17 - i);
        for (&self.trees, 0..) |*tree, i| {
            const pair = i / 2;
            tree.* = .{
                .key_digest = zero,
                .profile_digest = profile,
                .track = if (i % 2 == 0) .original else .own_quotient,
                .fold_height = self.heights[pair],
                .tree_log_size = self.heights[pair] - 1,
                .root_event = 17 + 3 * @as(u64, @intCast(pair)) + @as(u64, @intCast(i % 2)),
                .column_descriptors = &self.columns,
            };
        }
    }

    fn value(self: *const SparseH3TestManifest) descriptor.LineTreeManifestV2 {
        return .{ .key_digest = [_]u8{0} ** 32, .fold_heights = &self.heights, .trees = &self.trees };
    }
};

const ConstantLineTreeH3 = struct {
    row: [4]u32 = [_]u32{0} ** 4,
    siblings: [16]Digest32 = undefined,
    root: Digest32 = undefined,
    log_size: u32 = 0,

    fn init(log_size: u32) !ConstantLineTreeH3 {
        if (log_size == 0 or log_size > 16) return error.InvalidQueryGeometry;
        const hash = @import("blake2s_personalized_line_v2.zig");
        var out: ConstantLineTreeH3 = .{ .log_size = log_size };
        var node = try hash.hashCanonicalRow(&out.row);
        for (0..log_size) |level| {
            out.siblings[level] = node;
            node = hash.LineMerkleHasherV2.hashChildren(.{ .left = node, .right = node });
        }
        out.root = node;
        return out;
    }

    fn pair(self: *const ConstantLineTreeH3) [2]LineRowOpeningV2 {
        return .{
            .{ .row = self.row, .siblings = self.siblings[0..self.log_size] },
            .{ .row = self.row, .siblings = self.siblings[0..self.log_size] },
        };
    }
};

test "sparse H3 source roster binds mask instructions and rejects mutation" {
    const allocator = std.testing.allocator;
    const zero = [_]u8{0} ** 32;
    var manifest_storage: SparseH3TestManifest = .{};
    manifest_storage.init();
    const manifest = manifest_storage.value();
    var source = SparseH3TestRoster.init();
    var roster = source.slices();
    var python_vector: Digest32 = undefined;
    _ = try std.fmt.hexToBytes(&python_vector, "124863b2249a569cb93c812c706d43a2dc4d2be7d4cf21783366adfe6b615f6f");
    try std.testing.expectEqualDeep(python_vector, try sparseH3SourceRosterDigest(
        zero,
        17,
        16,
        0,
        &.{5},
        &.{[_]u8{0x11} ** 32},
        &.{.{ .count = 1, .values = .{ 0, 0 } }},
    ));
    _ = try std.fmt.hexToBytes(&python_vector, "dfe141c2b67f21080fad9bb4dadb71e6514833ac967aef893eb7da9a5e82adc0");
    const signed_ids = [_]Digest32{
        [_]u8{0x21} ** 32, [_]u8{0x22} ** 32, [_]u8{0x23} ** 32,
        [_]u8{0x24} ** 32, [_]u8{0x25} ** 32,
    };
    const signed_offsets = [_]SparseH3MaskOffsetsV2{
        .{ .count = 1, .values = .{ 0, 0 } },  .{ .count = 1, .values = .{ 0, 0 } },
        .{ .count = 1, .values = .{ 0, 0 } },  .{ .count = 1, .values = .{ 0, 0 } },
        .{ .count = 2, .values = .{ -1, 0 } },
    };
    try std.testing.expectEqualDeep(python_vector, try sparseH3SourceRosterDigest(
        zero,
        17,
        16,
        2,
        &.{ 11, 11, 11, 11, 11 },
        &signed_ids,
        &signed_offsets,
    ));
    var statement = try testStatement(manifest, allocator);
    for (&statement.source_tree_descriptors, 0..) |*digest, tree|
        digest.* = try sparseH3SourceRosterDigest(zero, 17, 16, tree, roster.column_log_sizes[tree], roster.column_descriptors[tree], roster.mask_offsets[tree]);
    const verifier = try OwnedPairedGateVerifierV2.initWithSparseH3SourceRoster(allocator, manifest, statement, roster);
    defer verifier.deinit();
    const counts = try verifier.sparseH3TermCounts();
    try std.testing.expectEqualDeep([3]usize{ 14, 28, 19 }, counts.original_by_height);
    try std.testing.expectEqualDeep([3]usize{ 18, 32, 23 }, counts.explicit_claims_by_height);
    try std.testing.expectEqualDeep([3]usize{ 4, 4, 4 }, counts.periodic_by_height);
    try std.testing.expectEqualDeep([3]usize{ 22, 36, 27 }, counts.quotient_by_height);
    try std.testing.expectEqual(@as(usize, 61), counts.original_by_height[0] + counts.original_by_height[1] + counts.original_by_height[2]);
    try std.testing.expectEqual(@as(usize, 85), counts.quotient_by_height[0] + counts.quotient_by_height[1] + counts.quotient_by_height[2]);
    try std.testing.expect(counts.original_by_height[0] != counts.quotient_by_height[0]);
    // friAnswers always inserts a third sample for two-point columns. When
    // called at the source height, that "periodic" sample is exactly sample
    // 1 again; it is not an independent OOD constraint.
    for (h3_projection.accepted_h3_logs) |height| {
        const period = canonic.CanonicCoset.new(height).step().repeatedDouble(height);
        try std.testing.expect(period.eql(circle.CirclePointM31.identity()));
    }
    try std.testing.expectError(error.QueriesNotDrawn, verifier.verifyAndKeepSparseH3SourcePair(0, undefined));
    source.offsets[2][4].values[0] = -2;
    roster = source.slices();
    try std.testing.expectError(error.SourceStatementMismatch, OwnedPairedGateVerifierV2.initWithSparseH3SourceRoster(allocator, manifest, statement, roster));
    source.offsets[2][4].values[0] = -1;
    // Removing a periodicity-bearing second claim cannot be made to look like
    // a valid 61-column/73-claim accepted profile.
    source.offsets[2][16].count = 1;
    roster = source.slices();
    try std.testing.expectError(error.InvalidSparseClaimLayout, OwnedPairedGateVerifierV2.initWithSparseH3SourceRoster(allocator, manifest, statement, roster));
    source.offsets[2][16].count = 2;
    source.logs[0][0] = 17;
    roster = source.slices();
    try std.testing.expectError(error.InvalidAcceptedRoster, OwnedPairedGateVerifierV2.initWithSparseH3SourceRoster(allocator, manifest, statement, roster));
}

test "sparse H3 authenticated lower-height insertions use private raw query" {
    const allocator = std.testing.allocator;
    const zero = [_]u8{0} ** 32;
    var manifest_storage: SparseH3TestManifest = .{};
    manifest_storage.init();
    const manifest = manifest_storage.value();
    var source = SparseH3TestRoster.init();
    const roster = source.slices();
    var statement = try testStatement(manifest, allocator);
    for (&statement.source_tree_descriptors, 0..) |*digest, tree|
        digest.* = try sparseH3SourceRosterDigest(zero, 17, 16, tree, roster.column_log_sizes[tree], roster.column_descriptors[tree], roster.mask_offsets[tree]);
    const verifier = try OwnedPairedGateVerifierV2.initWithSparseH3SourceRoster(allocator, manifest, statement, roster);
    defer verifier.deinit();
    const state = verifier.privateState();
    state.ood_point = try circle.secureFieldPointFromRandomSeedChecked(qm31FromLimbs(.{ 9, 3, 7, 2 }));
    state.batch_lambda = qm31.QM31.fromBase(m31.M31.fromCanonical(7));
    state.source_claim_count = 73;
    for (state.source_claims[0..73]) |*claim| claim.* = qm31.QM31.zero();
    state.source_claims[0] = qm31.QM31.fromBase(m31.M31.fromCanonical(5));
    state.source_claims[12] = qm31.QM31.fromBase(m31.M31.fromCanonical(13));
    state.source_claims[49] = qm31.QM31.fromBase(m31.M31.fromCanonical(7));
    state.source_claims[50] = qm31.QM31.fromBase(m31.M31.fromCanonical(11));
    const raw = try allocator.dupe(usize, &.{ 90528, 90528 });
    state.queries = .{ .raw = raw, .blocks_consumed = 1, .words_examined = 2, .words_rejected = 0 };
    state.sparse_h3_insertions = try allocator.alloc(?SparseH3PairWordsV2, 2);
    @memset(state.sparse_h3_insertions.?, null);
    state.literal_h3_claim_rows = try allocator.alloc(?*SparseH3LiteralClaimRowsV2, 2);
    @memset(state.literal_h3_claim_rows.?, null);
    state.weighted_h3_diagnostics = try allocator.alloc(?SparseH3PairWordsV2, 2);
    @memset(state.weighted_h3_diagnostics.?, null);

    var columns: [4][max_source_columns][2]m31.M31 = undefined;
    var witness: [4][16]Digest32 = undefined;
    var openings: [4]SourceTreePairOpeningV2 = undefined;
    for (h3_projection.accepted_h3_counts, 0..) |count, tree| {
        for (columns[tree][0..count], 0..) |*pair, col| {
            const value: u32 = if (tree == 0 and col == 0) 17 else if (tree == 1 and col == 0) 31 else if (tree == 2 and col == 16) 23 else 0;
            pair.* = .{ m31.M31.fromCanonical(value), m31.M31.fromCanonical(value) };
        }
        var leaf = source_merkle.SourceMerkleHasherV2.defaultWithInitialState();
        // Native lifted Merkle leaf order is ascending log, stable by column.
        for ([_]u32{ 5, 11, 17 }) |height| for (0..count) |col| {
            if (source.logs[tree][col] == height)
                leaf.updateLeaf(columns[tree][col][0..1]);
        };
        var node = leaf.finalize();
        for (0..17) |level| {
            if (level > 0) witness[tree][level - 1] = node;
            node = source_merkle.SourceMerkleHasherV2.hashChildren(.{ .left = node, .right = node });
        }
        state.source_roots[tree] = node;
        openings[tree] = .{ .columns = columns[tree][0..count], .hash_witness = &witness[tree] };
    }
    try std.testing.expectError(error.InvalidQueryIndex, verifier.verifyAndKeepSparseH3SourcePair(2, openings));
    try verifier.verifyAndKeepSparseH3SourcePair(0, openings);
    try verifier.verifyAndKeepSparseH3SourcePair(1, openings);
    const first = try verifier.sparseH3InsertionAt(0);
    const repeated = try verifier.sparseH3InsertionAt(1);
    try std.testing.expectEqualDeep(first, repeated);
    const weighted = try verifier.sparseH3CandidateWeightedAt(0);
    try std.testing.expectEqualDeep(weighted, try verifier.sparseH3CandidateWeightedAt(1));
    try std.testing.expect(state.paired_h3_insertions == null);
    var claim_counts = [_]usize{ 0, 0, 0 };
    for (0..73) |claim_index| {
        const literal = try verifier.sparseH3LiteralClaimAt(0, claim_index);
        try std.testing.expectEqual(@as(u8, @intCast(claim_index)), literal.claim_index);
        const bucket: usize = switch (literal.height) {
            17 => 0,
            11 => 1,
            5 => 2,
            else => return error.InvalidSparseClaimLayout,
        };
        claim_counts[bucket] += 1;
        try std.testing.expectEqualDeep(literal, try verifier.sparseH3LiteralClaimAt(1, claim_index));
    }
    try std.testing.expectEqualDeep([3]usize{ 18, 32, 23 }, claim_counts);
    var expected_claim: usize = 0;
    for (h3_projection.accepted_h3_counts, 0..) |count, tree| {
        for (0..count) |col| {
            for (0..source.offsets[tree][col].count) |_| {
                const record = try verifier.sparseH3LiteralClaimAt(0, expected_claim);
                try std.testing.expectEqual(@as(u8, @intCast(tree)), record.root_index);
                try std.testing.expectEqual(@as(u8, @intCast(col)), record.column_index);
                try std.testing.expectEqual(@as(u8, @intCast(source.logs[tree][col])), record.height);
                expected_claim += 1;
            }
        }
    }
    try std.testing.expectEqual(@as(usize, 73), expected_claim);
    try std.testing.expectError(error.InvalidQueryIndex, verifier.sparseH3LiteralClaimAt(0, 73));
    const shifted_claim = try verifier.sparseH3LiteralClaimAt(0, 49);
    const base_claim = try verifier.sparseH3LiteralClaimAt(0, 50);
    try std.testing.expectEqual(shifted_claim.root_index, base_claim.root_index);
    try std.testing.expectEqual(shifted_claim.column_index, base_claim.column_index);
    for (0..2) |side| try std.testing.expect(shifted_claim.words[side][0].eql(base_claim.words[side][0]));
    try std.testing.expect(!shifted_claim.words[0][1].eql(base_claim.words[0][1]));
    for (first[0..1]) |pair| for (pair) |tracks| for (tracks) |value|
        try std.testing.expect(value.eql(qm31.QM31.zero()));
    const lambda = state.batch_lambda.?;
    var lambda_8 = qm31.QM31.one();
    for (0..8) |_| lambda_8 = lambda_8.mul(lambda);
    const want_11_original = lambda_8.mul(qm31.QM31.fromBase(m31.M31.fromCanonical(31)));
    try std.testing.expect(first[1][0][0].eql(want_11_original));
    try std.testing.expect(first[1][1][0].eql(want_11_original));
    const lambda_16 = lambda_8.square();
    const want_literal_11_original = lambda_16.mul(qm31.QM31.fromBase(m31.M31.fromCanonical(31)));
    for (0..2) |side| try std.testing.expect(weighted[1][side][0].eql(want_literal_11_original));
    const projected_11 = try h3_projection.projectCirclePair(90528, 17, 11);
    const row_11 = canonic.CanonicCoset.new(11).circleDomain()
        .at(core_utils.bitReverseIndex(projected_11[0], 11));
    const point_11 = state.ood_point.?.repeatedDouble(6);
    var context_11 = try row_context.RowContextV2.init(allocator, point_11, &.{state.source_claims[12]}, qm31.QM31.one());
    defer context_11.deinit();
    const want_11_quotient = lambda_8.mul((try context_11.openedValues(&.{m31.M31.fromCanonical(31)}, row_11))[1]);
    try std.testing.expect(first[1][0][1].eql(want_11_quotient));
    const own_11 = (try context_11.openedValues(&.{m31.M31.fromCanonical(31)}, row_11))[1];
    try std.testing.expect(weighted[1][0][1].eql(lambda_16.mul(lambda).mul(own_11)));
    var lambda_15 = qm31.QM31.one();
    for (0..15) |_| lambda_15 = lambda_15.mul(lambda);
    const want_original = qm31.QM31.fromBase(m31.M31.fromCanonical(17)).add(lambda_15.mul(qm31.QM31.fromBase(m31.M31.fromCanonical(23))));
    try std.testing.expect(first[2][0][0].eql(want_original));
    try std.testing.expect(first[2][1][0].eql(want_original));
    // Differential against the separately implemented one-column row
    // context, including both explicit points and periodic sample first.
    const projected = try h3_projection.projectCirclePair(90528, 17, 5);
    const row = canonic.CanonicCoset.new(5).circleDomain()
        .at(core_utils.bitReverseIndex(projected[0], 5));
    const base_point = state.ood_point.?.repeatedDouble(12);
    const offset_point = canonic.CanonicCoset.new(16).step().mulSigned(-1);
    const shifted_point = state.ood_point.?.add(.{
        .x = qm31.QM31.fromBase(offset_point.x),
        .y = qm31.QM31.fromBase(offset_point.y),
    }).repeatedDouble(12);
    const periodic_step = canonic.CanonicCoset.new(5).step().repeatedDouble(5);
    const periodic_point = base_point.add(.{
        .x = qm31.QM31.fromBase(periodic_step.x),
        .y = qm31.QM31.fromBase(periodic_step.y),
    });
    const value_17 = [_]m31.M31{m31.M31.fromCanonical(17)};
    const value_23 = [_]m31.M31{m31.M31.fromCanonical(23)};
    var c0 = try row_context.RowContextV2.init(allocator, base_point, &.{state.source_claims[0]}, qm31.QM31.one());
    defer c0.deinit();
    var cp = try row_context.RowContextV2.init(allocator, periodic_point, &.{state.source_claims[50]}, qm31.QM31.one());
    defer cp.deinit();
    var c1 = try row_context.RowContextV2.init(allocator, shifted_point, &.{state.source_claims[49]}, qm31.QM31.one());
    defer c1.deinit();
    var c2 = try row_context.RowContextV2.init(allocator, base_point, &.{state.source_claims[50]}, qm31.QM31.one());
    defer c2.deinit();
    const q0 = (try c0.openedValues(&value_17, row))[1];
    const qp = (try cp.openedValues(&value_23, row))[1];
    const q1 = (try c1.openedValues(&value_23, row))[1];
    const q2 = (try c2.openedValues(&value_23, row))[1];
    try std.testing.expect(shifted_claim.words[0][1].eql(q1));
    try std.testing.expect(base_claim.words[0][1].eql(q2));
    const want_quotient = q0.add(lambda_15.mul(qp)).add(lambda_15.mul(lambda).mul(q1))
        .add(lambda_15.mul(lambda.square()).mul(q2));
    try std.testing.expect(first[2][0][1].eql(want_quotient));
    try std.testing.expectError(error.SparseSourceAlreadyVerified, verifier.verifyAndKeepSparseH3SourcePair(0, openings));
    state.sparse_h3_insertions.?[1] = null;
    allocator.destroy(state.literal_h3_claim_rows.?[1].?);
    state.literal_h3_claim_rows.?[1] = null;
    state.weighted_h3_diagnostics.?[1] = null;
    try verifier.verifyAndKeepSparseH3LiteralClaimPairs(1, openings);
    try std.testing.expect(state.sparse_h3_insertions.?[1] == null);
    try std.testing.expect(state.paired_h3_insertions == null);
    try std.testing.expectEqualDeep(shifted_claim, try verifier.sparseH3LiteralClaimAt(1, 49));
    try std.testing.expectError(error.SparseSourceAlreadyVerified, verifier.verifyAndKeepSparseH3LiteralClaimPairs(1, openings));
    allocator.destroy(state.literal_h3_claim_rows.?[1].?);
    state.literal_h3_claim_rows.?[1] = null;
    state.weighted_h3_diagnostics.?[1] = null;
    columns[0][0][0] = m31.M31.one();
    try std.testing.expectError(error.RootMismatch, verifier.verifyAndKeepSparseH3LiteralClaimPairs(1, openings));
    columns[0][0][0] = m31.M31.fromCanonical(17);
    witness[0][0][0] ^= 1;
    try std.testing.expectError(error.RootMismatch, verifier.verifyAndKeepSparseH3SourcePair(1, openings));
    witness[0][0][0] ^= 1;
    state.source_roots[0].?[0] ^= 1;
    try std.testing.expectError(error.RootMismatch, verifier.verifyAndKeepSparseH3SourcePair(1, openings));
    try std.testing.expect(state.sparse_h3_insertions.?[1] == null);
    try std.testing.expect(state.literal_h3_claim_rows.?[1] == null);
    try std.testing.expect(state.weighted_h3_diagnostics.?[1] == null);
}

test "sparse H3 committed cascade checks every step and all three source heights" {
    const allocator = std.testing.allocator;
    const zero = [_]u8{0} ** 32;
    var manifest_storage: SparseH3TestManifest = .{};
    manifest_storage.init();
    const manifest = manifest_storage.value();
    var source = SparseH3TestRoster.init();
    const roster = source.slices();
    var statement = try testStatement(manifest, allocator);
    for (&statement.source_tree_descriptors, 0..) |*digest, tree|
        digest.* = try sparseH3SourceRosterDigest(zero, 17, 16, tree, roster.column_log_sizes[tree], roster.column_descriptors[tree], roster.mask_offsets[tree]);
    const verifier = try OwnedPairedGateVerifierV2.initWithSparseH3SourceRoster(allocator, manifest, statement, roster);
    defer verifier.deinit();
    var lines: [26]ConstantLineTreeH3 = undefined;
    for (&lines, 0..) |*tree, index| tree.* = try ConstantLineTreeH3.init(manifest_storage.heights[index / 2] - 1);
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
    const claims = [_]u32{0} ** (73 * 4);
    try verifier.mixSampledValues(&claims);
    _ = try verifier.drawBatchLambda();
    for (0..14) |i| {
        const drawn = try verifier.drawFoldAlpha();
        try std.testing.expectEqualDeep(qm31FromLimbs(drawn), verifier.privateState().fold_alphas[i]);
        if (i < 13) {
            try verifier.captureOriginalLineRoot(lines[2 * i].root);
            try verifier.captureOwnQuotientLineRoot(lines[2 * i + 1].root);
        }
    }
    const terminal_event = verifier.nextEvent();
    try std.testing.expectError(error.InvalidTerminalShape, verifier.mixOriginalTerminalCoefficients(&.{ 0, 0, 0, 0 }));
    try std.testing.expectEqual(terminal_event, verifier.nextEvent());
    try verifier.mixOriginalTerminalCoefficients(&.{ 0, 0, 0, 0, 0, 0, 0, 0 });
    try std.testing.expectError(error.InvalidTerminalShape, verifier.mixOwnQuotientTerminalCoefficients(&.{ 0, 0, 0, 0 }));
    try verifier.mixOwnQuotientTerminalCoefficients(&.{ 0, 0, 0, 0, 0, 0, 0, 0 });
    _ = try verifier.beginFriPow(0);
    try verifier.acceptFriNonce(0);
    try verifier.drawQueries(2, 1);
    const state = verifier.privateState();
    const raw = try verifier.queryPosition(0);
    var inserted = std.mem.zeroes(SparseH3PairWordsV2);
    // Synthetic private-state fixture: at each populated source height the
    // nonzero quotient pair cancels under the actual verifier-drawn alpha.
    // Changing that alpha must break the authenticated zero line relation.
    for ([_]usize{ 0, 6, 12 }, 0..) |fold_index, slot| {
        const height: u32 = @intCast(17 - fold_index);
        const projected = try h3_projection.projectCirclePair(raw, 17, height);
        const y = canonic.CanonicCoset.new(height).circleDomain()
            .at(core_utils.bitReverseIndex(projected[0], height)).y;
        const y_secure = qm31.QM31.fromBase(y);
        const alpha = state.fold_alphas[fold_index];
        inserted[slot][0][1] = y_secure.sub(alpha);
        inserted[slot][1][1] = y_secure.add(alpha).neg();
        try std.testing.expect((try foldPair(inserted[slot][0][1], inserted[slot][1][1], y, alpha)).eql(qm31.QM31.zero()));
    }
    // Even a populated diagnostic source slot must not admit the paired
    // relation. Only a future source-ensemble verifier may fill its separate
    // private slot; this direct write is isolated to this kernel test.
    state.sparse_h3_insertions.?[0] = inserted;
    const lineOpenings = struct {
        fn at(trees: *const [26]ConstantLineTreeH3, i: usize) [2][2]LineRowOpeningV2 {
            return .{ trees[2 * i].pair(), trees[2 * i + 1].pair() };
        }
    }.at;
    try std.testing.expectError(error.SourceEnsembleNotAdmitted, verifier.verifySparseH3CommittedStepAtQuery(0, 0, null, lineOpenings(&lines, 0)));
    try std.testing.expectError(error.SourceEnsembleNotAdmitted, verifier.verifySparseH3TerminalAtQuery(0, lineOpenings(&lines, 12)));
    state.paired_h3_insertions = try allocator.alloc(?SparseH3PairWordsV2, 2);
    @memset(state.paired_h3_insertions.?, null);
    state.paired_h3_insertions.?[0] = inserted;
    try std.testing.expectError(error.CommittedFoldsNotChecked, verifier.verifySparseH3TerminalAtQuery(0, lineOpenings(&lines, 12)));
    for (0..13) |i| {
        const previous: ?[2][2]LineRowOpeningV2 = if (i == 0) null else lineOpenings(&lines, i - 1);
        try verifier.verifySparseH3CommittedStepAtQuery(i, 0, previous, lineOpenings(&lines, i));
    }
    try std.testing.expectEqual(@as(u16, 0x1fff), state.h3_fold_checked.?[0]);
    state.h3_fold_checked.?[0] &= ~@as(u16, 1 << 6);
    try std.testing.expectError(error.CommittedFoldsNotChecked, verifier.verifySparseH3TerminalAtQuery(0, lineOpenings(&lines, 12)));
    state.h3_fold_checked.?[0] |= @as(u16, 1 << 6);
    try verifier.verifySparseH3TerminalAtQuery(0, lineOpenings(&lines, 12));
    try std.testing.expectError(error.SourceContextMissing, verifier.verifySparseH3TerminalAtQuery(1, lineOpenings(&lines, 12)));
    try std.testing.expectError(error.InvalidQueryIndex, verifier.verifySparseH3TerminalAtQuery(2, lineOpenings(&lines, 12)));
    var terminal_wrong_path = lineOpenings(&lines, 12);
    terminal_wrong_path[1][1].row[0] = 1;
    try std.testing.expectError(error.InvalidLinePath, verifier.verifySparseH3TerminalAtQuery(0, terminal_wrong_path));
    const terminal_zero = state.h3_terminal_coefficients[0].?;
    state.h3_terminal_coefficients[0].?[0] = qm31.QM31.one();
    try std.testing.expectError(error.OriginalTerminalFoldMismatch, verifier.verifySparseH3TerminalAtQuery(0, lineOpenings(&lines, 12)));
    state.h3_terminal_coefficients[0] = terminal_zero;
    state.h3_terminal_coefficients[0].?[1] = qm31.QM31.one();
    try std.testing.expectError(error.OriginalTerminalFoldMismatch, verifier.verifySparseH3TerminalAtQuery(0, lineOpenings(&lines, 12)));
    state.h3_terminal_coefficients[0] = terminal_zero;
    state.h3_terminal_coefficients[1].?[0] = qm31.QM31.one();
    try std.testing.expectError(error.QuotientTerminalFoldMismatch, verifier.verifySparseH3TerminalAtQuery(0, lineOpenings(&lines, 12)));
    state.h3_terminal_coefficients[1] = terminal_zero;
    for ([_]usize{ 0, 6, 12 }, 0..) |i, slot| {
        const previous: ?[2][2]LineRowOpeningV2 = if (i == 0) null else lineOpenings(&lines, i - 1);
        const alpha = state.fold_alphas[i];
        state.fold_alphas[i] = alpha.add(qm31.QM31.one());
        try std.testing.expectError(error.QuotientIntermediateFoldMismatch, verifier.verifySparseH3CommittedStepAtQuery(i, 0, previous, lineOpenings(&lines, i)));
        state.fold_alphas[i] = alpha;
        var wrong_insertion = inserted;
        wrong_insertion[slot][0][1] = wrong_insertion[slot][0][1].add(qm31.QM31.one());
        state.paired_h3_insertions.?[0] = wrong_insertion;
        try std.testing.expectError(error.QuotientIntermediateFoldMismatch, verifier.verifySparseH3CommittedStepAtQuery(i, 0, previous, lineOpenings(&lines, i)));
        state.paired_h3_insertions.?[0] = inserted;
        wrong_insertion = inserted;
        wrong_insertion[slot][0][0] = qm31.QM31.one();
        state.paired_h3_insertions.?[0] = wrong_insertion;
        try std.testing.expectError(error.OriginalIntermediateFoldMismatch, verifier.verifySparseH3CommittedStepAtQuery(i, 0, previous, lineOpenings(&lines, i)));
        state.paired_h3_insertions.?[0] = inserted;
    }
    var bad_path = lineOpenings(&lines, 6);
    bad_path[0][0].row[0] = 1;
    try std.testing.expectError(error.InvalidLinePath, verifier.verifySparseH3CommittedStepAtQuery(6, 0, lineOpenings(&lines, 5), bad_path));
    var bad_previous = lineOpenings(&lines, 5);
    bad_previous[1][1].row[0] = 1;
    try std.testing.expectError(error.InvalidLinePath, verifier.verifySparseH3CommittedStepAtQuery(6, 0, bad_previous, lineOpenings(&lines, 6)));
    try std.testing.expectError(error.InvalidSourcePairShape, verifier.verifySparseH3CommittedStepAtQuery(6, 0, null, lineOpenings(&lines, 6)));
    try std.testing.expectError(error.SourceContextMissing, verifier.verifySparseH3CommittedStepAtQuery(6, 1, lineOpenings(&lines, 5), lineOpenings(&lines, 6)));
    try std.testing.expectError(error.InvalidQueryIndex, verifier.verifySparseH3CommittedStepAtQuery(6, 2, lineOpenings(&lines, 5), lineOpenings(&lines, 6)));
    try std.testing.expectError(error.InvalidTreeIndex, verifier.verifySparseH3CommittedStepAtQuery(13, 0, lineOpenings(&lines, 12), lineOpenings(&lines, 12)));
}

test "sparse H3 source-height insertion equation matches native one-step folds" {
    const folding = @import("../fri/folding.zig");
    const allocator = std.testing.allocator;
    const height: u32 = 5;
    const source_domain = canonic.CanonicCoset.new(height).circleDomain();
    const previous_domain = line.LineDomain.fromCircleDomain(canonic.CanonicCoset.new(height + 1).circleDomain());
    try std.testing.expect(previous_domain.double().coset().eql(source_domain.half_coset));
    const alpha = qm31FromLimbs(.{ 7, 2, 3, 1 });
    var previous: [32]qm31.QM31 = undefined;
    var inserted: [32]qm31.QM31 = undefined;
    for (&previous, &inserted, 0..) |*p, *s, i| {
        p.* = qm31.QM31.fromBase(m31.M31.fromCanonical(@intCast(3 * i + 5)));
        s.* = qm31.QM31.fromBase(m31.M31.fromCanonical(@intCast(7 * i + 11)));
    }
    var line_workspace = try folding.FoldLineWorkspace.init(allocator, 16);
    defer line_workspace.deinit(allocator);
    var circle_workspace = try folding.FoldCircleWorkspace.init(allocator, 16);
    defer circle_workspace.deinit(allocator);
    const line_fold = try folding.foldLineSingleStep(allocator, &previous, previous_domain, alpha, &line_workspace);
    defer allocator.free(line_fold.values);
    var source_fold = [_]qm31.QM31{qm31.QM31.zero()} ** 16;
    try folding.foldCircleIntoLineWithWorkspace(allocator, &source_fold, &inserted, source_domain, alpha, &circle_workspace);
    for (0..16) |pair| {
        const previous_x = previous_domain.at(core_utils.bitReverseIndex(2 * pair, height));
        const source_y = source_domain.at(core_utils.bitReverseIndex(2 * pair, height)).y;
        const local_previous = try foldPair(previous[2 * pair], previous[2 * pair + 1], previous_x, alpha);
        const local_source = try foldPair(inserted[2 * pair], inserted[2 * pair + 1], source_y, alpha);
        try std.testing.expect(local_previous.eql(line_fold.values[pair]));
        try std.testing.expect(local_source.eql(source_fold[pair]));
        try std.testing.expect(local_previous.add(alpha.square().mul(local_source)).eql(
            line_fold.values[pair].add(alpha.square().mul(source_fold[pair])),
        ));
    }
}

test "sparse H3 last fold coordinates and degree-one terminal match native fold" {
    const folding = @import("../fri/folding.zig");
    const allocator = std.testing.allocator;
    const previous_domain = line.LineDomain.fromCircleDomain(canonic.CanonicCoset.new(5).circleDomain());
    const terminal_domain = line.LineDomain.fromCircleDomain(canonic.CanonicCoset.new(4).circleDomain());
    try std.testing.expect(previous_domain.double().coset().eql(terminal_domain.coset()));
    const alpha = qm31FromLimbs(.{ 7, 2, 3, 1 });
    const one = qm31.QM31.one();
    const two = qm31.QM31.fromBase(m31.M31.fromCanonical(2));
    const three = qm31.QM31.fromBase(m31.M31.fromCanonical(3));
    const four = qm31.QM31.fromBase(m31.M31.fromCanonical(4));
    const six = qm31.QM31.fromBase(m31.M31.fromCanonical(6));
    var previous: [16]qm31.QM31 = undefined;
    for (&previous, 0..) |*value, row| {
        const x = qm31.QM31.fromBase(previous_domain.at(core_utils.bitReverseIndex(row, 4)));
        value.* = one.add(three.mul(x)).add(two.mul(x.square()));
    }
    var workspace = try folding.FoldLineWorkspace.init(allocator, 8);
    defer workspace.deinit(allocator);
    const native = try folding.foldLineSingleStep(allocator, &previous, previous_domain, alpha, &workspace);
    defer allocator.free(native.values);
    var coefficients = [2]qm31.QM31{ four.add(six.mul(alpha)), two };
    const terminal = line.LinePoly.fromOrderedCoefficients(&coefficients);
    for (0..8) |row| {
        const raw = row << 14;
        const pair_base = (raw >> 13) & ~@as(usize, 1);
        try std.testing.expectEqual(row * 2, pair_base);
        const x = previous_domain.at(core_utils.bitReverseIndex(pair_base, 4));
        const local = try foldPair(previous[pair_base], previous[pair_base + 1], x, alpha);
        const terminal_x = terminal_domain.at(core_utils.bitReverseIndex(raw >> 14, 3));
        const expected = try terminal.evalAtPoint(allocator, qm31.QM31.fromBase(terminal_x));
        try std.testing.expect(local.eql(native.values[row]));
        try std.testing.expect(local.eql(expected));
        const changed_alpha = try foldPair(previous[pair_base], previous[pair_base + 1], x, alpha.add(one));
        try std.testing.expect(!changed_alpha.eql(expected));
    }
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

const ConstantSourceTreeH1 = struct {
    count: usize,
    pair_witness: [2]Digest32,
    root: Digest32,

    fn init(count: usize) ConstantSourceTreeH1 {
        var leaf = source_merkle.SourceMerkleHasherV2.defaultWithInitialState();
        const zero = [_]m31.M31{m31.M31.zero()};
        for (0..count) |_| leaf.updateLeaf(&zero);
        const value = leaf.finalize();
        const parent = source_merkle.SourceMerkleHasherV2.hashChildren(.{ .left = value, .right = value });
        const grandparent = source_merkle.SourceMerkleHasherV2.hashChildren(.{ .left = parent, .right = parent });
        return .{
            .count = count,
            .pair_witness = .{ parent, grandparent },
            .root = source_merkle.SourceMerkleHasherV2.hashChildren(.{ .left = grandparent, .right = grandparent }),
        };
    }

    fn opening(self: *const ConstantSourceTreeH1, columns: *[8][2]m31.M31) SourceTreePairOpeningV2 {
        for (columns[0..self.count]) |*pair| pair.* = .{ m31.M31.zero(), m31.M31.zero() };
        return .{ .columns = columns[0..self.count], .hash_witness = @constCast(&self.pair_witness) };
    }
};

const ConstantLineTreeH1 = struct {
    row: [4]u32,
    pair_witness: [2]Digest32,
    root: Digest32,

    fn init(value: u32) !ConstantLineTreeH1 {
        const row = [_]u32{value} ** 4;
        const leaf = try @import("blake2s_personalized_line_v2.zig").hashCanonicalRow(&row);
        const parent = @import("blake2s_personalized_line_v2.zig").LineMerkleHasherV2.hashChildren(.{ .left = leaf, .right = leaf });
        return .{
            .row = row,
            .pair_witness = .{ leaf, parent },
            .root = @import("blake2s_personalized_line_v2.zig").LineMerkleHasherV2.hashChildren(.{ .left = parent, .right = parent }),
        };
    }

    fn pair(self: *const ConstantLineTreeH1) [2]LineRowOpeningV2 {
        return .{
            .{ .row = self.row, .siblings = &self.pair_witness },
            .{ .row = self.row, .siblings = &self.pair_witness },
        };
    }
};

const RowLineTreeH1 = struct {
    rows: [4][4]u32,
    paths: [4][2]Digest32,
    root: Digest32,

    fn init(words: [4]qm31.QM31) !RowLineTreeH1 {
        const hash = @import("blake2s_personalized_line_v2.zig");
        var out: RowLineTreeH1 = undefined;
        var leaves: [4]Digest32 = undefined;
        for (words, &out.rows, &leaves) |word, *row, *leaf| {
            const limbs = word.toM31Array();
            for (limbs, row) |limb, *slot| slot.* = limb.v;
            leaf.* = try hash.hashCanonicalRow(row);
        }
        const parent0 = hash.LineMerkleHasherV2.hashChildren(.{ .left = leaves[0], .right = leaves[1] });
        const parent1 = hash.LineMerkleHasherV2.hashChildren(.{ .left = leaves[2], .right = leaves[3] });
        out.root = hash.LineMerkleHasherV2.hashChildren(.{ .left = parent0, .right = parent1 });
        out.paths = .{
            .{ leaves[1], parent1 }, .{ leaves[0], parent1 },
            .{ leaves[3], parent0 }, .{ leaves[2], parent0 },
        };
        return out;
    }

    fn pair(self: *const RowLineTreeH1, base: usize) [2]LineRowOpeningV2 {
        return .{
            .{ .row = self.rows[base], .siblings = &self.paths[base] },
            .{ .row = self.rows[base + 1], .siblings = &self.paths[base + 1] },
        };
    }
};

fn h1FoldRoster() SourceRosterV2 {
    var roster = h1SourceRoster();
    roster.column_log_sizes = .{ &.{3}, &.{3}, &.{3}, &([_]u32{3} ** 8) };
    return roster;
}

fn h1FoldStatement(manifest: descriptor.LineTreeManifestV2, allocator: std.mem.Allocator) !framed.StatementBinding {
    var statement = try testStatement(manifest, allocator);
    const roster = h1FoldRoster();
    for (&statement.source_tree_descriptors, 0..) |*digest, tree|
        digest.* = try sourceRosterDigest(statement.key_digest, 3, tree, roster.column_log_sizes[tree], roster.column_descriptors[tree]);
    return statement;
}

fn beginH1Fold(
    allocator: std.mem.Allocator,
    source_trees: [4]ConstantSourceTreeH1,
    claims: []const u32,
) !*OwnedPairedGateVerifierV2 {
    const zero = [_]u8{0} ** 32;
    const profile = descriptor.lineHashProfileDigest();
    const columns = [_]Digest32{
        [_]u8{0x51} ** 32, [_]u8{0x52} ** 32, [_]u8{0x53} ** 32, [_]u8{0x54} ** 32,
    };
    const trees = [_]descriptor.LineTreeDescriptorV2{
        .{ .key_digest = zero, .profile_digest = profile, .track = .original, .fold_height = 3, .tree_log_size = 2, .root_event = 17, .column_descriptors = &columns },
        .{ .key_digest = zero, .profile_digest = profile, .track = .own_quotient, .fold_height = 3, .tree_log_size = 2, .root_event = 18, .column_descriptors = &columns },
    };
    const manifest = descriptor.LineTreeManifestV2{ .key_digest = zero, .fold_heights = &.{ 3, 2 }, .trees = &trees };
    const statement = try h1FoldStatement(manifest, allocator);
    const verifier = try OwnedPairedGateVerifierV2.initWithSourceRoster(allocator, manifest, statement, h1FoldRoster());
    errdefer verifier.deinit();
    try verifier.mixFixedRoot(source_trees[0].root);
    try verifier.mixCircuitIdentity(zero);
    try verifier.mixPublicValues(&.{ 0, 1, 2, 3 });
    try verifier.mixMainRoot(source_trees[1].root);
    _ = try verifier.beginInteractionPow(0);
    try verifier.acceptInteractionNonce(0);
    _ = try verifier.drawLookupPair();
    try verifier.mixInteractionClaim(&.{ 0, 1, 2, 3 });
    try verifier.mixInteractionRoot(source_trees[2].root);
    _ = try verifier.drawCompositionGamma();
    try verifier.mixCompositionRoot(source_trees[3].root);
    _ = try verifier.drawOodsSeed();
    try verifier.mixSampledValues(claims);
    _ = try verifier.drawBatchLambda();
    const alpha0 = try verifier.drawFoldAlpha();
    try std.testing.expectEqualDeep(qm31FromLimbs(alpha0), verifier.privateState().fold_alphas[0]);
    return verifier;
}

fn finishH1Fold(
    verifier: *OwnedPairedGateVerifierV2,
    line_roots: [2]Digest32,
    terminals: [2][4]u32,
    n_queries: usize,
) !void {
    try verifier.captureOriginalLineRoot(line_roots[0]);
    try verifier.captureOwnQuotientLineRoot(line_roots[1]);
    const alpha1 = try verifier.drawFoldAlpha();
    try std.testing.expectEqualDeep(qm31FromLimbs(alpha1), verifier.privateState().fold_alphas[1]);
    try verifier.mixOriginalTerminalCoefficients(&terminals[0]);
    try verifier.mixOwnQuotientTerminalCoefficients(&terminals[1]);
    _ = try verifier.beginFriPow(0);
    try verifier.acceptFriNonce(0);
    try verifier.drawQueries(n_queries, (n_queries + 7) / 8);
}

fn advanceH1Fold(
    allocator: std.mem.Allocator,
    source_trees: [4]ConstantSourceTreeH1,
    line_trees: [2]ConstantLineTreeH1,
    claims: []const u32,
    terminals: [2][4]u32,
    n_queries: usize,
) !*OwnedPairedGateVerifierV2 {
    const verifier = try beginH1Fold(allocator, source_trees, claims);
    errdefer verifier.deinit();
    try finishH1Fold(verifier, .{ line_trees[0].root, line_trees[1].root }, terminals, n_queries);
    return verifier;
}

fn authenticateH1FoldSource(
    verifier: *OwnedPairedGateVerifierV2,
    ordinal: usize,
    trees: *const [4]ConstantSourceTreeH1,
) !void {
    var columns: [4][8][2]m31.M31 = undefined;
    var openings: [4]SourceTreePairOpeningV2 = undefined;
    for (&openings, trees, &columns) |*opening, *tree, *cols|
        opening.* = tree.opening(cols);
    try verifier.verifyAndKeepSourcePair(ordinal, openings);
}

test "owned H1 fold checks source to both authenticated line tracks and zero-degree terminals" {
    const allocator = std.testing.allocator;
    const source_trees = [4]ConstantSourceTreeH1{
        ConstantSourceTreeH1.init(1), ConstantSourceTreeH1.init(1),
        ConstantSourceTreeH1.init(1), ConstantSourceTreeH1.init(8),
    };
    const zero_line = try ConstantLineTreeH1.init(0);
    const line_trees = [2]ConstantLineTreeH1{ zero_line, zero_line };
    const zero_claims = [_]u32{0} ** (4 * 11);
    const zero_terminals = [2][4]u32{ [_]u32{0} ** 4, [_]u32{0} ** 4 };
    const verifier = try advanceH1Fold(allocator, source_trees, line_trees, &zero_claims, zero_terminals, 232);
    defer verifier.deinit();
    try std.testing.expectError(error.SourceContextMissing, verifier.verifyH1OneStepAtQuery(0, .{ zero_line.pair(), zero_line.pair() }));
    var seen = [_]usize{0} ** 8;
    for (0..try verifier.queryCount()) |ordinal| {
        const raw = try verifier.queryPosition(ordinal);
        seen[raw] += 1;
        try authenticateH1FoldSource(verifier, ordinal, &source_trees);
        try verifier.verifyH1OneStepAtQuery(ordinal, .{ zero_line.pair(), zero_line.pair() });
        try std.testing.expectEqual(raw, try verifier.queryPosition(ordinal));
    }
    try std.testing.expectEqual(@as(usize, 232), try verifier.queryCount());
    for (seen) |count| try std.testing.expect(count > 1);
    try std.testing.expectError(error.InvalidQueryIndex, verifier.verifyH1OneStepAtQuery(232, .{ zero_line.pair(), zero_line.pair() }));
    var changed_row = zero_line.pair();
    changed_row[0].row[0] = 1;
    try std.testing.expectError(error.InvalidLinePath, verifier.verifyH1OneStepAtQuery(0, .{ changed_row, zero_line.pair() }));
}

test "owned H1 fold rejects authenticated wrong line, terminal, and canonical claim" {
    const allocator = std.testing.allocator;
    const source_trees = [4]ConstantSourceTreeH1{
        ConstantSourceTreeH1.init(1), ConstantSourceTreeH1.init(1),
        ConstantSourceTreeH1.init(1), ConstantSourceTreeH1.init(8),
    };
    const zero_line = try ConstantLineTreeH1.init(0);
    const one_line = try ConstantLineTreeH1.init(1);
    const zero_claims = [_]u32{0} ** (4 * 11);
    const zero_terminals = [2][4]u32{ [_]u32{0} ** 4, [_]u32{0} ** 4 };

    const wrong_line = try advanceH1Fold(allocator, source_trees, .{ one_line, zero_line }, &zero_claims, zero_terminals, 8);
    defer wrong_line.deinit();
    try authenticateH1FoldSource(wrong_line, 0, &source_trees);
    try std.testing.expectError(error.OriginalIntermediateFoldMismatch, wrong_line.verifyH1OneStepAtQuery(0, .{ one_line.pair(), zero_line.pair() }));

    var bad_original_terminal = zero_terminals;
    bad_original_terminal[0][0] = 1;
    const wrong_terminal = try advanceH1Fold(allocator, source_trees, .{ zero_line, zero_line }, &zero_claims, bad_original_terminal, 8);
    defer wrong_terminal.deinit();
    try authenticateH1FoldSource(wrong_terminal, 0, &source_trees);
    try std.testing.expectError(error.OriginalTerminalFoldMismatch, wrong_terminal.verifyH1OneStepAtQuery(0, .{ zero_line.pair(), zero_line.pair() }));

    var bad_quotient_terminal = zero_terminals;
    bad_quotient_terminal[1][0] = 1;
    const wrong_quotient_terminal = try advanceH1Fold(allocator, source_trees, .{ zero_line, zero_line }, &zero_claims, bad_quotient_terminal, 8);
    defer wrong_quotient_terminal.deinit();
    try authenticateH1FoldSource(wrong_quotient_terminal, 0, &source_trees);
    try std.testing.expectError(error.QuotientTerminalFoldMismatch, wrong_quotient_terminal.verifyH1OneStepAtQuery(0, .{ zero_line.pair(), zero_line.pair() }));

    var bad_claims = zero_claims;
    bad_claims[0] = 1;
    const wrong_claim = try advanceH1Fold(allocator, source_trees, .{ zero_line, zero_line }, &bad_claims, zero_terminals, 8);
    defer wrong_claim.deinit();
    try authenticateH1FoldSource(wrong_claim, 0, &source_trees);
    try std.testing.expectError(error.QuotientIntermediateFoldMismatch, wrong_claim.verifyH1OneStepAtQuery(0, .{ zero_line.pair(), zero_line.pair() }));

    const wrong_source_row = try advanceH1Fold(allocator, source_trees, .{ zero_line, zero_line }, &zero_claims, zero_terminals, 8);
    defer wrong_source_row.deinit();
    var source_columns: [4][8][2]m31.M31 = undefined;
    var source_openings: [4]SourceTreePairOpeningV2 = undefined;
    for (&source_openings, &source_trees, &source_columns) |*opening, *tree, *cols|
        opening.* = tree.opening(cols);
    source_columns[0][0][0] = m31.M31.one();
    try std.testing.expectError(error.RootMismatch, wrong_source_row.verifyAndKeepSourcePair(0, source_openings));
    try std.testing.expectError(error.SourceContextMissing, wrong_source_row.verifyH1OneStepAtQuery(0, .{ zero_line.pair(), zero_line.pair() }));
}

test "owned H1 degree-zero terminal length fails before transcript absorption" {
    const allocator = std.testing.allocator;
    const source_trees = [4]ConstantSourceTreeH1{
        ConstantSourceTreeH1.init(1), ConstantSourceTreeH1.init(1),
        ConstantSourceTreeH1.init(1), ConstantSourceTreeH1.init(8),
    };
    const zero_claims = [_]u32{0} ** (4 * 11);
    const zero_line = try ConstantLineTreeH1.init(0);
    const verifier = try beginH1Fold(allocator, source_trees, &zero_claims);
    defer verifier.deinit();
    try verifier.captureOriginalLineRoot(zero_line.root);
    try verifier.captureOwnQuotientLineRoot(zero_line.root);
    _ = try verifier.drawFoldAlpha();
    const before = verifier.nextEvent();
    try std.testing.expectError(error.InvalidTerminalShape, verifier.mixOriginalTerminalCoefficients(&.{ 0, 0, 0, 0, 0, 0, 0, 0 }));
    try std.testing.expectEqual(before, verifier.nextEvent());
    try verifier.mixOriginalTerminalCoefficients(&.{ 0, 0, 0, 0 });
    const after_first = verifier.nextEvent();
    try std.testing.expectError(error.InvalidTerminalShape, verifier.mixOwnQuotientTerminalCoefficients(&.{}));
    try std.testing.expectEqual(after_first, verifier.nextEvent());
}

test "owned H1 nonzero quotient fold is sensitive to both retained alphas" {
    const allocator = std.testing.allocator;
    const source_trees = [4]ConstantSourceTreeH1{
        ConstantSourceTreeH1.init(1), ConstantSourceTreeH1.init(1),
        ConstantSourceTreeH1.init(1), ConstantSourceTreeH1.init(8),
    };
    var claims = [_]u32{0} ** (4 * 11);
    claims[0] = 1;
    const verifier = try beginH1Fold(allocator, source_trees, &claims);
    defer verifier.deinit();
    const state = verifier.privateState();
    const source_domain = canonic.CanonicCoset.new(3).circleDomain();
    const context = state.source_context orelse return error.SourceContextMissing;
    const zero_row = [_]m31.M31{m31.M31.zero()} ** 11;
    var quotient_words: [4]qm31.QM31 = undefined;
    for (&quotient_words, 0..) |*word, pair| {
        const base = 2 * pair;
        const p0 = source_domain.at(core_utils.bitReverseIndex(base, 3));
        const p1 = source_domain.at(core_utils.bitReverseIndex(base + 1, 3));
        const even = try context.openedValues(&zero_row, p0);
        const odd = try context.openedValues(&zero_row, p1);
        word.* = try foldPair(even[1], odd[1], p0.y, state.fold_alphas[0]);
    }
    const quotient_line = try RowLineTreeH1.init(quotient_words);
    const original_line = try ConstantLineTreeH1.init(0);
    try verifier.captureOriginalLineRoot(original_line.root);
    try verifier.captureOwnQuotientLineRoot(quotient_line.root);
    _ = try verifier.drawFoldAlpha();
    const line_x = line.LineDomain.fromCircleDomain(source_domain).at(core_utils.bitReverseIndex(0, 2));
    const terminal_quotient = try foldPair(quotient_words[0], quotient_words[1], line_x, state.fold_alphas[1]);
    const terminal_limbs = terminal_quotient.toM31Array();
    var quotient_terminal: [4]u32 = undefined;
    for (terminal_limbs, &quotient_terminal) |limb, *slot| slot.* = limb.v;
    try verifier.mixOriginalTerminalCoefficients(&.{ 0, 0, 0, 0 });
    try verifier.mixOwnQuotientTerminalCoefficients(&quotient_terminal);
    _ = try verifier.beginFriPow(0);
    try verifier.acceptFriNonce(0);
    try verifier.drawQueries(232, 29);

    var selected: ?usize = null;
    for (0..try verifier.queryCount()) |ordinal| {
        if (try verifier.queryPosition(ordinal) < 4) {
            selected = ordinal;
            break;
        }
    }
    const ordinal = selected orelse return error.InvalidQueryIndex;
    try authenticateH1FoldSource(verifier, ordinal, &source_trees);
    const raw = try verifier.queryPosition(ordinal);
    const openings = [2][2]LineRowOpeningV2{ original_line.pair(), quotient_line.pair((raw >> 1) & ~@as(usize, 1)) };
    try verifier.verifyH1OneStepAtQuery(ordinal, openings);
    var wrong_neighbor = openings;
    wrong_neighbor[1][1] = wrong_neighbor[1][0];
    try std.testing.expectError(error.InvalidLinePath, verifier.verifyH1OneStepAtQuery(ordinal, wrong_neighbor));
    const inserted = state.source_insertions.?[ordinal].?;
    try std.testing.expect(!inserted[0][1].eql(inserted[1][1]));
    try std.testing.expect(!quotient_words[0].eql(quotient_words[1]));

    // Fault injection is test-only: the opaque API never exposes these
    // values. A changed alpha at either height must break the same path.
    const alpha0 = state.fold_alphas[0];
    state.fold_alphas[0] = alpha0.add(qm31.QM31.one());
    try std.testing.expectError(error.QuotientIntermediateFoldMismatch, verifier.verifyH1OneStepAtQuery(ordinal, openings));
    state.fold_alphas[0] = alpha0;
    const alpha1 = state.fold_alphas[1];
    state.fold_alphas[1] = alpha1.add(qm31.QM31.one());
    try std.testing.expectError(error.QuotientTerminalFoldMismatch, verifier.verifyH1OneStepAtQuery(ordinal, openings));
    state.fold_alphas[1] = alpha1;
    const original_insertion = state.source_insertions.?[ordinal].?;
    var wrong_insertion = original_insertion;
    wrong_insertion[0][1] = wrong_insertion[0][1].add(qm31.QM31.one());
    state.source_insertions.?[ordinal] = wrong_insertion;
    try std.testing.expectError(error.QuotientIntermediateFoldMismatch, verifier.verifyH1OneStepAtQuery(ordinal, openings));
}

test "H1 source and line pair coordinates match production single-step FRI" {
    const allocator = std.testing.allocator;
    const production = @import("../fri/folding.zig");
    const source_domain = canonic.CanonicCoset.new(3).circleDomain();
    const alpha = qm31.QM31.fromM31Array(.{
        m31.M31.fromCanonical(7), m31.M31.fromCanonical(2),
        m31.M31.fromCanonical(3), m31.M31.fromCanonical(1),
    });
    var source_values: [8]qm31.QM31 = undefined;
    for (&source_values, 0..) |*value, i| value.* = qm31.QM31.fromBase(m31.M31.fromCanonical(@intCast(3 * i + 1)));
    var production_source = [_]qm31.QM31{qm31.QM31.zero()} ** 4;
    try production.foldCircleIntoLine(&production_source, &source_values, source_domain, alpha);
    for (0..4) |pair| {
        const base = 2 * pair;
        const p0 = source_domain.at(core_utils.bitReverseIndex(base, 3));
        const candidate = try foldPair(source_values[base], source_values[base + 1], p0.y, alpha);
        try std.testing.expect(candidate.eql(production_source[pair]));
    }

    const line_domain = line.LineDomain.fromCircleDomain(source_domain);
    var workspace = try production.FoldLineWorkspace.init(allocator, 2);
    defer workspace.deinit(allocator);
    const folded = try production.foldLineSingleStep(allocator, &production_source, line_domain, alpha, &workspace);
    defer allocator.free(folded.values);
    for (0..2) |pair| {
        const base = 2 * pair;
        const x = line_domain.at(core_utils.bitReverseIndex(base, 2));
        const candidate = try foldPair(production_source[base], production_source[base + 1], x, alpha);
        try std.testing.expect(candidate.eql(folded.values[pair]));
    }
}
