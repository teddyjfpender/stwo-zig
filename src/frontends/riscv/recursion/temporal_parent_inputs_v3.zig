//! Typed input preimage for one future V3 temporal parent transaction.
//!
//! `ChildSourceV3` is the *required shape* of a child verifier publication,
//! not evidence that a proof was verified. A future transaction must fill it
//! only from two independent verifier captures and constrain every word of
//! this frame in committed AIR. Native equality here is a preparation gate.
const std = @import("std");
const core = @import("stwo_core");
const interval = @import("temporal_interval_v3.zig");
const span = @import("span_statement.zig");
const global = @import("segment_leaf_local_authority_v3.zig");
const segment = @import("segment_statement_v2.zig");
const channel = @import("poseidon2_channel.zig");
const row11 = @import("temporal_parent_row11_session_v3.zig");

const M31 = core.fields.m31.M31;
pub const FORMAT_VERSION: u32 = 3;
pub const SCHEMA_VERSION: u32 = 1;
pub const BOUNDARY_WORDS: usize = 85;
pub const COMPLETION_WORDS: usize = 8;
pub const CHILD_WORDS: usize = 1 + 8 + span.SPAN_STATEMENT_CANONICAL_WORDS +
    2 * BOUNDARY_WORDS + 16 + COMPLETION_WORDS;
pub const PARENT_WORDS: usize = span.SPAN_STATEMENT_CANONICAL_WORDS +
    2 * BOUNDARY_WORDS + 16 + COMPLETION_WORDS;
pub const HEADER_WORDS: usize = 2 + 16;
pub const TRAILER_WORDS: usize = 4 + 8 + 2 + 1;
pub const INPUT_WORDS: usize = HEADER_WORDS + 2 * CHILD_WORDS + PARENT_WORDS + TRAILER_WORDS;
pub const Words = [INPUT_WORDS]M31;
pub const PRODUCTION_ACTIVATION = false;

/// Stable coordinates for the typed sidecar AIR and future verifier sources.
pub const Layout = struct {
    pub const leaf_key_start = 2;
    pub const temporal_child_key_start = leaf_key_start + 8;
    pub const left_child_start = HEADER_WORDS;
    pub const right_child_start = left_child_start + CHILD_WORDS;
    pub const parent_start = right_child_start + CHILD_WORDS;
    pub const trailer_start = parent_start + PARENT_WORDS;

    pub const child_family = 0;
    pub const child_key_start = child_family + 1;
    pub const child_statement_start = child_key_start + 8;
    pub const child_entry_start = child_statement_start + span.SPAN_STATEMENT_CANONICAL_WORDS;
    pub const child_exit_start = child_entry_start + BOUNDARY_WORDS;
    pub const child_first_leaf_start = child_exit_start + BOUNDARY_WORDS;
    pub const child_last_leaf_start = child_first_leaf_start + 8;
    pub const child_completion_start = child_last_leaf_start + 8;

    pub const parent_statement_start = 0;
    pub const parent_entry_start = parent_statement_start + span.SPAN_STATEMENT_CANONICAL_WORDS;
    pub const parent_exit_start = parent_entry_start + BOUNDARY_WORDS;
    pub const parent_first_leaf_start = parent_exit_start + BOUNDARY_WORDS;
    pub const parent_last_leaf_start = parent_first_leaf_start + 8;
    pub const parent_completion_start = parent_last_leaf_start + 8;

    pub const global_join_cycle_start = 0;
    pub const shared_snapshot_start = global_join_cycle_start + 4;
    pub const shared_snapshot_count_start = shared_snapshot_start + 8;
    pub const shared_continuation_root = shared_snapshot_count_start + 2;
};

comptime {
    if (BOUNDARY_WORDS != 85 or COMPLETION_WORDS != 8 or
        CHILD_WORDS != 615 or PARENT_WORDS != 606 or INPUT_WORDS != 1869 or
        Layout.child_completion_start + COMPLETION_WORDS != CHILD_WORDS or
        Layout.parent_completion_start + COMPLETION_WORDS != PARENT_WORDS or
        Layout.shared_continuation_root + 1 != TRAILER_WORDS or
        Layout.trailer_start + TRAILER_WORDS != INPUT_WORDS or
        PRODUCTION_ACTIVATION)
        @compileError("V3 temporal parent input geometry drifted");
}

pub const KeyPinsV3 = struct {
    leaf_wrapper: channel.Digest,
    /// Key admitted for a child already proved as a temporal parent. This is
    /// not the as-yet-unavailable key of the parent being constructed here.
    temporal_child: channel.Digest,

    pub fn validate(self: KeyPinsV3) !void {
        try requireDigest(self.leaf_wrapper);
        try requireDigest(self.temporal_child);
        if (std.meta.eql(self.leaf_wrapper, self.temporal_child))
            return error.ParentChildKeyCollision;
    }

    pub fn forFamily(self: KeyPinsV3, family: interval.ChildFamily) channel.Digest {
        return switch (family) {
            .leaf_wrapper_v3 => self.leaf_wrapper,
            .temporal_parent_v3 => self.temporal_child,
        };
    }
};

/// The exact data a future verifier must publish for one ordered child.
/// Public construction is intentionally not proof admission; only a fresh
/// verifier transaction may eventually mint a trusted variant of this type.
pub const ChildSourceV3 = struct {
    family: interval.ChildFamily,
    verification_key_id: channel.Digest,
    statement_words: span.StatementWords,
    entry: global.BoundaryV3,
    exit: global.BoundaryV3,
    first_leaf_id: channel.Digest,
    last_leaf_id: channel.Digest,
    final_completion: ?segment.CompletionV2,

    fn validateAgainst(
        self: *const ChildSourceV3,
        pair: *const interval.PairPreflightV3,
        position: usize,
        pins: KeyPinsV3,
    ) !void {
        if (position >= 2) return error.InvalidChildPosition;
        try requireDigest(self.verification_key_id);
        try requireDigest(self.first_leaf_id);
        try requireDigest(self.last_leaf_id);
        if (self.family != pair.child_families[position] or
            !std.meta.eql(self.verification_key_id, pins.forFamily(self.family)))
            return error.ChildVerifierKeyMismatch;
        if (!std.meta.eql(self.statement_words, pair.child_statement_words[position]) or
            !std.meta.eql(self.entry, pair.child_entry_boundaries[position]) or
            !std.meta.eql(self.exit, pair.child_exit_boundaries[position]) or
            !std.meta.eql(self.first_leaf_id, pair.child_first_leaf_ids[position]) or
            !std.meta.eql(self.last_leaf_id, pair.child_last_leaf_ids[position]) or
            !std.meta.eql(self.final_completion, pair.child_final_completions[position]))
            return error.ChildVerifierSourceMismatch;
    }
};

pub const CandidateInputsV3 = struct {
    pair: interval.PairPreflightV3,
    left: interval.IntervalV3,
    right: interval.IntervalV3,
    sources: [2]ChildSourceV3,
    pins: KeyPinsV3,
    words: Words,

    pub fn init(
        pair: *const interval.PairPreflightV3,
        left: *const interval.IntervalV3,
        right: *const interval.IntervalV3,
        sources: [2]ChildSourceV3,
        pins: KeyPinsV3,
    ) !CandidateInputsV3 {
        try pins.validate();
        try pair.validateAgainst(left, right);
        for (&sources, 0..) |*source, position|
            try source.validateAgainst(pair, position, pins);
        try requireDigest(pair.parent_first_leaf_id);
        try requireDigest(pair.parent_last_leaf_id);
        var writer = Writer{};
        writer.put(FORMAT_VERSION);
        writer.put(SCHEMA_VERSION);
        writer.digest(pins.leaf_wrapper);
        writer.digest(pins.temporal_child);
        for (sources) |source| writer.child(source);
        writer.statement(&pair.parent_statement_words);
        writer.boundary(pair.parent_entry_boundary);
        writer.boundary(pair.parent_exit_boundary);
        writer.digest(pair.parent_first_leaf_id);
        writer.digest(pair.parent_last_leaf_id);
        writer.completion(pair.parent_final_completion);
        writer.u64Value(pair.global_join_cycle);
        writer.digest(pair.shared_snapshot_id);
        writer.u32Value(pair.shared_snapshot_count);
        writer.put(pair.shared_continuation_root);
        if (writer.at != INPUT_WORDS) return error.ParentInputGeometryMismatch;
        return .{
            .pair = pair.*,
            .left = left.*,
            .right = right.*,
            .sources = sources,
            .pins = pins,
            .words = writer.words,
        };
    }

    pub fn validate(self: *const CandidateInputsV3) !void {
        const fresh = try init(&self.pair, &self.left, &self.right, self.sources, self.pins);
        if (!std.meta.eql(self.*, fresh)) return error.ParentInputChanged;
    }

    /// Reuses the qualified log-12 statement component; it still does not
    /// commit the endpoint/source words or verify either child proof.
    pub fn fillRow11(
        self: *const CandidateInputsV3,
        session: *const row11.SessionV3,
        workspace: *row11.WorkspaceV3,
        trace: *row11.TraceV3,
    ) !void {
        try self.validate();
        try session.fillTrace(&self.pair, &self.left, &self.right, workspace, trace);
    }

    pub fn requireVerifiedParent(_: *const CandidateInputsV3) error{ParentProofUnavailable}!void {
        return error.ParentProofUnavailable;
    }
};

fn requireDigest(value: channel.Digest) !void {
    var aggregate: u32 = 0;
    for (value) |word| {
        if (word >= core.fields.m31.Modulus) return error.NonCanonicalParentDigest;
        aggregate |= word;
    }
    if (aggregate == 0) return error.ZeroParentDigest;
}

const Writer = struct {
    words: Words = undefined,
    at: usize = 0,

    fn put(self: *Writer, value: u32) void {
        std.debug.assert(self.at < INPUT_WORDS and value < core.fields.m31.Modulus);
        self.words[self.at] = M31.fromCanonical(value);
        self.at += 1;
    }

    fn u32Value(self: *Writer, value: u32) void {
        self.put(value & 0xffff);
        self.put(value >> 16);
    }

    fn u64Value(self: *Writer, value: u64) void {
        inline for (0..4) |i| self.put(@intCast((value >> (16 * i)) & 0xffff));
    }

    fn digest(self: *Writer, value: channel.Digest) void {
        for (value) |word| self.put(word);
    }

    fn statement(self: *Writer, value: *const span.StatementWords) void {
        for (value) |word| self.put(word.toU32());
    }

    fn boundary(self: *Writer, value: global.BoundaryV3) void {
        self.digest(value.snapshot_id);
        self.u32Value(value.snapshot_count);
        self.put(value.continuation_root);
        for (value.register_clocks) |clock| self.u32Value(clock);
        self.digest(value.memory_clock_id);
        self.u32Value(value.memory_clock_count);
    }

    fn completion(self: *Writer, value: ?segment.CompletionV2) void {
        if (value) |completion_value| {
            self.put(1);
            self.put(@intFromEnum(completion_value.kind));
            self.u32Value(completion_value.address);
            self.u32Value(completion_value.value);
            self.u32Value(completion_value.clock);
        } else for (0..COMPLETION_WORDS) |_| self.put(0);
    }

    fn child(self: *Writer, value: ChildSourceV3) void {
        self.put(@intFromEnum(value.family));
        self.digest(value.verification_key_id);
        self.statement(&value.statement_words);
        self.boundary(value.entry);
        self.boundary(value.exit);
        self.digest(value.first_leaf_id);
        self.digest(value.last_leaf_id);
        self.completion(value.final_completion);
    }
};
