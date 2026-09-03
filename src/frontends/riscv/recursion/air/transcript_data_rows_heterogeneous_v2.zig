//! Exact lane-specific preprocessing for transcript rows 2, 4, and 5.
//!
//! These append-only authorities compile the VM, left-child, and right-child
//! verifier schedules independently. Retained rows are reconstructed from the
//! admitted plans on every public validation boundary; their SHA-256 seals are
//! transport cross-checks, never substitutes for typed reconstruction.

const generic = @import("three_lane_preprocessed_heterogeneous_v2.zig");
const binding = @import("transcript_binding_witness_contract.zig");
const payload = @import("transcript_payload_witness_binding.zig");
const protocol = @import("../protocol.zig");
const schedule = @import("verifier_schedule.zig");
const word = @import("transcript_word_witness_binding.zig");

const BindingContext = struct {
    pub const Base = binding;
    pub const AUTHORITY_DOMAIN =
        "stwo-zig/typed-air/transcript-binding-heterogeneous/v2\x00";

    pub fn count(plan: *const schedule.Plan) Base.Error!usize {
        try Base.component.SourceAuthority.pinned().validate();
        return Base.callCount(plan);
    }

    pub const append = Base.appendPlanRows;
    pub const compare = Base.comparePlanRows;
    pub const logSize = Base.traceLogSize;
};

const WordBase = struct {
    pub const PreprocessedRow = word.Row;
    pub const Error = word.Error;
};

const WordContext = struct {
    pub const Base = WordBase;
    pub const AUTHORITY_DOMAIN =
        "stwo-zig/typed-air/transcript-word-heterogeneous/v2\x00";

    pub fn count(plan: *const schedule.Plan) Base.Error!usize {
        try word.component.SourceAuthority.pinned().validate();
        return word.laneRowCount(plan);
    }

    pub fn append(
        rows: []Base.PreprocessedRow,
        cursor: *usize,
        plan: *const schedule.Plan,
        verifier_id: u32,
        segment_mask: u32,
        binary_mask: u32,
    ) Base.Error!void {
        if (cursor.* > rows.len) return error.AuthorityMismatch;
        var sink = word.Sink.write(rows[cursor.*..]);
        try word.emitLane(
            &sink,
            plan,
            verifier_id,
            segment_mask,
            binary_mask,
        );
        cursor.* += sink.at;
    }

    pub fn compare(
        rows: []const Base.PreprocessedRow,
        cursor: *usize,
        plan: *const schedule.Plan,
        verifier_id: u32,
        segment_mask: u32,
        binary_mask: u32,
    ) Base.Error!void {
        if (cursor.* > rows.len) return error.AuthorityMismatch;
        var sink = word.Sink.compare(rows[cursor.*..]);
        try word.emitLane(
            &sink,
            plan,
            verifier_id,
            segment_mask,
            binary_mask,
        );
        cursor.* += sink.at;
    }

    pub const logSize = word.logSizeFor;
};

const PayloadBase = struct {
    pub const PreprocessedRow = payload.Row;
    pub const Error = payload.Error;
};

const PayloadContext = struct {
    pub const Base = PayloadBase;
    pub const AUTHORITY_DOMAIN =
        "stwo-zig/typed-air/transcript-payload-heterogeneous/v2\x00";

    pub fn count(plan: *const schedule.Plan) Base.Error!usize {
        try payload.component.SourceAuthority.pinned().validate();
        try (protocol.Profile{}).validate();
        return payload.laneRowCount(plan);
    }

    pub fn append(
        rows: []Base.PreprocessedRow,
        cursor: *usize,
        plan: *const schedule.Plan,
        verifier_id: u32,
        segment_mask: u32,
        binary_mask: u32,
    ) Base.Error!void {
        if (cursor.* > rows.len) return error.AuthorityMismatch;
        var sink = payload.Sink.write(rows[cursor.*..]);
        const protocol_id = protocol.protocolId();
        try payload.emitLane(
            &sink,
            plan,
            &protocol_id,
            verifier_id,
            segment_mask,
            binary_mask,
        );
        cursor.* += sink.at;
    }

    pub fn compare(
        rows: []const Base.PreprocessedRow,
        cursor: *usize,
        plan: *const schedule.Plan,
        verifier_id: u32,
        segment_mask: u32,
        binary_mask: u32,
    ) Base.Error!void {
        if (cursor.* > rows.len) return error.AuthorityMismatch;
        var sink = payload.Sink.compare(rows[cursor.*..]);
        const protocol_id = protocol.protocolId();
        try payload.emitLane(
            &sink,
            plan,
            &protocol_id,
            verifier_id,
            segment_mask,
            binary_mask,
        );
        cursor.* += sink.at;
    }

    pub fn logSize(row_count: usize) Base.Error!u32 {
        return @import("transcript_payload_witness_source.zig")
            .logSizeFor(row_count);
    }
};

pub const TranscriptBindingPreprocessedV2 = generic.Type(BindingContext);
pub const TranscriptWordPreprocessedV2 = generic.Type(WordContext);
pub const TranscriptPayloadPreprocessedV2 = generic.Type(PayloadContext);
