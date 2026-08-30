//! Fail-closed adapter from a V3 globally positioned leaf to the existing V2
//! native proof machinery.
//!
//! The VM AIR already constrains bounded local clocks. Rewriting that AIR just
//! to support a 64-bit job position would add a second prover implementation.
//! Instead, this adapter constructs a deterministic *local* V2 statement over
//! the same trace, CPU transition, sparse memory, and local predecessor clocks.
//! A recursive V3 wrapper must then bind that verified local statement to the
//! global metadata from `segment_leaf_local_authority_v3`.
//!
//! The projected `SegmentResult` is a borrowed shallow view. It owns no bytes,
//! must never be deinitialized, and its continuation token must never be used
//! to resume execution. `validateAgainst` re-derives every changed field from
//! the global source before the view may enter the V2 prover.

const std = @import("std");

const runner_result = @import("../runner/result.zig");
const span = @import("span_statement.zig");
const segment_v2 = @import("segment_statement_v2.zig");
const global_v3 = @import("segment_leaf_local_authority_v3.zig");

pub const FORMAT_VERSION: u16 = 3;
pub const SCHEMA_VERSION: u16 = 1;
pub const PRODUCTION_PROOF_ACTIVATION = false;
pub const RESUME_CAPABILITY_RETAINED = false;

pub const Error = global_v3.Error || error{
    LocalProjectionMismatch,
    UnsupportedVersion,
};

pub const ProjectionV3 = struct {
    format_version: u16 = FORMAT_VERSION,
    schema_version: u16 = SCHEMA_VERSION,
    local_statement: span.SpanStatement,
    /// Borrowed view; do not call `deinit` and do not resume its continuation.
    local_result: runner_result.SegmentResult,

    pub fn init(source: *const global_v3.SourceV3) Error!ProjectionV3 {
        try source.validate();
        var local_result = source.result.*;
        local_result.clock_frame = .global_continuous;
        local_result.global_first_cycle = 1;
        // Preserve presence and all source custody, but make the borrowed token
        // visibly non-resumable in the projected frame. The runner still owns
        // and validates the original leaf-local capability.
        if (local_result.continuation) |*token|
            token.clock_frame = .global_continuous;
        const result = ProjectionV3{
            .local_statement = try localStatement(source),
            .local_result = local_result,
        };
        try result.validateAgainst(source);
        return result;
    }

    pub fn validateAgainst(
        self: *const ProjectionV3,
        source: *const global_v3.SourceV3,
    ) Error!void {
        if (self.format_version != FORMAT_VERSION or
            self.schema_version != SCHEMA_VERSION)
        {
            return error.UnsupportedVersion;
        }
        try source.validate();
        const expected_statement = try localStatement(source);
        if (!std.meta.eql(self.local_statement, expected_statement))
            return error.LocalProjectionMismatch;

        var expected_result = source.result.*;
        expected_result.clock_frame = .global_continuous;
        expected_result.global_first_cycle = 1;
        if (expected_result.continuation) |*token|
            token.clock_frame = .global_continuous;
        if (!std.meta.eql(self.local_result, expected_result))
            return error.LocalProjectionMismatch;

        _ = try segment_v2.SourceV2.fromSegmentResult(
            placeholderSessionId(),
            self.local_statement,
            &self.local_result,
        );
    }

    /// Revalidates the global-to-local link before deriving the exact V2
    /// source. The caller-supplied session identity remains transcript-bound by
    /// V2 and is deliberately not invented by this adapter.
    pub fn sourceV2(
        self: *const ProjectionV3,
        source: *const global_v3.SourceV3,
        session_id: segment_v2.Digest,
    ) Error!segment_v2.SourceV2 {
        try self.validateAgainst(source);
        return segment_v2.SourceV2.fromSegmentResult(
            session_id,
            self.local_statement,
            &self.local_result,
        );
    }
};

fn localStatement(source: *const global_v3.SourceV3) Error!span.SpanStatement {
    const metadata = try source.metadata();
    return localStatementFromMetadata(&metadata);
}

/// Reconstruct the exact local V2 span from a validated pointer-free global
/// projection. Recursive ingress uses this to prove that the verified local
/// statement is the unique projection of the advertised global leaf.
pub fn localStatementFromMetadata(
    metadata: *const global_v3.MetadataV3,
) Error!span.SpanStatement {
    try metadata.validate();
    const global = span.SpanStatement.fromCanonicalWords(
        &metadata.base_statement_words,
    ) catch return error.BaseStatementMismatch;
    const global_span = switch (global.body) {
        .empty => return error.SegmentLeafRequired,
        .executed => |value| value,
    };
    var local_complete = global.job.complete;
    local_complete.total_cycles = metadata.local_cycle_count;
    const local_job = try span.JobContext.init(
        local_complete,
        global.job.segment_count,
    );
    return span.SpanStatement.segmentLeaf(
        local_job,
        metadata.segment_index,
        try span.ExecutedSpan.init(
            metadata.segment_index,
            1,
            0,
            metadata.local_cycle_count,
            global_span.entry,
            global_span.exit,
            global_span.input,
            global_span.output,
        ),
    );
}

/// Used only for structural validation before a caller supplies the real
/// transcript-bound session identity. It is nonzero and canonical.
fn placeholderSessionId() segment_v2.Digest {
    return .{ FORMAT_VERSION, SCHEMA_VERSION, 0x4c50_5633, 1, 2, 3, 4, 5 };
}
