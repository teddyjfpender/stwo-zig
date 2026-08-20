//! Retained, allocation-free interaction workspace for binary transcript rows.

const std = @import("std");
const stwo_core = @import("stwo_core");
const M31 = stwo_core.fields.m31.M31;
const binary_authority = @import("binary_pair_authority.zig");
const air = @import("air/mod.zig");
const binding = air.universal_relation_binding;
const framework = air.framework_interaction;

const ControlRelation = binding.Binding(air.control);
const TranscriptAirRelation = binding.Binding(air.transcript_air);
const TranscriptBindingRelation = binding.Binding(air.transcript_binding);
const TranscriptStateRelation = binding.Binding(air.transcript_state);
const TranscriptWordRelation = binding.Binding(air.transcript_word);
const TranscriptPayloadRelation = binding.Binding(air.transcript_payload);
const PowCheckRelation = binding.Binding(air.pow_check);
const PowFrameRelation = binding.Binding(air.pow_frame);
const RelationChallengeRelation = binding.Binding(air.relation_challenge);
const VerifierRandomnessRelation = binding.Binding(air.verifier_randomness);

const ControlFramework = framework.Runtime(ControlRelation.Runtime);
const TranscriptAirFramework = framework.Runtime(TranscriptAirRelation.Runtime);
const TranscriptBindingFramework = framework.Runtime(TranscriptBindingRelation.Runtime);
const TranscriptStateFramework = framework.Runtime(TranscriptStateRelation.Runtime);
const TranscriptWordFramework = framework.Runtime(TranscriptWordRelation.Runtime);
const TranscriptPayloadFramework = framework.Runtime(TranscriptPayloadRelation.Runtime);
const PowCheckFramework = framework.Runtime(PowCheckRelation.Runtime);
const PowFrameFramework = framework.Runtime(PowFrameRelation.Runtime);
const RelationChallengeFramework = framework.Runtime(RelationChallengeRelation.Runtime);
const VerifierRandomnessFramework = framework.Runtime(VerifierRandomnessRelation.Runtime);

pub fn Type(
    comptime Self: type,
    comptime Prepared: type,
    comptime LogSizes: type,
    comptime logicalStorageCount: anytype,
    comptime carveRows: anytype,
    comptime validateCarvedRows: anytype,
    comptime rowIndex: anytype,
) type {
    return struct {
        const InteractionWorkspace = @This();
        allocator: std.mem.Allocator,
        source_authority_seal: [32]u8,
        log_sizes: LogSizes,
        logical_storage: []M31,
        control_rows: []ControlRelation.Row,
        transcript_air_rows: []TranscriptAirRelation.Row,
        transcript_binding_rows: []TranscriptBindingRelation.Row,
        transcript_state_rows: []TranscriptStateRelation.Row,
        transcript_word_rows: []TranscriptWordRelation.Row,
        transcript_payload_rows: []TranscriptPayloadRelation.Row,
        pow_check_rows: []PowCheckRelation.Row,
        pow_frame_rows: []PowFrameRelation.Row,
        relation_challenge_rows: []RelationChallengeRelation.Row,
        verifier_randomness_rows: []VerifierRandomnessRelation.Row,
        control_framework: ControlFramework.Workspace,
        transcript_air_framework: TranscriptAirFramework.Workspace,
        transcript_binding_framework: TranscriptBindingFramework.Workspace,
        transcript_state_framework: TranscriptStateFramework.Workspace,
        transcript_word_framework: TranscriptWordFramework.Workspace,
        transcript_payload_framework: TranscriptPayloadFramework.Workspace,
        pow_check_framework: PowCheckFramework.Workspace,
        pow_frame_framework: PowFrameFramework.Workspace,
        relation_challenge_framework: RelationChallengeFramework.Workspace,
        verifier_randomness_framework: VerifierRandomnessFramework.Workspace,

        pub fn init(
            allocator: std.mem.Allocator,
            source: *const Self,
            preprocessing: *const binary_authority.TranscriptPreprocessing,
            prepared: *const Prepared,
        ) !InteractionWorkspace {
            const logical_count = try logicalStorageCount(
                source,
                preprocessing,
                prepared,
            );
            const logical_storage = try allocator.alloc(M31, logical_count);
            errdefer allocator.free(logical_storage);

            var cursor: usize = 0;
            const control_rows = try carveRows(
                ControlRelation.Row,
                logical_storage,
                &cursor,
                source.control_preprocessing.rows.len,
            );
            const transcript_air_rows = try carveRows(
                TranscriptAirRelation.Row,
                logical_storage,
                &cursor,
                prepared.transcript_air.rows.len,
            );
            const transcript_binding_rows = try carveRows(
                TranscriptBindingRelation.Row,
                logical_storage,
                &cursor,
                preprocessing.transcript_binding.rows.len,
            );
            const transcript_state_rows = try carveRows(
                TranscriptStateRelation.Row,
                logical_storage,
                &cursor,
                preprocessing.transcript_state.rows.len,
            );
            const transcript_word_rows = try carveRows(
                TranscriptWordRelation.Row,
                logical_storage,
                &cursor,
                preprocessing.transcript_word.rows.len,
            );
            const transcript_payload_rows = try carveRows(
                TranscriptPayloadRelation.Row,
                logical_storage,
                &cursor,
                preprocessing.transcript_payload.rows.len,
            );
            const pow_check_rows = try carveRows(
                PowCheckRelation.Row,
                logical_storage,
                &cursor,
                prepared.pow_check.invocations.len,
            );
            const pow_frame_rows = try carveRows(
                PowFrameRelation.Row,
                logical_storage,
                &cursor,
                prepared.pow_frame.invocations.len,
            );
            const relation_challenge_rows = try carveRows(
                RelationChallengeRelation.Row,
                logical_storage,
                &cursor,
                preprocessing.relation_challenge.rows.len,
            );
            const verifier_randomness_rows = try carveRows(
                VerifierRandomnessRelation.Row,
                logical_storage,
                &cursor,
                preprocessing.verifier_randomness.rows.len,
            );
            if (cursor != logical_storage.len)
                return error.InteractionWorkspaceGeometryMismatch;

            var control_framework = try ControlFramework.Workspace.init(
                allocator,
                source.log_sizes[rowIndex(.control)],
            );
            errdefer control_framework.deinit();
            var transcript_air_framework = try TranscriptAirFramework.Workspace.init(
                allocator,
                source.log_sizes[rowIndex(.transcript_air)],
            );
            errdefer transcript_air_framework.deinit();
            var transcript_binding_framework =
                try TranscriptBindingFramework.Workspace.init(
                    allocator,
                    source.log_sizes[rowIndex(.transcript_binding)],
                );
            errdefer transcript_binding_framework.deinit();
            var transcript_state_framework = try TranscriptStateFramework.Workspace.init(
                allocator,
                source.log_sizes[rowIndex(.transcript_state)],
            );
            errdefer transcript_state_framework.deinit();
            var transcript_word_framework = try TranscriptWordFramework.Workspace.init(
                allocator,
                source.log_sizes[rowIndex(.transcript_word)],
            );
            errdefer transcript_word_framework.deinit();
            var transcript_payload_framework =
                try TranscriptPayloadFramework.Workspace.init(
                    allocator,
                    source.log_sizes[rowIndex(.transcript_payload)],
                );
            errdefer transcript_payload_framework.deinit();
            var pow_check_framework = try PowCheckFramework.Workspace.init(
                allocator,
                source.log_sizes[rowIndex(.pow_check)],
            );
            errdefer pow_check_framework.deinit();
            var pow_frame_framework = try PowFrameFramework.Workspace.init(
                allocator,
                source.log_sizes[rowIndex(.pow_frame)],
            );
            errdefer pow_frame_framework.deinit();
            var relation_challenge_framework =
                try RelationChallengeFramework.Workspace.init(
                    allocator,
                    source.log_sizes[rowIndex(.relation_challenge)],
                );
            errdefer relation_challenge_framework.deinit();
            var verifier_randomness_framework =
                try VerifierRandomnessFramework.Workspace.init(
                    allocator,
                    source.log_sizes[rowIndex(.verifier_randomness)],
                );
            errdefer verifier_randomness_framework.deinit();

            return .{
                .allocator = allocator,
                .source_authority_seal = source.authority_seal,
                .log_sizes = source.log_sizes,
                .logical_storage = logical_storage,
                .control_rows = control_rows,
                .transcript_air_rows = transcript_air_rows,
                .transcript_binding_rows = transcript_binding_rows,
                .transcript_state_rows = transcript_state_rows,
                .transcript_word_rows = transcript_word_rows,
                .transcript_payload_rows = transcript_payload_rows,
                .pow_check_rows = pow_check_rows,
                .pow_frame_rows = pow_frame_rows,
                .relation_challenge_rows = relation_challenge_rows,
                .verifier_randomness_rows = verifier_randomness_rows,
                .control_framework = control_framework,
                .transcript_air_framework = transcript_air_framework,
                .transcript_binding_framework = transcript_binding_framework,
                .transcript_state_framework = transcript_state_framework,
                .transcript_word_framework = transcript_word_framework,
                .transcript_payload_framework = transcript_payload_framework,
                .pow_check_framework = pow_check_framework,
                .pow_frame_framework = pow_frame_framework,
                .relation_challenge_framework = relation_challenge_framework,
                .verifier_randomness_framework = verifier_randomness_framework,
            };
        }

        pub fn deinit(self: *InteractionWorkspace) void {
            self.verifier_randomness_framework.deinit();
            self.relation_challenge_framework.deinit();
            self.pow_frame_framework.deinit();
            self.pow_check_framework.deinit();
            self.transcript_payload_framework.deinit();
            self.transcript_word_framework.deinit();
            self.transcript_state_framework.deinit();
            self.transcript_binding_framework.deinit();
            self.transcript_air_framework.deinit();
            self.control_framework.deinit();
            self.allocator.free(self.logical_storage);
            self.* = undefined;
        }

        pub fn validateFor(
            self: *const InteractionWorkspace,
            source: *const Self,
            preprocessing: *const binary_authority.TranscriptPreprocessing,
            prepared: *const Prepared,
        ) !void {
            if (!std.mem.eql(
                u8,
                &self.source_authority_seal,
                &source.authority_seal,
            ) or !std.meta.eql(self.log_sizes, source.log_sizes) or
                self.logical_storage.len != try logicalStorageCount(
                    source,
                    preprocessing,
                    prepared,
                ))
            {
                return error.InteractionWorkspaceGeometryMismatch;
            }

            var cursor: usize = 0;
            try validateCarvedRows(
                ControlRelation.Row,
                self.logical_storage,
                &cursor,
                self.control_rows,
                source.control_preprocessing.rows.len,
            );
            try validateCarvedRows(
                TranscriptAirRelation.Row,
                self.logical_storage,
                &cursor,
                self.transcript_air_rows,
                prepared.transcript_air.rows.len,
            );
            try validateCarvedRows(
                TranscriptBindingRelation.Row,
                self.logical_storage,
                &cursor,
                self.transcript_binding_rows,
                preprocessing.transcript_binding.rows.len,
            );
            try validateCarvedRows(
                TranscriptStateRelation.Row,
                self.logical_storage,
                &cursor,
                self.transcript_state_rows,
                preprocessing.transcript_state.rows.len,
            );
            try validateCarvedRows(
                TranscriptWordRelation.Row,
                self.logical_storage,
                &cursor,
                self.transcript_word_rows,
                preprocessing.transcript_word.rows.len,
            );
            try validateCarvedRows(
                TranscriptPayloadRelation.Row,
                self.logical_storage,
                &cursor,
                self.transcript_payload_rows,
                preprocessing.transcript_payload.rows.len,
            );
            try validateCarvedRows(
                PowCheckRelation.Row,
                self.logical_storage,
                &cursor,
                self.pow_check_rows,
                prepared.pow_check.invocations.len,
            );
            try validateCarvedRows(
                PowFrameRelation.Row,
                self.logical_storage,
                &cursor,
                self.pow_frame_rows,
                prepared.pow_frame.invocations.len,
            );
            try validateCarvedRows(
                RelationChallengeRelation.Row,
                self.logical_storage,
                &cursor,
                self.relation_challenge_rows,
                preprocessing.relation_challenge.rows.len,
            );
            try validateCarvedRows(
                VerifierRandomnessRelation.Row,
                self.logical_storage,
                &cursor,
                self.verifier_randomness_rows,
                preprocessing.verifier_randomness.rows.len,
            );
            if (cursor != self.logical_storage.len)
                return error.InteractionWorkspaceGeometryMismatch;
        }
    };
}
