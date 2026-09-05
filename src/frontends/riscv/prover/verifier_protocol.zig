//! Statement-version transcript and public-boundary policy for the native
//! RISC-V verifier. Kept separate so the proof verifier retains headroom for
//! append-only protocol routes without duplicating statement semantics.

const pcs_core = @import("stwo_core").pcs;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const public_logup = @import("../air/public_logup.zig");
const relation_challenges = @import("../air/relation_challenges.zig");
const statement_v2 = @import("../air/statement_v2.zig");
const statement_validation = @import("statement_validation.zig");
const types = @import("types.zig");

pub const V1Protocol = struct {
    pub const Statement = types.RiscVStatement;
    pub const is_v2 = false;

    pub fn core(value: *const Statement) *const types.RiscVStatement {
        return value;
    }

    pub fn validate(value: *const Statement) !void {
        try statement_validation.validate(value.*, .proof);
    }

    pub fn bind(
        comptime Engine: type,
        pcs_config: pcs_core.PcsConfig,
        value: *const Statement,
        transcript_channel: *Engine.Channel,
    ) !void {
        if (comptime @hasDecl(Engine.Channel, "bindRiscVTranscript")) {
            try transcript_channel.bindRiscVTranscript(
                pcs_config,
                &value.public_data,
            );
        } else {
            pcs_config.mixInto(transcript_channel);
            value.public_data.mixInto(transcript_channel);
        }
    }

    pub fn publicBoundary(
        value: *const Statement,
        relations: *const relation_challenges.Relations,
    ) !QM31 {
        return public_logup.sum(&value.public_data, relations);
    }

    pub fn declaresPublicIo(value: *const Statement) bool {
        return value.public_data.declaresPublicIo();
    }
};

pub const V2Protocol = struct {
    pub const Statement = statement_v2.RiscVStatementV2;
    pub const is_v2 = true;

    pub fn core(value: *const Statement) *const types.RiscVStatement {
        return &value.core;
    }

    pub fn validate(value: *const Statement) !void {
        try statement_validation.validateV2(value, .proof);
    }

    pub fn bind(
        comptime Engine: type,
        pcs_config: pcs_core.PcsConfig,
        value: *const Statement,
        transcript_channel: *Engine.Channel,
    ) !void {
        pcs_config.mixInto(transcript_channel);
        try statement_v2.mixIntoNativeTranscript(
            &value.public_data,
            transcript_channel,
        );
    }

    pub fn publicBoundary(
        value: *const Statement,
        relations: *const relation_challenges.Relations,
    ) !QM31 {
        return statement_v2.nativeRelationSum(&value.public_data, relations);
    }

    pub fn declaresPublicIo(value: *const Statement) bool {
        return value.declaresPublicIo() catch true;
    }
};
