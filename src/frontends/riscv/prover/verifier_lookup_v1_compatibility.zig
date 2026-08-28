//! Explicit replay-only verifier for the retired SegmentV2 lookup layout.

const std = @import("std");
const pcs_core = @import("stwo_core").pcs;
const statement_v2 = @import("../air/statement_v2.zig");
const types = @import("types.zig");
const verifier = @import("verifier.zig");

pub fn verifyWithEngine(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    pcs_config: pcs_core.PcsConfig,
    statement: statement_v2.RiscVStatementV2,
    proof_in: types.ProofForEngine(Engine),
    claim: *const types.RiscVInteractionClaim,
) !void {
    var transcript_channel = Engine.Channel{};
    return verifyUsingChannel(
        Engine,
        allocator,
        pcs_config,
        statement,
        proof_in,
        claim,
        &transcript_channel,
    );
}

pub fn verifyUsingChannel(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    pcs_config: pcs_core.PcsConfig,
    statement: statement_v2.RiscVStatementV2,
    proof_in: types.ProofForEngine(Engine),
    claim: *const types.RiscVInteractionClaim,
    transcript_channel: *Engine.Channel,
) !void {
    return verifier.verifyRiscVWithEngineUsingChannelImpl(
        verifier.V2Protocol,
        Engine,
        .compatibility,
        allocator,
        pcs_config,
        statement,
        proof_in,
        claim,
        transcript_channel,
        null,
        null,
        null,
        null,
    );
}
