//! Retain actual independently admitted PAGE fixed factories and original live
//! statement/claim bodies. This marker never invokes a factory or proof body.
const std = @import("std");
const core = @import("stwo_core");
const Semantic = @import("prover/block_v5_memory_source_page_semantic_columns_v1.zig");
const Transcripts = @import("recursion/block_v5_memory_source_page_recursive_fixed_transcript_v1.zig");
const Pcs = @import("recursion/block_v5_native_recursive_fixed_pcs_v1.zig");
fn Bodies(comptime kind: Semantic.Kind) type {
    const Original = @import("prover/block_v5_memory_source_unified_page_proof_v1.zig").ForKind(kind);
    const Claims = @import("prover/block_v5_memory_source_unified_page_components_v1.zig").ForKind(kind).Claims;
    const Statement = @import("recursion/air/block_v5_memory_source_page_statement_v1.zig").ForKind(kind);
    const Transcript = Transcripts.ForKind(kind).Owned;
    const Ports = Pcs.ForPage(kind);
    return struct {
        fn claims(channel: *core.channel.blake3.Channel, values: Claims) void {
            Original.mixClaims(channel, values);
        }
        fn keep() void {
            inline for (.{ &Transcript.derive, &Transcript.validateAgainst, &Transcript.deinit, &Transcript.requireComplete, &Ports.derive, &Ports.validateAgainst, &Ports.Owned.deinit, &Statement.init, &Statement.deinit, &claims }) |body| std.mem.doNotOptimizeAway(body);
        }
    };
}
pub export fn stwo_page_fixed_transcript_body_gate() void {
    // Retain both original PAGE families in this compiler-only body gate.
    @setEvalBranchQuota(100_000);
    Bodies(.raw).keep();
    Bodies(.fold).keep();
}
