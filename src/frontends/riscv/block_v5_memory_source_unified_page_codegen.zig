//! Real new PAGE bodies retained; no PCS, proof, FRI, guest or device invoked.
const std = @import("std");
const core = @import("stwo_core");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const Semantic = @import("prover/block_v5_memory_source_page_semantic_columns_v1.zig");
const FoldStage = @import("prover/block_v5_memory_source_fold_premix_v1.zig").ForBackend(Cpu);
const Protocol = @import("prover/block_v5_memory_source_unified_page_protocol_v1.zig");
const Batch = @import("prover/block_v5_memory_source_batch_protocol_v1.zig");
const Raw = @import("prover/block_v5_memory_source_batch_raw_schema_v1.zig");
const Operand = @import("prover/block_v5_memory_source_packed_sha_replay_v1.zig");
const Seal = @import("prover/block_v5_source_seal_v1.zig");
const Page = @import("prover/block_v5_memory_source_unified_page_proof_v1.zig");
const Codec = @import("prover/block_v5_memory_source_unified_page_codec_v1.zig");
fn drawEpoch(a: std.mem.Allocator, admitted: *const Batch.Admission, raw_plan: Raw.Protocol.Plan, fold_plan: Protocol.FoldPlan, raw: []const Operand.Pin, fold: []const Protocol.FoldPin, sealed: Protocol.Sealed, expected: [32]u8, base: Seal.Sealed, limits: Protocol.Limits) !Protocol.SourceEpoch {
    return Protocol.draw(a, admitted, raw_plan, fold_plan, raw, fold, sealed, expected, base, limits);
}
test "source unified PAGE bodies: actual compact fold six-root collect replay retained leases and one-graph direct materialization" {
    inline for (.{
        &FoldStage.collect,          &FoldStage.persist,    &FoldStage.replay,                     &FoldStage.lease,          &FoldStage.Owner.require, &FoldStage.Owner.deinit, &FoldStage.Lease.takeScheme, &FoldStage.Lease.deinit,
        &Semantic.prepareRaw,        &Semantic.prepareFold, &Semantic.Prepared.readAndMaterialize, &Semantic.Prepared.deinit, &Protocol.FoldPlan.init,  &Protocol.seal,          &drawEpoch,                  &Protocol.beginSemantic,
        &Protocol.drawPageRelations,
    }) |body| std.mem.doNotOptimizeAway(body);
    inline for (.{
        @import("prover/block_v5_memory_source_page_input_component_v1.zig").ForWidth(960).Component,
        @import("prover/block_v5_memory_source_page_input_component_v1.zig").ForWidth(1859).Component,
        @import("prover/block_v5_memory_source_page_input_component_v1.zig").ForWidth(256).Component,
        @import("prover/block_v5_memory_source_page_input_component_v1.zig").ForWidth(192).Component,
        @import("prover/block_v5_memory_source_page_canonical_component_v1.zig").ForKind(.raw).Component,
        @import("prover/block_v5_memory_source_page_canonical_component_v1.zig").ForKind(.fold).Component,
        @import("prover/block_v5_memory_source_blake_capture_component_v1.zig").Component,
    }) |Component| {
        inline for (.{ &Component.asProverComponent, &Component.asVerifierComponent, &Component.traceLogDegreeBounds, &Component.maskPoints, &Component.evaluateConstraintQuotientsAtPoint, &Component.evaluateConstraintQuotientsOnDomain }) |body| std.mem.doNotOptimizeAway(body);
    }
    inline for (.{ Semantic.Kind.raw, Semantic.Kind.fold }) |kind| {
        const Typed = Page.ForKind(kind);
        const Producer = Typed.ForBackend(Cpu);
        const Artifact = Codec.ForKind(kind);
        const Arithmetic = @import("prover/block_v5_memory_source_page_arithmetic_columns_v1.zig").ForKind(kind);
        const Interaction = @import("prover/block_v5_memory_source_page_interaction_v1.zig").ForKind(kind);
        const Combined = @import("prover/block_v5_memory_source_unified_page_components_v1.zig").ForKind(kind);
        inline for (.{
            &Producer.prove,       &Producer.Proved.deinit,           &Typed.verifyOwned,                  &Typed.admit,
            &Typed.Admission.init, &Typed.Admission.deinit,           &Artifact.encode,                    &Artifact.decode,
            &Artifact.preflight,   &Arithmetic.Fixed.init,            &Arithmetic.Main.init,               &Interaction.generate,
            &Combined.Owner.init,  &Combined.Owner.asProverComponent, &Combined.Owner.asVerifierComponent,
        }) |body| std.mem.doNotOptimizeAway(body);
    }
    inline for (.{ &Page.Context.init, &Page.Context.require, &Page.Context.deinit, &@import("prover/block_v5_memory_source_fold_fixed_columns_v1.zig").Columns.init }) |body| std.mem.doNotOptimizeAway(body);
    _ = core;
}
