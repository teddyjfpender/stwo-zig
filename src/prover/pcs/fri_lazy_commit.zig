const std = @import("std");
const core_fri = @import("stwo_core").fri;
const circle_domain = @import("stwo_core").poly.circle.domain;
const quotient_ops = @import("quotient_ops.zig");
const work_profile = @import("stwo_prover_api").work_profile;

pub fn commitLazy(
    comptime Prover: type,
    comptime B: type,
    comptime H: type,
    allocator: std.mem.Allocator,
    channel: anytype,
    config: core_fri.FriConfig,
    column_domain: circle_domain.CircleDomain,
    provider: *quotient_ops.LazyQuotientProvider,
    work_recorder: ?*work_profile.Recorder(true),
    root_mix_capture: ?*Prover.RootMixCapture,
) !Prover {
    if (!column_domain.isCanonic()) return error.NotCanonicDomain;
    if (provider.domain_size != column_domain.size()) return error.ShapeMismatch;
    var work_audit: Prover.ProtocolWorkAudit = .{};
    const active_work_audit = if (work_recorder != null) &work_audit else null;

    // The existing fused transaction commits one coordinate per column. A
    // multi-fold schedule uses packed FRI leaves, so retain the generic path
    // until a backend transaction implements that protocol layout explicitly.
    if (config.fold_step == 1 and comptime @hasDecl(B, "commitLazyFriTransaction")) {
        const fused_transaction = if (active_work_audit) |audit| blk: {
            if (comptime @hasDecl(B, "commitLazyFriTransactionWithReceipt")) {
                break :blk try B.commitLazyFriTransactionWithReceipt(
                    H,
                    Prover.FirstLayerProver,
                    Prover.InnerLayerProver,
                    Prover.InnerCommitResult,
                    Prover.LazyFriCommitResult,
                    allocator,
                    channel,
                    config,
                    column_domain,
                    provider,
                    &audit.fold_executions,
                );
            }
            const result = try B.commitLazyFriTransaction(
                H,
                Prover.FirstLayerProver,
                Prover.InnerLayerProver,
                Prover.InnerCommitResult,
                Prover.LazyFriCommitResult,
                allocator,
                channel,
                config,
                column_domain,
                provider,
            );
            if (result != null) audit.complete = false;
            break :blk result;
        } else try B.commitLazyFriTransaction(
            H,
            Prover.FirstLayerProver,
            Prover.InnerLayerProver,
            Prover.InnerCommitResult,
            Prover.LazyFriCommitResult,
            allocator,
            channel,
            config,
            column_domain,
            provider,
        );
        if (fused_transaction) |transaction| {
            var first_layer = transaction.first_layer;
            errdefer first_layer.deinit(allocator);
            var inner_commit = transaction.inner_commit;
            if (active_work_audit) |audit| {
                audit.observeFusedMerkle(1);
                audit.observeFusedMerkle(inner_commit.inner_layers.len);
            }
            defer inner_commit.last_layer_evaluation.deinit(allocator);
            errdefer {
                for (inner_commit.inner_layers) |*layer| layer.deinit(allocator);
                allocator.free(inner_commit.inner_layers);
            }
            var last_layer_poly = try Prover.commitLastLayer(
                allocator,
                channel,
                config,
                &inner_commit.last_layer_evaluation,
                active_work_audit,
            );
            errdefer last_layer_poly.deinit(allocator);
            const result = Prover{
                .config = config,
                .first_layer = first_layer,
                .inner_layers = inner_commit.inner_layers,
                .last_layer_poly = last_layer_poly,
            };
            if (work_recorder != null) {
                Prover.completeProtocolWork(
                    work_recorder,
                    &work_audit,
                    &result,
                    config,
                    column_domain.size(),
                );
            }
            Prover.completeRootMixCapture(
                work_recorder,
                root_mix_capture,
                &work_audit,
                &result,
            );
            return result;
        }
    }

    var first_layer = try Prover.commitFirstLayerLazy(
        allocator,
        channel,
        column_domain,
        provider,
        config.fold_step,
        active_work_audit,
    );
    errdefer first_layer.deinit(allocator);
    var inner_commit = try Prover.commitInnerLayers(
        allocator,
        channel,
        config,
        first_layer,
        active_work_audit,
    );
    defer inner_commit.last_layer_evaluation.deinit(allocator);
    errdefer {
        for (inner_commit.inner_layers) |*layer| layer.deinit(allocator);
        allocator.free(inner_commit.inner_layers);
    }
    var last_layer_poly = try Prover.commitLastLayer(
        allocator,
        channel,
        config,
        &inner_commit.last_layer_evaluation,
        active_work_audit,
    );
    errdefer last_layer_poly.deinit(allocator);
    const result = Prover{
        .config = config,
        .first_layer = first_layer,
        .inner_layers = inner_commit.inner_layers,
        .last_layer_poly = last_layer_poly,
    };
    if (work_recorder != null) {
        Prover.completeProtocolWork(
            work_recorder,
            &work_audit,
            &result,
            config,
            column_domain.size(),
        );
    }
    Prover.completeRootMixCapture(
        work_recorder,
        root_mix_capture,
        &work_audit,
        &result,
    );
    return result;
}
