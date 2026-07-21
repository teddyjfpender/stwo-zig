const std = @import("std");
const core_fri = @import("stwo_core").fri;
const circle_domain = @import("stwo_core").poly.circle.domain;
const quotient_ops = @import("quotient_ops.zig");
const M31 = @import("stwo_core").fields.m31.M31;

pub fn commitLazy(
    comptime Prover: type,
    comptime B: type,
    comptime H: type,
    allocator: std.mem.Allocator,
    channel: anytype,
    config: core_fri.FriConfig,
    column_domain: circle_domain.CircleDomain,
    provider: *quotient_ops.LazyQuotientProvider,
    fold_itwiddles: ?[]const M31,
) !Prover {
    if (!column_domain.isCanonic()) return error.NotCanonicDomain;
    if (provider.domain_size != column_domain.size()) return error.ShapeMismatch;

    if (comptime @hasDecl(B, "commitLazyFriTransaction")) {
        if (try B.commitLazyFriTransaction(
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
        )) |transaction| {
            var first_layer = transaction.first_layer;
            errdefer first_layer.deinit(allocator);
            var inner_commit = transaction.inner_commit;
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
            );
            errdefer last_layer_poly.deinit(allocator);
            return .{
                .config = config,
                .first_layer = first_layer,
                .inner_layers = inner_commit.inner_layers,
                .last_layer_poly = last_layer_poly,
            };
        }
    }

    var first_layer = try Prover.commitFirstLayerLazy(
        allocator,
        channel,
        column_domain,
        provider,
    );
    errdefer first_layer.deinit(allocator);
    var inner_commit = try Prover.commitInnerLayers(allocator, channel, config, first_layer, fold_itwiddles);
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
    );
    errdefer last_layer_poly.deinit(allocator);
    return .{
        .config = config,
        .first_layer = first_layer,
        .inner_layers = inner_commit.inner_layers,
        .last_layer_poly = last_layer_poly,
    };
}
