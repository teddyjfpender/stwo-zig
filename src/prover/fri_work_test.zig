//! Exact FRI protocol-work derivation and adversarial receipt tests.

const std = @import("std");
const core_fri = @import("stwo_core").fri;
const qm31 = @import("stwo_core").fields.qm31;
const M31 = @import("stwo_core").fields.m31.M31;
const work_profile = @import("stwo_prover_api").work_profile;
const owner = @import("fri.zig");

const WorkRecorder = work_profile.Recorder(true);
const FriProtocolWorkAudit = owner.FriProtocolWorkAudit;
const deriveFriFoldWork = owner.testing.deriveFriFoldWork;
const recordFriProtocolWork = owner.testing.recordFriProtocolWork;
const max_fri_merkle_layers: usize = @bitSizeOf(usize) + 1;

const FriWorkTestDomain = struct {
    element_count: usize,

    fn size(self: @This()) usize {
        return self.element_count;
    }
};

const FriWorkTestShapeColumn = struct {
    element_count: usize,

    fn len(self: @This()) usize {
        return self.element_count;
    }
};

const FriWorkTestShapeLayer = struct {
    domain: FriWorkTestDomain,
    column: FriWorkTestShapeColumn,
    fold_step: u32,
};

test "FRI work derives circle, line, and final IFFT geometry from returned layers" {
    const inner_layers = [_]FriWorkTestShapeLayer{.{
        .domain = .{ .element_count = 16 },
        .column = .{ .element_count = 16 },
        .fold_step = 2,
    }};
    const prover = .{
        .first_layer = .{
            .domain = FriWorkTestDomain{ .element_count = 64 },
            .column = FriWorkTestShapeColumn{ .element_count = 64 },
        },
        .inner_layers = inner_layers[0..],
    };
    const config = core_fri.FriConfig{
        .log_blowup_factor = 1,
        .log_last_layer_degree_bound = 1,
        .n_queries = 1,
        .fold_step = 2,
    };

    const derived = try deriveFriFoldWork(&prover, config, 64);

    try std.testing.expectEqual(@as(u64, 32), derived.circle_folds);
    try std.testing.expectEqual(@as(u64, 28), derived.line_folds);
    try std.testing.expectEqual(@as(u64, 60), try derived.totalFolds());
    try std.testing.expectEqual(@as(u64, 4), derived.final_ifft_butterflies);
}

const FriWorkTestColumn = struct {
    columns: [qm31.SECURE_EXTENSION_DEGREE][]const M31,

    fn len(self: @This()) usize {
        return self.columns[0].len;
    }
};

const FriWorkTestLayer = struct {
    domain: FriWorkTestDomain,
    column: FriWorkTestColumn,
    fold_step: u32,
};

test "FRI work publishes one exact terminal transaction" {
    const Backend = struct {
        pub const reuses_constant_merkle_parents = false;
        pub const lazy_merkle_reuses_constant_parents = false;
    };
    const first_values = [_]M31{M31.one()} ** 16;
    const inner_values = [_]M31{M31.one()} ** 8;
    const first_column = FriWorkTestColumn{ .columns = .{
        &first_values,
        &first_values,
        &first_values,
        &first_values,
    } };
    const inner_column = FriWorkTestColumn{ .columns = .{
        &inner_values,
        &inner_values,
        &inner_values,
        &inner_values,
    } };
    const inner_layers = [_]FriWorkTestLayer{.{
        .domain = .{ .element_count = 8 },
        .column = inner_column,
        .fold_step = 1,
    }};
    const prover = .{
        .first_layer = .{
            .domain = FriWorkTestDomain{ .element_count = 16 },
            .column = first_column,
        },
        .inner_layers = inner_layers[0..],
    };
    const config = core_fri.FriConfig{
        .log_blowup_factor = 1,
        .log_last_layer_degree_bound = 1,
        .n_queries = 1,
        .fold_step = 1,
    };
    var audit: FriProtocolWorkAudit = .{};
    audit.observeLazyMerkle();
    audit.observeGenericMerkle();
    audit.fold_executions.observe(.{
        .kind = .circle_to_line,
        .initial_count = 16,
        .fold_count = 1,
        .domain_log_size = 3,
        .domain_initial_index = 1,
        .domain_step_size = 1 << 28,
        .inverse_path = .host_batch,
        .alpha_squares = 1,
        .domain_doubles = 0,
    });
    audit.fold_executions.observe(.{
        .kind = .line,
        .initial_count = 8,
        .fold_count = 1,
        .domain_log_size = 3,
        .domain_initial_index = 1,
        .domain_step_size = 1 << 28,
        .inverse_path = .host_batch,
        .alpha_squares = 1,
        .domain_doubles = 1,
    });
    audit.observeTerminalInterpolation(.{ .log_size = 2 });
    var recorder: WorkRecorder = .{};

    recordFriProtocolWork(Backend, &recorder, &audit, &prover, config, 16);

    try std.testing.expectEqual(@as(u64, 4), recorder.counters.fft_butterflies);
    try std.testing.expectEqual(@as(u64, 12), recorder.counters.fri_folds);
    try std.testing.expectEqual(@as(u64, 22), recorder.counters.merkle_compressions);
    try std.testing.expectEqual(@as(u64, 96), recorder.counters.field_additions);
    try std.testing.expectEqual(@as(u64, 164), recorder.counters.field_multiplications);
    try std.testing.expectEqual(@as(u64, 7), recorder.counters.field_inversions);
    try std.testing.expectEqual(@as(u64, 1), recorder.record_count);
    try std.testing.expectEqual(
        @as(u64, 1),
        recorder.completed_sites[@intFromEnum(work_profile.Site.fri_protocol)],
    );
    try std.testing.expect(!recorder.legacy_site_coverage);
    try std.testing.expect(!recorder.incomplete);
}

test "FRI work fails closed when returned fold geometry is inconsistent" {
    const Backend = struct {
        pub const reuses_constant_merkle_parents = false;
        pub const lazy_merkle_reuses_constant_parents = false;
    };
    const first_values = [_]M31{M31.one()} ** 16;
    const inner_values = [_]M31{M31.one()} ** 8;
    const first_column = FriWorkTestColumn{ .columns = .{
        &first_values,
        &first_values,
        &first_values,
        &first_values,
    } };
    const inner_column = FriWorkTestColumn{ .columns = .{
        &inner_values,
        &inner_values,
        &inner_values,
        &inner_values,
    } };
    const inner_layers = [_]FriWorkTestLayer{.{
        .domain = .{ .element_count = 4 },
        .column = inner_column,
        .fold_step = 1,
    }};
    const prover = .{
        .first_layer = .{
            .domain = FriWorkTestDomain{ .element_count = 16 },
            .column = first_column,
        },
        .inner_layers = inner_layers[0..],
    };
    const config = core_fri.FriConfig{
        .log_blowup_factor = 1,
        .log_last_layer_degree_bound = 1,
        .n_queries = 1,
        .fold_step = 1,
    };
    var audit: FriProtocolWorkAudit = .{};
    audit.observeLazyMerkle();
    audit.observeGenericMerkle();
    var recorder: WorkRecorder = .{};

    recordFriProtocolWork(Backend, &recorder, &audit, &prover, config, 16);

    try std.testing.expect(recorder.incomplete);
    try std.testing.expectEqual(@as(u64, 0), recorder.record_count);
    try std.testing.expectEqual(
        work_profile.Authority.unavailable,
        (try recorder.snapshot()).authority,
    );
}

test "FRI work fails closed when a fused backend omits Merkle semantics" {
    const UnsupportedFusedBackend = struct {};
    const first_values = [_]M31{M31.one()} ** 16;
    const inner_values = [_]M31{M31.one()} ** 8;
    const first_column = FriWorkTestColumn{ .columns = .{
        &first_values,
        &first_values,
        &first_values,
        &first_values,
    } };
    const inner_column = FriWorkTestColumn{ .columns = .{
        &inner_values,
        &inner_values,
        &inner_values,
        &inner_values,
    } };
    const inner_layers = [_]FriWorkTestLayer{.{
        .domain = .{ .element_count = 8 },
        .column = inner_column,
        .fold_step = 1,
    }};
    const prover = .{
        .first_layer = .{
            .domain = FriWorkTestDomain{ .element_count = 16 },
            .column = first_column,
        },
        .inner_layers = inner_layers[0..],
    };
    const config = core_fri.FriConfig{
        .log_blowup_factor = 1,
        .log_last_layer_degree_bound = 1,
        .n_queries = 1,
        .fold_step = 1,
    };
    var audit: FriProtocolWorkAudit = .{};
    audit.observeFusedMerkle(2);
    var recorder: WorkRecorder = .{};

    recordFriProtocolWork(
        UnsupportedFusedBackend,
        &recorder,
        &audit,
        &prover,
        config,
        16,
    );

    try std.testing.expect(recorder.incomplete);
    try std.testing.expectEqual(@as(u64, 0), recorder.record_count);
}

test "FRI work audit fails closed instead of truncating excess layers" {
    var audit: FriProtocolWorkAudit = .{};

    audit.observeFusedMerkle(max_fri_merkle_layers + 1);

    try std.testing.expect(!audit.complete);
    try std.testing.expectEqual(@as(usize, 0), audit.merkle_path_count);
}
