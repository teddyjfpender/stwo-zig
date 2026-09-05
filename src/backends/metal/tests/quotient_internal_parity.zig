const std = @import("std");

const core = @import("stwo_core");
const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
const CirclePointQM31 = core.circle.CirclePointQM31;
const TreeVec = core.pcs.utils.TreeVec;
const prover = @import("stwo_prover_engine");
const quotient_ops = prover.pcs.quotient_ops;
const tile_executor = prover.pcs.quotient_tile_executor;
const secure_column = prover.secure_column;
const work_pool = prover.work_pool;
const parity = @import("../quotient_internal_parity.zig");
const bindings = @import("../runtime/bindings.zig");

const RawBackend = struct {
    pub const rawQuotientInputs = true;
};

const InputStorage = struct {
    full: [32]M31,
    short: [8]M31,
    columns: [2]quotient_ops.ColumnEvaluation,
    column_trees: [1][]const quotient_ops.ColumnEvaluation,
    full_points: [1]CirclePointQM31,
    short_points: [2]CirclePointQM31,
    point_columns: [2][]CirclePointQM31,
    point_trees: [1][][]CirclePointQM31,
    full_values: [1]QM31,
    short_values: [2]QM31,
    value_columns: [2][]QM31,
    value_trees: [1][][]QM31,

    fn init(self: *InputStorage) void {
        for (&self.full, 0..) |*value, index|
            value.* = M31.fromCanonical(@intCast(index * 7 + 3));
        for (&self.short, 0..) |*value, index|
            value.* = M31.fromCanonical(@intCast(index * 11 + 101));
        self.columns = .{
            .{ .log_size = 5, .values = &self.full },
            .{ .log_size = 3, .values = &self.short },
        };
        self.column_trees = .{&self.columns};
        const point0 = core.circle.SECURE_FIELD_CIRCLE_GEN.mul(7);
        const point1 = core.circle.SECURE_FIELD_CIRCLE_GEN.mul(19);
        self.full_points = .{point0};
        self.short_points = .{ point0, point1 };
        self.point_columns = .{ &self.full_points, &self.short_points };
        self.point_trees = .{&self.point_columns};
        self.full_values = .{QM31.fromU32Unchecked(1, 2, 3, 4)};
        self.short_values = .{
            QM31.fromU32Unchecked(5, 6, 7, 8),
            QM31.fromU32Unchecked(9, 10, 11, 12),
        };
        self.value_columns = .{ &self.full_values, &self.short_values };
        self.value_trees = .{&self.value_columns};
    }

    fn columnTree(self: *InputStorage) TreeVec([]const quotient_ops.ColumnEvaluation) {
        return TreeVec([]const quotient_ops.ColumnEvaluation).initOwned(&self.column_trees);
    }

    fn pointTree(self: *InputStorage) TreeVec([][]CirclePointQM31) {
        return TreeVec([][]CirclePointQM31).initOwned(&self.point_trees);
    }

    fn valueTree(self: *InputStorage) TreeVec([][]QM31) {
        return TreeVec([][]QM31).initOwned(&self.value_trees);
    }
};

const Fixture = struct {
    storage: *InputStorage,
    provider: quotient_ops.LazyQuotientProvider,
    final: secure_column.SecureColumnByCoords,

    fn init(allocator: std.mem.Allocator) !Fixture {
        const storage = try allocator.create(InputStorage);
        errdefer allocator.destroy(storage);
        storage.init();
        const alpha = QM31.fromU32Unchecked(3, 0, 1, 0);
        var final = try quotient_ops.computeFriQuotients(
            allocator,
            storage.columnTree(),
            storage.pointTree(),
            storage.valueTree(),
            alpha,
            5,
            1,
        );
        errdefer final.deinit(allocator);
        const provider = try quotient_ops.LazyQuotientProvider.initForBackend(
            RawBackend,
            allocator,
            storage.columnTree(),
            storage.pointTree(),
            storage.valueTree(),
            alpha,
            5,
        );
        return .{ .storage = storage, .provider = provider, .final = final };
    }

    fn deinit(self: *Fixture, allocator: std.mem.Allocator) void {
        self.provider.deinit(allocator);
        self.final.deinit(allocator);
        allocator.destroy(self.storage);
        self.* = undefined;
    }
};

const Segment = struct {
    event: parity.abi.EventV1,
    views: []parity.abi.RawViewV1,
    numerators: []u32,

    fn deinit(self: *Segment, allocator: std.mem.Allocator) void {
        allocator.free(self.numerators);
        allocator.free(self.views);
        self.* = undefined;
    }
};

fn domainWords(
    allocator: std.mem.Allocator,
    provider: *const quotient_ops.LazyQuotientProvider,
) !struct { x: []u32, y: []u32 } {
    const x = try allocator.alloc(u32, provider.domain_size);
    errdefer allocator.free(x);
    const y = try allocator.alloc(u32, provider.domain_size);
    errdefer allocator.free(y);
    for (0..provider.domain_size) |row| {
        const point = provider.domain.at(core.utils.bitReverseIndex(
            row,
            provider.lifting_log_size,
        ));
        x[row] = point.x.v;
        y[row] = point.y.v;
    }
    return .{ .x = x, .y = y };
}

fn makeSegment(
    allocator: std.mem.Allocator,
    provider: *const quotient_ops.LazyQuotientProvider,
    segment_index: usize,
) !Segment {
    const active_indices = provider.prepared.contribution_plan.active_column_indices;
    const ranges = provider.prepared.contribution_plan.ranges;
    if (active_indices.len != 2 or segment_index >= 2)
        return error.UnexpectedFixtureShape;
    var flat_offset: usize = 0;
    for (0..segment_index) |position| {
        flat_offset += provider.raw_columns[active_indices[position]].values.len;
    }
    const column = provider.raw_columns[active_indices[segment_index]];
    const range = ranges[segment_index];
    const views = try allocator.alloc(parity.abi.RawViewV1, range.len);
    errdefer allocator.free(views);
    var min_batch: u32 = std.math.maxInt(u32);
    var max_batch: u32 = 0;
    for (
        provider.prepared.contribution_plan.contributions[range.start..][0..range.len],
        views,
    ) |contribution, *view| {
        const coefficients = contribution.value_coeff.toM31Array();
        view.* = .{
            .offset = 0,
            .length = @intCast(column.values.len),
            .batch = @intCast(contribution.batch_index),
            .shift = provider.lifting_log_size - column.log_size + 1,
            .direct = @intFromBool(column.log_size == provider.lifting_log_size),
            .coeff_a = coefficients[0].v,
            .coeff_b = coefficients[1].v,
            .coeff_c = coefficients[2].v,
            .coeff_d = coefficients[3].v,
        };
        min_batch = @min(min_batch, view.batch);
        max_batch = @max(max_batch, view.batch);
    }

    const flags = try allocator.alloc(bool, provider.raw_columns.len);
    defer allocator.free(flags);
    @memset(flags, false);
    for (0..segment_index + 1) |position|
        flags[active_indices[position]] = true;
    var direct = try tile_executor.buildDirectContributionPlan(
        allocator,
        provider.raw_columns,
        active_indices,
        ranges,
        flags,
        provider.lifting_log_size,
        null,
    );
    defer direct.deinit(allocator);
    const value_count = provider.domain_size *
        provider.prepared.sample_batches.len * parity.COORDINATE_COUNT;
    const numerators = try allocator.alloc(u32, value_count);
    errdefer allocator.free(numerators);
    var scratch = try tile_executor.Scratch.init(
        allocator,
        provider.prepared.sample_batches.len,
        provider.domain_size,
    );
    defer scratch.deinit(allocator);
    try tile_executor.accumulateDirectNumeratorTile(
        &scratch,
        direct.views,
        direct.ranges,
        provider.prepared.contribution_plan.contributions,
        0,
        provider.domain_size,
    );
    for (0..provider.prepared.sample_batches.len) |batch| {
        for (0..provider.domain_size) |row| {
            inline for (0..parity.COORDINATE_COUNT) |coordinate| {
                numerators[
                    (batch * provider.domain_size + row) *
                        parity.COORDINATE_COUNT + coordinate
                ] =
                    (try tile_executor.directNumeratorValue(
                        &scratch,
                        batch,
                        coordinate,
                        row,
                    )).v;
            }
        }
    }
    return .{
        .event = .{
            .schema_version = parity.abi.SCHEMA_VERSION,
            .phase = @intFromEnum(parity.abi.PhaseV1.raw_segment),
            .segment_index = @intCast(segment_index),
            .segment_count = 2,
            .first_column = @intCast(segment_index),
            .column_count = 1,
            .view_count = @intCast(views.len),
            .batch_count = @intCast(provider.prepared.sample_batches.len),
            .row_count = provider.domain_size,
            .flat_offset = flat_offset,
            .run_words = column.values.len,
            .source_binding_offset = 0,
            .flags = 0,
            .min_batch = min_batch,
            .max_batch = max_batch,
            .reserved = 0,
            .min_original_offset = flat_offset,
            .max_original_offset = flat_offset,
            .min_rebased_offset = 0,
            .max_rebased_offset = 0,
        },
        .views = views,
        .numerators = numerators,
    };
}

fn finalWords(
    allocator: std.mem.Allocator,
    final: *const secure_column.SecureColumnByCoords,
) ![]u32 {
    const words = try allocator.alloc(u32, final.len() * parity.COORDINATE_COUNT);
    for (final.columns, 0..) |column, coordinate| {
        for (column, 0..) |value, row|
            words[coordinate * final.len() + row] = value.v;
    }
    return words;
}

fn finalEvent(
    provider: *const quotient_ops.LazyQuotientProvider,
) parity.abi.EventV1 {
    var raw_words: usize = 0;
    for (provider.prepared.contribution_plan.active_column_indices) |column_index|
        raw_words += provider.raw_columns[column_index].values.len;
    return .{
        .schema_version = parity.abi.SCHEMA_VERSION,
        .phase = @intFromEnum(parity.abi.PhaseV1.finalized_quotient),
        .segment_index = 2,
        .segment_count = 2,
        .first_column = 0,
        .column_count = @intCast(provider.prepared.contribution_plan.active_column_indices.len),
        .view_count = @intCast(provider.prepared.contribution_plan.contributions.len),
        .batch_count = @intCast(provider.prepared.sample_batches.len),
        .row_count = provider.domain_size,
        .flat_offset = 0,
        .run_words = raw_words,
        .source_binding_offset = 0,
        .flags = 0,
        .min_batch = 0,
        .max_batch = 0,
        .reserved = 0,
        .min_original_offset = 0,
        .max_original_offset = 0,
        .min_rebased_offset = 0,
        .max_rebased_offset = 0,
    };
}

fn observeExact(
    allocator: std.mem.Allocator,
    provider: *const quotient_ops.LazyQuotientProvider,
    final: *const secure_column.SecureColumnByCoords,
) !parity.ReceiptV1 {
    var context = try parity.ContextV1.init(allocator, provider);
    defer context.deinit();
    const domain = try domainWords(allocator, provider);
    defer allocator.free(domain.y);
    defer allocator.free(domain.x);
    for (0..2) |segment_index| {
        var segment = try makeSegment(allocator, provider, segment_index);
        defer segment.deinit(allocator);
        try context.observe(
            &segment.event,
            segment.views.ptr,
            domain.x.ptr,
            domain.y.ptr,
            segment.numerators.ptr,
            segment.numerators.len,
        );
    }
    const words = try finalWords(allocator, final);
    defer allocator.free(words);
    const event = finalEvent(provider);
    try context.observe(
        &event,
        null,
        domain.x.ptr,
        domain.y.ptr,
        words.ptr,
        words.len,
    );
    return context.finish();
}

test "Metal quotient internal parity binds two cumulative raw segments and final output" {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit(std.testing.allocator);
    const receipt = try observeExact(
        std.testing.allocator,
        &fixture.provider,
        &fixture.final,
    );
    try receipt.validate();
    try std.testing.expectEqual(@as(usize, 2), receipt.source_run_count);
    try std.testing.expectEqual(@as(usize, 1), receipt.oracle_worker_count);
    try std.testing.expectEqual(@as(usize, 0), receipt.resident_run_count);
    try std.testing.expectEqual(@as(u64, 64), receipt.domain_values);
    try std.testing.expectEqual(@as(u64, 128), receipt.final_values);
}

test "Metal quotient incremental oracle is scheduling independent across four workers" {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit(std.testing.allocator);
    const serial = try observeExact(
        std.testing.allocator,
        &fixture.provider,
        &fixture.final,
    );

    var pool: work_pool.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{
        .worker_count = 4,
        .stack_size = 1024 * 1024,
    });
    defer pool.deinit();
    var binding = try work_pool.ScopedPoolBinding.init(&pool);
    defer binding.deinit();
    const parallel = try observeExact(
        std.testing.allocator,
        &fixture.provider,
        &fixture.final,
    );
    try parallel.validate();
    try std.testing.expectEqual(@as(usize, 4), parallel.oracle_worker_count);
    try std.testing.expectEqualSlices(u8, &serial.expected_sha256, &parallel.expected_sha256);
    try std.testing.expectEqualSlices(u8, &serial.actual_sha256, &parallel.actual_sha256);
    try std.testing.expectEqual(serial.partial_values, parallel.partial_values);
}

test "Metal quotient internal parity reports segment component row coordinate mutation" {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit(std.testing.allocator);
    var context = try parity.ContextV1.init(std.testing.allocator, &fixture.provider);
    defer context.deinit();
    const domain = try domainWords(std.testing.allocator, &fixture.provider);
    defer std.testing.allocator.free(domain.y);
    defer std.testing.allocator.free(domain.x);
    var first = try makeSegment(std.testing.allocator, &fixture.provider, 0);
    defer first.deinit(std.testing.allocator);
    try context.observe(
        &first.event,
        first.views.ptr,
        domain.x.ptr,
        domain.y.ptr,
        first.numerators.ptr,
        first.numerators.len,
    );
    var second = try makeSegment(std.testing.allocator, &fixture.provider, 1);
    defer second.deinit(std.testing.allocator);
    const batch: usize = 0;
    const row: usize = 17;
    const coordinate: usize = 2;
    const mutated_index = (batch * fixture.provider.domain_size + row) *
        parity.COORDINATE_COUNT + coordinate;
    second.numerators[mutated_index] =
        M31.fromCanonical(second.numerators[mutated_index]).add(M31.one()).v;
    try std.testing.expectError(
        error.MetalQuotientInternalParityMismatch,
        context.observe(
            &second.event,
            second.views.ptr,
            domain.x.ptr,
            domain.y.ptr,
            second.numerators.ptr,
            second.numerators.len,
        ),
    );
    const mismatch = context.mismatch orelse return error.ExpectedStructuredMismatch;
    try std.testing.expectEqual(parity.MismatchKindV1.raw_numerator, mismatch.kind);
    try std.testing.expectEqual(@as(usize, 1), mismatch.segment_index);
    try std.testing.expectEqual(batch, mismatch.component_index);
    try std.testing.expectEqual(row, mismatch.row);
    try std.testing.expectEqual(@as(u8, coordinate), mismatch.coordinate);
}

test "Metal quotient internal parity rejects domain and source-run authority drift" {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit(std.testing.allocator);
    const domain = try domainWords(std.testing.allocator, &fixture.provider);
    defer std.testing.allocator.free(domain.y);
    defer std.testing.allocator.free(domain.x);
    var first = try makeSegment(std.testing.allocator, &fixture.provider, 0);
    defer first.deinit(std.testing.allocator);

    var domain_context = try parity.ContextV1.init(std.testing.allocator, &fixture.provider);
    defer domain_context.deinit();
    domain.x[9] = M31.fromCanonical(domain.x[9]).add(M31.one()).v;
    try std.testing.expectError(
        error.MetalQuotientInternalParityMismatch,
        domain_context.observe(
            &first.event,
            first.views.ptr,
            domain.x.ptr,
            domain.y.ptr,
            first.numerators.ptr,
            first.numerators.len,
        ),
    );
    try std.testing.expectEqual(
        parity.MismatchKindV1.domain_x,
        domain_context.mismatch.?.kind,
    );

    domain.x[9] = fixture.provider.domain.at(core.utils.bitReverseIndex(9, 5)).x.v;
    var metadata_context = try parity.ContextV1.init(std.testing.allocator, &fixture.provider);
    defer metadata_context.deinit();
    first.event.flat_offset = 1;
    try std.testing.expectError(
        error.MetalQuotientInternalParityMismatch,
        metadata_context.observe(
            &first.event,
            first.views.ptr,
            domain.x.ptr,
            domain.y.ptr,
            first.numerators.ptr,
            first.numerators.len,
        ),
    );
    try std.testing.expectEqual(
        parity.MismatchKindV1.metadata,
        metadata_context.mismatch.?.kind,
    );

    first.event.flat_offset = 0;
    first.event.flags = parity.abi.FLAG_PAGE_ALIAS_SOURCE;
    first.event.source_binding_offset = @intCast(
        @intFromPtr(fixture.provider.raw_columns[
            fixture.provider.prepared.contribution_plan.active_column_indices[0]
        ].values.ptr) % std.heap.pageSize(),
    );
    var alias_context = try parity.ContextV1.init(std.testing.allocator, &fixture.provider);
    defer alias_context.deinit();
    first.event.source_binding_offset += 1;
    try std.testing.expectError(
        error.MetalQuotientInternalParityMismatch,
        alias_context.observe(
            &first.event,
            first.views.ptr,
            domain.x.ptr,
            domain.y.ptr,
            first.numerators.ptr,
            first.numerators.len,
        ),
    );
    try std.testing.expectEqual(
        parity.MismatchKindV1.metadata,
        alias_context.mismatch.?.kind,
    );
}

test "Metal quotient internal parity reports finalized quotient mutation before FRI" {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit(std.testing.allocator);
    var context = try parity.ContextV1.init(std.testing.allocator, &fixture.provider);
    defer context.deinit();
    const domain = try domainWords(std.testing.allocator, &fixture.provider);
    defer std.testing.allocator.free(domain.y);
    defer std.testing.allocator.free(domain.x);
    for (0..2) |segment_index| {
        var segment = try makeSegment(std.testing.allocator, &fixture.provider, segment_index);
        defer segment.deinit(std.testing.allocator);
        try context.observe(
            &segment.event,
            segment.views.ptr,
            domain.x.ptr,
            domain.y.ptr,
            segment.numerators.ptr,
            segment.numerators.len,
        );
    }
    const words = try finalWords(std.testing.allocator, &fixture.final);
    defer std.testing.allocator.free(words);
    words[2 * fixture.provider.domain_size + 11] =
        M31.fromCanonical(words[2 * fixture.provider.domain_size + 11]).add(M31.one()).v;
    const event = finalEvent(&fixture.provider);
    try std.testing.expectError(
        error.MetalQuotientInternalParityMismatch,
        context.observe(
            &event,
            null,
            domain.x.ptr,
            domain.y.ptr,
            words.ptr,
            words.len,
        ),
    );
    const mismatch = context.mismatch orelse return error.ExpectedStructuredMismatch;
    try std.testing.expectEqual(
        parity.MismatchKindV1.finalized_quotient,
        mismatch.kind,
    );
    try std.testing.expectEqual(@as(usize, 11), mismatch.row);
    try std.testing.expectEqual(@as(u8, 2), mismatch.coordinate);
}

test "Metal quotient internal parity releases every diagnostic allocation" {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit(std.testing.allocator);
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        observeExactForAllocationTest,
        .{ &fixture.provider, &fixture.final },
    );
}

test "Metal quotient wide source views reject wrap reorder and local overflow" {
    const column_count = 258;
    const row_count: u32 = 1 << 24;
    const lengths: [column_count]usize = [_]usize{row_count} ** column_count;
    var views: [column_count]bindings.RawQuotientSourceViewV2 = undefined;
    var logical_offset: u64 = 0;
    for (&views) |*view| {
        view.* = .{
            .offset = logical_offset,
            .length = row_count,
            .batch = 0,
            .shift = 1,
            .direct = 1,
            .coeff_a = 1,
            .coeff_b = 2,
            .coeff_c = 3,
            .coeff_d = 4,
        };
        logical_offset += row_count;
    }
    try std.testing.expectEqual(@as(u64, 1) << 32, views[256].offset);
    try std.testing.expect(bindings.stwo_zig_metal_validate_raw_quotient_source_views_v2(
        &lengths,
        column_count,
        &views,
        column_count,
        row_count,
        1,
    ));

    var local: parity.abi.RawViewV1 = undefined;
    try std.testing.expect(bindings.stwo_zig_metal_local_raw_quotient_view_v2(
        &views[256],
        0,
        row_count,
        1,
        &local,
    ));
    try std.testing.expectEqual(@as(u32, 0), local.offset);
    const largest_local = std.math.maxInt(u32) - (row_count - 1);
    try std.testing.expect(bindings.stwo_zig_metal_local_raw_quotient_view_v2(
        &views[256],
        largest_local,
        row_count,
        1,
        &local,
    ));
    try std.testing.expect(!bindings.stwo_zig_metal_local_raw_quotient_view_v2(
        &views[256],
        @as(u64, largest_local) + 1,
        row_count,
        1,
        &local,
    ));

    const exact_offset = views[256].offset;
    views[256].offset = @as(u32, @truncate(exact_offset));
    try std.testing.expect(!bindings.stwo_zig_metal_validate_raw_quotient_source_views_v2(
        &lengths,
        column_count,
        &views,
        column_count,
        row_count,
        1,
    ));
    views[256].offset = exact_offset;

    std.mem.swap(bindings.RawQuotientSourceViewV2, &views[255], &views[256]);
    try std.testing.expect(!bindings.stwo_zig_metal_validate_raw_quotient_source_views_v2(
        &lengths,
        column_count,
        &views,
        column_count,
        row_count,
        1,
    ));
    std.mem.swap(bindings.RawQuotientSourceViewV2, &views[255], &views[256]);

    views[257].offset = std.math.maxInt(u64);
    try std.testing.expect(!bindings.stwo_zig_metal_validate_raw_quotient_source_views_v2(
        &lengths,
        column_count,
        &views,
        column_count,
        row_count,
        1,
    ));
}

fn observeExactForAllocationTest(
    allocator: std.mem.Allocator,
    provider: *const quotient_ops.LazyQuotientProvider,
    final: *const secure_column.SecureColumnByCoords,
) !void {
    _ = try observeExact(allocator, provider, final);
}
