//! Rust-oracle comparison for source-recorded Cairo interaction components.

const std = @import("std");
const QM31 = @import("stwo_core").fields.qm31.QM31;
const producer_output = @import("../witness/producer_output.zig");
const interaction_checkpoint = @import("interaction_checkpoint.zig");
const interaction_executor = @import("../witness/interaction_executor.zig");
const feed_topology = @import("../witness/feed_topology.zig");
const interaction_topology = @import("../witness/interaction_topology.zig");
const interaction_trace = @import("../witness/interaction_trace.zig");
const work_pool = @import("stwo_prover_impl").work_pool;

pub const MismatchKind = enum {
    lookup_geometry,
    interaction_geometry,
    claimed_sum,
    column_digest,
};

pub const Mismatch = struct {
    kind: MismatchKind,
    component_ordinal: u32,
    component_label: []const u8,
    column_ordinal: ?u32 = null,
    expected_digest: ?interaction_checkpoint.Digest = null,
    actual_digest: ?interaction_checkpoint.Digest = null,
};

pub const LookupSource = struct {
    label: []const u8,
    row_count: u32,
    active_rows: u32,
    words_per_row: u32,
    column_major_words: []const u32,
};

pub const MaterializedTrace = interaction_executor.MaterializedTrace;

/// Compares one generated component against an official interaction receipt.
///
/// Secure columns are materialized one component at a time. Coordinate hashes
/// are computed directly from that storage, avoiding four additional base
/// column copies.
pub fn compareComponent(
    allocator: std.mem.Allocator,
    component: feed_topology.Component,
    producer: producer_output.ProducerOutput,
    expected: interaction_checkpoint.Component,
    z: interaction_checkpoint.SecureLimbs,
    alpha_powers: []const interaction_checkpoint.SecureLimbs,
) !?Mismatch {
    return compareLookupComponent(
        allocator,
        component,
        .{
            .label = producer.label,
            .row_count = producer.row_count,
            .active_rows = producer.active_rows,
            .words_per_row = producer.lookup_words_per_row,
            .column_major_words = producer.lookup_words,
        },
        expected,
        z,
        alpha_powers,
    );
}

pub fn compareLookupComponent(
    allocator: std.mem.Allocator,
    component: feed_topology.Component,
    source: LookupSource,
    expected: interaction_checkpoint.Component,
    z: interaction_checkpoint.SecureLimbs,
    alpha_powers: []const interaction_checkpoint.SecureLimbs,
) !?Mismatch {
    if (!std.mem.eql(u8, component.producer, source.label) or
        !std.mem.eql(u8, source.label, expected.label) or
        source.words_per_row != component.lookup_words_per_row or
        source.column_major_words.len !=
            @as(usize, source.row_count) * source.words_per_row)
        return mismatch(.lookup_geometry, expected);

    var compiled = try interaction_topology.compile(
        allocator,
        component,
        source.column_major_words,
        source.row_count,
    );
    defer compiled.deinit();
    return compareTrace(
        allocator,
        compiled.descriptors,
        try interaction_trace.SourceView.lookupWords(
            try interaction_trace.LookupColumns.init(
                source.column_major_words,
                source.row_count,
            ),
            source.active_rows,
        ),
        expected,
        z,
        alpha_powers,
    );
}

pub fn compareTrace(
    allocator: std.mem.Allocator,
    descriptors: []const u32,
    source: interaction_trace.SourceView,
    expected: interaction_checkpoint.Component,
    z: interaction_checkpoint.SecureLimbs,
    alpha_powers: []const interaction_checkpoint.SecureLimbs,
) !?Mismatch {
    const powers = try secureFields(allocator, alpha_powers);
    defer allocator.free(powers);
    var materialized = try materializeTrace(
        allocator,
        descriptors,
        source,
        secureField(z),
        powers,
    );
    defer materialized.deinit();

    const descriptor_count = descriptors.len / interaction_trace.descriptor_words;
    if (descriptors.len == 0 or
        descriptors.len % interaction_trace.descriptor_words != 0 or
        expected.columns.len != descriptor_count * 4)
        return mismatch(.interaction_geometry, expected);
    if (!materialized.claimed_sum.eql(secureField(expected.claimed_sum_m31)))
        return mismatch(.claimed_sum, expected);

    for (0..materialized.column_count) |secure_column| {
        const secure_values = materialized.column(secure_column);
        for (0..4) |coordinate| {
            const column_ordinal: u32 = @intCast(secure_column * 4 + coordinate);
            const actual = try interaction_checkpoint.digestSecureCoordinate(
                expected.ordinal,
                expected.label,
                column_ordinal,
                secure_values,
                @intCast(coordinate),
            );
            const expected_column = expected.columns[column_ordinal];
            if (expected_column.row_count != materialized.row_count)
                return mismatch(.interaction_geometry, expected);
            if (!std.mem.eql(u8, &actual, &expected_column.sha256)) return .{
                .kind = .column_digest,
                .component_ordinal = expected.ordinal,
                .component_label = expected.label,
                .column_ordinal = column_ordinal,
                .expected_digest = expected_column.sha256,
                .actual_digest = actual,
            };
        }
    }
    return null;
}

pub fn materializeTrace(
    allocator: std.mem.Allocator,
    descriptors: []const u32,
    source: interaction_trace.SourceView,
    z: QM31,
    alpha_powers: []const QM31,
) !MaterializedTrace {
    var reference = try interaction_trace.Reference.init(
        allocator,
        descriptors,
        source,
        z,
        alpha_powers,
    );
    defer reference.deinit();

    const value_count = std.math.mul(
        usize,
        reference.columnCount(),
        source.rows(),
    ) catch return error.AllocationSizeOverflow;
    const values = try allocator.alloc(QM31, value_count);
    errdefer allocator.free(values);
    const batch_rows: usize = 1 << 15;
    const claimed_sum = if (source.rows() > batch_rows)
        try evaluateRangesParallel(
            allocator,
            descriptors,
            source,
            z,
            alpha_powers,
            values,
            batch_rows,
        ) orelse try evaluateRangesSerial(&reference, values, batch_rows)
    else
        try evaluateRangesSerial(&reference, values, batch_rows);
    const final_column =
        values[(reference.columnCount() - 1) * source.rows() ..][0..source.rows()];
    const final_prefix = try interaction_trace.scanLastColumnInPlace(
        final_column,
        claimed_sum,
    );
    if (!final_prefix.eql(QM31.zero())) return error.InvalidInteractionSum;
    return .{
        .allocator = allocator,
        .values = values,
        .row_count = source.rows(),
        .column_count = reference.columnCount(),
        .claimed_sum = claimed_sum,
    };
}

fn evaluateRangesSerial(
    reference: *interaction_trace.Reference,
    values: []QM31,
    batch_rows: usize,
) !QM31 {
    var claimed_sum = QM31.zero();
    var first_row: usize = 0;
    while (first_row < reference.source.rows()) : (first_row += batch_rows) {
        const rows = @min(batch_rows, reference.source.rows() - first_row);
        claimed_sum = claimed_sum.add(try reference.evaluateRange(
            first_row,
            rows,
            values,
        ));
    }
    return claimed_sum;
}

fn evaluateRangesParallel(
    allocator: std.mem.Allocator,
    descriptors: []const u32,
    source: interaction_trace.SourceView,
    z: QM31,
    alpha_powers: []const QM31,
    values: []QM31,
    batch_rows: usize,
) !?QM31 {
    const pool = work_pool.getGlobalPool() orelse return null;
    const batch_count = std.math.divCeil(usize, source.rows(), batch_rows) catch
        unreachable;
    const worker_count = @min(pool.workerCount(), batch_count);
    if (worker_count <= 1) return null;
    const batches_per_worker = std.math.divCeil(
        usize,
        batch_count,
        worker_count,
    ) catch unreachable;

    const Worker = struct {
        allocator: std.mem.Allocator,
        descriptors: []const u32,
        source: interaction_trace.SourceView,
        z: QM31,
        alpha_powers: []const QM31,
        values: []QM31,
        batch_rows: usize,
        first_row: usize,
        end_row: usize,
        claimed_sum: QM31 = QM31.zero(),
        failure: ?anyerror = null,

        fn run(self: *@This()) void {
            var reference = interaction_trace.Reference.init(
                self.allocator,
                self.descriptors,
                self.source,
                self.z,
                self.alpha_powers,
            ) catch |err| {
                self.failure = err;
                return;
            };
            defer reference.deinit();

            var first_row = self.first_row;
            while (first_row < self.end_row) : (first_row += self.batch_rows) {
                const rows = @min(self.batch_rows, self.end_row - first_row);
                const batch_sum = reference.evaluateRange(
                    first_row,
                    rows,
                    self.values,
                ) catch |err| {
                    self.failure = err;
                    return;
                };
                self.claimed_sum = self.claimed_sum.add(batch_sum);
            }
        }
    };

    var workers: [work_pool.MAX_WORKERS]Worker = undefined;
    var active_workers: usize = 0;
    for (0..worker_count) |worker_index| {
        const first_batch = worker_index * batches_per_worker;
        if (first_batch >= batch_count) break;
        const end_batch = @min(batch_count, first_batch + batches_per_worker);
        workers[active_workers] = .{
            .allocator = allocator,
            .descriptors = descriptors,
            .source = source,
            .z = z,
            .alpha_powers = alpha_powers,
            .values = values,
            .batch_rows = batch_rows,
            .first_row = first_batch * batch_rows,
            .end_row = @min(source.rows(), end_batch * batch_rows),
        };
        active_workers += 1;
    }
    if (active_workers <= 1) return null;

    var wait_group: std.Thread.WaitGroup = .{};
    for (workers[1..active_workers]) |*worker| {
        pool.spawnWg(&wait_group, Worker.run, .{worker});
    }
    Worker.run(&workers[0]);
    wait_group.wait();

    var claimed_sum = QM31.zero();
    for (workers[0..active_workers]) |worker| {
        if (worker.failure) |err| return err;
        claimed_sum = claimed_sum.add(worker.claimed_sum);
    }
    return claimed_sum;
}

fn secureFields(
    allocator: std.mem.Allocator,
    limbs: []const interaction_checkpoint.SecureLimbs,
) ![]QM31 {
    const result = try allocator.alloc(QM31, limbs.len);
    for (limbs, result) |value, *field| field.* = secureField(value);
    return result;
}

fn secureField(limbs: interaction_checkpoint.SecureLimbs) QM31 {
    return QM31.fromU32Unchecked(limbs[0], limbs[1], limbs[2], limbs[3]);
}

fn mismatch(
    kind: MismatchKind,
    expected: interaction_checkpoint.Component,
) Mismatch {
    return .{
        .kind = kind,
        .component_ordinal = expected.ordinal,
        .component_label = expected.label,
    };
}
