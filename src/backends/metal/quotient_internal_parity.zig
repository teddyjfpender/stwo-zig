//! Exact process-local parity for Metal's segmented quotient numerator path.
//!
//! The large Stage101 quotient cannot be represented by the legacy single
//! `u32` flattened-source ABI. Metal therefore accumulates multiple raw source
//! runs into one numerator arena before applying the quotient denominator.
//! This diagnostic observes that arena after every real dispatch and compares
//! it against the ordinary CPU direct-column plan. It also binds the generated
//! circle-domain points and the finalized quotient before FRI starts.
//!
//! Nothing in this file is serialized or admitted as proof authority.

const std = @import("std");

const core = @import("stwo_core");
const prover = @import("stwo_prover_engine");
const M31 = core.fields.m31.M31;
const m31 = core.fields.m31;
const quotient_ops = prover.pcs.quotient_ops;
const tile_executor = prover.pcs.quotient_tile_executor;
const tile_sink = prover.pcs.quotient_tile_sink;
const secure_column = prover.secure_column;
const work_pool = prover.work_pool;
const output_parity = @import("quotient_output_parity.zig");
pub const abi = @import("runtime/quotient_internal_parity_abi.zig");

pub const ENV_NAME = "STWO_ZIG_METAL_QUOTIENT_INTERNAL_PARITY";
pub const SCHEMA_VERSION: u16 = 1;
pub const COORDINATE_COUNT: usize = 4;

pub const MismatchKindV1 = enum(u8) {
    metadata,
    domain_x,
    domain_y,
    raw_numerator,
    finalized_quotient,
};

pub const MismatchV1 = struct {
    kind: MismatchKindV1,
    segment_index: usize,
    component_index: usize,
    row: usize,
    coordinate: u8,
    expected: u64,
    actual: u64,
};

pub const ReceiptV1 = struct {
    schema_version: u16 = SCHEMA_VERSION,
    lifting_log_size: u32,
    row_count: usize,
    batch_count: usize,
    source_run_count: usize,
    oracle_worker_count: usize,
    resident_run_count: usize,
    page_alias_run_count: usize,
    raw_view_count: usize,
    domain_values: u64,
    partial_values: u64,
    final_values: u64,
    expected_sha256: [32]u8,
    actual_sha256: [32]u8,

    pub fn validate(self: ReceiptV1) !void {
        if (self.lifting_log_size >= @bitSizeOf(usize))
            return error.InvalidMetalQuotientInternalParityReceipt;
        const expected_rows = @as(usize, 1) << @intCast(self.lifting_log_size);
        const expected_domain = std.math.mul(
            u64,
            @intCast(self.row_count),
            2,
        ) catch return error.InvalidMetalQuotientInternalParityReceipt;
        const values_per_run = std.math.mul(
            u64,
            @intCast(self.row_count),
            std.math.mul(
                u64,
                @intCast(self.batch_count),
                COORDINATE_COUNT,
            ) catch return error.InvalidMetalQuotientInternalParityReceipt,
        ) catch return error.InvalidMetalQuotientInternalParityReceipt;
        const expected_partials = std.math.mul(
            u64,
            values_per_run,
            @intCast(self.source_run_count),
        ) catch return error.InvalidMetalQuotientInternalParityReceipt;
        const expected_final = std.math.mul(
            u64,
            @intCast(self.row_count),
            COORDINATE_COUNT,
        ) catch return error.InvalidMetalQuotientInternalParityReceipt;
        if (self.schema_version != SCHEMA_VERSION or
            self.row_count != expected_rows or
            self.batch_count == 0 or
            self.source_run_count == 0 or
            self.oracle_worker_count == 0 or
            self.oracle_worker_count > work_pool.MAX_WORKERS or
            self.resident_run_count > self.source_run_count or
            self.page_alias_run_count > self.source_run_count or
            self.raw_view_count == 0 or
            self.domain_values != expected_domain or
            self.partial_values != expected_partials or
            self.final_values != expected_final or
            !std.mem.eql(u8, &self.expected_sha256, &self.actual_sha256) or
            std.mem.allEqual(u8, &self.actual_sha256, 0))
        {
            return error.InvalidMetalQuotientInternalParityReceipt;
        }
    }
};

pub fn enabled() bool {
    return std.process.hasEnvVarConstant(ENV_NAME);
}

pub const ContextV1 = struct {
    allocator: std.mem.Allocator,
    provider: *const quotient_ops.LazyQuotientProvider,
    active_columns: []bool,
    scratches: []tile_executor.Scratch,
    expected_words: []u32,
    expected_domain_x: []u32,
    expected_domain_y: []u32,
    expected_hash: std.crypto.hash.sha2.Sha256,
    actual_hash: std.crypto.hash.sha2.Sha256,
    next_segment: usize = 0,
    segment_count: ?usize = null,
    next_column: usize = 0,
    next_flat_offset: usize = 0,
    resident_run_count: usize = 0,
    page_alias_run_count: usize = 0,
    observed_view_count: usize = 0,
    max_oracle_worker_count: usize = 1,
    domain_compared: bool = false,
    final_compared: bool = false,
    mismatch: ?MismatchV1 = null,
    failure: ?anyerror = null,
    final_receipt: ?output_parity.ReceiptV1 = null,

    pub fn init(
        allocator: std.mem.Allocator,
        provider: *const quotient_ops.LazyQuotientProvider,
    ) !ContextV1 {
        if (provider.input_mode != .raw_backend or
            provider.domain_size == 0 or
            provider.raw_columns.len == 0 or
            provider.prepared.sample_batches.len == 0 or
            provider.prepared.contribution_plan.active_column_indices.len == 0)
        {
            return error.InvalidMetalQuotientInternalParityInput;
        }
        const active_columns = try allocator.alloc(bool, provider.raw_columns.len);
        errdefer allocator.free(active_columns);
        @memset(active_columns, false);
        const requested_workers = if (work_pool.getGlobalPool()) |pool|
            @min(pool.workerCount(), provider.domain_size)
        else
            1;
        const scratches = try allocator.alloc(
            tile_executor.Scratch,
            requested_workers,
        );
        errdefer allocator.free(scratches);
        var initialized_scratches: usize = 0;
        errdefer for (scratches[0..initialized_scratches]) |*scratch|
            scratch.deinit(allocator);
        for (scratches) |*scratch| {
            scratch.* = try tile_executor.Scratch.init(
                allocator,
                provider.prepared.sample_batches.len,
                tile_sink.DEFAULT_TILE_ROWS,
            );
            initialized_scratches += 1;
        }
        const expected_word_count = try numeratorValueCount(
            provider.domain_size,
            provider.prepared.sample_batches.len,
        );
        const expected_words = try allocator.alloc(u32, expected_word_count);
        errdefer allocator.free(expected_words);
        @memset(expected_words, 0);
        const expected_domain_x = try allocator.alloc(u32, scratches[0].row_capacity);
        errdefer allocator.free(expected_domain_x);
        const expected_domain_y = try allocator.alloc(u32, scratches[0].row_capacity);
        errdefer allocator.free(expected_domain_y);
        return .{
            .allocator = allocator,
            .provider = provider,
            .active_columns = active_columns,
            .scratches = scratches,
            .expected_words = expected_words,
            .expected_domain_x = expected_domain_x,
            .expected_domain_y = expected_domain_y,
            .expected_hash = std.crypto.hash.sha2.Sha256.init(.{}),
            .actual_hash = std.crypto.hash.sha2.Sha256.init(.{}),
        };
    }

    pub fn deinit(self: *ContextV1) void {
        self.allocator.free(self.expected_domain_y);
        self.allocator.free(self.expected_domain_x);
        self.allocator.free(self.expected_words);
        for (self.scratches) |*scratch| scratch.deinit(self.allocator);
        self.allocator.free(self.scratches);
        self.allocator.free(self.active_columns);
        self.* = undefined;
    }

    pub fn observer(
        raw_context: ?*anyopaque,
        event: *const abi.EventV1,
        mapped_views: ?[*]const abi.RawViewV1,
        domain_x: [*]const u32,
        domain_y: [*]const u32,
        values: [*]const u32,
        value_count: usize,
    ) callconv(.c) bool {
        const context: *ContextV1 = @ptrCast(@alignCast(raw_context orelse return false));
        context.observe(
            event,
            mapped_views,
            domain_x,
            domain_y,
            values,
            value_count,
        ) catch |err| {
            if (context.failure == null) context.failure = err;
            return false;
        };
        return true;
    }

    pub fn observe(
        self: *ContextV1,
        event: *const abi.EventV1,
        mapped_views: ?[*]const abi.RawViewV1,
        domain_x: [*]const u32,
        domain_y: [*]const u32,
        values: [*]const u32,
        value_count: usize,
    ) !void {
        if (self.failure != null or self.mismatch != null or self.final_compared)
            return error.InvalidMetalQuotientInternalParitySequence;
        const phase = std.meta.intToEnum(abi.PhaseV1, event.phase) catch
            return self.failMetadata(self.next_segment, event.phase, 0);
        switch (phase) {
            .raw_segment => try self.observeRawSegment(
                event,
                mapped_views orelse
                    return error.InvalidMetalQuotientInternalParityInput,
                domain_x,
                domain_y,
                values,
                value_count,
            ),
            .finalized_quotient => try self.observeFinal(
                event,
                mapped_views,
                values,
                value_count,
            ),
        }
    }

    pub fn finish(self: *ContextV1) !ReceiptV1 {
        if (self.failure) |err| return err;
        if (self.mismatch != null)
            return error.MetalQuotientInternalParityMismatch;
        if (!self.domain_compared or !self.final_compared or
            self.segment_count == null or
            self.next_segment != self.segment_count.? or
            self.next_column != self.activeCount() or
            self.observed_view_count != self.totalViewCount() or
            self.final_receipt == null)
        {
            return error.InvalidMetalQuotientInternalParitySequence;
        }
        var expected_sha256: [32]u8 = undefined;
        var actual_sha256: [32]u8 = undefined;
        self.expected_hash.final(&expected_sha256);
        self.actual_hash.final(&actual_sha256);
        const receipt = ReceiptV1{
            .lifting_log_size = self.provider.lifting_log_size,
            .row_count = self.provider.domain_size,
            .batch_count = self.provider.prepared.sample_batches.len,
            .source_run_count = self.segment_count.?,
            .oracle_worker_count = self.max_oracle_worker_count,
            .resident_run_count = self.resident_run_count,
            .page_alias_run_count = self.page_alias_run_count,
            .raw_view_count = self.observed_view_count,
            .domain_values = try std.math.mul(
                u64,
                @intCast(self.provider.domain_size),
                2,
            ),
            .partial_values = try std.math.mul(
                u64,
                @intCast(self.segment_count.?),
                try std.math.mul(
                    u64,
                    @intCast(self.provider.domain_size),
                    try std.math.mul(
                        u64,
                        @intCast(self.provider.prepared.sample_batches.len),
                        COORDINATE_COUNT,
                    ),
                ),
            ),
            .final_values = self.final_receipt.?.compared_values,
            .expected_sha256 = expected_sha256,
            .actual_sha256 = actual_sha256,
        };
        try receipt.validate();
        return receipt;
    }

    pub fn printFailure(self: *const ContextV1) void {
        if (self.mismatch) |mismatch| {
            std.debug.print(
                "METAL_QUOTIENT_INTERNAL_PARITY=mismatch kind={s} segment={} component={} row={} coordinate={} expected={} actual={}\n",
                .{
                    @tagName(mismatch.kind),
                    mismatch.segment_index,
                    mismatch.component_index,
                    mismatch.row,
                    mismatch.coordinate,
                    mismatch.expected,
                    mismatch.actual,
                },
            );
        } else if (self.failure) |err| {
            std.debug.print(
                "METAL_QUOTIENT_INTERNAL_PARITY=invalid error={s} segment={}\n",
                .{ @errorName(err), self.next_segment },
            );
        }
    }

    fn observeRawSegment(
        self: *ContextV1,
        event: *const abi.EventV1,
        mapped_views_ptr: [*]const abi.RawViewV1,
        domain_x_ptr: [*]const u32,
        domain_y_ptr: [*]const u32,
        actual_words_ptr: [*]const u32,
        actual_word_count: usize,
    ) !void {
        try self.validateCommonEvent(event, .raw_segment);
        const active_indices = self.provider.prepared.contribution_plan.active_column_indices;
        const ranges = self.provider.prepared.contribution_plan.ranges;
        if (event.segment_index != self.next_segment or
            event.first_column != self.next_column or
            event.column_count == 0 or
            event.first_column > active_indices.len or
            event.column_count > active_indices.len - event.first_column or
            event.flat_offset != self.next_flat_offset or
            event.flags & ~abi.KNOWN_FLAGS != 0 or
            event.flags & abi.FLAG_RESIDENT_SOURCE != 0 and
                event.flags & abi.FLAG_PAGE_ALIAS_SOURCE != 0)
        {
            return self.failMetadata(self.next_segment, event.segment_index, self.next_segment);
        }
        if (self.segment_count) |count| {
            if (event.segment_count != count)
                return self.failMetadata(self.next_segment, event.segment_count, count);
        } else {
            if (event.segment_count == 0)
                return self.failMetadata(self.next_segment, event.segment_count, 1);
            self.segment_count = event.segment_count;
        }
        if (event.segment_index >= event.segment_count)
            return self.failMetadata(self.next_segment, event.segment_index, event.segment_count);

        const first_column: usize = @intCast(event.first_column);
        const column_count: usize = @intCast(event.column_count);
        const end_column = first_column + column_count;
        const first_provider_column = active_indices[first_column];
        if (first_provider_column >= self.provider.raw_columns.len)
            return error.InvalidMetalQuotientInternalParityInput;
        const expected_source_binding_offset: u64 = if (event.flags & abi.FLAG_RESIDENT_SOURCE != 0)
            event.source_binding_offset
        else if (event.flags & abi.FLAG_PAGE_ALIAS_SOURCE != 0)
            @intCast(
                @intFromPtr(self.provider.raw_columns[first_provider_column].values.ptr) %
                    std.heap.pageSize(),
            )
        else
            0;
        if (event.flags & abi.FLAG_RESIDENT_SOURCE != 0 and
            event.source_binding_offset % @sizeOf(u32) != 0)
        {
            return self.failMetadata(
                self.next_segment,
                event.source_binding_offset,
                event.source_binding_offset / @sizeOf(u32) * @sizeOf(u32),
            );
        }
        var run_words: usize = 0;
        var expected_view_count: usize = 0;
        var min_original: u64 = std.math.maxInt(u64);
        var max_original: u64 = 0;
        var min_rebased: u64 = std.math.maxInt(u64);
        var max_rebased: u64 = 0;
        var min_batch: u32 = std.math.maxInt(u32);
        var max_batch: u32 = 0;
        @memset(self.active_columns, false);
        const mapped_views = mapped_views_ptr[0..event.view_count];
        var observed_view: usize = 0;
        for (first_column..end_column) |active_position| {
            const column_index = active_indices[active_position];
            if (column_index >= self.provider.raw_columns.len)
                return error.InvalidMetalQuotientInternalParityInput;
            const column = self.provider.raw_columns[column_index];
            const logical_offset = try std.math.add(
                usize,
                self.next_flat_offset,
                run_words,
            );
            const range = ranges[active_position];
            if (range.start > self.provider.prepared.contribution_plan.contributions.len or
                range.len > self.provider.prepared.contribution_plan.contributions.len - range.start)
            {
                return error.InvalidMetalQuotientInternalParityInput;
            }
            for (self.provider.prepared.contribution_plan.contributions[range.start..][0..range.len]) |contribution| {
                if (observed_view >= mapped_views.len)
                    return self.failMetadata(self.next_segment, observed_view, mapped_views.len);
                const actual = mapped_views[observed_view];
                const coefficients = contribution.value_coeff.toM31Array();
                const shift = self.provider.lifting_log_size - column.log_size + 1;
                const local_offset = logical_offset - self.next_flat_offset;
                if (actual.length != column.values.len or
                    actual.batch != contribution.batch_index or
                    actual.shift != shift or
                    actual.direct != @intFromBool(column.log_size == self.provider.lifting_log_size) or
                    actual.coeff_a != coefficients[0].v or
                    actual.coeff_b != coefficients[1].v or
                    actual.coeff_c != coefficients[2].v or
                    actual.coeff_d != coefficients[3].v or
                    (event.flags & abi.FLAG_RESIDENT_SOURCE == 0 and
                        actual.offset != local_offset))
                {
                    return self.failMetadata(self.next_segment, observed_view, expected_view_count);
                }
                min_original = @min(min_original, logical_offset);
                max_original = @max(max_original, logical_offset);
                min_rebased = @min(min_rebased, actual.offset);
                max_rebased = @max(max_rebased, actual.offset);
                min_batch = @min(min_batch, actual.batch);
                max_batch = @max(max_batch, actual.batch);
                observed_view += 1;
                expected_view_count += 1;
            }
            run_words = try std.math.add(usize, run_words, column.values.len);
            self.active_columns[column_index] = true;
        }
        if (expected_view_count == 0 or
            event.view_count != expected_view_count or
            event.run_words != run_words or
            event.min_original_offset != min_original or
            event.max_original_offset != max_original or
            event.min_rebased_offset != min_rebased or
            event.max_rebased_offset != max_rebased or
            event.min_batch != min_batch or event.max_batch != max_batch or
            event.source_binding_offset != expected_source_binding_offset)
        {
            return self.failMetadata(self.next_segment, event.view_count, expected_view_count);
        }
        try self.compareDomain(domain_x_ptr, domain_y_ptr);

        const expected_values = try numeratorValueCount(
            self.provider.domain_size,
            self.provider.prepared.sample_batches.len,
        );
        if (actual_word_count != expected_values)
            return self.failMetadata(self.next_segment, actual_word_count, expected_values);
        var direct = try tile_executor.buildDirectContributionPlan(
            self.allocator,
            self.provider.raw_columns,
            active_indices,
            ranges,
            self.active_columns,
            self.provider.lifting_log_size,
            null,
        );
        defer direct.deinit(self.allocator);

        const actual_words = actual_words_ptr[0..actual_word_count];
        try self.compareIncrementalNumerator(&direct, actual_words);

        if (event.flags & abi.FLAG_RESIDENT_SOURCE != 0)
            self.resident_run_count += 1;
        if (event.flags & abi.FLAG_PAGE_ALIAS_SOURCE != 0)
            self.page_alias_run_count += 1;
        self.observed_view_count += expected_view_count;
        self.next_column = end_column;
        self.next_flat_offset = try std.math.add(
            usize,
            self.next_flat_offset,
            run_words,
        );
        self.next_segment += 1;
    }

    fn compareIncrementalNumerator(
        self: *ContextV1,
        direct: *const tile_executor.DirectContributionPlan,
        actual_words: []const u32,
    ) !void {
        if (actual_words.len != self.expected_words.len)
            return error.InvalidMetalQuotientInternalParityInput;
        const pool = work_pool.getGlobalPool();
        const worker_count = if (pool) |active|
            @min(active.workerCount(), self.scratches.len, self.provider.domain_size)
        else
            1;
        if (worker_count == 0) return error.InvalidMetalQuotientInternalParityInput;
        self.max_oracle_worker_count = @max(
            self.max_oracle_worker_count,
            worker_count,
        );
        var work: [work_pool.MAX_WORKERS]NumeratorOracleWorkV1 = undefined;
        const base_rows = self.provider.domain_size / worker_count;
        const extra_rows = self.provider.domain_size % worker_count;
        for (work[0..worker_count], 0..) |*item, worker_index| {
            const start = worker_index * base_rows + @min(worker_index, extra_rows);
            const count = base_rows + @intFromBool(worker_index < extra_rows);
            item.* = .{
                .provider = self.provider,
                .views = direct.views,
                .ranges = direct.ranges,
                .scratch = &self.scratches[worker_index],
                .expected_words = self.expected_words,
                .actual_words = actual_words,
                .start = start,
                .end = start + count,
                .segment_index = self.next_segment,
            };
        }
        if (worker_count == 1) {
            work[0].run();
        } else {
            var wait_group: std.Thread.WaitGroup = .{};
            for (work[1..worker_count]) |*item|
                pool.?.spawnWg(&wait_group, NumeratorOracleWorkV1.run, .{item});
            work[0].run();
            wait_group.wait();
        }
        for (work[0..worker_count]) |*item| {
            if (item.failure) |err| return err;
            if (item.mismatch) |mismatch| return self.fail(mismatch);
        }
        self.expected_hash.update(std.mem.sliceAsBytes(self.expected_words));
        self.actual_hash.update(std.mem.sliceAsBytes(actual_words));
    }

    fn observeFinal(
        self: *ContextV1,
        event: *const abi.EventV1,
        mapped_views: ?[*]const abi.RawViewV1,
        actual_words_ptr: [*]const u32,
        actual_word_count: usize,
    ) !void {
        try self.validateCommonEvent(event, .finalized_quotient);
        if (mapped_views != null or self.segment_count == null or
            self.next_segment != self.segment_count.? or
            event.segment_index != self.next_segment or
            event.segment_count != self.segment_count.? or
            event.first_column != 0 or event.column_count != self.activeCount() or
            event.view_count != self.totalViewCount() or
            event.flat_offset != 0 or event.run_words != self.next_flat_offset or
            event.source_binding_offset != 0 or event.flags != 0 or
            event.min_batch != 0 or event.max_batch != 0 or
            event.min_original_offset != 0 or event.max_original_offset != 0 or
            event.min_rebased_offset != 0 or event.max_rebased_offset != 0)
        {
            return self.failMetadata(self.next_segment, event.view_count, self.totalViewCount());
        }
        const expected_values = try std.math.mul(
            usize,
            self.provider.domain_size,
            COORDINATE_COUNT,
        );
        if (actual_word_count != expected_values)
            return self.failMetadata(self.next_segment, actual_word_count, expected_values);
        const actual_m31: [*]M31 = @ptrCast(@alignCast(@constCast(actual_words_ptr)));
        var actual = secure_column.SecureColumnByCoords{
            .columns = .{
                actual_m31[0 * self.provider.domain_size ..][0..self.provider.domain_size],
                actual_m31[1 * self.provider.domain_size ..][0..self.provider.domain_size],
                actual_m31[2 * self.provider.domain_size ..][0..self.provider.domain_size],
                actual_m31[3 * self.provider.domain_size ..][0..self.provider.domain_size],
            },
            .owns_columns = false,
            .contiguous = true,
        };
        const result = try output_parity.compareRawProviderAgainstCpu(
            self.allocator,
            self.provider,
            &actual,
        );
        switch (result) {
            .exact => |receipt| {
                try receipt.validate();
                self.expected_hash.update(&receipt.expected_sha256);
                self.actual_hash.update(&receipt.actual_sha256);
                self.final_receipt = receipt;
            },
            .mismatch => |mismatch| return self.fail(.{
                .kind = .finalized_quotient,
                .segment_index = self.next_segment,
                .component_index = std.math.maxInt(usize),
                .row = mismatch.row,
                .coordinate = mismatch.coordinate,
                .expected = mismatch.expected.v,
                .actual = mismatch.actual.v,
            }),
        }
        self.final_compared = true;
    }

    fn compareDomain(
        self: *ContextV1,
        actual_x_ptr: [*]const u32,
        actual_y_ptr: [*]const u32,
    ) !void {
        if (self.domain_compared) return;
        const actual_x = actual_x_ptr[0..self.provider.domain_size];
        const actual_y = actual_y_ptr[0..self.provider.domain_size];
        var start: usize = 0;
        while (start < self.provider.domain_size) {
            const count = @min(
                self.expected_domain_x.len,
                self.provider.domain_size - start,
            );
            for (0..count) |local_row| {
                const row = start + local_row;
                const point = self.provider.domain.at(core.utils.bitReverseIndex(
                    row,
                    self.provider.lifting_log_size,
                ));
                self.expected_domain_x[local_row] = point.x.v;
                self.expected_domain_y[local_row] = point.y.v;
                if (actual_x[row] >= m31.Modulus or point.x.v != actual_x[row]) {
                    return self.fail(.{
                        .kind = .domain_x,
                        .segment_index = self.next_segment,
                        .component_index = std.math.maxInt(usize),
                        .row = row,
                        .coordinate = 0,
                        .expected = point.x.v,
                        .actual = actual_x[row],
                    });
                }
                if (actual_y[row] >= m31.Modulus or point.y.v != actual_y[row]) {
                    return self.fail(.{
                        .kind = .domain_y,
                        .segment_index = self.next_segment,
                        .component_index = std.math.maxInt(usize),
                        .row = row,
                        .coordinate = 1,
                        .expected = point.y.v,
                        .actual = actual_y[row],
                    });
                }
            }
            self.expected_hash.update(std.mem.sliceAsBytes(self.expected_domain_x[0..count]));
            self.expected_hash.update(std.mem.sliceAsBytes(self.expected_domain_y[0..count]));
            self.actual_hash.update(std.mem.sliceAsBytes(actual_x[start..][0..count]));
            self.actual_hash.update(std.mem.sliceAsBytes(actual_y[start..][0..count]));
            start += count;
        }
        self.domain_compared = true;
    }

    fn validateCommonEvent(
        self: *ContextV1,
        event: *const abi.EventV1,
        phase: abi.PhaseV1,
    ) !void {
        if (event.schema_version != abi.SCHEMA_VERSION or
            event.phase != @intFromEnum(phase) or event.reserved != 0 or
            event.row_count != self.provider.domain_size or
            event.batch_count != self.provider.prepared.sample_batches.len)
        {
            return self.failMetadata(self.next_segment, event.schema_version, abi.SCHEMA_VERSION);
        }
    }

    fn activeCount(self: *const ContextV1) usize {
        return self.provider.prepared.contribution_plan.active_column_indices.len;
    }

    fn totalViewCount(self: *const ContextV1) usize {
        return self.provider.prepared.contribution_plan.contributions.len;
    }

    fn failMetadata(
        self: *ContextV1,
        component: usize,
        actual: anytype,
        expected: anytype,
    ) error{MetalQuotientInternalParityMismatch} {
        return self.fail(.{
            .kind = .metadata,
            .segment_index = self.next_segment,
            .component_index = component,
            .row = 0,
            .coordinate = 0,
            .expected = @intCast(expected),
            .actual = @intCast(actual),
        });
    }

    fn fail(
        self: *ContextV1,
        mismatch: MismatchV1,
    ) error{MetalQuotientInternalParityMismatch} {
        if (self.mismatch == null) self.mismatch = mismatch;
        return error.MetalQuotientInternalParityMismatch;
    }
};

const NumeratorOracleWorkV1 = struct {
    provider: *const quotient_ops.LazyQuotientProvider,
    views: @FieldType(tile_executor.DirectContributionPlan, "views"),
    ranges: @FieldType(tile_executor.DirectContributionPlan, "ranges"),
    scratch: *tile_executor.Scratch,
    expected_words: []u32,
    actual_words: []const u32,
    start: usize,
    end: usize,
    segment_index: usize,
    mismatch: ?MismatchV1 = null,
    failure: ?anyerror = null,

    fn run(self: *NumeratorOracleWorkV1) void {
        self.execute() catch |err| {
            self.failure = err;
        };
    }

    fn execute(self: *NumeratorOracleWorkV1) !void {
        if (self.start >= self.end or
            self.expected_words.len != self.actual_words.len)
        {
            return error.InvalidMetalQuotientInternalParityInput;
        }
        var tile_start = self.start;
        while (tile_start < self.end) {
            const count = @min(self.scratch.row_capacity, self.end - tile_start);
            try tile_executor.accumulateDirectNumeratorTile(
                self.scratch,
                self.views,
                self.ranges,
                self.provider.prepared.contribution_plan.contributions,
                tile_start,
                count,
            );
            for (0..self.provider.prepared.sample_batches.len) |batch| {
                for (0..count) |local_row| {
                    inline for (0..COORDINATE_COUNT) |coordinate| {
                        const index = ((batch * self.provider.domain_size +
                            tile_start + local_row) * COORDINATE_COUNT) + coordinate;
                        const prior = self.expected_words[index];
                        if (prior >= m31.Modulus)
                            return error.InvalidMetalQuotientInternalParityInput;
                        const increment = try tile_executor.directNumeratorValue(
                            self.scratch,
                            batch,
                            coordinate,
                            local_row,
                        );
                        const expected = M31.fromCanonical(prior).add(increment).v;
                        self.expected_words[index] = expected;
                        const actual = self.actual_words[index];
                        if (actual >= m31.Modulus or expected != actual) {
                            self.mismatch = .{
                                .kind = .raw_numerator,
                                .segment_index = self.segment_index,
                                .component_index = batch,
                                .row = tile_start + local_row,
                                .coordinate = @intCast(coordinate),
                                .expected = expected,
                                .actual = actual,
                            };
                            return;
                        }
                    }
                }
            }
            tile_start += count;
        }
    }
};

fn numeratorValueCount(row_count: usize, batch_count: usize) !usize {
    return std.math.mul(
        usize,
        try std.math.mul(usize, row_count, batch_count),
        COORDINATE_COUNT,
    );
}
