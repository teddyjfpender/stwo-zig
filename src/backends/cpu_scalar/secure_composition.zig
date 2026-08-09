//! SIMD- and row-parallel secure-composition evaluation for admitted CPU AIRs.

const std = @import("std");
const constraints = @import("stwo_core").constraints;
const m31 = @import("stwo_core").fields.m31;
const qm31 = @import("stwo_core").fields.qm31;
const canonic = @import("stwo_core").poly.circle.canonic;
const prover = @import("stwo_prover_engine");

const M31 = m31.M31;
const QM31 = qm31.QM31;
const PackedM31 = m31.PackedM31;
const ComponentProver = prover.air.component_prover.ComponentProver;
const Trace = prover.air.component_prover.Trace;
const SecureColumnByCoords = prover.secure_column.SecureColumnByCoords;

// The recurrence plan amortizes worker fan-out from a 2^15 evaluation domain
// onward. Narrow AIRs never reach this implementation because admission also
// requires a structurally matched, contiguous recurrence trace.
const min_eval_log_size: u32 = 15;
const min_recurrence_columns: usize = 32;

const RecurrenceShape = struct {
    first_column: [*]const M31,
    row_count: usize,
    column_count: usize,
    column_stride: usize,
    constraint_count: usize,
    eval_log_size: u32,
};

const PackedPower = struct {
    coordinates: [qm31.SECURE_EXTENSION_DEGREE]PackedM31,
};

const Worker = struct {
    first_column: [*]const M31,
    outputs: [qm31.SECURE_EXTENSION_DEGREE][*]M31,
    powers: []const PackedPower,
    denominator_inverses: [2]PackedM31,
    row_count: usize,
    column_count: usize,
    column_stride: usize,
    row_start: usize,
    row_end: usize,

    fn run(self: *Worker) void {
        const half = self.row_count / 2;
        var row = self.row_start;
        // Two independent packed row groups break the 98-column recurrence's
        // multiply dependency chain. This keeps both integer SIMD multiply
        // pipes occupied without the register spills seen in wider FFT
        // radix experiments.
        while (row + 2 * m31.PACK_WIDTH <= self.row_end) : (row += 2 * m31.PACK_WIDTH) {
            var a0 = m31.loadPacked(self.first_column + row);
            var b0 = m31.loadPacked(self.first_column + self.column_stride + row);
            var a1 = m31.loadPacked(self.first_column + row + m31.PACK_WIDTH);
            var b1 = m31.loadPacked(
                self.first_column + self.column_stride + row + m31.PACK_WIDTH,
            );
            var a0_squared = m31.mulPacked(a0, a0);
            var b0_squared = m31.mulPacked(b0, b0);
            var a1_squared = m31.mulPacked(a1, a1);
            var b1_squared = m31.mulPacked(b1, b1);
            var accumulators0: [qm31.SECURE_EXTENSION_DEGREE]PackedM31 = .{
                @splat(0), @splat(0), @splat(0), @splat(0),
            };
            var accumulators1: [qm31.SECURE_EXTENSION_DEGREE]PackedM31 = .{
                @splat(0), @splat(0), @splat(0), @splat(0),
            };

            var column: usize = 2;
            while (column < self.column_count) : (column += 1) {
                const column_start = self.first_column + column * self.column_stride + row;
                const c0 = m31.loadPacked(column_start);
                const c1 = m31.loadPacked(column_start + m31.PACK_WIDTH);
                const recurrence0 = m31.subPacked(
                    c0,
                    m31.addPacked(a0_squared, b0_squared),
                );
                const recurrence1 = m31.subPacked(
                    c1,
                    m31.addPacked(a1_squared, b1_squared),
                );
                const power = self.powers[self.column_count - 1 - column];
                inline for (0..qm31.SECURE_EXTENSION_DEGREE) |coordinate| {
                    const coefficient = power.coordinates[coordinate];
                    accumulators0[coordinate] = m31.addPacked(
                        accumulators0[coordinate],
                        m31.mulPacked(recurrence0, coefficient),
                    );
                    accumulators1[coordinate] = m31.addPacked(
                        accumulators1[coordinate],
                        m31.mulPacked(recurrence1, coefficient),
                    );
                }
                a0 = b0;
                b0 = c0;
                a1 = b1;
                b1 = c1;
                a0_squared = b0_squared;
                a1_squared = b1_squared;
                if (column + 1 < self.column_count) {
                    b0_squared = m31.mulPacked(c0, c0);
                    b1_squared = m31.mulPacked(c1, c1);
                }
            }

            const denominator0 = self.denominator_inverses[@intFromBool(row >= half)];
            const denominator1 = self.denominator_inverses[
                @intFromBool(row + m31.PACK_WIDTH >= half)
            ];
            inline for (0..qm31.SECURE_EXTENSION_DEGREE) |coordinate| {
                m31.storePacked(
                    self.outputs[coordinate] + row,
                    m31.mulPacked(accumulators0[coordinate], denominator0),
                );
                m31.storePacked(
                    self.outputs[coordinate] + row + m31.PACK_WIDTH,
                    m31.mulPacked(accumulators1[coordinate], denominator1),
                );
            }
        }
        while (row < self.row_end) : (row += m31.PACK_WIDTH) {
            var a = m31.loadPacked(self.first_column + row);
            var b = m31.loadPacked(self.first_column + self.column_stride + row);
            var a_squared = m31.mulPacked(a, a);
            var b_squared = m31.mulPacked(b, b);
            var accumulators: [qm31.SECURE_EXTENSION_DEGREE]PackedM31 = .{
                @splat(0), @splat(0), @splat(0), @splat(0),
            };

            var column: usize = 2;
            while (column < self.column_count) : (column += 1) {
                const c = m31.loadPacked(self.first_column + column * self.column_stride + row);
                const expected = m31.addPacked(a_squared, b_squared);
                const recurrence = m31.subPacked(c, expected);
                const power = self.powers[self.column_count - 1 - column];
                inline for (0..qm31.SECURE_EXTENSION_DEGREE) |coordinate| {
                    accumulators[coordinate] = m31.addPacked(
                        accumulators[coordinate],
                        m31.mulPacked(recurrence, power.coordinates[coordinate]),
                    );
                }
                a = b;
                b = c;
                a_squared = b_squared;
                if (column + 1 < self.column_count) b_squared = m31.mulPacked(c, c);
            }

            const denominator = self.denominator_inverses[@intFromBool(row >= half)];
            inline for (0..qm31.SECURE_EXTENSION_DEGREE) |coordinate| {
                m31.storePacked(
                    self.outputs[coordinate] + row,
                    m31.mulPacked(accumulators[coordinate], denominator),
                );
            }
        }
    }
};

pub fn evaluateLargeRecurrenceComposition(
    allocator: std.mem.Allocator,
    components: []const ComponentProver,
    random_coeff: QM31,
    trace: *const Trace,
    execution: prover.air.composition_execution.Execution,
) !?SecureColumnByCoords {
    const shape = recurrenceShape(components, trace) orelse return null;
    const packed_rows = shape.row_count / m31.PACK_WIDTH;
    var adjusted = execution.adjustedForAvailablePool();
    if (adjusted.worker_budget.count > 1 and adjusted.pool == null) {
        return error.WorkPoolRequired;
    }
    const helper_stack_bytes = if (adjusted.pool) |pool| try std.math.mul(
        usize,
        pool.stackSize(),
        adjusted.worker_budget.helperCount(),
    ) else 0;
    if (try requiredHostBytes(
        shape,
        @min(adjusted.worker_budget.count, packed_rows),
        helper_stack_bytes,
    ) >
        execution.host_byte_budget)
    {
        return error.TaskMemoryBudgetExceeded;
    }

    const powers = try prover.air.accumulation.generateSecurePowers(
        allocator,
        random_coeff,
        shape.constraint_count,
    );
    defer allocator.free(powers);
    const packed_powers = try allocator.alloc(PackedPower, powers.len);
    defer allocator.free(packed_powers);
    for (powers, packed_powers) |power, *packed_power| {
        const coordinates = power.toM31Array();
        inline for (0..qm31.SECURE_EXTENSION_DEGREE) |coordinate| {
            packed_power.coordinates[coordinate] = m31.splatPacked(coordinates[coordinate]);
        }
    }

    const eval_domain = canonic.CanonicCoset.new(shape.eval_log_size).circleDomain();
    const trace_coset = canonic.CanonicCoset.new(shape.eval_log_size - 1).coset();
    const denominator_scalars = [2]M31{
        try constraints.cosetVanishing(M31, trace_coset, eval_domain.at(0)).inv(),
        try constraints.cosetVanishing(M31, trace_coset, eval_domain.at(1)).inv(),
    };
    const denominators = [2]PackedM31{
        m31.splatPacked(denominator_scalars[0]),
        m31.splatPacked(denominator_scalars[1]),
    };

    var output = try SecureColumnByCoords.uninitialized(allocator, shape.row_count);
    errdefer output.deinit(allocator);
    var output_pointers: [qm31.SECURE_EXTENSION_DEGREE][*]M31 = undefined;
    inline for (0..qm31.SECURE_EXTENSION_DEGREE) |coordinate| {
        output_pointers[coordinate] = output.columns[coordinate].ptr;
    }

    // Hold the shared lease only after all large, fallible preparation has
    // completed. Compatibility contention can still reuse the same immutable
    // powers and output allocation under a serial partition.
    var lease_storage: prover.work_pool.WorkLease = undefined;
    var lease: ?*prover.work_pool.WorkLease = null;
    if (adjusted.pool) |pool| {
        if (pool.acquire(adjusted.worker_budget)) |acquired| {
            lease_storage = acquired;
            lease = &lease_storage;
        } else |failure| switch (failure) {
            error.WorkerBudgetUnavailable => if (execution.isStrict()) {
                return failure;
            } else {
                adjusted = execution.serial();
            },
            else => return failure,
        }
    }
    defer if (lease) |active| active.deinit();

    const worker_count = @min(adjusted.worker_budget.count, packed_rows);
    const workers = try allocator.alloc(Worker, worker_count);
    defer allocator.free(workers);
    for (workers, 0..) |*worker, index| {
        const start_batch = packed_rows * index / worker_count;
        const end_batch = packed_rows * (index + 1) / worker_count;
        worker.* = .{
            .first_column = shape.first_column,
            .outputs = output_pointers,
            .powers = packed_powers,
            .denominator_inverses = denominators,
            .row_count = shape.row_count,
            .column_count = shape.column_count,
            .column_stride = shape.column_stride,
            .row_start = start_batch * m31.PACK_WIDTH,
            .row_end = end_batch * m31.PACK_WIDTH,
        };
    }

    if (lease) |active| {
        var wait_group = std.Thread.WaitGroup{};
        var submitted: usize = 0;
        for (workers[1..]) |*worker| {
            active.spawnWg(&wait_group, Worker.run, .{worker}) catch |failure| {
                if (submitted != 0) {
                    wait_group.wait();
                    active.completeWave();
                }
                return failure;
            };
            submitted += 1;
        }
        Worker.run(&workers[0]);
        wait_group.wait();
        if (submitted != 0) active.completeWave();
    } else {
        Worker.run(&workers[0]);
    }

    return output;
}

fn requiredHostBytes(
    shape: RecurrenceShape,
    worker_count: usize,
    helper_stack_bytes: usize,
) !usize {
    var total: usize = 0;
    inline for (.{
        .{ shape.constraint_count, @sizeOf(QM31) },
        .{ shape.constraint_count, @sizeOf(PackedPower) },
        .{ shape.row_count, qm31.SECURE_EXTENSION_DEGREE * @sizeOf(M31) },
        .{ worker_count, @sizeOf(Worker) },
    }) |term| {
        const bytes = std.math.mul(usize, term[0], term[1]) catch
            return error.ResourceReservationOverflow;
        total = std.math.add(usize, total, bytes) catch
            return error.ResourceReservationOverflow;
    }
    return std.math.add(usize, total, helper_stack_bytes) catch
        error.ResourceReservationOverflow;
}

fn recurrenceShape(components: []const ComponentProver, trace: *const Trace) ?RecurrenceShape {
    if (components.len != 1) return null;
    const component = components[0];
    const capability = component.backend_composition_capability orelse return null;
    const recurrence = switch (capability) {
        .quadratic_sum_squares_v1 => |value| value,
        else => return null,
    };
    if (recurrence.first_column != 0 or
        recurrence.trace_tree_index >= trace.polys.items.len) return null;
    for (trace.polys.items, 0..) |tree, tree_index| {
        if (tree_index != recurrence.trace_tree_index and tree.len != 0) return null;
    }
    const columns = trace.polys.items[recurrence.trace_tree_index];
    if (columns.len < min_recurrence_columns or component.nConstraints() != columns.len - 2) return null;
    const eval_log_size = component.maxConstraintLogDegreeBound();
    if (eval_log_size < min_eval_log_size or eval_log_size >= @bitSizeOf(usize)) return null;
    const row_count = @as(usize, 1) << @intCast(eval_log_size);
    if (row_count % m31.PACK_WIDTH != 0) return null;
    for (columns) |column| {
        if (column.log_size != eval_log_size or column.values.len != row_count) return null;
    }

    const first_address = @intFromPtr(columns[0].values.ptr);
    const second_address = @intFromPtr(columns[1].values.ptr);
    if (second_address <= first_address) return null;
    const stride_bytes = second_address - first_address;
    if (stride_bytes % @sizeOf(M31) != 0) return null;
    const column_stride = stride_bytes / @sizeOf(M31);
    if (column_stride < row_count) return null;
    for (columns, 0..) |column, index| {
        const offset = std.math.mul(usize, index, stride_bytes) catch return null;
        const expected = std.math.add(usize, first_address, offset) catch return null;
        if (@intFromPtr(column.values.ptr) != expected) return null;
    }
    return .{
        .first_column = columns[0].values.ptr,
        .row_count = row_count,
        .column_count = columns.len,
        .column_stride = column_stride,
        .constraint_count = columns.len - 2,
        .eval_log_size = eval_log_size,
    };
}

test "secure composition host accounting is closed over owned buffers" {
    var first = [_]M31{M31.zero()};
    const shape = RecurrenceShape{
        .first_column = &first,
        .row_count = 1024,
        .column_count = 34,
        .column_stride = 1024,
        .constraint_count = 32,
        .eval_log_size = 10,
    };
    const helper_stack_bytes: usize = 3 * 128 * 1024;
    const expected = shape.constraint_count * @sizeOf(QM31) +
        shape.constraint_count * @sizeOf(PackedPower) +
        shape.row_count * qm31.SECURE_EXTENSION_DEGREE * @sizeOf(M31) +
        4 * @sizeOf(Worker) + helper_stack_bytes;
    try std.testing.expectEqual(
        expected,
        try requiredHostBytes(shape, 4, helper_stack_bytes),
    );
}

test "secure composition host accounting rejects overflow" {
    var first = [_]M31{M31.zero()};
    const shape = RecurrenceShape{
        .first_column = &first,
        .row_count = std.math.maxInt(usize),
        .column_count = 34,
        .column_stride = 1,
        .constraint_count = 32,
        .eval_log_size = 10,
    };
    try std.testing.expectError(
        error.ResourceReservationOverflow,
        requiredHostBytes(shape, 1, 0),
    );
}
