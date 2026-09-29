//! Backend-neutral execution of one recorded Cairo witness component.

const std = @import("std");
const adapter = @import("../adapter/mod.zig");
const component_layout = @import("component_layout.zig");
const deductions = @import("deductions/mod.zig");
const execution_tables = @import("execution_tables.zig");
const generated = @import("generated_executor.zig");
const interaction_executor = @import("interaction_executor.zig");
const interaction_residency = @import("interaction_residency.zig");
const program_mod = @import("program.zig");
const row_ranges = @import("row_ranges.zig");
const prover = @import("stwo_prover_engine");
const work_pool = prover.work_pool;

pub const Error = error{
    AllocationSizeOverflow,
    InvalidReceiptGeometry,
    UnsupportedMultiplicityTable,
    WitnessInputCountMismatch,
};

pub const Execution = struct {
    allocator: std.mem.Allocator,
    row_count: usize,
    output_storage: []u32,
    output_columns: [][]u32,
    lookup_words: []u32,
    lookup_allocation: ?interaction_residency.LookupAllocation,
    sub_words: []u32,

    pub fn deinit(self: *Execution) void {
        self.allocator.free(self.sub_words);
        var lookup = interaction_residency.RetainedLookup{
            .words = self.lookup_words,
            .allocation = self.lookup_allocation,
        };
        lookup.deinit(self.allocator);
        self.allocator.free(self.output_columns);
        self.allocator.free(self.output_storage);
        self.* = undefined;
    }

    pub fn takeLookup(self: *Execution) interaction_residency.RetainedLookup {
        const retained = interaction_residency.RetainedLookup{
            .words = self.lookup_words,
            .allocation = self.lookup_allocation,
        };
        self.lookup_words = &.{};
        self.lookup_allocation = null;
        return retained;
    }

    pub fn takeSubWords(self: *Execution) []u32 {
        const words = self.sub_words;
        self.sub_words = &.{};
        return words;
    }
};

pub fn execute(
    allocator: std.mem.Allocator,
    input: *const adapter.ProverInput,
    witness_program: program_mod.Program,
    generated_executor: ?generated.Executor,
    interaction_backend: ?interaction_executor.Executor,
    interaction_columns: usize,
    source: anytype,
    layout: component_layout.ComponentLayout,
    pedersen_table: ?deductions.PedersenTable,
    recorder: ?*prover.stage_profile.Recorder,
) !Execution {
    return executeInto(allocator, input, witness_program, generated_executor, interaction_backend, interaction_columns, source, layout, pedersen_table, recorder, null);
}

/// Borrow final trace columns for this call; only locally allocated outputs
/// belong to the returned execution. Feed storage always retains its own owner.
pub fn executeInto(
    allocator: std.mem.Allocator,
    input: *const adapter.ProverInput,
    witness_program: program_mod.Program,
    generated_executor: ?generated.Executor,
    interaction_backend: ?interaction_executor.Executor,
    interaction_columns: usize,
    source: anytype,
    layout: component_layout.ComponentLayout,
    pedersen_table: ?deductions.PedersenTable,
    recorder: ?*prover.stage_profile.Recorder,
    borrowed_outputs: ?[]const []u32,
) !Execution {
    layout.validate() catch return Error.InvalidReceiptGeometry;
    if (witness_program.n_inputs != source.columnCount())
        return Error.WitnessInputCountMismatch;
    if (witness_program.n_cols != layout.column_count)
        return Error.InvalidReceiptGeometry;
    if (witness_program.n_mult_tables != 0)
        return Error.UnsupportedMultiplicityTable;
    const row_count = layout.row_count;
    if (borrowed_outputs) |columns| {
        if (columns.len != witness_program.n_cols) return Error.InvalidReceiptGeometry;
        for (columns) |column| if (column.len != row_count) return Error.InvalidReceiptGeometry;
    }
    source.validateRowCount(row_count) catch return Error.InvalidReceiptGeometry;

    const input_words = std.math.mul(usize, source.columnCount(), row_count) catch
        return Error.AllocationSizeOverflow;
    const output_words = std.math.mul(usize, witness_program.n_cols, row_count) catch
        return Error.AllocationSizeOverflow;
    const lookup_words = std.math.mul(usize, witness_program.n_lookup_words, row_count) catch
        return Error.AllocationSizeOverflow;
    const sub_words = std.math.mul(usize, witness_program.n_sub_words, row_count) catch
        return Error.AllocationSizeOverflow;

    var input_stage = try prover.stage_profile.StageScope.begin(
        recorder,
        "witness_input_materialize",
        "Witness input materialization",
    );
    defer input_stage.end();
    // Gathered sources already own immutable column-major storage. Borrow it
    // until the joined execution ends instead of allocating and copying it again.
    const borrowed_input = comptime @hasDecl(@TypeOf(source), "borrowColumn");
    const input_storage: []u32 = if (borrowed_input) &.{} else try allocator.alloc(u32, input_words);
    defer allocator.free(input_storage);
    const input_columns = try allocator.alloc([]const u32, source.columnCount());
    defer allocator.free(input_columns);
    const native_input_columns = try allocator.alloc(
        generated.ConstColumnView,
        source.columnCount(),
    );
    defer allocator.free(native_input_columns);
    for (input_columns, 0..) |*column, column_index| {
        const start = column_index * row_count;
        const values = if (borrowed_input)
            try source.borrowColumn(column_index)
        else blk: {
            const destination = input_storage[start .. start + row_count];
            try source.writeColumn(column_index, destination);
            break :blk destination;
        };
        if (values.len != row_count) return Error.InvalidReceiptGeometry;
        column.* = values;
        native_input_columns[column_index] = .{
            .ptr = values.ptr,
            .len = values.len,
        };
    }
    input_stage.end();

    var output_stage = try prover.stage_profile.StageScope.begin(
        recorder,
        "witness_output_allocate",
        "Witness output allocation",
    );
    defer output_stage.end();
    var result = Execution{
        .allocator = allocator,
        .row_count = row_count,
        .output_storage = if (borrowed_outputs == null) try allocator.alloc(u32, output_words) else &.{},
        .output_columns = &.{},
        .lookup_words = &.{},
        .lookup_allocation = null,
        .sub_words = &.{},
    };
    errdefer allocator.free(result.output_storage);
    result.output_columns = try allocator.alloc([]u32, witness_program.n_cols);
    errdefer allocator.free(result.output_columns);
    for (result.output_columns, 0..) |*column, column_index| {
        const start = column_index * row_count;
        column.* = if (borrowed_outputs) |columns| columns[column_index] else result.output_storage[start .. start + row_count];
    }
    const native_output_columns = try allocator.alloc(
        generated.ColumnView,
        witness_program.n_cols,
    );
    defer allocator.free(native_output_columns);
    for (result.output_columns, native_output_columns) |column, *view| {
        view.* = .{ .ptr = column.ptr, .len = column.len };
    }
    if (interaction_backend) |backend| {
        if (try backend.allocateLookup(allocator, .{
            .rows = row_count,
            .word_columns = witness_program.n_lookup_words,
            .interaction_columns = interaction_columns,
        })) |allocation| {
            if (allocation.words.len != lookup_words) {
                var invalid = allocation;
                invalid.deinit();
                return Error.InvalidReceiptGeometry;
            }
            result.lookup_words = allocation.words;
            result.lookup_allocation = allocation;
        }
    }
    if (result.lookup_allocation == null) {
        result.lookup_words = try allocator.alloc(u32, lookup_words);
    }
    errdefer {
        if (result.lookup_allocation) |*allocation|
            allocation.deinit()
        else
            allocator.free(result.lookup_words);
    }
    result.sub_words = try allocator.alloc(u32, sub_words);
    errdefer allocator.free(result.sub_words);
    output_stage.end();

    const no_multiplicity_tables = [_][]u32{};
    const auxiliary = program_mod.AuxiliaryOutputs{
        .lookup_words = result.lookup_words,
        .sub_words = result.sub_words,
        .multiplicity_tables = &no_multiplicity_tables,
    };
    {
        var stage = try prover.stage_profile.StageScope.begin(
            recorder,
            "witness_output_initialize",
            "Witness output initialization",
        );
        defer stage.end();
        _ = try program_mod.initializeAllOutputs(
            witness_program,
            input_columns,
            result.output_columns,
            auxiliary,
        );
    }

    var execute_stage = try prover.stage_profile.StageScope.begin(
        recorder,
        "witness_program_execute",
        "Witness program execution",
    );
    defer execute_stage.end();
    const active_pool = work_pool.getGlobalPool();
    const rows_per_worker = parallelRowsPerWorker(witness_program);
    const worker_count = if (active_pool) |pool|
        @max(
            @as(usize, 1),
            @min(
                pool.workerCount(),
                std.math.divCeil(usize, row_count, rows_per_worker) catch
                    unreachable,
            ),
        )
    else
        1;
    const scratch_words = std.math.mul(
        usize,
        witness_program.n_regs,
        worker_count,
    ) catch return Error.AllocationSizeOverflow;
    const register_storage = try allocator.alloc(u32, scratch_words);
    defer allocator.free(register_storage);
    const deduce_storage = try allocator.alloc(u32, scratch_words);
    defer allocator.free(deduce_storage);
    const deduction_config = deductions.Context{
        .pedersen_table = pedersen_table,
    };
    const dynamic_enabled = if (std.posix.getenv("STWO_CAIRO_WITNESS_DYNAMIC_RANGES")) |value|
        std.mem.eql(u8, value, "1")
    else
        false;
    const dynamic_grain = if (dynamic_enabled)
        row_ranges.grain(row_count, worker_count, rows_per_worker)
    else
        null;
    var queue = row_ranges.Queue{ .row_count = row_count, .grain = dynamic_grain orelse 1 };

    const Work = struct {
        program: program_mod.Program,
        input_columns: []const []const u32,
        output_columns: []const []u32,
        native_input_columns: []const generated.ConstColumnView,
        native_output_columns: []const generated.ColumnView,
        auxiliary: program_mod.AuxiliaryOutputs,
        start: usize,
        end: usize,
        queue: ?*row_ranges.Queue,
        registers: []u32,
        deduce_args: []u32,
        tables: program_mod.TableContext,
        deduce: program_mod.DeduceContext,
        generated_writer: ?generated.Writer,
        failure: ?anyerror = null,

        fn run(self: *@This()) void {
            if (self.queue) |tickets| {
                while (tickets.take()) |range| {
                    self.executeRange(range.start, range.end) catch |err| {
                        self.failure = err;
                        return;
                    };
                }
            } else {
                self.executeRange(self.start, self.end) catch |err| {
                    self.failure = err;
                };
            }
        }

        fn executeRange(self: *@This(), start: usize, end: usize) !void {
            const execution_result = if (self.generated_writer) |writer|
                writer(.{
                    .input_columns = self.input_columns,
                    .output_columns = self.output_columns,
                    .native_input_columns = self.native_input_columns,
                    .native_output_columns = self.native_output_columns,
                    .auxiliary = self.auxiliary,
                    .start = start,
                    .end = end,
                    .registers = self.registers,
                    .deduce_args = self.deduce_args,
                    .tables = self.tables,
                    .deduce = self.deduce,
                })
            else
                program_mod.executeAllRange(
                    self.program,
                    self.input_columns,
                    self.output_columns,
                    self.auxiliary,
                    start,
                    end,
                    self.registers,
                    self.deduce_args,
                    self.tables,
                    self.deduce,
                );
            try execution_result;
        }
    };
    const chunk_len = std.math.divCeil(
        usize,
        row_count,
        worker_count,
    ) catch unreachable;
    var works: [work_pool.MAX_WORKERS]Work = undefined;
    for (0..worker_count) |worker| {
        const start = worker * chunk_len;
        works[worker] = .{
            .program = witness_program,
            .input_columns = input_columns,
            .output_columns = result.output_columns,
            .native_input_columns = native_input_columns,
            .native_output_columns = native_output_columns,
            .auxiliary = auxiliary,
            .start = start,
            .end = @min(row_count, start + chunk_len),
            .queue = if (dynamic_grain != null) &queue else null,
            .registers = register_storage[worker * witness_program.n_regs .. (worker + 1) * witness_program.n_regs],
            .deduce_args = deduce_storage[worker * witness_program.n_regs .. (worker + 1) * witness_program.n_regs],
            .tables = execution_tables.fromInput(input),
            .deduce = deductions.contextWithConfig(&deduction_config),
            .generated_writer = if (generated_executor) |executor|
                executor.resolve(witness_program)
            else
                null,
        };
    }
    if (worker_count > 1) {
        var wait_group: std.Thread.WaitGroup = .{};
        for (works[1..worker_count]) |*work| {
            active_pool.?.spawnWg(&wait_group, Work.run, .{work});
        }
        Work.run(&works[0]);
        wait_group.wait();
    } else {
        Work.run(&works[0]);
    }
    for (works[0..worker_count]) |work| {
        if (work.failure) |err| return err;
    }
    execute_stage.end();
    return result;
}

/// Recorded deductions can contain field inversions, hash rounds, or elliptic
/// curve arithmetic. Their row cost is orders of magnitude above the scalar
/// interpreter, so use finer ranges whenever a program contains a deduction.
fn parallelRowsPerWorker(witness_program: program_mod.Program) usize {
    for (witness_program.insts) |inst| {
        if (std.meta.intToEnum(program_mod.Op, inst.op) catch null == .deduce_call)
            return 32;
    }
    return 4096;
}

test "Cairo component executor assigns finer ranges to computed deductions" {
    _ = row_ranges;
    const plain = [_]program_mod.Inst{.{
        .op = @intFromEnum(program_mod.Op.constant),
        .dst = 0,
        .a = 0,
        .b = 0,
        .imm = 1,
    }};
    const computed = [_]program_mod.Inst{.{
        .op = @intFromEnum(program_mod.Op.deduce_call),
        .dst = 0,
        .a = 0,
        .b = 1,
        .imm = 0,
    }};
    try std.testing.expectEqual(
        @as(usize, 4096),
        parallelRowsPerWorker(.{
            .insts = &plain,
            .n_regs = 1,
            .n_inputs = 0,
            .n_cols = 1,
            .n_mult_tables = 0,
            .n_lookup_words = 0,
            .n_sub_words = 0,
        }),
    );
    try std.testing.expectEqual(
        @as(usize, 32),
        parallelRowsPerWorker(.{
            .insts = &computed,
            .n_regs = 1,
            .n_inputs = 0,
            .n_cols = 1,
            .n_mult_tables = 0,
            .n_lookup_words = 0,
            .n_sub_words = 0,
        }),
    );
}
