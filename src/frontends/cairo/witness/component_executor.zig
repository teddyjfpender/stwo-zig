//! Backend-neutral execution of one recorded Cairo witness component.

const std = @import("std");
const adapter = @import("../adapter/mod.zig");
const component_layout = @import("component_layout.zig");
const deductions = @import("deductions/mod.zig");
const execution_tables = @import("execution_tables.zig");
const generated = @import("generated_executor.zig");
const program_mod = @import("program.zig");
const prover = @import("stwo_prover_impl");
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
    sub_words: []u32,

    pub fn deinit(self: *Execution) void {
        self.allocator.free(self.sub_words);
        self.allocator.free(self.lookup_words);
        self.allocator.free(self.output_columns);
        self.allocator.free(self.output_storage);
        self.* = undefined;
    }

    pub fn takeLookupWords(self: *Execution) []u32 {
        const words = self.lookup_words;
        self.lookup_words = &.{};
        return words;
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
    source: anytype,
    layout: component_layout.ComponentLayout,
    pedersen_table: ?deductions.PedersenTable,
    recorder: ?*prover.stage_profile.Recorder,
) !Execution {
    layout.validate() catch return Error.InvalidReceiptGeometry;
    if (witness_program.n_inputs != source.columnCount())
        return Error.WitnessInputCountMismatch;
    if (witness_program.n_cols != layout.column_count)
        return Error.InvalidReceiptGeometry;
    if (witness_program.n_mult_tables != 0)
        return Error.UnsupportedMultiplicityTable;
    const row_count = layout.row_count;
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
    const input_storage = try allocator.alloc(u32, input_words);
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
        const values = input_storage[start .. start + row_count];
        try source.writeColumn(column_index, values);
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
        .output_storage = try allocator.alloc(u32, output_words),
        .output_columns = &.{},
        .lookup_words = &.{},
        .sub_words = &.{},
    };
    errdefer allocator.free(result.output_storage);
    result.output_columns = try allocator.alloc([]u32, witness_program.n_cols);
    errdefer allocator.free(result.output_columns);
    for (result.output_columns, 0..) |*column, column_index| {
        const start = column_index * row_count;
        column.* = result.output_storage[start .. start + row_count];
    }
    const native_output_columns = try allocator.alloc(
        generated.ColumnView,
        witness_program.n_cols,
    );
    defer allocator.free(native_output_columns);
    for (result.output_columns, native_output_columns) |column, *view| {
        view.* = .{ .ptr = column.ptr, .len = column.len };
    }
    result.lookup_words = try allocator.alloc(u32, lookup_words);
    errdefer allocator.free(result.lookup_words);
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

    const Work = struct {
        program: program_mod.Program,
        input_columns: []const []const u32,
        output_columns: []const []u32,
        native_input_columns: []const generated.ConstColumnView,
        native_output_columns: []const generated.ColumnView,
        auxiliary: program_mod.AuxiliaryOutputs,
        start: usize,
        end: usize,
        registers: []u32,
        deduce_args: []u32,
        tables: program_mod.TableContext,
        deduce: program_mod.DeduceContext,
        generated_writer: ?generated.Writer,
        failure: ?anyerror = null,

        fn run(self: *@This()) void {
            const execution_result = if (self.generated_writer) |writer|
                writer(.{
                    .input_columns = self.input_columns,
                    .output_columns = self.output_columns,
                    .native_input_columns = self.native_input_columns,
                    .native_output_columns = self.native_output_columns,
                    .auxiliary = self.auxiliary,
                    .start = self.start,
                    .end = self.end,
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
                    self.start,
                    self.end,
                    self.registers,
                    self.deduce_args,
                    self.tables,
                    self.deduce,
                );
            execution_result catch |err| {
                self.failure = err;
            };
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
