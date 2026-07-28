//! Authenticated generated-writer admission and native execution ABI.

const program = @import("program.zig");

pub const ConstColumnView = extern struct {
    ptr: [*]const u32,
    len: usize,
};

pub const ColumnView = extern struct {
    ptr: [*]u32,
    len: usize,
};

/// Complete caller-owned state for executing one disjoint row range. Generated
/// writers consume this ABI so the frontend retains ownership of allocation,
/// parallelism, tables, and deductions.
pub const RangeExecution = struct {
    input_columns: []const []const u32,
    output_columns: []const []u32,
    native_input_columns: []const ConstColumnView,
    native_output_columns: []const ColumnView,
    auxiliary: program.AuxiliaryOutputs,
    start: usize,
    end: usize,
    registers: []u32,
    deduce_args: []u32,
    tables: program.TableContext,
    deduce: program.DeduceContext,
};

pub const Writer = *const fn (RangeExecution) anyerror!void;

pub const NativeRangeExecution = extern struct {
    input_columns: [*]const ConstColumnView,
    output_columns: [*]const ColumnView,
    lookup_words: [*]u32,
    sub_words: [*]u32,
    registers: [*]u32,
    deduce_args: [*]u32,
    row_count: usize,
    start: usize,
    end: usize,
    bridge_context: *anyopaque,
    table_limb_fn: *const fn (
        *anyopaque,
        u32,
        u32,
        u32,
    ) callconv(.c) u32,
    deduce_fn: *const fn (
        *anyopaque,
        u32,
        [*]const u32,
        usize,
        [*]u32,
        usize,
    ) callconv(.c) c_int,
};

pub const NativeWriter = *const fn (
    *const NativeRangeExecution,
) callconv(.c) c_int;

pub fn executeNative(writer: NativeWriter, run: RangeExecution) !void {
    if (run.native_input_columns.len != run.input_columns.len or
        run.native_output_columns.len != run.output_columns.len)
        return error.InvalidGeneratedColumns;
    var bridge = NativeBridge{ .run = &run };
    const native = NativeRangeExecution{
        .input_columns = run.native_input_columns.ptr,
        .output_columns = run.native_output_columns.ptr,
        .lookup_words = run.auxiliary.lookup_words.ptr,
        .sub_words = run.auxiliary.sub_words.ptr,
        .registers = run.registers.ptr,
        .deduce_args = run.deduce_args.ptr,
        .row_count = run.output_columns[0].len,
        .start = run.start,
        .end = run.end,
        .bridge_context = &bridge,
        .table_limb_fn = NativeBridge.tableLimb,
        .deduce_fn = NativeBridge.deduce,
    };
    if (writer(&native) != 0)
        return bridge.failure orelse error.GeneratedWriterFailed;
}

/// Collision-resistant admission boundary for generated witness writers.
/// Resolvers must key writers by `Program.semanticIdentity`, never labels or
/// the legacy 64-bit diagnostic hash.
pub const Executor = struct {
    context: ?*anyopaque = null,
    resolve_fn: *const fn (?*anyopaque, [32]u8) ?Writer,

    pub fn resolve(
        self: Executor,
        witness_program: program.Program,
    ) ?Writer {
        return self.resolve_fn(
            self.context,
            witness_program.semanticIdentity(),
        );
    }
};

const NativeBridge = struct {
    run: *const RangeExecution,
    failure: ?anyerror = null,

    fn tableLimb(
        raw_context: *anyopaque,
        table: u32,
        row: u32,
        limb_index: u32,
    ) callconv(.c) u32 {
        const self: *NativeBridge = @ptrCast(@alignCast(raw_context));
        return self.run.tables.limb(table, row, limb_index);
    }

    fn deduce(
        raw_context: *anyopaque,
        selector: u32,
        args: [*]const u32,
        arg_count: usize,
        outputs: [*]u32,
        output_count: usize,
    ) callconv(.c) c_int {
        const self: *NativeBridge = @ptrCast(@alignCast(raw_context));
        self.run.deduce.call(
            selector,
            args[0..arg_count],
            outputs[0..output_count],
            self.run.tables,
        ) catch |err| {
            self.failure = err;
            return 1;
        };
        return 0;
    }
};
