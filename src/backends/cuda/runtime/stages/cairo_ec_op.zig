//! Checked resident launch of Cairo's native EC-op witness graph.

const std = @import("std");
const abi = @import("../../abi/stages/cairo_ec_op.zig");
const common = @import("common.zig");
const contract_module = @import("cairo_ec_op_contract.zig");
const layout = @import("resident_layout.zig");
const runtime_error = @import("../error.zig");
const telemetry = @import("../telemetry.zig");

pub const Native = OpsFor(abi);
pub const Geometry = contract_module.Geometry;
pub const Contract = contract_module.Contract;

const pointer_words = @sizeOf(usize) / @sizeOf(u32);
const read_range_count = contract_module.execution_table_count + 2;
const write_range_count = contract_module.trace_column_count +
    contract_module.partial_input_column_count + 5;

comptime {
    std.debug.assert(pointer_words == 2);
}

pub const Buffers = struct {
    /// Device-resident table of the 37 execution-column pointers.
    execution_pointer_table: common.Words,
    /// Exact pointees named by `execution_pointer_table`.
    execution_tables: []const common.Words,
    segment_start: common.Words,
    trace_columns: []const common.Words,
    lookup_words_word_major: common.Words,
    partial_input_columns: []const common.Words,
    address_counts: common.Words,
    big_counts: common.Words,
    small_counts: common.Words,
    range_check_8_counts: common.Words,
};

pub const Prepared = struct {
    contract: Contract,
    execution_pointer_table: [*]const [*]const u32,
    segment_start: [*]const u32,
    trace_pointers: [contract_module.trace_column_count][*]u32,
    lookup_words: [*]u32,
    partial_pointers: [contract_module.partial_input_column_count][*]u32,
    address_counts: [*]u32,
    big_counts: [*]u32,
    small_counts: [*]u32,
    range_check_8_counts: [*]u32,
    context_anchor: common.Words,

    pub fn launch(
        self: *const Prepared,
        session: anytype,
    ) runtime_error.Error!void {
        const stage = telemetry.Stage.trace_generation;
        try common.requireStage(session, stage);
        const anchor = try layout.resident(
            session,
            u32,
            self.context_anchor,
            self.context_anchor.len,
        );
        if (@intFromPtr(anchor.pointer) != self.context_anchor.address)
            return error.ContextMismatch;

        const geometry = self.contract.geometry;
        const status = abi.ec_op_builtin_witness_on(
            self.execution_pointer_table,
            geometry.n_addresses,
            geometry.n_big,
            geometry.n_small,
            self.segment_start,
            geometry.row_count,
            &self.trace_pointers,
            self.lookup_words,
            &self.partial_pointers,
            try geometry.partialRowCount(),
            self.address_counts,
            geometry.address_count_words,
            self.big_counts,
            geometry.big_count_words,
            self.small_counts,
            geometry.small_count_words,
            self.range_check_8_counts,
            geometry.range_check_8_count_words,
            session.context.stream,
        );
        try common.recordMany(session, stage, status, 3);
    }
};

pub fn OpsFor(comptime Api: type) type {
    return struct {
        pub fn prepare(
            session: anytype,
            geometry: Geometry,
            buffers: Buffers,
        ) runtime_error.Error!Prepared {
            try common.requireStage(session, .ingress);
            const contract = try Contract.compile(geometry);
            if (buffers.execution_tables.len !=
                contract_module.execution_table_count or
                buffers.trace_columns.len !=
                    contract_module.trace_column_count or
                buffers.partial_input_columns.len !=
                    contract_module.partial_input_column_count)
            {
                return error.InvalidKernelDescriptor;
            }

            const pointer_table_words = contract_module.execution_table_count *
                pointer_words;
            const execution_pointers = exactResident(
                session,
                buffers.execution_pointer_table,
                pointer_table_words,
                @alignOf(usize),
            ) catch |err| {
                debugBufferFailure(
                    "execution_pointer_table",
                    null,
                    buffers.execution_pointer_table,
                    err,
                );
                return err;
            };
            const segment_start = exactResident(
                session,
                buffers.segment_start,
                1,
                @alignOf(u32),
            ) catch |err| {
                debugBufferFailure(
                    "segment_start",
                    null,
                    buffers.segment_start,
                    err,
                );
                return err;
            };

            var reads: [read_range_count]layout.DeviceRange = undefined;
            reads[0] = execution_pointers.range;
            reads[1] = segment_start.range;
            for (buffers.execution_tables, 0..) |table, index| {
                const minimum: usize = if (index == 0)
                    geometry.n_addresses
                else if (index <= contract_module.execution_big_limb_count)
                    geometry.n_big
                else
                    geometry.n_small;
                const resident = layout.resident(
                    session,
                    u32,
                    table,
                    minimum,
                ) catch |err| {
                    debugBufferFailure(
                        "execution_table",
                        index,
                        table,
                        err,
                    );
                    return err;
                };
                reads[index + 2] = resident.range;
            }

            var writes: [write_range_count]layout.DeviceRange = undefined;
            var trace_pointers: [contract_module.trace_column_count][*]u32 = undefined;
            var write_index: usize = 0;
            for (buffers.trace_columns, 0..) |column, index| {
                const resident = exactResident(
                    session,
                    column,
                    geometry.row_count,
                    @alignOf(u32),
                ) catch |err| {
                    debugBufferFailure(
                        "trace_column",
                        index,
                        column,
                        err,
                    );
                    return err;
                };
                trace_pointers[index] = resident.pointer;
                writes[write_index] = resident.range;
                write_index += 1;
            }

            const lookup_words = exactResident(
                session,
                buffers.lookup_words_word_major,
                try wordsForRows(
                    geometry.row_count,
                    contract_module.lookup_words_per_row,
                ),
                @alignOf(u32),
            ) catch |err| {
                debugBufferFailure(
                    "lookup_words",
                    null,
                    buffers.lookup_words_word_major,
                    err,
                );
                return err;
            };
            writes[write_index] = lookup_words.range;
            write_index += 1;

            const partial_rows = try geometry.partialRowCount();
            var partial_pointers: [contract_module.partial_input_column_count][*]u32 = undefined;
            for (buffers.partial_input_columns, 0..) |column, index| {
                const resident = exactResident(
                    session,
                    column,
                    partial_rows,
                    @alignOf(u32),
                ) catch |err| {
                    debugBufferFailure(
                        "partial_input_column",
                        index,
                        column,
                        err,
                    );
                    return err;
                };
                partial_pointers[index] = resident.pointer;
                writes[write_index] = resident.range;
                write_index += 1;
            }

            const address_counts = exactResident(
                session,
                buffers.address_counts,
                geometry.address_count_words,
                @alignOf(u32),
            ) catch |err| {
                debugBufferFailure(
                    "address_counts",
                    null,
                    buffers.address_counts,
                    err,
                );
                return err;
            };
            writes[write_index] = address_counts.range;
            write_index += 1;
            const big_counts = exactResident(
                session,
                buffers.big_counts,
                geometry.big_count_words,
                @alignOf(u32),
            ) catch |err| {
                debugBufferFailure(
                    "big_counts",
                    null,
                    buffers.big_counts,
                    err,
                );
                return err;
            };
            writes[write_index] = big_counts.range;
            write_index += 1;
            const small_counts = exactResident(
                session,
                buffers.small_counts,
                geometry.small_count_words,
                @alignOf(u32),
            ) catch |err| {
                debugBufferFailure(
                    "small_counts",
                    null,
                    buffers.small_counts,
                    err,
                );
                return err;
            };
            writes[write_index] = small_counts.range;
            write_index += 1;
            const range_check_8_counts = exactResident(
                session,
                buffers.range_check_8_counts,
                geometry.range_check_8_count_words,
                @alignOf(u32),
            ) catch |err| {
                debugBufferFailure(
                    "range_check_8_counts",
                    null,
                    buffers.range_check_8_counts,
                    err,
                );
                return err;
            };
            writes[write_index] = range_check_8_counts.range;
            write_index += 1;
            std.debug.assert(write_index == writes.len);
            try layout.requireDisjoint(&writes, &reads);

            return .{
                .contract = contract,
                .execution_pointer_table = @ptrCast(@alignCast(execution_pointers.pointer)),
                .segment_start = segment_start.pointer,
                .trace_pointers = trace_pointers,
                .lookup_words = lookup_words.pointer,
                .partial_pointers = partial_pointers,
                .address_counts = address_counts.pointer,
                .big_counts = big_counts.pointer,
                .small_counts = small_counts.pointer,
                .range_check_8_counts = range_check_8_counts.pointer,
                .context_anchor = buffers.execution_pointer_table,
            };
        }

        pub fn launch(
            prepared: *const Prepared,
            session: anytype,
        ) runtime_error.Error!void {
            const stage = telemetry.Stage.trace_generation;
            try common.requireStage(session, stage);
            const geometry = prepared.contract.geometry;
            const status = Api.ec_op_builtin_witness_on(
                prepared.execution_pointer_table,
                geometry.n_addresses,
                geometry.n_big,
                geometry.n_small,
                prepared.segment_start,
                geometry.row_count,
                &prepared.trace_pointers,
                prepared.lookup_words,
                &prepared.partial_pointers,
                try geometry.partialRowCount(),
                prepared.address_counts,
                geometry.address_count_words,
                prepared.big_counts,
                geometry.big_count_words,
                prepared.small_counts,
                geometry.small_count_words,
                prepared.range_check_8_counts,
                geometry.range_check_8_count_words,
                session.context.stream,
            );
            try common.recordMany(session, stage, status, 3);
        }
    };
}

fn exactResident(
    session: anytype,
    slice: common.Words,
    expected: usize,
    alignment: usize,
) runtime_error.Error!layout.Resident(u32) {
    if (slice.len != expected or slice.address % alignment != 0)
        return error.InvalidKernelDescriptor;
    return layout.resident(session, u32, slice, expected);
}

fn debugBufferFailure(
    label: []const u8,
    index: ?usize,
    view: common.Words,
    err: anyerror,
) void {
    std.debug.print(
        "cairo-cuda ec buffer {s}[{?}] failed: {s} " ++
            "address={} len={} owner={} generation={}\n",
        .{
            label,
            index,
            @errorName(err),
            view.address,
            view.len,
            view.owner,
            view.generation,
        },
    );
}

fn wordsForRows(
    rows: u32,
    words_per_row: usize,
) runtime_error.Error!usize {
    return std.math.mul(
        usize,
        rows,
        words_per_row,
    ) catch return error.SizeOverflow;
}

test "native EC-op prepares exact resident graph and records three kernels" {
    const geometry = Geometry{
        .row_count = 16,
        .n_addresses = 113,
        .n_big = 80,
        .n_small = 16,
        .address_count_words = 112,
        .big_count_words = 80,
        .small_count_words = 16,
        .range_check_8_count_words = 256,
    };
    var fixture = TestFixture.init(geometry);
    var session = TestSession{};
    const prepared = try OpsFor(TestApi).prepare(
        &session,
        geometry,
        fixture.buffers(),
    );
    session.context.active_stage = .trace_generation;
    try OpsFor(TestApi).launch(&prepared, &session);
    try std.testing.expectEqual(@as(u64, 3), session.launches);
    try std.testing.expectEqual(@as(u32, 4096), TestApi.partial_rows);
}

test "native EC-op rejects extent and output alias drift" {
    const geometry = Geometry{
        .row_count = 16,
        .n_addresses = 113,
        .n_big = 80,
        .n_small = 16,
        .address_count_words = 112,
        .big_count_words = 80,
        .small_count_words = 16,
        .range_check_8_count_words = 256,
    };
    var fixture = TestFixture.init(geometry);
    var buffers = fixture.buffers();
    var session = TestSession{};
    buffers.lookup_words_word_major.len -= 1;
    try std.testing.expectError(
        error.InvalidKernelDescriptor,
        OpsFor(TestApi).prepare(&session, geometry, buffers),
    );
    fixture.trace_columns[0].address =
        fixture.partial_input_columns[0].address;
    buffers = fixture.buffers();
    try std.testing.expectError(
        error.OverlappingDeviceRange,
        OpsFor(TestApi).prepare(&session, geometry, buffers),
    );
}

const TestApi = struct {
    var partial_rows: u32 = 0;

    pub fn ec_op_builtin_witness_on(
        _: [*]const [*]const u32,
        _: u32,
        _: u32,
        _: u32,
        _: [*]const u32,
        _: u32,
        _: [*]const [*]u32,
        _: [*]u32,
        _: [*]const [*]u32,
        observed_partial_rows: u32,
        _: [*]u32,
        _: u32,
        _: [*]u32,
        _: u32,
        _: [*]u32,
        _: u32,
        _: [*]u32,
        _: u32,
        _: *anyopaque,
    ) c_int {
        partial_rows = observed_partial_rows;
        return 0;
    }
};

const TestSession = struct {
    context: TestContext = .{},
    launches: u64 = 0,

    pub fn recordOrdinaryKernels(
        self: *TestSession,
        stage: telemetry.Stage,
        status: c_int,
        launches: u64,
    ) !void {
        if (stage != .trace_generation or status != 0)
            return error.InvalidState;
        self.launches += launches;
    }
};

const TestContext = struct {
    stream: *anyopaque = @ptrFromInt(1),
    active_stage: telemetry.Stage = .ingress,

    pub fn requireStage(self: *TestContext, stage: telemetry.Stage) !void {
        if (stage != self.active_stage) return error.StageOrderViolation;
    }

    pub fn deviceSlicePointer(
        _: *TestContext,
        comptime T: type,
        slice: anytype,
        minimum: usize,
    ) ![*]T {
        if (slice.len < minimum or slice.address == 0 or
            slice.address % @alignOf(T) != 0)
        {
            return error.InvalidDeviceAddress;
        }
        return @ptrFromInt(slice.address);
    }
};

const TestFixture = struct {
    execution_tables: [contract_module.execution_table_count]common.Words,
    trace_columns: [contract_module.trace_column_count]common.Words,
    partial_input_columns: [contract_module.partial_input_column_count]common.Words,
    geometry: Geometry,

    fn init(geometry: Geometry) TestFixture {
        var result: TestFixture = undefined;
        result.geometry = geometry;
        var address: usize = 0x2000;
        for (&result.execution_tables, 0..) |*table, index| {
            const len: usize = if (index == 0)
                geometry.n_addresses
            else if (index <= contract_module.execution_big_limb_count)
                geometry.n_big
            else
                geometry.n_small;
            table.* = words(address, len);
            address += 0x1000;
        }
        address = 0x100000;
        for (&result.trace_columns) |*column| {
            column.* = words(address, geometry.row_count);
            address += 0x1000;
        }
        address = 0x300000;
        for (&result.partial_input_columns) |*column| {
            column.* = words(
                address,
                geometry.row_count * contract_module.partial_padded_rounds,
            );
            address += 0x10000;
        }
        return result;
    }

    fn buffers(self: *TestFixture) Buffers {
        return .{
            .execution_pointer_table = words(
                0x1000,
                contract_module.execution_table_count * pointer_words,
            ),
            .execution_tables = &self.execution_tables,
            .segment_start = words(0x0f0000, 1),
            .trace_columns = &self.trace_columns,
            .lookup_words_word_major = words(
                0x2000000,
                self.geometry.row_count *
                    contract_module.lookup_words_per_row,
            ),
            .partial_input_columns = &self.partial_input_columns,
            .address_counts = words(
                0x2100000,
                self.geometry.address_count_words,
            ),
            .big_counts = words(
                0x2200000,
                self.geometry.big_count_words,
            ),
            .small_counts = words(
                0x2300000,
                self.geometry.small_count_words,
            ),
            .range_check_8_counts = words(
                0x2400000,
                self.geometry.range_check_8_count_words,
            ),
        };
    }
};

fn words(address: usize, len: usize) common.Words {
    return .{
        .address = address,
        .len = len,
        .owner = 7,
        .generation = 11,
    };
}
