//! Strict-AOT binding for one authenticated Cairo recorded-witness program.
//!
//! Kernel selection is resolved from the immutable product registry. Callers
//! provide resident pointer tables and their complete pointee sets so this
//! boundary can validate ownership, shape, and aliasing before launch.

const std = @import("std");
const product_aot = @import("../../backends/cuda/aot/product_registry.zig");
const kernel_module = @import("../../backends/cuda/runtime/kernel.zig");
const runtime_error = @import("../../backends/cuda/runtime/error.zig");
const common = @import("../../backends/cuda/runtime/stages/common.zig");
const layout = @import("../../backends/cuda/runtime/stages/resident_layout.zig");
const telemetry = @import("../../backends/cuda/runtime/telemetry.zig");
const witness_program = @import("stwo_cairo_frontend").witness.program;
const binding = @import("recorded_binding.zig");

pub const argument_count: u32 = 8;
pub const execution_table_count: u32 = 37;
pub const execution_stride_count: u32 = 3;
const launch_block: u32 = 256;
const pointer_words = @sizeOf(usize) / @sizeOf(u32);
const native_composite_label = "partial_ec_mul_generic";

comptime {
    std.debug.assert(pointer_words == 2);
}

pub const Buffers = struct {
    input_pointer_table: common.Words,
    input_columns: []const common.Words,
    execution_pointer_table: common.Words,
    execution_tables: []const common.Words,
    execution_strides: common.Words,
    output_pointer_table: common.Words,
    output_columns: []const common.Words,
    multiplicity_pointer_table: common.Words,
    multiplicity_tables: []const common.Words,
    /// Auxiliary outputs use CUDA's word-major [word][row] layout.
    lookup_words_word_major: common.Words,
    sub_words_word_major: common.Words,
    pedersen_w18: ?PedersenW18Table = null,
};

pub const PedersenW18Table = struct {
    columns: [product_aot_module_globals.pedersen_w18_column_count]common.Words,
    identity: [32]u8,
};

pub const ComponentGeometry = binding.ComponentGeometry;
pub const catalogIdentity = binding.catalogIdentity;

pub const PreparedLaunch = struct {
    allocator: std.mem.Allocator,
    kernel_name: [:0]u8,
    kernel: kernel_module.Kernel,
    arguments: Arguments,
    pedersen_w18: ?kernel_module.PedersenW18Publication,
    catalog_identity: [32]u8,
    binding_identity: [32]u8,

    pub fn deinit(self: *PreparedLaunch) void {
        self.allocator.free(self.kernel_name);
        self.* = undefined;
    }

    pub fn launch(
        self: *PreparedLaunch,
        session: anytype,
    ) runtime_error.Error!void {
        var pointers = self.arguments.pointers();
        if (self.pedersen_w18) |publication| {
            try session.launchKernelWithPedersenW18(
                self.kernel,
                &pointers,
                publication,
            );
        } else {
            try session.launchKernel(self.kernel, &pointers);
        }
    }
};

const Arguments = struct {
    input_columns: [*]u32,
    execution_tables: [*]u32,
    execution_strides: [*]u32,
    output_columns: [*]u32,
    multiplicity_tables: [*]u32,
    lookup_words: [*]u32,
    sub_words: [*]u32,
    row_count: u32,

    fn pointers(self: *Arguments) [argument_count]?*anyopaque {
        return .{
            @ptrCast(&self.input_columns),
            @ptrCast(&self.execution_tables),
            @ptrCast(&self.execution_strides),
            @ptrCast(&self.output_columns),
            @ptrCast(&self.multiplicity_tables),
            @ptrCast(&self.lookup_words),
            @ptrCast(&self.sub_words),
            @ptrCast(&self.row_count),
        };
    }
};

pub fn prepare(
    allocator: std.mem.Allocator,
    session: anytype,
    registry: product_aot.Registry,
    label: []const u8,
    semantic_hash: u64,
    program: witness_program.Program,
    component: ComponentGeometry,
    row_count: u32,
    buffers: Buffers,
) !PreparedLaunch {
    return prepareImpl(
        allocator,
        session,
        registry,
        label,
        semantic_hash,
        program,
        component,
        row_count,
        buffers,
        false,
    );
}

/// The native EC-op graph is the sole producer authorized to feed this
/// composite consumer. Keeping the label out of this API prevents callers from
/// turning other provenance-only entries into standalone recorded launches.
pub fn prepareNativeEcConsumer(
    allocator: std.mem.Allocator,
    session: anytype,
    registry: product_aot.Registry,
    semantic_hash: u64,
    program: witness_program.Program,
    component: ComponentGeometry,
    row_count: u32,
    buffers: Buffers,
) !PreparedLaunch {
    return prepareImpl(
        allocator,
        session,
        registry,
        native_composite_label,
        semantic_hash,
        program,
        component,
        row_count,
        buffers,
        true,
    );
}

fn prepareImpl(
    allocator: std.mem.Allocator,
    session: anytype,
    registry: product_aot.Registry,
    label: []const u8,
    semantic_hash: u64,
    program: witness_program.Program,
    component: ComponentGeometry,
    row_count: u32,
    buffers: Buffers,
    allow_native_composite: bool,
) !PreparedLaunch {
    try common.requireStage(session, .ingress);
    try program.validate();
    try component.validateRows(row_count);
    if (row_count == 0 or semantic_hash == 0)
        return error.InvalidKernelDescriptor;
    // This label is packaged for provenance only. Production EC-op execution
    // is a native multi-kernel graph with a dedicated workspace, not a
    // standalone recorded-witness launch.
    const is_native_composite = std.mem.eql(
        u8,
        label,
        native_composite_label,
    );
    if (is_native_composite != allow_native_composite)
        return error.StrictAotViolation;
    const admitted = registry.resolveRecordedWitness(.{
        .label = label,
        .semantic_hash = semantic_hash,
        .program_identity = program.semanticIdentity(),
    }) orelse return error.StrictAotViolation;
    if (admitted.semantic_hash != semantic_hash)
        return error.StrictAotViolation;
    const expected_globals: product_aot.ModuleGlobals =
        if (program.deductionRequirements().pedersen_table)
            .pedersen_w18_columns_rows_v1
        else
            .none;
    if (admitted.module_globals != expected_globals)
        return error.StrictAotViolation;
    const catalog_identity = catalogIdentity(
        component,
        label,
        admitted,
        allow_native_composite,
    );

    const input_count = try common.count(buffers.input_columns.len);
    const output_count = try common.count(buffers.output_columns.len);
    const multiplicity_count = try common.count(
        buffers.multiplicity_tables.len,
    );
    if (input_count != program.n_inputs or
        output_count != program.n_cols or
        multiplicity_count != program.n_mult_tables or
        buffers.execution_tables.len != execution_table_count)
    {
        return error.InvalidKernelDescriptor;
    }

    const input_pointers = try exactResident(
        session,
        buffers.input_pointer_table,
        try pointerTableWords(input_count),
        @alignOf(usize),
    );
    const execution_pointers = try exactResident(
        session,
        buffers.execution_pointer_table,
        try pointerTableWords(execution_table_count),
        @alignOf(usize),
    );
    const strides = try exactResident(
        session,
        buffers.execution_strides,
        execution_stride_count,
        @alignOf(u32),
    );
    const output_pointers = try exactResident(
        session,
        buffers.output_pointer_table,
        try pointerTableWords(output_count),
        @alignOf(usize),
    );
    const multiplicity_pointers = try exactResident(
        session,
        buffers.multiplicity_pointer_table,
        try pointerTableWords(multiplicity_count),
        @alignOf(usize),
    );
    const lookup = try exactResident(
        session,
        buffers.lookup_words_word_major,
        try auxiliaryWords(row_count, program.n_lookup_words),
        @alignOf(u32),
    );
    const sub = try exactResident(
        session,
        buffers.sub_words_word_major,
        try auxiliaryWords(row_count, program.n_sub_words),
        @alignOf(u32),
    );

    var reads = std.ArrayList(layout.DeviceRange).empty;
    defer reads.deinit(allocator);
    var writes = std.ArrayList(layout.DeviceRange).empty;
    defer writes.deinit(allocator);
    try reads.appendSlice(allocator, &.{
        input_pointers.range,
        execution_pointers.range,
        strides.range,
        output_pointers.range,
        multiplicity_pointers.range,
    });
    for (buffers.input_columns) |column| {
        const resident = try layout.resident(session, u32, column, row_count);
        try reads.append(allocator, resident.range);
    }
    for (buffers.execution_tables) |table| {
        if (table.len == 0) return error.InvalidKernelDescriptor;
        const resident = try layout.resident(session, u32, table, table.len);
        try reads.append(allocator, resident.range);
    }
    var pedersen_publication: ?kernel_module.PedersenW18Publication = null;
    if (buffers.pedersen_w18) |table| {
        if (expected_globals != .pedersen_w18_columns_rows_v1 or
            std.mem.allEqual(u8, &table.identity, 0))
        {
            return error.InvalidKernelDescriptor;
        }
        var publication = kernel_module.PedersenW18Publication{
            .columns = undefined,
            .row_count = product_aot_module_globals.pedersen_w18_row_count,
            .table_identity = table.identity,
        };
        for (table.columns, 0..) |column, index| {
            const resident = try exactResident(
                session,
                column,
                product_aot_module_globals.pedersen_w18_row_count,
                @alignOf(u32),
            );
            publication.columns[index] = @intFromPtr(resident.pointer);
            try reads.append(allocator, resident.range);
        }
        try publication.validate();
        pedersen_publication = publication;
    } else if (expected_globals != .none) {
        return error.StrictAotViolation;
    }
    for (buffers.output_columns) |column| {
        const resident = try exactResident(
            session,
            column,
            row_count,
            @alignOf(u32),
        );
        try writes.append(allocator, resident.range);
    }
    for (buffers.multiplicity_tables) |table| {
        if (table.len == 0) return error.InvalidKernelDescriptor;
        const resident = try layout.resident(session, u32, table, table.len);
        try writes.append(allocator, resident.range);
    }
    try writes.appendSlice(allocator, &.{ lookup.range, sub.range });
    try layout.requireDisjoint(writes.items, reads.items);
    try binding.uploadCanonical(
        allocator,
        &session.context,
        buffers,
    );
    const binding_identity = binding.bindingIdentity(
        catalog_identity,
        buffers,
    );
    if (std.mem.allEqual(u8, &binding_identity, 0))
        return error.InvalidKernelDescriptor;

    const owned_name = try allocator.dupeZ(u8, admitted.kernel_name);
    errdefer allocator.free(owned_name);
    const kernel = kernel_module.Kernel{
        .stage = .trace_generation,
        .abi_schema = .recorded_witness_v1,
        .cache_key = admitted.cache_key,
        .name = owned_name,
        .grid = .{ 1 + (row_count - 1) / launch_block, 1, 1 },
        .block = .{ launch_block, 1, 1 },
        .argument_count = argument_count,
        .module_globals = admitted.module_globals,
    };
    try kernel.validate();
    return .{
        .allocator = allocator,
        .kernel_name = owned_name,
        .kernel = kernel,
        .pedersen_w18 = pedersen_publication,
        .catalog_identity = catalog_identity,
        .binding_identity = binding_identity,
        .arguments = .{
            .input_columns = input_pointers.pointer,
            .execution_tables = execution_pointers.pointer,
            .execution_strides = strides.pointer,
            .output_columns = output_pointers.pointer,
            .multiplicity_tables = multiplicity_pointers.pointer,
            .lookup_words = lookup.pointer,
            .sub_words = sub.pointer,
            .row_count = row_count,
        },
    };
}

const product_aot_module_globals =
    @import("../../backends/cuda/aot/module_globals.zig");

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

fn pointerTableWords(count: u32) runtime_error.Error!usize {
    return std.math.mul(
        usize,
        @max(count, 1),
        pointer_words,
    ) catch return error.SizeOverflow;
}

fn auxiliaryWords(
    row_count: u32,
    column_count: u32,
) runtime_error.Error!usize {
    if (column_count == 0) return 1;
    return std.math.mul(
        usize,
        row_count,
        column_count,
    ) catch return error.SizeOverflow;
}

test "recorded witness binding resolves exact product identity and owns name" {
    const witness_bundle = @import("stwo_cairo_frontend").witness.bundle;
    var witnesses = try witness_bundle.Bundle.readFile(
        std.testing.allocator,
        "vectors/cairo/sn_pie_2_witness_programs.bin",
    );
    defer witnesses.deinit();
    const witness = witnesses.find("add_ap_opcode") orelse
        return error.MissingCanonicalWitness;
    var registry = try product_aot.Registry.initProduct(
        std.testing.allocator,
    );
    var session = TestSession{};
    var fixture = try TestBuffers.init(
        std.testing.allocator,
        witness.program,
        8,
    );
    defer fixture.deinit();
    var prepared = try prepare(
        std.testing.allocator,
        &session,
        registry,
        witness.label,
        witness.semantic_hash,
        witness.program,
        testComponent(3),
        8,
        fixture.buffers(),
    );
    registry.deinit();
    defer prepared.deinit();

    try std.testing.expectEqual(
        @as(u64, 0x735903777afd70d2),
        prepared.kernel.cache_key,
    );
    try std.testing.expectEqualStrings(
        "stwo_jit_witness_d94540f2fd219001",
        prepared.kernel.name,
    );
    const original_binding = prepared.binding_identity;
    fixture.input_columns[0].generation += 1;
    try std.testing.expect(!std.mem.eql(
        u8,
        &original_binding,
        &binding.bindingIdentity(
            prepared.catalog_identity,
            fixture.buffers(),
        ),
    ));
    fixture.input_columns[0].generation -= 1;
    try std.testing.expectEqual(@as(u64, 5), session.context.uploads);
    session.context.active_stage = .trace_generation;
    try prepared.launch(&session);
    try std.testing.expectEqual(@as(u64, 1), session.launches);
}

test "recorded witness binding rejects identity and alias drift" {
    const witness_bundle = @import("stwo_cairo_frontend").witness.bundle;
    var witnesses = try witness_bundle.Bundle.readFile(
        std.testing.allocator,
        "vectors/cairo/sn_pie_2_witness_programs.bin",
    );
    defer witnesses.deinit();
    const witness = witnesses.find("add_ap_opcode") orelse
        return error.MissingCanonicalWitness;
    var registry = try product_aot.Registry.initProduct(
        std.testing.allocator,
    );
    defer registry.deinit();
    var session = TestSession{};
    var fixture = try TestBuffers.init(
        std.testing.allocator,
        witness.program,
        8,
    );
    defer fixture.deinit();

    try std.testing.expectError(
        error.StrictAotViolation,
        prepare(
            std.testing.allocator,
            &session,
            registry,
            witness.label,
            witness.semantic_hash ^ 1,
            witness.program,
            testComponent(3),
            8,
            fixture.buffers(),
        ),
    );
    const pedersen = witnesses.find(
        "partial_ec_mul_window_bits_18",
    ) orelse return error.MissingCanonicalWitness;
    try std.testing.expect(
        pedersen.program.deductionRequirements().pedersen_table,
    );
    var pedersen_fixture = try TestBuffers.init(
        std.testing.allocator,
        pedersen.program,
        8,
    );
    defer pedersen_fixture.deinit();
    try std.testing.expectError(
        error.StrictAotViolation,
        prepare(
            std.testing.allocator,
            &session,
            registry,
            pedersen.label,
            pedersen.semantic_hash,
            pedersen.program,
            testComponent(3),
            8,
            pedersen_fixture.buffers(),
        ),
    );
    const composite = witnesses.find(native_composite_label) orelse
        return error.MissingCanonicalWitness;
    try std.testing.expectError(
        error.StrictAotViolation,
        prepare(
            std.testing.allocator,
            &session,
            registry,
            composite.label,
            composite.semantic_hash,
            composite.program,
            testComponent(3),
            8,
            fixture.buffers(),
        ),
    );
    fixture.output_columns[0].address =
        fixture.input_columns[0].address;
    try std.testing.expectError(
        error.OverlappingDeviceRange,
        prepare(
            std.testing.allocator,
            &session,
            registry,
            witness.label,
            witness.semantic_hash,
            witness.program,
            testComponent(3),
            8,
            fixture.buffers(),
        ),
    );
}

test "native EC composite is the only admitted partial-EC launch path" {
    const witness_bundle = @import("stwo_cairo_frontend").witness.bundle;
    var witnesses = try witness_bundle.Bundle.readFile(
        std.testing.allocator,
        "vectors/cairo/sn_pie_2_witness_programs.bin",
    );
    defer witnesses.deinit();
    const composite = witnesses.find(native_composite_label) orelse
        return error.MissingCanonicalWitness;
    try std.testing.expect(
        !composite.program.deductionRequirements().pedersen_table,
    );
    var registry = try product_aot.Registry.initProduct(
        std.testing.allocator,
    );
    defer registry.deinit();
    var session = TestSession{};
    const partial_rows: u32 = 16 * 256;
    var fixture = try TestBuffers.init(
        std.testing.allocator,
        composite.program,
        partial_rows,
    );
    defer fixture.deinit();

    const buffers = fixture.buffers();
    var prepared = try prepareNativeEcConsumer(
        std.testing.allocator,
        &session,
        registry,
        composite.semantic_hash,
        composite.program,
        testComponent(12),
        partial_rows,
        buffers,
    );
    defer prepared.deinit();
    try std.testing.expectEqual(
        product_aot.ModuleGlobals.none,
        prepared.kernel.module_globals,
    );
    session.context.active_stage = .trace_generation;
    try prepared.launch(&session);
    try std.testing.expectEqual(@as(u64, 1), session.launches);
}

const TestBuffers = struct {
    allocator: std.mem.Allocator,
    input_columns: []common.Words,
    execution_tables: []common.Words,
    output_columns: []common.Words,
    multiplicity_tables: []common.Words,
    input_pointer_table: common.Words,
    execution_pointer_table: common.Words,
    execution_strides: common.Words,
    output_pointer_table: common.Words,
    multiplicity_pointer_table: common.Words,
    lookup_words: common.Words,
    sub_words: common.Words,

    fn init(
        allocator: std.mem.Allocator,
        program: witness_program.Program,
        rows: u32,
    ) !TestBuffers {
        const inputs = try allocator.alloc(common.Words, program.n_inputs);
        errdefer allocator.free(inputs);
        const tables = try allocator.alloc(
            common.Words,
            execution_table_count,
        );
        errdefer allocator.free(tables);
        const outputs = try allocator.alloc(common.Words, program.n_cols);
        errdefer allocator.free(outputs);
        const multiplicities = try allocator.alloc(
            common.Words,
            program.n_mult_tables,
        );
        errdefer allocator.free(multiplicities);
        var address: usize = 0x10_0000;
        fillSlices(inputs, &address, rows);
        fillSlices(tables, &address, 512);
        fillSlices(outputs, &address, rows);
        fillSlices(multiplicities, &address, 512);
        return .{
            .allocator = allocator,
            .input_columns = inputs,
            .execution_tables = tables,
            .output_columns = outputs,
            .multiplicity_tables = multiplicities,
            .input_pointer_table = nextSlice(
                &address,
                try pointerTableWords(program.n_inputs),
            ),
            .execution_pointer_table = nextSlice(
                &address,
                try pointerTableWords(execution_table_count),
            ),
            .execution_strides = nextSlice(
                &address,
                execution_stride_count,
            ),
            .output_pointer_table = nextSlice(
                &address,
                try pointerTableWords(program.n_cols),
            ),
            .multiplicity_pointer_table = nextSlice(
                &address,
                try pointerTableWords(program.n_mult_tables),
            ),
            .lookup_words = nextSlice(
                &address,
                try auxiliaryWords(rows, program.n_lookup_words),
            ),
            .sub_words = nextSlice(
                &address,
                try auxiliaryWords(rows, program.n_sub_words),
            ),
        };
    }

    fn deinit(self: *TestBuffers) void {
        self.allocator.free(self.input_columns);
        self.allocator.free(self.execution_tables);
        self.allocator.free(self.output_columns);
        self.allocator.free(self.multiplicity_tables);
        self.* = undefined;
    }

    fn buffers(self: *const TestBuffers) Buffers {
        return .{
            .input_pointer_table = self.input_pointer_table,
            .input_columns = self.input_columns,
            .execution_pointer_table = self.execution_pointer_table,
            .execution_tables = self.execution_tables,
            .execution_strides = self.execution_strides,
            .output_pointer_table = self.output_pointer_table,
            .output_columns = self.output_columns,
            .multiplicity_pointer_table = self.multiplicity_pointer_table,
            .multiplicity_tables = self.multiplicity_tables,
            .lookup_words_word_major = self.lookup_words,
            .sub_words_word_major = self.sub_words,
        };
    }
};

const TestSession = struct {
    context: TestContext = .{},
    launches: u64 = 0,

    pub fn launchKernel(
        self: *TestSession,
        kernel: kernel_module.Kernel,
        arguments: []const ?*anyopaque,
    ) runtime_error.Error!void {
        try kernel.validate();
        if (arguments.len != argument_count)
            return error.ArgumentCountMismatch;
        self.launches += 1;
    }

    pub fn launchKernelWithPedersenW18(
        self: *TestSession,
        kernel: kernel_module.Kernel,
        arguments: []const ?*anyopaque,
        publication: kernel_module.PedersenW18Publication,
    ) runtime_error.Error!void {
        try publication.validate();
        if (kernel.module_globals != .pedersen_w18_columns_rows_v1)
            return error.InvalidKernelDescriptor;
        try self.launchKernel(kernel, arguments);
    }
};

const TestContext = struct {
    active_stage: telemetry.Stage = .ingress,
    uploads: u64 = 0,

    pub fn requireStage(
        self: *TestContext,
        expected: telemetry.Stage,
    ) runtime_error.Error!void {
        if (self.active_stage != expected) return error.StageOrderViolation;
    }

    pub fn deviceSlicePointer(
        _: *TestContext,
        comptime F: type,
        slice: anytype,
        minimum: usize,
    ) runtime_error.Error![*]F {
        if (minimum == 0 or slice.len < minimum or
            slice.owner != 7 or slice.generation != 11 or
            slice.address % @alignOf(F) != 0)
        {
            return error.InvalidDeviceAddress;
        }
        return @ptrFromInt(slice.address);
    }

    pub fn uploadSlice(
        self: *TestContext,
        comptime F: type,
        destination: anytype,
        source: []const F,
    ) runtime_error.Error!void {
        if (self.active_stage != .ingress or
            destination.len != source.len or source.len == 0)
        {
            return error.InvalidKernelDescriptor;
        }
        _ = try self.deviceSlicePointer(F, destination, source.len);
        self.uploads += 1;
    }
};

fn testComponent(trace_log_size: u32) ComponentGeometry {
    return .{
        .canonical_ordinal = 0,
        .instance = 0,
        .trace_log_size = trace_log_size,
    };
}

fn fillSlices(
    slices: []common.Words,
    address: *usize,
    words: usize,
) void {
    for (slices) |*slice| slice.* = nextSlice(address, words);
}

fn nextSlice(address: *usize, words: usize) common.Words {
    address.* = std.mem.alignForward(usize, address.*, @alignOf(usize));
    const result = common.Words{
        .address = address.*,
        .len = words,
        .owner = 7,
        .generation = 11,
    };
    address.* += words * @sizeOf(u32) + 64;
    return result;
}
