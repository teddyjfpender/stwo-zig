//! Ordered resident graph for `ec_op_builtin` and `partial_ec_mul_generic`.

const std = @import("std");
const product_aot = @import("stwo_cuda_backend").aot.product_registry;
const cairo_ec_op =
    @import("stwo_cuda_backend").runtime.stages.cairo_ec_op;
const common = @import("stwo_cuda_backend").runtime.stages.common;
const recorded_binding = @import("recorded_binding.zig");
const recorded_witness = @import("recorded_witness.zig");
const witness_program = @import("stwo_cairo_frontend").witness.program;

pub const Prepared = struct {
    ec_op: cairo_ec_op.Prepared,
    partial_ec_mul: recorded_witness.PreparedLaunch,
    catalog_identity: [32]u8,
    binding_identity: [32]u8,

    pub fn deinit(self: *Prepared) void {
        self.partial_ec_mul.deinit();
        self.* = undefined;
    }

    pub fn launch(self: *Prepared, session: anytype) !void {
        // The AOT consumer reads the exact padded columns written by the
        // ordered native graph on the same proof stream.
        try cairo_ec_op.Native.launch(&self.ec_op, session);
        try self.partial_ec_mul.launch(session);
    }
};

pub fn catalogIdentity(
    component: recorded_binding.ComponentGeometry,
    contract_identity: [32]u8,
) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo-zig/cairo/cuda/base-native-ec/v1\x00");
    recorded_binding.hashInt(
        &hash,
        u32,
        component.canonical_ordinal,
    );
    recorded_binding.hashBytes(&hash, "ec_op_builtin");
    recorded_binding.hashInt(&hash, u32, component.instance);
    hash.update(&contract_identity);
    return hash.finalResult();
}

pub fn prepare(
    allocator: std.mem.Allocator,
    session: anytype,
    registry: product_aot.Registry,
    component: recorded_binding.ComponentGeometry,
    partial_component: recorded_binding.ComponentGeometry,
    geometry: cairo_ec_op.Geometry,
    ec_buffers: cairo_ec_op.Buffers,
    partial_semantic_hash: u64,
    partial_program: witness_program.Program,
    partial_buffers: recorded_witness.Buffers,
) !Prepared {
    const partial_rows = try geometry.partialRowCount();
    try component.validateRows(geometry.row_count);
    try partial_component.validateRows(partial_rows);
    try validateConsumerLink(
        partial_rows,
        ec_buffers.partial_input_columns,
        partial_buffers.input_columns,
    );
    const ec_op = try cairo_ec_op.Native.prepare(
        session,
        geometry,
        ec_buffers,
    );
    try uploadExecutionPointers(
        allocator,
        &session.context,
        ec_buffers,
    );
    const partial_ec_mul = try recorded_witness.prepareNativeEcConsumer(
        allocator,
        session,
        registry,
        partial_semantic_hash,
        partial_program,
        partial_component,
        partial_rows,
        partial_buffers,
    );
    const catalog_identity = catalogIdentity(
        component,
        ec_op.contract.identity,
    );
    const binding_identity = residentBindingIdentity(
        catalog_identity,
        partial_ec_mul.binding_identity,
        ec_buffers,
    );
    return .{
        .ec_op = ec_op,
        .partial_ec_mul = partial_ec_mul,
        .catalog_identity = catalog_identity,
        .binding_identity = binding_identity,
    };
}

fn uploadExecutionPointers(
    allocator: std.mem.Allocator,
    uploader: anytype,
    buffers: cairo_ec_op.Buffers,
) !void {
    const words = try allocator.alloc(
        u32,
        buffers.execution_pointer_table.len,
    );
    defer allocator.free(words);
    try recorded_binding.encodePointerTable(
        words,
        buffers.execution_tables,
    );
    try uploader.uploadSlice(
        u32,
        buffers.execution_pointer_table,
        words,
    );
}

fn residentBindingIdentity(
    catalog_identity: [32]u8,
    partial_identity: [32]u8,
    buffers: cairo_ec_op.Buffers,
) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo-zig/cairo/cuda/native-ec-resident-binding/v1\x00");
    hash.update(&catalog_identity);
    hash.update(&partial_identity);
    recorded_binding.hashSlice(&hash, buffers.execution_pointer_table);
    hashSlices(&hash, buffers.execution_tables);
    recorded_binding.hashSlice(&hash, buffers.segment_start);
    hashSlices(&hash, buffers.trace_columns);
    recorded_binding.hashSlice(&hash, buffers.lookup_words_word_major);
    hashSlices(&hash, buffers.partial_input_columns);
    recorded_binding.hashSlice(&hash, buffers.address_counts);
    recorded_binding.hashSlice(&hash, buffers.big_counts);
    recorded_binding.hashSlice(&hash, buffers.small_counts);
    recorded_binding.hashSlice(&hash, buffers.range_check_8_counts);
    return hash.finalResult();
}

fn hashSlices(
    hash: *std.crypto.hash.sha2.Sha256,
    slices: []const common.Words,
) void {
    recorded_binding.hashInt(hash, u64, slices.len);
    for (slices) |slice| recorded_binding.hashSlice(hash, slice);
}

fn validateConsumerLink(
    partial_rows: u32,
    native_outputs: []const common.Words,
    aot_inputs: []const common.Words,
) !void {
    if (native_outputs.len !=
        cairo_ec_op_contract.partial_input_column_count or
        aot_inputs.len + 1 != native_outputs.len)
    {
        return error.InvalidKernelDescriptor;
    }
    for (native_outputs[0..aot_inputs.len], aot_inputs) |output, input| {
        if (output.address != input.address or
            output.len != partial_rows or input.len != partial_rows or
            output.owner != input.owner or
            output.generation != input.generation)
        {
            return error.InvalidKernelDescriptor;
        }
    }
}

const cairo_ec_op_contract =
    @import("stwo_cuda_backend").runtime.stages.cairo_ec_op_contract;

test "native EC consumer binding requires exact resident slice identities" {
    var outputs: [cairo_ec_op_contract.partial_input_column_count]common.Words =
        undefined;
    for (&outputs, 0..) |*output, index| {
        output.* = .{
            .address = 0x1000 + index * 0x10000,
            .len = 4096,
            .owner = 7,
            .generation = 11,
        };
    }
    var inputs = outputs;
    try validateConsumerLink(4096, &outputs, inputs[0 .. inputs.len - 1]);
    inputs[64].generation += 1;
    try std.testing.expectError(
        error.InvalidKernelDescriptor,
        validateConsumerLink(4096, &outputs, inputs[0 .. inputs.len - 1]),
    );
    inputs = outputs;
    inputs[0].address += 4;
    try std.testing.expectError(
        error.InvalidKernelDescriptor,
        validateConsumerLink(4096, &outputs, inputs[0 .. inputs.len - 1]),
    );
    inputs = outputs;
    try std.testing.expectError(
        error.InvalidKernelDescriptor,
        validateConsumerLink(4096, &outputs, &inputs),
    );
}

test "native EC seal binds root geometry, child, and resident graph" {
    const component = recorded_binding.ComponentGeometry{
        .canonical_ordinal = 4,
        .instance = 0,
        .trace_log_size = 4,
    };
    const root_catalog = catalogIdentity(component, [_]u8{0x71} ** 32);
    const child_seal = [_]u8{0x82} ** 32;
    var execution = [_]common.Words{testWords(0x1000, 16)};
    const traces = [_]common.Words{testWords(0x2000, 16)};
    const partial = [_]common.Words{testWords(0x3000, 4096)};
    const buffers = cairo_ec_op.Buffers{
        .execution_pointer_table = testWords(0x4000, 2),
        .execution_tables = &execution,
        .segment_start = testWords(0x5000, 1),
        .trace_columns = &traces,
        .lookup_words_word_major = testWords(0x6000, 16),
        .partial_input_columns = &partial,
        .address_counts = testWords(0x7000, 16),
        .big_counts = testWords(0x8000, 16),
        .small_counts = testWords(0x9000, 16),
        .range_check_8_counts = testWords(0xa000, 256),
    };
    const original = residentBindingIdentity(
        root_catalog,
        child_seal,
        buffers,
    );
    execution[0].generation += 1;
    try std.testing.expect(!std.mem.eql(
        u8,
        &original,
        &residentBindingIdentity(root_catalog, child_seal, buffers),
    ));
    try std.testing.expect(!std.mem.eql(
        u8,
        &root_catalog,
        &catalogIdentity(.{
            .canonical_ordinal = component.canonical_ordinal + 1,
            .instance = component.instance,
            .trace_log_size = component.trace_log_size,
        }, [_]u8{0x71} ** 32),
    ));
}

fn testWords(address: usize, len: usize) common.Words {
    return .{
        .address = address,
        .len = len,
        .owner = 7,
        .generation = 11,
    };
}
