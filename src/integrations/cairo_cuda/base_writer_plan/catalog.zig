//! Fail-closed inventory of every Cairo base-trace producer in one proof.

const std = @import("std");
const product_aot = @import("../../../backends/cuda/aot/product_registry.zig");
const ec_contract = @import(
    "../../../backends/cuda/runtime/stages/cairo_ec_op_contract.zig",
);
const adapter = @import("stwo_cairo_frontend").adapter;
const proof_plan = @import("stwo_cairo_frontend").proof_plan;
const composition = @import("stwo_cairo_frontend").witness.composition_bundle;
const feed_bundle = @import("stwo_cairo_frontend").witness.feed_bundle;
const fixed_bundle = @import("stwo_cairo_frontend").witness.fixed_table_bundle;
const witness_bundle = @import("stwo_cairo_frontend").witness.bundle;
const fixed_tables = @import("fixed_tables.zig");
const memory = @import("memory.zig");
const recorded_binding = @import("../recorded_binding.zig");
const native_ec = @import("../native_ec.zig");

pub const Entry = struct {
    component_index: u32,
    name: []const u8,
    instance: u32,
    writer: proof_plan.WriterKind,
    identity: [32]u8,
};

pub const Catalog = struct {
    allocator: std.mem.Allocator,
    entries: []Entry,
    writer_counts: [std.meta.fields(proof_plan.WriterKind).len]u32,
    identity: [32]u8,

    pub fn deinit(self: *Catalog) void {
        self.allocator.free(self.entries);
        self.* = undefined;
    }

    pub fn find(
        self: Catalog,
        name: []const u8,
        instance: u32,
    ) ?Entry {
        for (self.entries) |entry| {
            if (entry.instance == instance and
                std.mem.eql(u8, entry.name, name))
            {
                return entry;
            }
        }
        return null;
    }
};

pub fn compile(
    allocator: std.mem.Allocator,
    proof: *const proof_plan.CairoProofPlan,
    components: composition.Bundle,
    witnesses: witness_bundle.Bundle,
    fixed: fixed_bundle.Bundle,
    input: *const adapter.ProverInput,
    registry: product_aot.Registry,
) !Catalog {
    if (proof.components.len != components.components.len)
        return error.BaseWriterInventoryMismatch;

    var fixed_plan = try fixed_tables.compile(
        allocator,
        components,
        fixed,
    );
    defer fixed_plan.deinit();
    var memory_plan = try memory.compile(
        allocator,
        components,
        input,
    );
    defer memory_plan.deinit();

    const entries = try allocator.alloc(Entry, proof.components.len);
    errdefer allocator.free(entries);
    var writer_counts =
        [_]u32{0} ** std.meta.fields(proof_plan.WriterKind).len;
    for (
        proof.components,
        components.components,
        entries,
        0..,
    ) |planned, component, *entry, component_index| {
        if (!std.mem.eql(u8, planned.name, component.label) or
            planned.instance != component.instance or
            planned.canonical_ordinal != component_index)
        {
            return error.BaseWriterInventoryMismatch;
        }
        const identity: [32]u8 = switch (planned.writer) {
            .recorded_aot => try recordedIdentity(
                planned,
                component,
                witnesses,
                registry,
                false,
            ),
            .native_backend => try nativeIdentity(
                proof,
                components,
                planned,
                component,
                witnesses,
                input,
                registry,
            ),
            .fixed_table => blk: {
                const lowering = fixed_plan.find(
                    planned.name,
                    planned.instance,
                ) orelse return error.MissingFixedTableLowering;
                break :blk lowering.identity;
            },
            .memory_trace => blk: {
                const lowering = findMemory(
                    memory_plan.entries,
                    planned.name,
                    planned.instance,
                ) orelse return error.MissingMemoryLowering;
                break :blk lowering.identity;
            },
        };
        entry.* = .{
            .component_index = @intCast(component_index),
            .name = planned.name,
            .instance = planned.instance,
            .writer = planned.writer,
            .identity = identity,
        };
        writer_counts[@intFromEnum(planned.writer)] += 1;
    }
    try validateCounts(writer_counts);
    return .{
        .allocator = allocator,
        .entries = entries,
        .writer_counts = writer_counts,
        .identity = catalogIdentity(entries),
    };
}

fn recordedIdentity(
    planned: proof_plan.Component,
    component: composition.Component,
    witnesses: witness_bundle.Bundle,
    registry: product_aot.Registry,
    native_consumer: bool,
) ![32]u8 {
    const witness = witnesses.find(planned.name) orelse
        return error.MissingRecordedWitnessLowering;
    const admitted = registry.resolveRecordedWitness(.{
        .label = witness.label,
        .semantic_hash = witness.semantic_hash,
        .program_identity = witness.program.semanticIdentity(),
    }) orelse return error.MissingRecordedWitnessLowering;
    const expected_globals: product_aot.ModuleGlobals =
        if (witness.program.deductionRequirements().pedersen_table)
            .pedersen_w18_columns_rows_v1
        else
            .none;
    if (admitted.module_globals != expected_globals)
        return error.RecordedWitnessGlobalsMismatch;

    return recorded_binding.catalogIdentity(.{
        .canonical_ordinal = planned.canonical_ordinal,
        .instance = planned.instance,
        .trace_log_size = component.trace_log_size,
    }, planned.name, admitted, native_consumer);
}

fn nativeIdentity(
    proof: *const proof_plan.CairoProofPlan,
    components: composition.Bundle,
    planned: proof_plan.Component,
    component: composition.Component,
    witnesses: witness_bundle.Bundle,
    input: *const adapter.ProverInput,
    registry: product_aot.Registry,
) ![32]u8 {
    if (std.mem.eql(u8, planned.name, "partial_ec_mul_generic")) {
        return recordedIdentity(
            planned,
            component,
            witnesses,
            registry,
            true,
        );
    }
    if (!std.mem.eql(u8, planned.name, "ec_op_builtin"))
        return error.MissingNativeBaseWriterLowering;

    const partial = findComponent(
        proof,
        "partial_ec_mul_generic",
        0,
    ) orelse return error.MissingNativeBaseWriterLowering;
    const contract = try ec_contract.Contract.compile(.{
        .row_count = try rows(component.trace_log_size),
        .n_addresses = try castU32(input.memory.address_to_id.len),
        .n_big = try castU32(input.memory.f252_values.len),
        .n_small = try castU32(input.memory.small_values.len),
        .address_count_words = try castU32(
            input.memory.address_to_id.len -| 1,
        ),
        .big_count_words = try castU32(input.memory.f252_values.len),
        .small_count_words = try castU32(input.memory.small_values.len),
        .range_check_8_count_words = 256,
    });
    const partial_ordinal = std.math.cast(
        usize,
        partial.canonical_ordinal,
    ) orelse return error.MissingNativeBaseWriterLowering;
    if (partial_ordinal >= components.components.len)
        return error.MissingNativeBaseWriterLowering;
    const partial_component = components.components[partial_ordinal];
    if (!std.mem.eql(
        u8,
        partial_component.label,
        partial.name,
    ) or partial_component.instance != partial.instance) {
        return error.MissingNativeBaseWriterLowering;
    }
    if (try rows(partial_component.trace_log_size) !=
        try contract.geometry.partialRowCount())
    {
        return error.NativeEcConsumerGeometryMismatch;
    }

    return native_ec.catalogIdentity(.{
        .canonical_ordinal = planned.canonical_ordinal,
        .instance = planned.instance,
        .trace_log_size = component.trace_log_size,
    }, contract.identity);
}

fn findMemory(
    entries: []const memory.Entry,
    name: []const u8,
    instance: u32,
) ?memory.Entry {
    for (entries) |entry| {
        if (entry.instance == instance and std.mem.eql(u8, entry.name, name))
            return entry;
    }
    return null;
}

fn findComponent(
    proof: *const proof_plan.CairoProofPlan,
    name: []const u8,
    instance: u32,
) ?*const proof_plan.Component {
    return proof.findInstance(name, instance);
}

fn validateCounts(
    counts: [std.meta.fields(proof_plan.WriterKind).len]u32,
) !void {
    if (counts[@intFromEnum(proof_plan.WriterKind.recorded_aot)] != 32 or
        counts[@intFromEnum(proof_plan.WriterKind.native_backend)] != 2 or
        counts[@intFromEnum(proof_plan.WriterKind.fixed_table)] != 21 or
        counts[@intFromEnum(proof_plan.WriterKind.memory_trace)] != 3)
    {
        return error.BaseWriterInventoryMismatch;
    }
}

fn catalogIdentity(entries: []const Entry) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo-zig/cairo/cuda/base-writer-catalog/v1\x00");
    hashInt(&hash, u64, entries.len);
    for (entries) |entry| {
        hashInt(&hash, u32, entry.component_index);
        hashBytes(&hash, entry.name);
        hashInt(&hash, u32, entry.instance);
        hashInt(&hash, u8, @intFromEnum(entry.writer));
        hash.update(&entry.identity);
    }
    return hash.finalResult();
}

fn rows(log_size: u32) !u32 {
    if (log_size >= 32) return error.BaseWriterGeometryOverflow;
    return @as(u32, 1) << @intCast(log_size);
}

fn castU32(value: usize) !u32 {
    return std.math.cast(u32, value) orelse
        error.BaseWriterGeometryOverflow;
}

fn hashBytes(
    hash: *std.crypto.hash.sha2.Sha256,
    bytes: []const u8,
) void {
    hashInt(hash, u64, bytes.len);
    hash.update(bytes);
}

fn hashInt(
    hash: *std.crypto.hash.sha2.Sha256,
    comptime T: type,
    value: T,
) void {
    var encoded: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &encoded, value, .little);
    hash.update(&encoded);
}

test "SN2 base catalog admits all 58 canonical producers exactly once" {
    const allocator = std.testing.allocator;
    const path = std.process.getEnvVarOwned(
        allocator,
        "STWO_ZIG_TEST_SN2_ADAPTED_INPUT",
    ) catch return error.SkipZigTest;
    defer allocator.free(path);
    var input = try adapter.adapted_input.readFile(allocator, path);
    defer input.deinit(allocator);
    var components = try composition.Bundle.readFile(
        allocator,
        "vectors/cairo/sn_pie_2_composition.bin",
    );
    defer components.deinit();
    var witnesses = try witness_bundle.Bundle.readFile(
        allocator,
        "vectors/cairo/sn_pie_2_witness_programs.bin",
    );
    defer witnesses.deinit();
    var feeds = try feed_bundle.Bundle.readFile(
        allocator,
        "vectors/cairo/sn_pie_2_multiplicity_feeds.bin",
    );
    defer feeds.deinit();
    var fixed = try fixed_bundle.Bundle.readFile(
        allocator,
        "vectors/cairo/cairo_fixed_tables.bin",
    );
    defer fixed.deinit();
    var proof = try proof_plan.CairoProofPlan.fromSemanticArtifacts(
        allocator,
        witnesses,
        feeds,
        fixed,
        components,
        &input,
    );
    defer proof.deinit();
    var registry = try product_aot.Registry.initProduct(allocator);
    defer registry.deinit();
    var catalog = try compile(
        allocator,
        &proof,
        components,
        witnesses,
        fixed,
        &input,
        registry,
    );
    defer catalog.deinit();

    try std.testing.expectEqual(@as(usize, 58), catalog.entries.len);
    try std.testing.expectEqual(
        @as(u32, 32),
        catalog.writer_counts[
            @intFromEnum(proof_plan.WriterKind.recorded_aot)
        ],
    );
    try std.testing.expectEqual(
        @as(u32, 2),
        catalog.writer_counts[
            @intFromEnum(proof_plan.WriterKind.native_backend)
        ],
    );
    try std.testing.expectEqual(
        @as(u32, 21),
        catalog.writer_counts[
            @intFromEnum(proof_plan.WriterKind.fixed_table)
        ],
    );
    try std.testing.expectEqual(
        @as(u32, 3),
        catalog.writer_counts[
            @intFromEnum(proof_plan.WriterKind.memory_trace)
        ],
    );
    try std.testing.expect(!std.mem.allEqual(u8, &catalog.identity, 0));
    for (catalog.entries, 0..) |entry, index| {
        try std.testing.expectEqual(@as(u32, @intCast(index)), entry.component_index);
        try std.testing.expect(!std.mem.allEqual(u8, &entry.identity, 0));
        try std.testing.expectEqual(
            entry,
            catalog.find(entry.name, entry.instance).?,
        );
    }
}
