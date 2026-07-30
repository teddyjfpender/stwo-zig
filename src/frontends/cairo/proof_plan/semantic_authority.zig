//! Authenticated Cairo component geometry joined with backend-neutral writers.

const std = @import("std");
const adapter = @import("../adapter/mod.zig");
const opcodes = @import("../adapter/opcodes.zig");
const claim_generator = @import("../claim_generator.zig");
const witness_bundle = @import("../witness/bundle.zig");
const composition_bundle = @import("../witness/composition_bundle.zig");
const fixed_table_bundle = @import("../witness/fixed_table_bundle.zig");
const memory_tables = @import("../witness/memory_tables.zig");

pub const WriterAuthority = enum {
    recorded_aot,
    native_backend,
    fixed_table,
    memory_trace,
};

pub const ComponentFacts = struct {
    writer: WriterAuthority,
    real_rows: ?u32,
};

pub fn validateAndClassify(
    allocator: std.mem.Allocator,
    witnesses: witness_bundle.Bundle,
    fixed_tables: fixed_table_bundle.Bundle,
    composition: composition_bundle.Bundle,
    input: *const adapter.ProverInput,
    facts: []ComponentFacts,
) !void {
    if (facts.len != composition.components.len) return error.ComponentCardinalityMismatch;
    const memory_big_count = countComponents(composition, "memory_id_to_big");
    var claims = try claim_generator.deriveFromProverInput(allocator, input, .{
        .preprocessed_variant = try preprocessedVariant(fixed_tables),
        .memory_id_to_big_components = memory_big_count,
    });
    defer claims.deinit();
    if (claims.components.len != composition.components.len)
        return error.ComponentCardinalityMismatch;

    for (composition.components, claims.components, facts) |component, claim, *fact| {
        if (!std.mem.eql(u8, component.label, claim.name) or component.instance != claim.instance)
            return error.ComponentOrderMismatch;
        switch (claim.log_size) {
            .known => |log_size| if (component.trace_log_size != log_size)
                return error.ComponentLogSizeMismatch,
            // The authenticated composition records feed-dependent logs. The
            // producer graph resolves real rows separately below.
            .deferred => {},
        }
        if (component.trace_log_size >= 32) return error.InvalidComponentLogSize;
        const padded_rows = @as(u32, 1) << @intCast(component.trace_log_size);
        fact.* = try classify(
            component,
            witnesses,
            fixed_tables,
            input,
            padded_rows,
        );
    }
}

/// Derives exact preprocessed column domains from authenticated fixed-table
/// sources or a canonical generated-column family.
pub fn preprocessedLogs(
    allocator: std.mem.Allocator,
    fixed_tables: fixed_table_bundle.Bundle,
) ![]u32 {
    const unresolved = std.math.maxInt(u32);
    const logs = try allocator.alloc(u32, fixed_tables.preprocessed_identities.len);
    errdefer allocator.free(logs);
    @memset(logs, unresolved);
    for (fixed_tables.entries) |entry| {
        for (entry.preprocessed_sources) |source| {
            // The bundle carries writer metadata for every preprocessed
            // variant. Sources outside this proof's authenticated identity
            // list are inactive, not missing.
            const index = fixed_tables.identityOrdinal(source) orelse continue;
            if (logs[index] != unresolved and logs[index] != entry.log_size)
                return error.PreprocessedGeometryMismatch;
            logs[index] = entry.log_size;
        }
    }
    for (logs, fixed_tables.preprocessed_identities) |*log_size, identity| {
        if (log_size.* != unresolved) continue;
        if (std.mem.startsWith(u8, identity, "seq_")) {
            log_size.* = std.fmt.parseUnsigned(u32, identity["seq_".len..], 10) catch
                return error.InvalidSequenceIdentity;
            continue;
        }
        if (std.mem.startsWith(u8, identity, "bitwise_xor_")) {
            const rest = identity["bitwise_xor_".len..];
            const separator = std.mem.indexOfScalar(u8, rest, '_') orelse
                return error.InvalidBitwiseIdentity;
            const bits = std.fmt.parseUnsigned(u32, rest[0..separator], 10) catch
                return error.InvalidBitwiseIdentity;
            log_size.* = std.math.mul(u32, bits, 2) catch
                return error.InvalidBitwiseIdentity;
            continue;
        }
        std.log.err("preprocessed identity has no geometry authority: {s}", .{identity});
        return error.MissingPreprocessedGeometry;
    }
    return logs;
}

fn classify(
    component: composition_bundle.Component,
    witnesses: witness_bundle.Bundle,
    fixed_tables: fixed_table_bundle.Bundle,
    input: *const adapter.ProverInput,
    padded_rows: u32,
) !ComponentFacts {
    if (witnesses.find(component.label) != null) return .{
        .writer = if (std.mem.eql(u8, component.label, "partial_ec_mul_generic"))
            .native_backend
        else
            .recorded_aot,
        .real_rows = directRealRows(input, component.label, padded_rows),
    };
    if (fixed_tables.find(component.label)) |entry| {
        if (entry.log_size != component.trace_log_size or entry.row_count != padded_rows)
            return error.FixedTableGeometryMismatch;
        return .{ .writer = .fixed_table, .real_rows = entry.row_count };
    }
    if (std.mem.eql(u8, component.label, "memory_address_to_id")) return .{
        .writer = .memory_trace,
        .real_rows = try exactRows(try memory_tables.addressRowCount(input), padded_rows),
    };
    if (std.mem.eql(u8, component.label, "memory_id_to_big")) return .{
        .writer = .memory_trace,
        .real_rows = try exactRows(
            try memory_tables.bigRowCount(input, component.instance),
            padded_rows,
        ),
    };
    if (std.mem.eql(u8, component.label, "memory_id_to_small")) return .{
        .writer = .memory_trace,
        .real_rows = try exactRows(try memory_tables.smallRowCount(input), padded_rows),
    };
    if (std.mem.eql(u8, component.label, "ec_op_builtin")) return .{
        .writer = .native_backend,
        .real_rows = try builtinRows(input.builtin_segments.ec_op_builtin, 7, padded_rows),
    };
    return error.MissingComponentWriter;
}

fn directRealRows(
    input: *const adapter.ProverInput,
    component: []const u8,
    padded_rows: u32,
) ?u32 {
    if (std.meta.stringToEnum(opcodes.OpcodeTag, component)) |tag|
        return checkedRows(
            input.state_transitions.casm_states_by_opcode.getConst(tag).len,
            padded_rows,
        );
    const Builtin = struct {
        name: []const u8,
        segment: ?adapter.MemorySegmentAddresses,
        cells: usize,
    };
    const builtins = [_]Builtin{
        .{ .name = "bitwise_builtin", .segment = input.builtin_segments.bitwise_builtin, .cells = 5 },
        .{ .name = "range_check_builtin", .segment = input.builtin_segments.range_check_builtin, .cells = 1 },
        .{ .name = "pedersen_builtin", .segment = input.builtin_segments.pedersen_builtin, .cells = 3 },
        .{ .name = "poseidon_builtin", .segment = input.builtin_segments.poseidon_builtin, .cells = 6 },
    };
    for (builtins) |builtin| {
        if (!std.mem.eql(u8, component, builtin.name)) continue;
        return segmentRows(builtin.segment, builtin.cells, padded_rows);
    }
    if (std.mem.eql(u8, component, "partial_ec_mul_generic")) return padded_rows;
    return null;
}

fn builtinRows(
    segment: ?adapter.MemorySegmentAddresses,
    cells: usize,
    padded_rows: u32,
) !u32 {
    return segmentRows(segment, cells, padded_rows) orelse
        return error.InvalidBuiltinGeometry;
}

fn segmentRows(
    optional: ?adapter.MemorySegmentAddresses,
    cells: usize,
    padded_rows: u32,
) ?u32 {
    const segment = optional orelse return null;
    if (segment.stop_ptr <= segment.begin_addr) return null;
    const length = segment.stop_ptr - segment.begin_addr;
    if (length % cells != 0) return null;
    return checkedRows(length / cells, padded_rows);
}

fn checkedRows(rows: usize, padded_rows: u32) ?u32 {
    if (rows == 0 or rows > padded_rows or rows > std.math.maxInt(u32)) return null;
    return @intCast(rows);
}

fn exactRows(rows: usize, padded_rows: u32) !u32 {
    const exact = checkedRows(rows, padded_rows) orelse return error.InvalidWriterGeometry;
    if (exact != padded_rows) return error.WriterGeometryMismatch;
    return exact;
}

fn countComponents(bundle: composition_bundle.Bundle, label: []const u8) usize {
    var count: usize = 0;
    for (bundle.components) |component| if (std.mem.eql(u8, component.label, label)) {
        count += 1;
    };
    return count;
}

fn preprocessedVariant(
    fixed_tables: fixed_table_bundle.Bundle,
) !claim_generator.PreprocessedVariant {
    return switch (fixed_tables.preprocessed_identities.len) {
        161 => .canonical,
        105 => .canonical_without_pedersen,
        156 => .canonical_small,
        else => error.UnsupportedPreprocessedVariant,
    };
}

test "semantic authority derives every canonical preprocessed domain exactly" {
    const allocator = std.testing.allocator;
    var fixed_tables = try fixed_table_bundle.Bundle.readFile(
        allocator,
        "vectors/cairo/cairo_fixed_tables.bin",
    );
    defer fixed_tables.deinit();
    const logs = try preprocessedLogs(allocator, fixed_tables);
    defer allocator.free(logs);
    try std.testing.expectEqual(fixed_tables.preprocessed_identities.len, logs.len);
    try std.testing.expectEqual(
        @as(u32, 25),
        logs[fixed_tables.identityOrdinal("seq_25").?],
    );
    try std.testing.expectEqual(
        @as(u32, 20),
        logs[fixed_tables.identityOrdinal("bitwise_xor_10_0").?],
    );
}
