//! Diagnostic only: no proof or admission receipt. Bounds are conservative;
//! exceeding a declaration identifies a candidate, not a proven degree error.
const std = @import("std");
const core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");
const manifest_mod = @import("recursive_common_ethereum_incremental_leaf_universal_manifest_v4.zig");
const air = frontend.recursion.air;
const M31 = core.fields.m31.M31;
const Catalog = manifest_mod.StatementRootProfile.StatementRoutingOuterCatalog;

const Value = struct {
    degree: u32,
    constant: ?M31 = null,

    fn fixed(value: M31) Value {
        return .{ .degree = 0, .constant = value };
    }
    fn add(a: Value, b: Value) Value {
        if (a.constant) |x| if (b.constant) |y| return fixed(x.add(y));
        return .{ .degree = @max(a.degree, b.degree) };
    }
    fn neg(a: Value) Value {
        if (a.constant) |x| return fixed(x.neg());
        return a;
    }
    fn mul(a: Value, b: Value) Value {
        if (a.constant) |x| if (x.isZero()) return a;
        if (b.constant) |x| if (x.isZero()) return b;
        if (a.constant) |x| if (b.constant) |y| return fixed(x.mul(y));
        return .{ .degree = a.degree + b.degree };
    }
};

fn evaluate(op: anytype, slots: []const Value) Value {
    return switch (op) {
        .constant => |v| Value.fixed(M31.fromCanonical(v)),
        .add => |v| slots[v.lhs].add(slots[v.rhs]),
        .sub => |v| if (v.lhs == v.rhs) Value.fixed(M31.zero()) else slots[v.lhs].add(slots[v.rhs].neg()),
        .mul => |v| slots[v.lhs].mul(slots[v.rhs]),
        .neg => |v| slots[v].neg(),
        .select => |v| if (v.when_true == v.when_false) slots[v.when_true] else slots[v.when_false].add(slots[v.selector].mul(slots[v.when_true].add(slots[v.when_false].neg()))),
    };
}

pub const Degrees = struct { direct: u32 = 0, logup: u32 = 0 };

/// Physical main and preprocessing inputs are polynomials. The trailing
/// adapter parameters are degree-zero constants, even if their values vary
/// between different component instances. null keeps their values unknown.
pub fn degrees(comptime Air: type, direct: anytype, plan: anytype, parameters: ?[]const M31) Degrees {
    const physical = Air.PHYSICAL_MAIN_COLUMN_COUNT + Air.PREPROCESSED_COLUMN_COUNT;
    const capacity = @max(air.direct_constraint_program.MAX_NODES, air.relation_interaction.MAX_COMPILED_NODES + Air.LOGICAL_INPUT_COUNT);
    var slots: [capacity]Value = undefined;
    for (0..Air.LOGICAL_INPUT_COUNT) |i| slots[i] = if (i < physical)
        .{ .degree = 1 }
    else if (parameters) |values|
        Value.fixed(values[i - physical])
    else
        .{ .degree = 0 };
    for (direct.nodes[0..direct.compiled_node_count]) |node| slots[node.destination] = evaluate(node.op, &slots);
    var result = Degrees{};
    for (direct.constraints[0..direct.constraint_count]) |constraint| {
        var root = slots[constraint.root];
        if (constraint.gate != std.math.maxInt(u16)) root = root.mul(slots[constraint.gate]);
        result.direct = @max(result.direct, root.degree);
    }
    // Both programs start with the same input slots, but assign different
    // subsequent slots; evaluate the relation compiler independently.
    for (plan.compiled_nodes[0..plan.compiled_node_count]) |node| slots[node.destination] = evaluate(node.op, &slots);
    for (plan.batches) |batch| {
        const first = plan.events[batch.first];
        var d1: u32 = 0;
        for (first.value_slots[0..first.arity]) |slot| d1 = @max(d1, slots[slot].degree);
        const n1 = slots[first.numerator_slot].degree;
        var d2: u32 = 0;
        var n2: u32 = 0;
        if (batch.second) |index| {
            const second = plan.events[index];
            for (second.value_slots[0..second.arity]) |slot| d2 = @max(d2, slots[slot].degree);
            n2 = slots[second.numerator_slot].degree;
        }
        // (current - previous - previous_column + shift) * d1 * d2
        // - n1*d2 - n2*d1. Interaction columns have degree one.
        result.logup = @max(result.logup, @max(1 + d1 + d2, @max(n1 + d2, n2 + d1)));
    }
    return result;
}

fn report(comptime Air: type, name: []const u8, result: Degrees) void {
    const declared = air.universal_typed_component.protocolMaximumConstraintDegree(Air);
    std.debug.print("ETHEREUM_AIR_DEGREE component={s} direct_bound={d} logup_bound={d} declared={d} candidate={} conservative=true\n", .{ name, result.direct, result.logup, declared, @max(result.direct, result.logup) > declared });
}

pub fn checkParameters(comptime Air: type, rows: []const [Air.LOGICAL_INPUT_COUNT]M31, parameters: []const M31) !void {
    const offset = Air.PHYSICAL_MAIN_COLUMN_COUNT + Air.PREPROCESSED_COLUMN_COUNT;
    if (parameters.len != Air.LOGICAL_INPUT_COUNT - offset) return error.InvalidParameterGeometry;
    for (rows, 0..) |row, row_index| for (parameters, 0..) |expected, parameter_index| {
        const actual = row[offset + parameter_index];
        if (!actual.eql(expected)) {
            std.debug.print("ETHEREUM_AIR_PARAMETER row={d} parameter={d} expected={d} actual={d}\n", .{ row_index, parameter_index, expected.toU32(), actual.toU32() });
            return error.NonuniformTypedAirParameter;
        }
    };
}

// Writers zero-pad physical columns, while the adapter still injects its
// fixed parameters. Framework generation assumes every padded numerator is
// zero without evaluating the AIR. Check that assumption explicitly.
fn checkPadding(comptime Air: type, direct: anytype, plan: anytype, parameters: []const M31) !void {
    const offset = Air.PHYSICAL_MAIN_COLUMN_COUNT + Air.PREPROCESSED_COLUMN_COUNT;
    var row = [_]M31{M31.zero()} ** Air.LOGICAL_INPUT_COUNT;
    @memcpy(row[offset..], parameters);
    var scratch: [air.direct_constraint_program.MAX_NODES]M31 = undefined;
    var roots: [Air.DIRECT_CONSTRAINT_COUNT]M31 = undefined;
    try direct.evaluateBaseInto(&row, &scratch, &roots);
    for (roots, 0..) |root, index| if (!root.isZero()) {
        std.debug.print("ETHEREUM_AIR_PADDING direct_constraint={d} value={d}\n", .{ index, root.toU32() });
        return error.InvalidTypedAirPaddingConstraint;
    };
    var slots: [air.relation_interaction.MAX_COMPILED_NODES + Air.LOGICAL_INPUT_COUNT]Value = undefined;
    for (row, 0..) |value, index| slots[index] = Value.fixed(value);
    for (plan.compiled_nodes[0..plan.compiled_node_count]) |node| slots[node.destination] = evaluate(node.op, &slots);
    for (plan.events, 0..) |event, index| if (!slots[event.numerator_slot].constant.?.isZero()) {
        std.debug.print("ETHEREUM_AIR_PADDING relation_event={d} numerator={d}\n", .{ index, slots[event.numerator_slot].constant.?.toU32() });
        return error.InvalidTypedAirPaddingNumerator;
    };
}

/// Streams the existing native physical traces, with the parameter values
/// selected by the same helpers used by the production adapter initializer.
pub const NativeObserver = struct {
    pub fn logical(_: NativeObserver, comptime Air: type, rows: []const [Air.LOGICAL_INPUT_COUNT]M31, parameters: []const M31) !void {
        try checkParameters(Air, rows, parameters);
    }

    pub fn check(_: NativeObserver, comptime Air: type, comptime roster_row: usize, placement: anytype, pp: anytype, main: anytype, parameters: []const M31, definition: *const Air.Definition, relation: anytype, logical_rows: usize) !void {
        const direct = try air.direct_constraint_program.authenticate(&definition.arena, Air.SEMANTIC_DIGEST, Air.LOGICAL_INPUT_COUNT);
        const row_count = @as(usize, 1) << @intCast(placement.geometry.log_size);
        if (logical_rows > row_count) return error.InvalidNativeDiagnosticGeometry;
        for (pp) |column| if (column.values.len != row_count) return error.InvalidNativeDiagnosticGeometry;
        for (main) |column| if (column.values.len != row_count) return error.InvalidNativeDiagnosticGeometry;
        var scratch: [air.direct_constraint_program.MAX_NODES]M31 = undefined;
        var roots: [Air.DIRECT_CONSTRAINT_COUNT]M31 = undefined;
        var row: [Air.LOGICAL_INPUT_COUNT]M31 = undefined;
        const physical = Air.PHYSICAL_MAIN_COLUMN_COUNT + Air.PREPROCESSED_COLUMN_COUNT;
        if (parameters.len != Air.LOGICAL_INPUT_COUNT - physical) return error.InvalidParameterGeometry;
        @memcpy(row[physical..], parameters);
        std.debug.print("ETHEREUM_NATIVE_AIR_PREFLIGHT component={d} committed_rows={d} logical_rows={d} begin=true\n", .{ roster_row, row_count, logical_rows });
        for (0..row_count) |committed_row| {
            for (main, row[0..Air.PHYSICAL_MAIN_COLUMN_COUNT]) |column, *value| value.* = column.values[committed_row];
            for (pp, row[Air.PHYSICAL_MAIN_COLUMN_COUNT..physical]) |column, *value| value.* = column.values[committed_row];
            try direct.evaluateBaseInto(&row, &scratch, &roots);
            for (roots, 0..) |root, constraint| if (!root.isZero()) {
                std.debug.print("ETHEREUM_NATIVE_AIR_CONSTRAINT component={d} committed_row={d} constraint={d} value={d}\n", .{ roster_row, committed_row, constraint, root.toU32() });
                return error.NativeTypedAirConstraintViolation;
            };
        }
        if (logical_rows < row_count) try checkPadding(Air, &direct, relation, parameters);
        report(Air, @tagName(Catalog.LOGICAL_ROWS[roster_row].row), degrees(Air, &direct, relation, parameters));
        std.debug.print("ETHEREUM_NATIVE_AIR_PREFLIGHT component={d} direct_roots=true padding=true\n", .{roster_row});
    }
};

const PreparedObserver = struct {
    pub fn check(_: PreparedObserver, comptime Air: type, comptime name: []const u8, rows: []const [Air.LOGICAL_INPUT_COUNT]M31, parameters: []const M31, direct: anytype, relation: anytype) !void {
        try checkParameters(Air, rows, parameters);
        try checkPadding(Air, direct, relation, parameters);
        report(Air, name, degrees(Air, direct, relation, parameters));
    }
};

const WireDimensions = frontend.recursion.fixed_wire.Dimensions;

fn reportWireDimensions(materialized: anytype, manifest: *const manifest_mod.Manifest) !WireDimensions {
    const dimensions = try @import("ethereum_wrapper_child_shape_v1.zig").dimensionsForManifest(manifest);
    std.debug.print("ETHEREUM_WRAPPER_WIRE_DIMENSIONS global_segment={d} dimensions={any} proof_verified=false\n", .{ materialized.base.input.coordinate.index, dimensions });
    return dimensions;
}

pub fn requireMatchingWireDimensions(expected: WireDimensions, actual: WireDimensions) !void {
    if (!std.meta.eql(expected, actual)) return error.EthereumWrapperWireGeometryMismatch;
}

/// Checks a candidate against independently admitted child geometry without
/// additional AIR row scans, a tuple ledger, or PCS storage. The shared geometry
/// owner still allocates its authenticated plan and witness backing.
pub fn geometryOnly(comptime Engine: type, allocator: std.mem.Allocator, materialized: anytype, expected: WireDimensions) !void {
    const Geometry = @import("recursive_common_ethereum_incremental_leaf_universal_geometry_authority_v4.zig").OwnerV4(Engine);
    var geometry = try Geometry.init(allocator, materialized);
    defer geometry.deinit();
    const actual = try reportWireDimensions(materialized, try geometry.manifest());
    try requireMatchingWireDimensions(expected, actual);
    std.debug.print("ETHEREUM_WRAPPER_GEOMETRY_COMPATIBILITY global_segment={d} compatible=true row_audit=false ledger=false pcs=false proof_verified=false\n", .{materialized.base.input.coordinate.index});
}

/// Reconstructs only geometry and the prefix/suffix row owners. Constructors
/// check their direct roots; this scan additionally compares every omitted
/// parameter tail with the exact constants selected by their typed adapter.
/// No global tuple ledger, source commitments, or PCS are allocated here.
pub fn audit(comptime Engine: type, allocator: std.mem.Allocator, materialized: anytype) !void {
    const Geometry = @import("recursive_common_ethereum_incremental_leaf_universal_geometry_authority_v4.zig").OwnerV4(Engine);
    const Prefix = @import("recursive_common_ethereum_incremental_leaf_transcript_cohort_v4.zig").PreparedV4(Engine);
    const Suffix = @import("recursive_common_ethereum_incremental_leaf_suffix_cohort_v4.zig").PreparedV4(Engine);
    var geometry = try Geometry.init(allocator, materialized);
    defer geometry.deinit();
    const manifest = try geometry.manifest();
    _ = try reportWireDimensions(materialized, manifest);
    var prefix = try Prefix.init(allocator, try geometry.transcriptRows(), manifest);
    defer prefix.deinit();
    var suffix = try Suffix.init(allocator, try geometry.rows10Through34(), manifest);
    defer suffix.deinit();
    try prefix.auditTypedAirRows(PreparedObserver{});
    try suffix.auditTypedAirRows(PreparedObserver{});
    const native = try (try geometry.rows10Through34()).nativeCore();
    try native.auditTypedAirRows(NativeObserver{});
    std.debug.print("ETHEREUM_AIR_PREFLIGHT checked_components=34 direct_roots=true adapter_parameters=true padding=true provider_rows_checked=false wrapper_verified=false\n", .{});
}

test "Ethereum typed AIR compiled degree inventory" {
    inline for (Catalog.LOGICAL_ROWS) |entry| {
        var definition = if (entry.requires_location) try entry.Air.build(std.testing.allocator, .generated) else try entry.Air.build(std.testing.allocator);
        defer definition.deinit();
        const direct = try air.direct_constraint_program.authenticate(&definition.arena, entry.Air.SEMANTIC_DIGEST, entry.Air.LOGICAL_INPUT_COUNT);
        const relation = try air.universal_relation_binding.Binding(entry.Air).authenticate(&definition);
        report(entry.Air, @tagName(entry.row), degrees(entry.Air, &direct, &relation, null));
    }
}

test "Ethereum typed AIR preflight rejects dropped parameter changes" {
    const Tiny = struct {
        pub const PHYSICAL_MAIN_COLUMN_COUNT = 1;
        pub const PREPROCESSED_COLUMN_COUNT = 1;
        pub const LOGICAL_INPUT_COUNT = 3;
    };
    var rows = [_][3]M31{.{ M31.zero(), M31.zero(), M31.one() }} ** 2;
    try checkParameters(Tiny, &rows, &.{M31.one()});
    rows[1][2] = M31.zero();
    try std.testing.expectError(error.NonuniformTypedAirParameter, checkParameters(Tiny, &rows, &.{M31.one()}));
}
