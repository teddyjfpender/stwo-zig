//! Ordered shadow import of one complete production opcode-family program.
//!
//! This layer consumes the exact `constraint_program.Builder(symbolic.Scalar)`
//! result. It adds ordered direct constraints to the typed arena and retains a
//! compatibility record for every lookup numerator and tuple field. Lookup
//! values remain field-polynomial values here: production symbolic extraction
//! carries no semantic field types, so full typed-effect validation belongs to
//! later authoring/lowering work rather than being guessed at this boundary.

const std = @import("std");
const constraint_program = @import("../constraint_program.zig");
const production_entry = @import("../lookups/entry.zig");
const model = @import("../extract/model.zig");
const symbolic = @import("../extract/symbolic.zig");
const trace = @import("../../runner/trace.zig");
const program = @import("program.zig");
const relation = @import("relation.zig");
const shadow_import = @import("shadow_import.zig");
const source_mod = @import("source.zig");
const types = @import("types.zig");
const validate_mod = @import("validate.zig");

const Builder = constraint_program.Builder(symbolic.Scalar);

pub const ValidationError = validate_mod.Error || relation.Error || shadow_import.ImportError || error{
    InvalidActiveRow,
    InvalidBatchSize,
    InvalidColumnLayout,
    InvalidConstraintCount,
    InvalidConstraintMap,
    InvalidConstraintMetadata,
    InvalidLookupCount,
    InvalidLookupRange,
    InvalidLookupValue,
    InvalidNumerator,
    InvalidSelector,
    InvalidSourceSpan,
};

pub const ImportError = error{
    ConstraintNameTooLong,
    InvalidLookupArity,
    InvalidLookupValueCount,
    InvalidMainColumnCount,
    InvalidSourceReference,
    InvalidSourceSelector,
};

pub const Error = shadow_import.Error ||
    ValidationError ||
    ImportError ||
    program.RangeError;

/// Exact pre-lowering lookup metadata. `numerator` retains the shipped signed
/// polynomial; `role` is construction metadata and is not applied a second
/// time. Later typed-effect lowering may normalize that representation only
/// under an exact compatibility test.
pub const Lookup = struct {
    schema: types.RelationSchemaId,
    role: relation.Role,
    numerator: types.ValueId,
    source_numerator: u32,
    fields: program.RefRange,
    source_fields: program.RefRange,
    access_ordinal: ?u8,
    source_span: source_mod.SourceSpan,
};

pub const ImportedProgram = struct {
    allocator: std.mem.Allocator,
    family: trace.OpcodeFamily,
    imported: shadow_import.Imported,
    main_column_count: usize,
    selector: types.ValueId,
    source_selector: u32,
    active_row: types.ValueId,
    source_active_row: u32,
    direct_constraints: []types.ConstraintId,
    direct_source_roots: []u32,
    lookups: []Lookup,
    lookup_values: []types.ValueId,
    source_lookup_values: []u32,
    batch_size: u8,

    pub fn deinit(self: *ImportedProgram) void {
        self.allocator.free(self.source_lookup_values);
        self.allocator.free(self.lookup_values);
        self.allocator.free(self.lookups);
        self.allocator.free(self.direct_source_roots);
        self.allocator.free(self.direct_constraints);
        self.imported.deinit();
        self.* = undefined;
    }

    pub fn mainColumns(self: *const ImportedProgram) []const types.ValueId {
        return self.imported.columns[0..self.main_column_count];
    }

    pub fn lookupFields(
        self: *const ImportedProgram,
        index: usize,
    ) ?[]const types.ValueId {
        if (index >= self.lookups.len) return null;
        return self.lookups[index].fields.slice(self.lookup_values);
    }

    pub fn sourceLookupFields(
        self: *const ImportedProgram,
        index: usize,
    ) ?[]const u32 {
        if (index >= self.lookups.len) return null;
        const range = self.lookups[index].source_fields;
        const start: usize = range.start;
        const len: usize = range.len;
        const end = std.math.add(usize, start, len) catch return null;
        if (end > self.source_lookup_values.len) return null;
        return self.source_lookup_values[start..end];
    }

    pub fn batchCount(self: *const ImportedProgram) usize {
        if (self.batch_size == 0) return 0;
        return (self.lookups.len + self.batch_size - 1) / self.batch_size;
    }

    /// Rechecks the complete owned compatibility record without relying on
    /// constructor success. Relation field *types* are intentionally not
    /// claimed at this shadow boundary; shape, role, ordinal, values, and order
    /// are all checked.
    pub fn validate(self: *const ImportedProgram) ValidationError!void {
        try self.imported.validateSourceCopy();
        try validate_mod.validate(&self.imported.arena);
        if (self.main_column_count != Builder.mainColumnCount(self.family) or
            self.imported.columns.len != self.main_column_count + 1)
        {
            return error.InvalidColumnLayout;
        }
        if (self.selector != self.imported.columns[self.main_column_count])
            return error.InvalidSelector;
        if (self.source_selector >= self.imported.source_nodes.len or
            self.imported.valueForSourceNode(self.source_selector) != self.selector)
        {
            return error.InvalidSelector;
        }
        const selector_node = self.imported.arena.node(self.selector) orelse
            return error.InvalidSelector;
        const selector_name = switch (selector_node.key.op) {
            .input => |name| self.imported.arena.name(name) orelse
                return error.InvalidSelector,
            else => return error.InvalidSelector,
        };
        if (!selector_node.key.ty.isFieldScalar() or
            !std.mem.eql(u8, selector_name, "is_active"))
        {
            return error.InvalidSelector;
        }

        const active_node = self.imported.arena.node(self.active_row) orelse
            return error.InvalidActiveRow;
        if (!active_node.key.ty.isFieldScalar()) return error.InvalidActiveRow;
        if (self.source_active_row >= self.imported.source_nodes.len or
            self.imported.valueForSourceNode(self.source_active_row) != self.active_row)
        {
            return error.InvalidActiveRow;
        }

        if (self.direct_constraints.len != Builder.constraintCount(self.family) or
            self.imported.arena.constraintsView().len != self.direct_constraints.len or
            self.direct_source_roots.len != self.direct_constraints.len)
        {
            return error.InvalidConstraintCount;
        }
        for (self.direct_constraints, 0..) |constraint_id, index| {
            if (types.idIndex(constraint_id) != index)
                return error.InvalidConstraintMap;
            const constraint = self.imported.arena.constraint(constraint_id) orelse
                return error.InvalidConstraintMap;
            const source_root = self.direct_source_roots[index];
            if (source_root >= self.imported.source_nodes.len or
                self.imported.valueForSourceNode(source_root) != constraint.root)
            {
                return error.InvalidConstraintMap;
            }
            if (constraint.gate != null or constraint.category != .semantic)
                return error.InvalidConstraintMetadata;
            var name_buffer: [96]u8 = undefined;
            const expected_name = constraintName(
                &name_buffer,
                self.family,
                index,
            ) catch return error.InvalidConstraintMetadata;
            const actual_name = self.imported.arena.name(constraint.name) orelse
                return error.InvalidConstraintMetadata;
            if (!std.mem.eql(u8, expected_name, actual_name))
                return error.InvalidConstraintMetadata;
        }

        if (self.lookups.len != constraint_program.entryCount(self.family))
            return error.InvalidLookupCount;
        const expected_batch_size = constraint_program.batchSize(self.family);
        if (self.batch_size == 0 or self.batch_size != expected_batch_size)
            return error.InvalidBatchSize;

        var value_cursor: usize = 0;
        var source_value_cursor: usize = 0;
        for (self.lookups, 0..) |lookup, lookup_index| {
            if (lookup.fields.start != value_cursor)
                return error.InvalidLookupRange;
            const fields = lookup.fields.slice(self.lookup_values) orelse
                return error.InvalidLookupRange;
            value_cursor = std.math.add(usize, value_cursor, fields.len) catch
                return error.InvalidLookupRange;
            if (lookup.source_fields.start != source_value_cursor)
                return error.InvalidLookupRange;
            const source_fields = self.sourceLookupFields(lookup_index) orelse
                return error.InvalidLookupRange;
            source_value_cursor = std.math.add(
                usize,
                source_value_cursor,
                source_fields.len,
            ) catch return error.InvalidLookupRange;
            if (source_fields.len != fields.len) {
                return error.InvalidLookupValue;
            }
            _ = relation.validateEventShape(
                lookup.schema,
                lookup.role,
                fields.len,
                lookup.access_ordinal,
            ) catch |err| return err;
            const numerator = self.imported.arena.node(lookup.numerator) orelse
                return error.InvalidNumerator;
            if (!numerator.key.ty.isFieldScalar())
                return error.InvalidNumerator;
            if (lookup.source_numerator >= self.imported.source_nodes.len or
                self.imported.valueForSourceNode(lookup.source_numerator) !=
                    lookup.numerator)
            {
                return error.InvalidLookupValue;
            }
            for (fields, source_fields) |field, source_field| {
                const node = self.imported.arena.node(field) orelse
                    return error.InvalidLookupValue;
                if (!node.key.ty.isFieldScalar())
                    return error.InvalidLookupValue;
                if (source_field >= self.imported.source_nodes.len or
                    self.imported.valueForSourceNode(source_field) != field)
                {
                    return error.InvalidLookupValue;
                }
            }
            self.imported.arena.validateSpan(lookup.source_span) catch
                return error.InvalidSourceSpan;
        }
        if (value_cursor != self.lookup_values.len)
            return error.InvalidLookupRange;
        if (source_value_cursor != self.source_lookup_values.len)
            return error.InvalidLookupRange;
    }
};

/// Builds and imports the exact complete production program for one family.
/// The returned object owns no reference to the temporary symbolic arena.
pub fn buildProduction(
    allocator: std.mem.Allocator,
    family: trace.OpcodeFamily,
    span: source_mod.SourceSpan,
) !ImportedProgram {
    var source_arena = symbolic.Arena.init(allocator);
    defer source_arena.deinit();
    symbolic.begin(&source_arena);
    defer symbolic.end();

    const main_column_count = Builder.mainColumnCount(family);
    var columns: [trace.MAX_FAMILY_COLUMNS]symbolic.Scalar = undefined;
    try model.declareColumns(
        &source_arena,
        family,
        columns[0..main_column_count],
    );
    const selector = source_arena.column("is_active");
    const source_program = try Builder.build(
        family,
        columns[0..main_column_count],
        selector,
    );
    return importBuilt(
        allocator,
        family,
        &source_arena,
        main_column_count,
        selector,
        &source_program,
        span,
    );
}

/// Imports an already-built production program. This seam lets compatibility
/// tests compare the source records and typed records from the same arena,
/// avoiding a second build whose determinism would otherwise be an assumption.
pub fn importBuilt(
    allocator: std.mem.Allocator,
    family: trace.OpcodeFamily,
    source_arena: *const symbolic.Arena,
    main_column_count: usize,
    source_selector: symbolic.Scalar,
    source_program: *const Builder.ConstraintProgram,
    span: source_mod.SourceSpan,
) Error!ImportedProgram {
    if (main_column_count != Builder.mainColumnCount(family))
        return error.InvalidMainColumnCount;
    const expected_columns = std.math.add(usize, main_column_count, 1) catch
        return error.InvalidMainColumnCount;
    if (source_arena.names.items.len != expected_columns)
        return error.InvalidMainColumnCount;
    const selector_index: usize = source_selector.id;
    if (selector_index >= source_arena.nodes.items.len)
        return error.InvalidSourceReference;
    const selector_node = source_arena.nodes.items[selector_index];
    if (selector_node.op != .column or
        selector_node.value != main_column_count or
        !std.mem.eql(u8, source_arena.names.items[main_column_count], "is_active"))
    {
        return error.InvalidSourceSelector;
    }
    if (source_program.direct_constraints.len >
        source_program.direct_constraints.values.len)
    {
        return error.InvalidConstraintCount;
    }
    if (source_program.lookup_entries.len >
        source_program.lookup_entries.entries.len)
    {
        return error.InvalidLookupCount;
    }
    if (source_program.lookup_entries.batch_size == 0 or
        source_program.lookup_entries.batch_size > std.math.maxInt(u8))
    {
        return error.InvalidBatchSize;
    }

    var imported = try shadow_import.import(allocator, source_arena, span);
    errdefer imported.deinit();
    const direct_constraints = try allocator.alloc(
        types.ConstraintId,
        source_program.direct_constraints.len,
    );
    errdefer allocator.free(direct_constraints);
    const direct_source_roots = try allocator.alloc(
        u32,
        source_program.direct_constraints.len,
    );
    errdefer allocator.free(direct_source_roots);
    for (
        source_program.direct_constraints.values[0..source_program.direct_constraints.len],
        direct_constraints,
        direct_source_roots,
        0..,
    ) |source_root, *destination, *source_destination, index| {
        const root = try mapSourceValue(&imported, source_root.id);
        var name_buffer: [96]u8 = undefined;
        const name = constraintName(&name_buffer, family, index) catch
            return error.ConstraintNameTooLong;
        destination.* = try imported.arena.assertZero(
            name,
            root,
            null,
            .semantic,
            span,
        );
        source_destination.* = source_root.id;
    }

    var lookup_value_count: usize = 0;
    for (source_program.lookup_entries.entries[0..source_program.lookup_entries.len]) |lookup| {
        if (lookup.arity > production_entry.MAX_ARITY)
            return error.InvalidLookupArity;
        lookup_value_count = std.math.add(
            usize,
            lookup_value_count,
            lookup.arity,
        ) catch return error.InvalidLookupValueCount;
    }
    const lookups = try allocator.alloc(Lookup, source_program.lookup_entries.len);
    errdefer allocator.free(lookups);
    const lookup_values = try allocator.alloc(types.ValueId, lookup_value_count);
    errdefer allocator.free(lookup_values);
    const source_lookup_values = try allocator.alloc(u32, lookup_value_count);
    errdefer allocator.free(source_lookup_values);

    var value_cursor: usize = 0;
    for (
        source_program.lookup_entries.entries[0..source_program.lookup_entries.len],
        lookups,
    ) |source_lookup, *destination| {
        const domain = relationDomain(source_lookup.domain);
        const role = relationRole(source_lookup.role);
        _ = try relation.validateEventShape(
            relation.id(domain),
            role,
            source_lookup.arity,
            source_lookup.access_ordinal,
        );
        const value_range = try program.RefRange.init(
            value_cursor,
            source_lookup.arity,
        );
        const source_value_range = try program.RefRange.init(
            value_cursor,
            source_lookup.arity,
        );
        destination.* = .{
            .schema = relation.id(domain),
            .role = role,
            .numerator = try mapSourceValue(&imported, source_lookup.numerator.id),
            .source_numerator = source_lookup.numerator.id,
            .fields = value_range,
            .source_fields = source_value_range,
            .access_ordinal = source_lookup.access_ordinal,
            .source_span = span,
        };
        for (source_lookup.values[0..source_lookup.arity]) |source_value| {
            lookup_values[value_cursor] = try mapSourceValue(
                &imported,
                source_value.id,
            );
            source_lookup_values[value_cursor] = source_value.id;
            value_cursor += 1;
        }
    }
    std.debug.assert(value_cursor == lookup_values.len);

    const result = ImportedProgram{
        .allocator = allocator,
        .family = family,
        .imported = imported,
        .main_column_count = main_column_count,
        .selector = try mapSourceValue(&imported, source_selector.id),
        .source_selector = source_selector.id,
        .active_row = try mapSourceValue(&imported, source_program.active_row.id),
        .source_active_row = source_program.active_row.id,
        .direct_constraints = direct_constraints,
        .direct_source_roots = direct_source_roots,
        .lookups = lookups,
        .lookup_values = lookup_values,
        .source_lookup_values = source_lookup_values,
        .batch_size = @intCast(source_program.lookup_entries.batch_size),
    };
    try result.validate();
    return result;
}

fn mapSourceValue(
    imported: *const shadow_import.Imported,
    source_id: u32,
) ImportError!types.ValueId {
    return imported.valueForSourceNode(source_id) orelse
        error.InvalidSourceReference;
}

fn constraintName(
    buffer: *[96]u8,
    family: trace.OpcodeFamily,
    index: usize,
) error{ConstraintNameTooLong}![]const u8 {
    return std.fmt.bufPrint(
        buffer,
        "compat.riscv.{s}.direct.{d}",
        .{ @tagName(family), index },
    ) catch error.ConstraintNameTooLong;
}

fn relationDomain(domain: production_entry.Domain) relation.Domain {
    return switch (domain) {
        .registers_state => .registers_state,
        .memory_access => .memory_access,
        .program_access => .program_access,
        .merkle => .merkle,
        .poseidon2 => .poseidon2,
        .poseidon2_io => .poseidon2_io,
        .bitwise => .bitwise,
        .range_check_20 => .range_check_20,
        .range_check_8_11 => .range_check_8_11,
        .range_check_8_8_4 => .range_check_8_8_4,
        .range_check_8_8 => .range_check_8_8,
        .range_check_m31 => .range_check_m31,
    };
}

fn relationRole(role: production_entry.EventRole) relation.Role {
    return switch (role) {
        .request => .request,
        .consume => .consume,
        .emit => .emit,
    };
}
