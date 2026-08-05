//! Role-normalized `compat-v1` lowering of ordered production lookups.
//!
//! The production shadow retains already-signed numerators. This pass exposes
//! their unsigned liveness polynomial separately and binds the cached signed
//! root back to the event role: request/consume are negative; emit is positive.
//! Tuple fields, access ordinals, event order, batch boundaries, and physical
//! interaction-column positions are preserved exactly. Semantic field types
//! remain intentionally unclaimed at this erased compatibility boundary.

const std = @import("std");
const qm31 = @import("stwo_core").fields.qm31;
const constraint_program = @import("../constraint_program.zig");
const production_entry = @import("../lookups/entry.zig");
const trace = @import("../../runner/trace.zig");
const compat_layout = @import("compat_layout.zig");
const lower_constraint = @import("lower_constraint.zig");
const relation = @import("relation.zig");
const shadow_program = @import("shadow_program.zig");
const types = @import("types.zig");

const no_node = std.math.maxInt(u32);

pub const ValidationError = lower_constraint.ValidationError || relation.Error || error{
    InvalidBatchLayout,
    InvalidColumnCount,
    InvalidEventCount,
    InvalidEventRoot,
    InvalidFamily,
    InvalidNumeratorSign,
    InvalidRootOrder,
    InvalidValueTail,
};

pub const LowerError = lower_constraint.LowerError || ValidationError;

pub const Event = struct {
    schema: types.RelationSchemaId,
    role: relation.Role,
    /// Unsigned multiplicity polynomial. Its semantic Boolean/range evidence
    /// is established only when an authored typed effect replaces the shadow.
    liveness: u32,
    /// Cached production numerator, structurally bound to `role` and
    /// `liveness` by `Program.validate`.
    numerator: u32,
    values: [production_entry.MAX_ARITY]u32 =
        .{no_node} ** production_entry.MAX_ARITY,
    arity: u8,
    access_ordinal: ?u8,

    pub fn valueSlice(self: *const Event) ?[]const u32 {
        if (self.arity > self.values.len) return null;
        return self.values[0..self.arity];
    }
};

pub const Batch = struct {
    first_event: u32,
    event_count: u8,
    interaction_columns: [qm31.SECURE_EXTENSION_DEGREE]compat_layout.ColumnRef,
};

pub const Program = struct {
    allocator: std.mem.Allocator,
    family: trace.OpcodeFamily,
    polynomials: lower_constraint.Program,
    events: []Event,
    batches: []Batch,
    batch_size: u8,

    pub fn deinit(self: *Program) void {
        self.allocator.free(self.batches);
        self.allocator.free(self.events);
        self.polynomials.deinit();
        self.* = undefined;
    }

    /// Allocation-free validation of the complete normalized relation view.
    pub fn validate(self: *const Program) ValidationError!void {
        try self.polynomials.validate();
        if (self.polynomials.columnCount() != trace.nColumnsForFamily(self.family))
            return error.InvalidColumnCount;
        if (self.events.len != constraint_program.entryCount(self.family))
            return error.InvalidEventCount;
        const expected_batch_size = constraint_program.batchSize(self.family);
        if (self.batch_size != expected_batch_size)
            return error.InvalidBatchLayout;

        var root_cursor: usize = 0;
        for (self.events) |event| {
            const values = event.valueSlice() orelse
                return error.InvalidEventRoot;
            _ = try relation.validateEventShape(
                event.schema,
                event.role,
                event.arity,
                event.access_ordinal,
            );
            if (event.numerator >= self.polynomials.nodes.len or
                event.liveness >= self.polynomials.nodes.len)
            {
                return error.InvalidEventRoot;
            }
            if (hasNegativeNumerator(event.role)) {
                const numerator = self.polynomials.nodes[event.numerator];
                if (numerator.op != .neg or numerator.lhs != event.liveness)
                    return error.InvalidNumeratorSign;
            } else if (event.numerator != event.liveness) {
                return error.InvalidNumeratorSign;
            }

            if (root_cursor >= self.polynomials.roots.len or
                self.polynomials.roots[root_cursor] != event.numerator)
            {
                return error.InvalidRootOrder;
            }
            root_cursor += 1;
            for (values) |value| {
                if (value >= self.polynomials.nodes.len)
                    return error.InvalidEventRoot;
                if (root_cursor >= self.polynomials.roots.len or
                    self.polynomials.roots[root_cursor] != value)
                {
                    return error.InvalidRootOrder;
                }
                root_cursor += 1;
            }
            for (event.values[event.arity..]) |unused| {
                if (unused != no_node) return error.InvalidValueTail;
            }
        }
        if (root_cursor != self.polynomials.roots.len)
            return error.InvalidRootOrder;

        const expected_batches = batchCount(self.events.len, self.batch_size);
        if (self.batches.len != expected_batches)
            return error.InvalidBatchLayout;
        for (self.batches, 0..) |batch, batch_index| {
            const first_event = std.math.mul(
                usize,
                batch_index,
                self.batch_size,
            ) catch return error.InvalidBatchLayout;
            const event_count = @min(
                @as(usize, self.batch_size),
                self.events.len - first_event,
            );
            if (batch.first_event != first_event or
                batch.event_count != event_count)
            {
                return error.InvalidBatchLayout;
            }
            for (batch.interaction_columns, 0..) |column, coordinate| {
                const local_index = std.math.add(
                    usize,
                    std.math.mul(
                        usize,
                        batch_index,
                        qm31.SECURE_EXTENSION_DEGREE,
                    ) catch return error.InvalidBatchLayout,
                    coordinate,
                ) catch return error.InvalidBatchLayout;
                if (column.tree != .interaction or
                    column.local_index != local_index)
                {
                    return error.InvalidBatchLayout;
                }
            }
        }
    }
};

pub fn lower(
    allocator: std.mem.Allocator,
    imported: *const shadow_program.ImportedProgram,
    layout: *const compat_layout.Layout,
) LowerError!Program {
    try layout.validate(imported);

    var root_count: usize = 0;
    for (imported.lookups, 0..) |lookup, index| {
        _ = try sourceLiveness(imported, lookup);
        const fields = imported.lookupFields(index) orelse
            return error.InvalidLookupRange;
        root_count = std.math.add(usize, root_count, 1 + fields.len) catch
            return error.CountOverflow;
    }
    const roots = try allocator.alloc(types.ValueId, root_count);
    defer allocator.free(roots);
    var root_cursor: usize = 0;
    for (imported.lookups, 0..) |lookup, index| {
        roots[root_cursor] = lookup.numerator;
        root_cursor += 1;
        const fields = imported.lookupFields(index) orelse
            return error.InvalidLookupRange;
        @memcpy(roots[root_cursor .. root_cursor + fields.len], fields);
        root_cursor += fields.len;
    }
    std.debug.assert(root_cursor == roots.len);

    var polynomials = try lower_constraint.lowerValues(
        allocator,
        imported,
        layout,
        roots,
        .main,
    );
    errdefer polynomials.deinit();

    const events = try allocator.alloc(Event, imported.lookups.len);
    errdefer allocator.free(events);
    root_cursor = 0;
    for (imported.lookups, events, 0..) |lookup, *event, index| {
        const fields = imported.lookupFields(index) orelse
            return error.InvalidLookupRange;
        const numerator = polynomials.roots[root_cursor];
        root_cursor += 1;
        const liveness = if (hasNegativeNumerator(lookup.role)) blk: {
            const node = polynomials.nodes[numerator];
            if (node.op != .neg) return error.InvalidNumeratorSign;
            break :blk node.lhs;
        } else numerator;
        event.* = .{
            .schema = lookup.schema,
            .role = lookup.role,
            .liveness = liveness,
            .numerator = numerator,
            .arity = @intCast(fields.len),
            .access_ordinal = lookup.access_ordinal,
        };
        @memcpy(
            event.values[0..fields.len],
            polynomials.roots[root_cursor .. root_cursor + fields.len],
        );
        root_cursor += fields.len;
    }
    std.debug.assert(root_cursor == polynomials.roots.len);

    const batches = try allocator.alloc(Batch, imported.batchCount());
    errdefer allocator.free(batches);
    const interactions = layout.interactions();
    for (batches, 0..) |*batch, batch_index| {
        const first_event = batch_index * imported.batch_size;
        batch.* = .{
            .first_event = @intCast(first_event),
            .event_count = @intCast(@min(
                @as(usize, imported.batch_size),
                imported.lookups.len - first_event,
            )),
            .interaction_columns = undefined,
        };
        for (&batch.interaction_columns, 0..) |*reference, coordinate| {
            const interaction_index =
                batch_index * qm31.SECURE_EXTENSION_DEGREE + coordinate;
            reference.* = interactions[interaction_index].reference;
        }
    }

    var result = Program{
        .allocator = allocator,
        .family = imported.family,
        .polynomials = polynomials,
        .events = events,
        .batches = batches,
        .batch_size = imported.batch_size,
    };
    try result.validate();
    return result;
}

fn sourceLiveness(
    imported: *const shadow_program.ImportedProgram,
    lookup: shadow_program.Lookup,
) ValidationError!types.ValueId {
    if (!hasNegativeNumerator(lookup.role)) return lookup.numerator;
    const numerator = imported.imported.arena.node(lookup.numerator) orelse
        return error.InvalidEventRoot;
    return switch (numerator.key.op) {
        .neg => |liveness| liveness,
        else => error.InvalidNumeratorSign,
    };
}

fn hasNegativeNumerator(role: relation.Role) bool {
    return switch (role) {
        .request, .consume => true,
        .emit => false,
    };
}

fn batchCount(event_count: usize, size: u8) usize {
    if (size == 0) return 0;
    return (event_count + size - 1) / size;
}
