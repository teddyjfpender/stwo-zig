//! Evaluator slot tables built from a projection source.
//!
//! The slot order is the projection header's `slots` list, which the oracle
//! read from upstream `all_components` (83 Cairo slots) and
//! `all_circuit_components` (11 circuit components). It is the only source of
//! that order in this package. A slot is either a generated evaluator (a
//! projected function of the same name) or a hand-written one; the per-source
//! modules `cairo_components.zig` and `circuit_components.zig` name the
//! hand-written slots and their shapes. The circuit shapes come from
//! `common/component_list.zig`, the one definition of the circuit components'
//! static facts.

const std = @import("std");
const projection_mod = @import("projection.zig");
const constraint_eval = @import("../stark_verifier/constraint_eval.zig");
const component_list = @import("../common/component_list.zig");
const interpreter = @import("interpreter.zig");
const manual_cairo = @import("manual/cairo.zig");
const manual_circuit = @import("manual/circuit.zig");

const Projection = projection_mod.Projection;
const Source = projection_mod.Source;
const RelationUse = component_list.RelationUse;

pub const Manual = union(enum) {
    cairo_memory_address_to_id,
    /// One evaluator parameterised by the component index `0..16`.
    cairo_memory_id_to_big: u32,
    cairo_verify_bitwise_xor_12,
    circuit_eq,
    circuit_qm31_ops,
    circuit_verify_bitwise_xor_12,
};

pub const Evaluator = union(enum) {
    /// Index into the source's projected functions.
    generated: u32,
    manual: Manual,
};

/// `CircuitEval::log_size`.
pub const LogSize = union(enum) {
    /// Determined by the proof (`None` upstream).
    dynamic,
    fixed: u32,
    /// The log size of this preprocessed column (Gate components).
    preprocessed_column: []const u8,
};

/// The `CircuitEval` constants of a component.
pub const Shape = struct {
    trace_columns: usize,
    interaction_columns: usize,
    relation_uses_per_row: []const RelationUse,
    log_size: LogSize,

    /// The shape of a circuit-AIR component, from its static facts.
    pub fn fromFacts(facts: component_list.ComponentFacts) Shape {
        return .{
            .trace_columns = facts.trace_columns,
            .interaction_columns = facts.interaction_columns,
            .relation_uses_per_row = facts.relation_uses_per_row,
            .log_size = switch (facts.log_size) {
                .fixed => |value| .{ .fixed = value },
                .preprocessed_column => |column| .{ .preprocessed_column = column },
            },
        };
    }

    pub fn eql(a: Shape, b: Shape) bool {
        if (a.trace_columns != b.trace_columns or a.interaction_columns != b.interaction_columns) return false;
        if (a.relation_uses_per_row.len != b.relation_uses_per_row.len) return false;
        for (a.relation_uses_per_row, b.relation_uses_per_row) |x, y| {
            if (x.uses != y.uses or !std.mem.eql(u8, x.relation_id, y.relation_id)) return false;
        }
        return switch (a.log_size) {
            .dynamic => b.log_size == .dynamic,
            .fixed => |value| b.log_size == .fixed and b.log_size.fixed == value,
            .preprocessed_column => |column| b.log_size == .preprocessed_column and
                std.mem.eql(u8, b.log_size.preprocessed_column, column),
        };
    }
};

pub const Entry = struct {
    /// Slot name (`CircuitEval::name`).
    name: []const u8,
    evaluator: Evaluator,
    shape: Shape,
};

/// Classifies a hand-written slot and gives its shape; returns null for a
/// generated slot.
pub const ManualResolver = *const fn (slot: []const u8, constants: manual_cairo.Constants) ?ManualSlot;

pub const ManualSlot = struct {
    manual: Manual,
    shape: Shape,
    /// The compiled-AIR function the slot replaces (must be listed as hand-written).
    compiled_name: ?[]const u8,
};

pub const Table = struct {
    arena: std.heap.ArenaAllocator,
    projection: *const Projection,
    source: *const Source,
    constants: manual_cairo.Constants,
    entries: []const Entry,

    pub fn deinit(table: *Table) void {
        table.arena.deinit();
        table.* = undefined;
    }

    pub fn find(table: *const Table, name: []const u8) ?usize {
        for (table.entries, 0..) |entry, i| {
            if (std.mem.eql(u8, entry.name, name)) return i;
        }
        return null;
    }

    /// `CircuitEval::evaluate` of slot `index`: emits the component's
    /// constraints and lookup terms into `acc` (the caller then runs
    /// `finalize_logup_in_pairs`). `scratch` backs the interpreter frames and
    /// may be reset after the call.
    pub fn evaluate(
        table: *const Table,
        index: usize,
        comptime Ctx: type,
        ctx: *Ctx,
        data: anytype,
        acc: *constraint_eval.CompositionConstraintAccumulator(Ctx),
        scratch: std.mem.Allocator,
    ) !void {
        const Data = @TypeOf(data.*);
        var interp: interpreter.Interpreter(Ctx, Data) = .{
            .projection = table.projection,
            .source = table.source,
            .ctx = ctx,
            .data = data,
            .acc = acc,
            .scratch = scratch,
        };
        switch (table.entries[index].evaluator) {
            .generated => |function| try interp.evaluateComponent(function),
            .manual => |manual| switch (manual) {
                .cairo_memory_address_to_id => try manual_cairo.evaluateMemoryAddressToId(&interp, table.constants),
                .cairo_memory_id_to_big => |component| try manual_cairo.evaluateMemoryIdToBig(&interp, table.constants, component),
                .cairo_verify_bitwise_xor_12 => try manual_cairo.evaluateVerifyBitwiseXor12(&interp),
                .circuit_eq => try manual_circuit.evaluateEq(&interp),
                .circuit_qm31_ops => try manual_circuit.evaluateQm31Ops(&interp),
                .circuit_verify_bitwise_xor_12 => try manual_circuit.evaluateVerifyBitwiseXor12(&interp),
            },
        }
    }
};

pub const BuildError = error{
    MissingSource,
    MissingConstant,
    UnknownSlot,
    HandWrittenMismatch,
    SlotIsInline,
    SlotCountMismatch,
    /// The circuit slots differ from `component_list.ComponentList` order.
    SlotOrderMismatch,
    /// A circuit slot's constants differ from `component_list.component_facts`.
    ComponentFactsMismatch,
} || std.mem.Allocator.Error;

pub fn build(
    gpa: std.mem.Allocator,
    projection: *const Projection,
    label: []const u8,
    resolve: ManualResolver,
) BuildError!Table {
    const source = projection.source(label) orelse return error.MissingSource;
    var arena = std.heap.ArenaAllocator.init(gpa);
    errdefer arena.deinit();
    const allocator = arena.allocator();
    const constants = try headerConstants(projection);

    const slots = projection.nameList(source.slots);
    const entries = try allocator.alloc(Entry, slots.len);
    var hand_written_seen = try allocator.alloc(bool, source.hand_written.len);
    @memset(hand_written_seen, false);
    for (slots, entries) |slot, *entry| {
        const name = projection.str(slot);
        if (resolve(name, constants)) |manual| {
            if (manual.compiled_name) |compiled| {
                const position = handWrittenIndex(projection, source, compiled) orelse return error.HandWrittenMismatch;
                hand_written_seen[position] = true;
            }
            entry.* = .{ .name = name, .evaluator = .{ .manual = manual.manual }, .shape = manual.shape };
            continue;
        }
        const index = source.findFunction(projection, name) orelse return error.UnknownSlot;
        entry.* = try generatedEntry(allocator, projection, source, index);
    }
    // Every hand-written function of the source must back some slot.
    for (hand_written_seen) |seen| if (!seen) return error.HandWrittenMismatch;
    return .{ .arena = arena, .projection = projection, .source = source, .constants = constants, .entries = entries };
}

fn headerConstants(projection: *const Projection) BuildError!manual_cairo.Constants {
    return .{
        .large_memory_value_id_base = projection.constant("LARGE_MEMORY_VALUE_ID_BASE") orelse return error.MissingConstant,
        .max_sequence_log_size = projection.constant("MAX_SEQUENCE_LOG_SIZE") orelse return error.MissingConstant,
        .memory_address_to_id_split = projection.constant("MEMORY_ADDRESS_TO_ID_SPLIT") orelse return error.MissingConstant,
    };
}

fn handWrittenIndex(projection: *const Projection, source: *const Source, name: []const u8) ?usize {
    for (projection.nameList(source.hand_written), 0..) |candidate, i| {
        if (std.mem.eql(u8, projection.str(candidate), name)) return i;
    }
    return null;
}

/// The constants the generator emits for a component (`N_TRACE_COLUMNS`,
/// `N_INTERACTION_COLUMNS`, `RELATION_USES_PER_ROW`, `log_size`).
fn generatedEntry(allocator: std.mem.Allocator, projection: *const Projection, source: *const Source, index: u32) BuildError!Entry {
    const function = &source.functions[index];
    if (function.trace_type == .inline_fn) return error.SlotIsInline;
    const lookups = function.constraint_lookups.slice(projection_mod.ConstraintLookup, projection.lookups);
    const log_size: LogSize = if (function.trace_type == .gate) blk: {
        const columns = projection.nameList(function.external_states);
        if (columns.len == 0) return error.UnknownSlot;
        break :blk .{ .preprocessed_column = projection.str(columns[0]) };
    } else if (function.log_height) |fixed| .{ .fixed = fixed } else .dynamic;
    return .{
        .name = projection.str(function.name),
        .evaluator = .{ .generated = index },
        .shape = .{
            .trace_columns = projection.nameList(function.state_names).len,
            .interaction_columns = 4 * ((lookups.len + 1) / 2),
            .relation_uses_per_row = try relationUses(allocator, projection, lookups),
            .log_size = log_size,
        },
    };
}

/// `generate_relation_uses`: the `Use` count per relation, sorted by relation
/// name (Rust `String` order, which is byte order).
fn relationUses(
    allocator: std.mem.Allocator,
    projection: *const Projection,
    lookups: []const projection_mod.ConstraintLookup,
) BuildError![]const RelationUse {
    var uses: std.ArrayList(RelationUse) = .empty;
    for (lookups) |lookup| {
        if (lookup.use_or_yield != .use) continue;
        const relation = projection.str(lookup.relation);
        for (uses.items) |*existing| {
            if (std.mem.eql(u8, existing.relation_id, relation)) {
                existing.uses += 1;
                break;
            }
        } else try uses.append(allocator, .{ .relation_id = relation, .uses = 1 });
    }
    std.sort.insertion(RelationUse, uses.items, {}, struct {
        fn lessThan(_: void, a: RelationUse, b: RelationUse) bool {
            return std.mem.order(u8, a.relation_id, b.relation_id) == .lt;
        }
    }.lessThan);
    return uses.items;
}
