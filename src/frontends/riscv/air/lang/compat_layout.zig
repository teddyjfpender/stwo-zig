//! Exact local physical mapping for the shipped opcode-family protocol.
//!
//! `compat-v1` is deliberately not an allocator. It maps the already imported
//! logical inputs onto the three production commitment trees without adding,
//! removing, or reordering a column. Logical names and `ValueId`s are borrowed
//! from the imported program; physical names come from the frozen witness
//! layout authority. The mapping must not outlive its imported program.

const std = @import("std");
const qm31 = @import("stwo_core").fields.qm31;
const entry = @import("../lookups/entry.zig");
const opcode_entries = @import("../lookups/opcode_entries.zig");
const trace = @import("../../runner/trace.zig");
const witness_layout = @import("../../witness_layout.zig");
const shadow_program = @import("shadow_program.zig");
const types = @import("types.zig");

pub const policy_id = "stwo.riscv.opcode.compat-v1";
pub const policy_version: u16 = 1;

pub const PREPROCESSED_COLUMN_COUNT: usize = 2;
pub const MAX_MAIN_COLUMNS: usize = trace.MAX_FAMILY_COLUMNS;
pub const MAX_INTERACTION_COLUMNS: usize =
    entry.MAX_BATCHES * qm31.SECURE_EXTENSION_DEGREE;

comptime {
    if (qm31.SECURE_EXTENSION_DEGREE != 4)
        @compileError("compat-v1 fixes the four-coordinate QM31 layout");
}

/// Production commitment-tree order. The integer values are protocol-visible
/// backend capability indices, not arbitrary enum ordinals.
pub const Tree = enum(u8) {
    preprocessed = 0,
    main = 1,
    interaction = 2,
};

pub const Window = enum(u8) {
    current,
    current_and_previous,
};

pub const PreprocessedKind = enum(u8) {
    is_first,
    is_active,
};

/// `QM31.toM31Array` order: `{ c0.a, c0.b, c1.a, c1.b }`.
pub const SecureCoordinate = enum(u8) {
    c0_a = 0,
    c0_b = 1,
    c1_a = 2,
    c1_b = 3,
};

pub const ColumnRef = struct {
    tree: Tree,
    local_index: u32,

    pub fn resolve(
        self: ColumnRef,
        offsets: TreeOffsets,
    ) error{ColumnIndexOverflow}!ResolvedColumn {
        const offset = switch (self.tree) {
            .preprocessed => offsets.preprocessed,
            .main => offsets.main,
            .interaction => offsets.interaction,
        };
        return .{
            .tree = self.tree,
            .index = std.math.add(
                usize,
                offset,
                @as(usize, self.local_index),
            ) catch return error.ColumnIndexOverflow,
        };
    }
};

pub const TreeOffsets = struct {
    preprocessed: usize,
    main: usize,
    interaction: usize,
};

pub const ResolvedColumn = struct {
    tree: Tree,
    index: usize,
};

pub const PreprocessedColumn = struct {
    reference: ColumnRef,
    kind: PreprocessedKind,
    name: []const u8,
    /// `is_first` belongs to interaction lowering and has no logical source
    /// value yet. `is_active` maps the imported production selector exactly.
    value: ?types.ValueId,
    window: Window,
};

pub const MainColumn = struct {
    reference: ColumnRef,
    value: types.ValueId,
    logical_name: []const u8,
    physical_name: []const u8,
    window: Window,
};

pub const InteractionColumn = struct {
    reference: ColumnRef,
    batch: u32,
    coordinate: SecureCoordinate,
    first_lookup: u32,
    entry_count: u8,
    window: Window,
};

const unused_main = MainColumn{
    .reference = .{ .tree = .main, .local_index = std.math.maxInt(u32) },
    .value = @enumFromInt(std.math.maxInt(u32)),
    .logical_name = "",
    .physical_name = "",
    .window = .current,
};

const unused_interaction = InteractionColumn{
    .reference = .{ .tree = .interaction, .local_index = std.math.maxInt(u32) },
    .batch = std.math.maxInt(u32),
    .coordinate = .c0_a,
    .first_lookup = std.math.maxInt(u32),
    .entry_count = 0,
    .window = .current_and_previous,
};

pub const Error = shadow_program.ValidationError || error{
    ColumnIndexOverflow,
    InvalidFamily,
    InvalidInteractionLayout,
    InvalidMainLayout,
    InvalidPreprocessedLayout,
};

pub const Layout = struct {
    family: trace.OpcodeFamily,
    lookup_count: usize,
    batch_size: u8,
    preprocessed: [PREPROCESSED_COLUMN_COUNT]PreprocessedColumn,
    main_storage: [MAX_MAIN_COLUMNS]MainColumn =
        .{unused_main} ** MAX_MAIN_COLUMNS,
    main_count: usize,
    interaction_storage: [MAX_INTERACTION_COLUMNS]InteractionColumn =
        .{unused_interaction} ** MAX_INTERACTION_COLUMNS,
    interaction_count: usize,

    pub fn main(self: *const Layout) []const MainColumn {
        return self.main_storage[0..self.main_count];
    }

    pub fn interactions(self: *const Layout) []const InteractionColumn {
        return self.interaction_storage[0..self.interaction_count];
    }

    /// Reverse mapping used by lowerers. It includes the external active-row
    /// selector and every main-tree input; `is_first` has no logical `ValueId`.
    pub fn referenceForValue(
        self: *const Layout,
        value: types.ValueId,
    ) ?ColumnRef {
        if (self.preprocessed[1].value == value)
            return self.preprocessed[1].reference;
        for (self.main()) |column| {
            if (column.value == value) return column.reference;
        }
        return null;
    }

    /// Rechecks the stored mapping against the complete imported program. This
    /// does not trust successful construction and is allocation-free.
    pub fn validate(
        self: *const Layout,
        imported: *const shadow_program.ImportedProgram,
    ) Error!void {
        try imported.validate();
        if (self.family != imported.family) return error.InvalidFamily;
        if (self.lookup_count != imported.lookups.len or
            self.batch_size != imported.batch_size)
        {
            return error.InvalidInteractionLayout;
        }

        const expected_preprocessed = [_]PreprocessedColumn{
            .{
                .reference = .{ .tree = .preprocessed, .local_index = 0 },
                .kind = .is_first,
                .name = "is_first",
                .value = null,
                .window = .current,
            },
            .{
                .reference = .{ .tree = .preprocessed, .local_index = 1 },
                .kind = .is_active,
                .name = "is_active",
                .value = imported.selector,
                .window = .current,
            },
        };
        for (self.preprocessed, expected_preprocessed) |actual, expected| {
            if (!std.meta.eql(actual.reference, expected.reference) or
                actual.kind != expected.kind or
                !std.mem.eql(u8, actual.name, expected.name) or
                actual.value != expected.value or
                actual.window != expected.window)
            {
                return error.InvalidPreprocessedLayout;
            }
        }

        const imported_main = imported.mainColumns();
        const physical_names = witness_layout.columnNames(self.family);
        if (self.main_count != imported_main.len or
            self.main_count != trace.nColumnsForFamily(self.family) or
            self.main_count != physical_names.len)
        {
            return error.InvalidMainLayout;
        }
        for (self.main(), imported_main, 0..) |column, value, index| {
            const expected_name = inputName(imported, value) orelse
                return error.InvalidMainLayout;
            if (column.reference.tree != .main or
                column.reference.local_index != index or
                column.value != value or
                !std.mem.eql(u8, column.logical_name, expected_name) or
                !std.mem.eql(u8, column.physical_name, physical_names[index]) or
                column.window != .current)
            {
                return error.InvalidMainLayout;
            }
        }
        for (self.main_storage[self.main_count..]) |column| {
            if (!std.meta.eql(column, unused_main))
                return error.InvalidMainLayout;
        }

        const batch_count = imported.batchCount();
        const expected_interactions = std.math.mul(
            usize,
            batch_count,
            qm31.SECURE_EXTENSION_DEGREE,
        ) catch return error.InvalidInteractionLayout;
        if (self.interaction_count != expected_interactions or
            self.interaction_count != opcode_entries.interactionColumnCount(self.family))
        {
            return error.InvalidInteractionLayout;
        }
        for (self.interactions(), 0..) |column, index| {
            const batch = index / qm31.SECURE_EXTENSION_DEGREE;
            const coordinate = index % qm31.SECURE_EXTENSION_DEGREE;
            const first_lookup = std.math.mul(
                usize,
                batch,
                self.batch_size,
            ) catch return error.InvalidInteractionLayout;
            if (first_lookup >= self.lookup_count)
                return error.InvalidInteractionLayout;
            const entry_count = @min(
                @as(usize, self.batch_size),
                self.lookup_count - first_lookup,
            );
            if (column.reference.tree != .interaction or
                column.reference.local_index != index or
                column.batch != batch or
                @intFromEnum(column.coordinate) != coordinate or
                column.first_lookup != first_lookup or
                column.entry_count != entry_count or
                column.window != .current_and_previous)
            {
                return error.InvalidInteractionLayout;
            }
        }
        for (self.interaction_storage[self.interaction_count..]) |column| {
            if (!std.meta.eql(column, unused_interaction))
                return error.InvalidInteractionLayout;
        }
    }
};

pub fn build(
    imported: *const shadow_program.ImportedProgram,
) Error!Layout {
    try imported.validate();
    const main_count = imported.mainColumns().len;
    const interaction_count = std.math.mul(
        usize,
        imported.batchCount(),
        qm31.SECURE_EXTENSION_DEGREE,
    ) catch return error.InvalidInteractionLayout;
    if (main_count > MAX_MAIN_COLUMNS) return error.InvalidMainLayout;
    if (interaction_count > MAX_INTERACTION_COLUMNS)
        return error.InvalidInteractionLayout;

    var result = Layout{
        .family = imported.family,
        .lookup_count = imported.lookups.len,
        .batch_size = imported.batch_size,
        .preprocessed = .{
            .{
                .reference = .{ .tree = .preprocessed, .local_index = 0 },
                .kind = .is_first,
                .name = "is_first",
                .value = null,
                .window = .current,
            },
            .{
                .reference = .{ .tree = .preprocessed, .local_index = 1 },
                .kind = .is_active,
                .name = "is_active",
                .value = imported.selector,
                .window = .current,
            },
        },
        .main_count = main_count,
        .interaction_count = interaction_count,
    };
    const physical_names = witness_layout.columnNames(imported.family);
    if (physical_names.len != main_count) return error.InvalidMainLayout;
    for (imported.mainColumns(), result.main_storage[0..main_count], 0..) |value, *column, index| {
        column.* = .{
            .reference = .{ .tree = .main, .local_index = @intCast(index) },
            .value = value,
            .logical_name = inputName(imported, value) orelse
                return error.InvalidMainLayout,
            .physical_name = physical_names[index],
            .window = .current,
        };
    }
    for (result.interaction_storage[0..interaction_count], 0..) |*column, index| {
        const batch = index / qm31.SECURE_EXTENSION_DEGREE;
        const first_lookup = batch * imported.batch_size;
        column.* = .{
            .reference = .{
                .tree = .interaction,
                .local_index = @intCast(index),
            },
            .batch = @intCast(batch),
            .coordinate = @enumFromInt(index % qm31.SECURE_EXTENSION_DEGREE),
            .first_lookup = @intCast(first_lookup),
            .entry_count = @intCast(@min(
                @as(usize, imported.batch_size),
                imported.lookups.len - first_lookup,
            )),
            .window = .current_and_previous,
        };
    }
    try result.validate(imported);
    return result;
}

fn inputName(
    imported: *const shadow_program.ImportedProgram,
    value: types.ValueId,
) ?[]const u8 {
    const node = imported.imported.arena.node(value) orelse return null;
    const name = switch (node.key.op) {
        .input => |name_id| name_id,
        else => return null,
    };
    return imported.imported.arena.name(name);
}
