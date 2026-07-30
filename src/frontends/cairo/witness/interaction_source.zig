//! Typed, backend-neutral source addressing for Cairo lookup relations.
//!
//! The layouts mirror the protocol relation templates, not a backend buffer
//! ABI. Sparse columns let CPU conformance code borrow independently owned
//! trace columns without assembling a Metal-style arena.

const std = @import("std");
const m31_mod = @import("stwo_core").fields.m31;
const M31 = m31_mod.M31;
const relation_bundle = @import("relation_bundle.zig");
const interaction_residency = @import("interaction_residency.zig");

pub const Error = error{
    InvalidDescriptor,
    InvalidRow,
    InvalidSourceShape,
    NonCanonicalM31,
};

/// Column-major lookup words stored in one contiguous allocation.
pub const LookupColumns = struct {
    pub const ReadFn = *const fn (
        context: *const anyopaque,
        column: usize,
        row: usize,
    ) Error!u32;

    const Virtual = struct {
        context: *const anyopaque,
        read: ReadFn,
    };

    const LookupStorage = union(enum) {
        dense: []const u32,
        virtual: Virtual,
    };

    storage: LookupStorage,
    rows: usize,
    columns: usize,

    pub fn init(words: []const u32, rows: usize) Error!LookupColumns {
        if (rows == 0 or words.len == 0 or words.len % rows != 0)
            return Error.InvalidSourceShape;
        return .{
            .storage = .{ .dense = words },
            .rows = rows,
            .columns = words.len / rows,
        };
    }

    pub fn virtual(
        rows: usize,
        columns: usize,
        context: *const anyopaque,
        read: ReadFn,
    ) Error!LookupColumns {
        if (rows == 0 or columns == 0) return Error.InvalidSourceShape;
        return .{
            .storage = .{ .virtual = .{ .context = context, .read = read } },
            .rows = rows,
            .columns = columns,
        };
    }

    fn value(self: LookupColumns, column: usize, row: usize) Error!M31 {
        if (column >= self.columns or row >= self.rows) return Error.InvalidSourceShape;
        const raw = switch (self.storage) {
            .dense => |words| words[column * self.rows + row],
            .virtual => |source| try source.read(source.context, column, row),
        };
        return canonical(raw);
    }

    fn access(self: LookupColumns, column: usize) Error!ColumnAccess {
        if (column >= self.columns) return Error.InvalidSourceShape;
        return switch (self.storage) {
            .dense => |words| .{ .dense = words.ptr + column * self.rows },
            .virtual => |source| .{ .virtual = .{
                .context = source.context,
                .read = source.read,
                .column = column,
            } },
        };
    }
};

/// A resolved indirect reader for one virtual lookup column.
pub const VirtualColumn = struct {
    context: *const anyopaque,
    read: LookupColumns.ReadFn,
    column: usize,

    pub fn value(self: VirtualColumn, row: usize) Error!M31 {
        return canonical(try self.read(self.context, self.column, row));
    }
};

/// A borrowed column reader resolved once per relation use instead of once per
/// element. `dense` addresses at least the view's visible rows.
pub const ColumnAccess = union(enum) {
    dense: [*]const u32,
    virtual: VirtualColumn,
};

/// Row-indexed reader for one relation word of one use, resolved once.
///
/// Descriptor dispatch, index arithmetic, and bounds validation happen when the
/// access is built; evaluation then reads rows through a two-way union whose
/// dense arm is a plain contiguous load.
pub const WordAccess = union(enum) {
    dense: [*]const u32,
    /// `row + base`, range-checked against the modulus.
    row_plus: u64,
    /// `((row + base) | 2^30)`, range-checked below `2^30 - 1`.
    tagged_big: u32,
    /// Synthesized `verify_bitwise_xor_12` operand words.
    bitwise: struct { arg: u32, word: usize },
    virtual: VirtualColumn,

    pub fn value(self: WordAccess, row: usize) Error!M31 {
        return switch (self) {
            .dense => |words| canonical(words[row]),
            .row_plus => |base| canonicalWide(@as(u64, row) + base),
            .tagged_big => |base| taggedBigAddress(row, base),
            .bitwise => |synthetic| bitwiseWord(synthetic.arg, synthetic.word, row),
            .virtual => |source| source.value(row),
        };
    }
};

/// Row-indexed multiplicity reader for one use, resolved once.
pub const MultiplicityAccess = union(enum) {
    one,
    /// `1` while the row is inside the source's real prefix, else `0`.
    row_enabler: usize,
    dense: [*]const u32,
    virtual: VirtualColumn,

    pub fn value(self: MultiplicityAccess, row: usize) Error!M31 {
        return switch (self) {
            .one => M31.one(),
            .row_enabler => |real_rows| M31.fromCanonical(@intFromBool(row < real_rows)),
            .dense => |words| canonical(words[row]),
            .virtual => |source| source.value(row),
        };
    }
};

/// Independently borrowed source columns. Columns may be larger than `rows`,
/// matching the relation backend contract, but only the first `rows` values
/// are visible to this trace instance.
pub const SparseColumns = struct {
    values: []const []const u32,
    rows: usize,

    pub fn init(values: []const []const u32, rows: usize) Error!SparseColumns {
        if (rows == 0 or values.len == 0) return Error.InvalidSourceShape;
        for (values) |column| if (column.len < rows) return Error.InvalidSourceShape;
        return .{ .values = values, .rows = rows };
    }

    fn value(self: SparseColumns, column: usize, row: usize) Error!M31 {
        if (column >= self.values.len or row >= self.rows) return Error.InvalidSourceShape;
        return canonical(self.values[column][row]);
    }

    fn access(self: SparseColumns, column: usize) Error!ColumnAccess {
        if (column >= self.values.len or self.values[column].len < self.rows)
            return Error.InvalidSourceShape;
        return .{ .dense = self.values[column].ptr };
    }
};

const Storage = union(relation_bundle.SourceLayout) {
    lookup_words: LookupColumns,
    memory_address: SparseColumns,
    memory_big: SparseColumns,
    memory_small: SparseColumns,
    bitwise_xor_12: SparseColumns,
};

/// A relation source with protocol geometry and row-domain metadata.
pub const SourceView = struct {
    storage: Storage,
    real_rows: usize,
    source_offset_rows: u32,
    residency: ?interaction_residency.Residency = null,

    pub fn lookupWords(columns: LookupColumns, real_rows: usize) Error!SourceView {
        try validateRows(columns.rows, real_rows);
        return .{
            .storage = .{ .lookup_words = columns },
            .real_rows = real_rows,
            .source_offset_rows = 0,
        };
    }

    pub fn memoryAddress(
        columns: SparseColumns,
        instances: u32,
        real_rows: usize,
    ) Error!SourceView {
        try validateRows(columns.rows, real_rows);
        if (instances == 0 or columns.values.len != @as(usize, instances) * 2)
            return Error.InvalidSourceShape;
        return .{
            .storage = .{ .memory_address = columns },
            .real_rows = real_rows,
            .source_offset_rows = 0,
        };
    }

    pub fn memoryBig(
        columns: SparseColumns,
        value_columns: u32,
        real_rows: usize,
        source_offset_rows: u32,
    ) Error!SourceView {
        try validateMemoryColumns(columns, value_columns, real_rows);
        return .{
            .storage = .{ .memory_big = columns },
            .real_rows = real_rows,
            .source_offset_rows = source_offset_rows,
        };
    }

    pub fn memorySmall(
        columns: SparseColumns,
        value_columns: u32,
        real_rows: usize,
        source_offset_rows: u32,
    ) Error!SourceView {
        try validateMemoryColumns(columns, value_columns, real_rows);
        return .{
            .storage = .{ .memory_small = columns },
            .real_rows = real_rows,
            .source_offset_rows = source_offset_rows,
        };
    }

    pub fn bitwiseXor12(
        multiplicities: SparseColumns,
        partitions: u32,
        real_rows: usize,
    ) Error!SourceView {
        try validateRows(multiplicities.rows, real_rows);
        if (partitions == 0 or multiplicities.values.len != partitions)
            return Error.InvalidSourceShape;
        return .{
            .storage = .{ .bitwise_xor_12 = multiplicities },
            .real_rows = real_rows,
            .source_offset_rows = 0,
        };
    }

    pub fn rows(self: SourceView) usize {
        return switch (self.storage) {
            inline else => |source| source.rows,
        };
    }

    pub fn realRows(self: SourceView) usize {
        return self.real_rows;
    }

    pub fn sourceOffsetRows(self: SourceView) u32 {
        return self.source_offset_rows;
    }

    pub fn backendResidency(self: SourceView) ?interaction_residency.Residency {
        return self.residency;
    }

    pub fn withResidency(
        self: SourceView,
        residency: ?interaction_residency.Residency,
    ) SourceView {
        var result = self;
        result.residency = residency;
        return result;
    }

    /// Physical columns in the relation-kernel ABI. Lookup words form one
    /// dense column-major slab; the other layouts bind sparse columns.
    pub fn physicalColumnCount(self: SourceView) usize {
        return switch (self.storage) {
            .lookup_words => |source| source.columns,
            inline else => |source| source.values.len,
        };
    }

    pub fn copyPhysicalColumn(
        self: SourceView,
        column: usize,
        destination: []u32,
    ) Error!void {
        if (destination.len != self.rows() or
            column >= self.physicalColumnCount())
            return Error.InvalidSourceShape;
        switch (self.storage) {
            .lookup_words => |source| {
                for (destination, 0..) |*value, row|
                    value.* = (try source.value(column, row)).v;
            },
            inline else => |source| {
                for (destination, 0..) |*value, row|
                    value.* = (try source.value(column, row)).v;
            },
        }
    }

    pub fn layout(self: SourceView) relation_bundle.SourceLayout {
        return std.meta.activeTag(self.storage);
    }

    pub fn layoutArg(self: SourceView) usize {
        return switch (self.storage) {
            .lookup_words => |source| source.columns,
            .memory_address => |source| source.values.len / 2,
            .memory_big, .memory_small => |source| source.values.len - 1,
            .bitwise_xor_12 => |source| source.values.len,
        };
    }

    pub fn validateDeclaration(
        self: SourceView,
        declared_layout: relation_bundle.SourceLayout,
        layout_arg: u32,
    ) Error!void {
        if (self.layout() != declared_layout or self.layoutArg() != layout_arg)
            return Error.InvalidSourceShape;
    }

    pub fn validateUse(self: SourceView, use: []const u32, alpha_count: usize) Error!void {
        if (use.len != 7 or use[2] == 0 or use[2] > alpha_count or
            use[3] == 0 or use[3] >= m31_mod.Modulus or use[6] > 1)
            return Error.InvalidDescriptor;
        try self.validateSourceUse(use[0], use[1], use[2]);
        try self.validateMultiplicityUse(use[4], use[5]);
    }

    pub fn relationWord(
        self: SourceView,
        kind: u32,
        arg: u32,
        word: usize,
        row: usize,
    ) Error!M31 {
        if (row >= self.rows()) return Error.InvalidRow;
        if (word == 0) return Error.InvalidDescriptor;
        return switch (self.storage) {
            .lookup_words => |source| if (kind == 0)
                source.value(try addIndex(arg, word), row)
            else
                Error.InvalidDescriptor,
            .memory_address => |source| if (kind == 1)
                if (word == 1)
                    canonicalWide(@as(u64, row) + 1 + @as(u64, arg) * source.rows)
                else
                    source.value(try mulIndex(arg, 2), row)
            else
                Error.InvalidDescriptor,
            .memory_big => |source| switch (kind) {
                2 => source.value(try addIndex(arg, word - 1), row),
                3 => if (word == 1)
                    taggedBigAddress(row, self.source_offset_rows)
                else
                    source.value(word - 2, row),
                else => Error.InvalidDescriptor,
            },
            .memory_small => |source| switch (kind) {
                4 => source.value(try addIndex(arg, word - 1), row),
                5 => if (word == 1)
                    canonicalWide(@as(u64, row) + self.source_offset_rows)
                else
                    source.value(word - 2, row),
                else => Error.InvalidDescriptor,
            },
            .bitwise_xor_12 => if (kind == 6)
                bitwiseWord(arg, word, row)
            else
                Error.InvalidDescriptor,
        };
    }

    pub fn multiplicity(self: SourceView, kind: u32, arg: u32, row: usize) Error!M31 {
        if (row >= self.rows()) return Error.InvalidRow;
        return switch (kind) {
            0 => M31.one(),
            1 => M31.fromCanonical(@intFromBool(row < self.real_rows)),
            2 => switch (self.storage) {
                .lookup_words => |source| source.value(arg, row),
                else => Error.InvalidDescriptor,
            },
            3 => switch (self.storage) {
                .memory_address => |source| source.value(try addIndex(try mulIndex(arg, 2), 1), row),
                else => Error.InvalidDescriptor,
            },
            4 => switch (self.storage) {
                .memory_big => |source| source.value(arg, row),
                else => Error.InvalidDescriptor,
            },
            5 => switch (self.storage) {
                .memory_small => |source| source.value(arg, row),
                else => Error.InvalidDescriptor,
            },
            6 => switch (self.storage) {
                .bitwise_xor_12 => |source| source.value(arg, row),
                else => Error.InvalidDescriptor,
            },
            else => Error.InvalidDescriptor,
        };
    }

    /// Resolves the row reader for one relation word of one use.
    ///
    /// This is the hoisted form of `relationWord`: it performs the same layout
    /// dispatch, index arithmetic, and bounds validation once per use instead
    /// of once per element, and the returned access reproduces `relationWord`
    /// for every row of the view.
    pub fn resolveWord(
        self: SourceView,
        kind: u32,
        arg: u32,
        word: usize,
    ) Error!WordAccess {
        if (word == 0) return Error.InvalidDescriptor;
        return switch (self.storage) {
            .lookup_words => |source| if (kind == 0)
                fromColumn(try source.access(try addIndex(arg, word)))
            else
                Error.InvalidDescriptor,
            .memory_address => |source| if (kind == 1)
                if (word == 1)
                    WordAccess{ .row_plus = 1 + @as(u64, arg) * source.rows }
                else
                    fromColumn(try source.access(try mulIndex(arg, 2)))
            else
                Error.InvalidDescriptor,
            .memory_big => |source| switch (kind) {
                2 => fromColumn(try source.access(try addIndex(arg, word - 1))),
                3 => if (word == 1)
                    WordAccess{ .tagged_big = self.source_offset_rows }
                else
                    fromColumn(try source.access(word - 2)),
                else => Error.InvalidDescriptor,
            },
            .memory_small => |source| switch (kind) {
                4 => fromColumn(try source.access(try addIndex(arg, word - 1))),
                5 => if (word == 1)
                    WordAccess{ .row_plus = self.source_offset_rows }
                else
                    fromColumn(try source.access(word - 2)),
                else => Error.InvalidDescriptor,
            },
            .bitwise_xor_12 => if (kind == 6)
                WordAccess{ .bitwise = .{ .arg = arg, .word = word } }
            else
                Error.InvalidDescriptor,
        };
    }

    /// Resolves the row reader for one use's multiplicity. Hoisted form of
    /// `multiplicity`, with the same dispatch and bounds semantics.
    pub fn resolveMultiplicity(
        self: SourceView,
        kind: u32,
        arg: u32,
    ) Error!MultiplicityAccess {
        return switch (kind) {
            0 => .one,
            1 => .{ .row_enabler = self.real_rows },
            2 => switch (self.storage) {
                .lookup_words => |source| fromMultiplicityColumn(try source.access(arg)),
                else => Error.InvalidDescriptor,
            },
            3 => switch (self.storage) {
                .memory_address => |source| fromMultiplicityColumn(
                    try source.access(try addIndex(try mulIndex(arg, 2), 1)),
                ),
                else => Error.InvalidDescriptor,
            },
            4 => switch (self.storage) {
                .memory_big => |source| fromMultiplicityColumn(try source.access(arg)),
                else => Error.InvalidDescriptor,
            },
            5 => switch (self.storage) {
                .memory_small => |source| fromMultiplicityColumn(try source.access(arg)),
                else => Error.InvalidDescriptor,
            },
            6 => switch (self.storage) {
                .bitwise_xor_12 => |source| fromMultiplicityColumn(try source.access(arg)),
                else => Error.InvalidDescriptor,
            },
            else => Error.InvalidDescriptor,
        };
    }

    fn validateSourceUse(self: SourceView, kind: u32, arg: u32, words: u32) Error!void {
        const last_word: usize = words - 1;
        switch (self.storage) {
            .lookup_words => |source| {
                if (kind != 0) return Error.InvalidDescriptor;
                if (words > 1 and try addIndex(arg, last_word) >= source.columns)
                    return Error.InvalidDescriptor;
            },
            .memory_address => |source| {
                if (kind != 1) return Error.InvalidDescriptor;
                if (words > 1 and (arg >= source.values.len / 2 or
                    try mulIndex(arg, 2) >= source.values.len))
                    return Error.InvalidDescriptor;
            },
            .memory_big => |source| switch (kind) {
                2 => if (words > 1 and try addIndex(arg, last_word - 1) >= source.values.len)
                    return Error.InvalidDescriptor,
                3 => if (words > 1 and
                    (arg != 0 or (words > 2 and last_word - 1 >= source.values.len)))
                    return Error.InvalidDescriptor,
                else => return Error.InvalidDescriptor,
            },
            .memory_small => |source| switch (kind) {
                4 => if (words > 1 and try addIndex(arg, last_word - 1) >= source.values.len)
                    return Error.InvalidDescriptor,
                5 => if (words > 1 and
                    (arg != 0 or (words > 2 and last_word - 1 >= source.values.len)))
                    return Error.InvalidDescriptor,
                else => return Error.InvalidDescriptor,
            },
            .bitwise_xor_12 => |source| {
                if (kind != 6) return Error.InvalidDescriptor;
                if (words > 1 and arg >= source.values.len) return Error.InvalidDescriptor;
            },
        }
    }

    fn validateMultiplicityUse(self: SourceView, kind: u32, arg: u32) Error!void {
        if (kind <= 1) return;
        const valid = switch (self.storage) {
            .lookup_words => |source| kind == 2 and arg < source.columns,
            .memory_address => |source| kind == 3 and arg < source.values.len / 2,
            .memory_big => |source| kind == 4 and @as(usize, arg) == source.values.len - 1,
            .memory_small => |source| kind == 5 and @as(usize, arg) == source.values.len - 1,
            .bitwise_xor_12 => |source| kind == 6 and arg < source.values.len,
        };
        if (!valid) return Error.InvalidDescriptor;
    }
};

fn fromColumn(column: ColumnAccess) WordAccess {
    return switch (column) {
        .dense => |words| .{ .dense = words },
        .virtual => |source| .{ .virtual = source },
    };
}

fn fromMultiplicityColumn(column: ColumnAccess) MultiplicityAccess {
    return switch (column) {
        .dense => |words| .{ .dense = words },
        .virtual => |source| .{ .virtual = source },
    };
}

fn validateMemoryColumns(columns: SparseColumns, value_columns: u32, real_rows: usize) Error!void {
    try validateRows(columns.rows, real_rows);
    if (value_columns == 0 or columns.values.len != @as(usize, value_columns) + 1)
        return Error.InvalidSourceShape;
}

fn validateRows(rows: usize, real_rows: usize) Error!void {
    if (rows == 0 or real_rows > rows) return Error.InvalidSourceShape;
}

fn canonical(raw: u32) Error!M31 {
    if (raw >= m31_mod.Modulus) return Error.NonCanonicalM31;
    return M31.fromCanonical(raw);
}

fn canonicalWide(raw: u64) Error!M31 {
    if (raw >= m31_mod.Modulus) return Error.NonCanonicalM31;
    return M31.fromCanonical(@intCast(raw));
}

fn taggedBigAddress(row: usize, source_offset_rows: u32) Error!M31 {
    const raw = @as(u64, row) + source_offset_rows;
    if (raw >= 0x3fff_ffff) return Error.NonCanonicalM31;
    return M31.fromCanonical(@as(u32, @intCast(raw)) | 0x4000_0000);
}

fn bitwiseWord(arg: u32, word: usize, row: usize) Error!M31 {
    const a = (@as(u64, arg >> 2) << 10) | (@as(u64, row) >> 10);
    const b = (@as(u64, arg & 3) << 10) | (@as(u64, row) & 0x3ff);
    return switch (word) {
        1 => canonicalWide(a),
        2 => canonicalWide(b),
        else => canonicalWide(a ^ b),
    };
}

fn addIndex(lhs: anytype, rhs: usize) Error!usize {
    return std.math.add(usize, @intCast(lhs), rhs) catch Error.InvalidDescriptor;
}

fn mulIndex(lhs: anytype, rhs: usize) Error!usize {
    return std.math.mul(usize, @intCast(lhs), rhs) catch Error.InvalidDescriptor;
}

test "Cairo interaction sources address lookup words and row enablers" {
    const words = [_]u32{ 10, 11, 20, 21, 30, 31 };
    const source = try SourceView.lookupWords(try LookupColumns.init(&words, 2), 1);
    try std.testing.expectEqual(@as(u32, 30), (try source.relationWord(0, 1, 1, 0)).v);
    try std.testing.expectEqual(@as(u32, 20), (try source.multiplicity(2, 1, 0)).v);
    try std.testing.expectEqual(@as(u32, 1), (try source.multiplicity(1, 0, 0)).v);
    try std.testing.expectEqual(@as(u32, 0), (try source.multiplicity(1, 0, 1)).v);
}

test "Cairo interaction sources support lazy lookup columns" {
    const Context = struct {
        fn read(_: *const anyopaque, column: usize, row: usize) Error!u32 {
            return @intCast(column * 10 + row);
        }
    };
    const context: u8 = 0;
    const columns = try LookupColumns.virtual(2, 3, &context, Context.read);
    const source = try SourceView.lookupWords(columns, 2);
    try std.testing.expectEqual(@as(u32, 21), (try source.relationWord(0, 1, 1, 1)).v);
}

test "Cairo interaction sources address memory relations" {
    const c0 = [_]u32{ 7, 8 };
    const c1 = [_]u32{ 9, 10 };
    const c2 = [_]u32{ 11, 12 };
    const c3 = [_]u32{ 13, 14 };
    const address_columns = [_][]const u32{ &c0, &c1, &c2, &c3 };
    const address = try SourceView.memoryAddress(try SparseColumns.init(&address_columns, 2), 2, 2);
    try std.testing.expectEqual(@as(u32, 4), (try address.relationWord(1, 1, 1, 1)).v);
    try std.testing.expectEqual(@as(u32, 12), (try address.relationWord(1, 1, 2, 1)).v);
    try std.testing.expectEqual(@as(u32, 14), (try address.multiplicity(3, 1, 1)).v);

    const memory_columns = [_][]const u32{ &c0, &c1, &c2 };
    const big = try SourceView.memoryBig(try SparseColumns.init(&memory_columns, 2), 2, 2, 5);
    try std.testing.expectEqual(@as(u32, 12), (try big.relationWord(2, 1, 2, 1)).v);
    try std.testing.expectEqual(@as(u32, 0x4000_0006), (try big.relationWord(3, 0, 1, 1)).v);
    try std.testing.expectEqual(@as(u32, 12), (try big.multiplicity(4, 2, 1)).v);

    const small = try SourceView.memorySmall(try SparseColumns.init(&memory_columns, 2), 2, 2, 5);
    try std.testing.expectEqual(@as(u32, 6), (try small.relationWord(5, 0, 1, 1)).v);
    try std.testing.expectEqual(@as(u32, 10), (try small.relationWord(5, 0, 3, 1)).v);
    try std.testing.expectEqual(@as(u32, 12), (try small.multiplicity(5, 2, 1)).v);
}

test "Cairo interaction sources synthesize bitwise xor partitions" {
    const multiplicity = [_]u32{ 7, 8 };
    const columns = [_][]const u32{&multiplicity} ** 16;
    const source = try SourceView.bitwiseXor12(try SparseColumns.init(&columns, 2), 16, 2);
    try std.testing.expectEqual(@as(u32, 1024), (try source.relationWord(6, 4, 1, 0)).v);
    try std.testing.expectEqual(@as(u32, 0), (try source.relationWord(6, 4, 2, 0)).v);
    try std.testing.expectEqual(@as(u32, 1024), (try source.relationWord(6, 4, 3, 0)).v);
    try std.testing.expectEqual(@as(u32, 8), (try source.multiplicity(6, 0, 1)).v);
}

test "Cairo interaction sources resolve row readers that match element addressing" {
    const words = [_]u32{ 10, 11, 20, 21, 30, 31 };
    const c0 = [_]u32{ 7, 8 };
    const c1 = [_]u32{ 9, 10 };
    const c2 = [_]u32{ 11, 12 };
    const c3 = [_]u32{ 13, 14 };
    const address_columns = [_][]const u32{ &c0, &c1, &c2, &c3 };
    const memory_columns = [_][]const u32{ &c0, &c1, &c2 };
    const xor_columns = [_][]const u32{&c0} ** 16;

    const Case = struct {
        view: SourceView,
        kind: u32,
        arg: u32,
        words: usize,
        multiplicity_kind: u32,
        multiplicity_arg: u32,
    };
    const cases = [_]Case{
        .{
            .view = try SourceView.lookupWords(try LookupColumns.init(&words, 2), 1),
            .kind = 0,
            .arg = 0,
            .words = 3,
            .multiplicity_kind = 2,
            .multiplicity_arg = 1,
        },
        .{
            .view = try SourceView.lookupWords(try LookupColumns.init(&words, 2), 1),
            .kind = 0,
            .arg = 0,
            .words = 1,
            .multiplicity_kind = 1,
            .multiplicity_arg = 0,
        },
        .{
            .view = try SourceView.memoryAddress(
                try SparseColumns.init(&address_columns, 2),
                2,
                2,
            ),
            .kind = 1,
            .arg = 1,
            .words = 3,
            .multiplicity_kind = 3,
            .multiplicity_arg = 1,
        },
        .{
            .view = try SourceView.memoryBig(
                try SparseColumns.init(&memory_columns, 2),
                2,
                2,
                5,
            ),
            .kind = 2,
            .arg = 1,
            .words = 3,
            .multiplicity_kind = 4,
            .multiplicity_arg = 2,
        },
        .{
            .view = try SourceView.memoryBig(
                try SparseColumns.init(&memory_columns, 2),
                2,
                2,
                5,
            ),
            .kind = 3,
            .arg = 0,
            .words = 3,
            .multiplicity_kind = 0,
            .multiplicity_arg = 0,
        },
        .{
            .view = try SourceView.memorySmall(
                try SparseColumns.init(&memory_columns, 2),
                2,
                2,
                5,
            ),
            .kind = 5,
            .arg = 0,
            .words = 4,
            .multiplicity_kind = 5,
            .multiplicity_arg = 2,
        },
        .{
            .view = try SourceView.bitwiseXor12(
                try SparseColumns.init(&xor_columns, 2),
                16,
                2,
            ),
            .kind = 6,
            .arg = 4,
            .words = 4,
            .multiplicity_kind = 6,
            .multiplicity_arg = 0,
        },
    };

    for (cases) |case| {
        for (1..case.words) |word| {
            const access = try case.view.resolveWord(case.kind, case.arg, word);
            for (0..case.view.rows()) |row|
                try std.testing.expectEqual(
                    (try case.view.relationWord(case.kind, case.arg, word, row)).v,
                    (try access.value(row)).v,
                );
        }
        const multiplicity = try case.view.resolveMultiplicity(
            case.multiplicity_kind,
            case.multiplicity_arg,
        );
        for (0..case.view.rows()) |row|
            try std.testing.expectEqual(
                (try case.view.multiplicity(
                    case.multiplicity_kind,
                    case.multiplicity_arg,
                    row,
                )).v,
                (try multiplicity.value(row)).v,
            );
    }

    const Context = struct {
        fn read(_: *const anyopaque, column: usize, row: usize) Error!u32 {
            return @intCast(column * 10 + row);
        }
    };
    const context: u8 = 0;
    const lazy = try SourceView.lookupWords(
        try LookupColumns.virtual(2, 3, &context, Context.read),
        2,
    );
    const lazy_access = try lazy.resolveWord(0, 1, 1);
    try std.testing.expectEqual(@as(u32, 21), (try lazy_access.value(1)).v);
    const lazy_multiplicity = try lazy.resolveMultiplicity(2, 2);
    try std.testing.expectEqual(@as(u32, 21), (try lazy_multiplicity.value(1)).v);
    try std.testing.expectError(
        Error.InvalidDescriptor,
        lazy.resolveWord(1, 0, 1),
    );
    try std.testing.expectError(
        Error.InvalidSourceShape,
        lazy.resolveWord(0, 2, 1),
    );
}

test "Cairo interaction sources reject shape, bounds, and non-canonical values" {
    const good = [_]u32{1};
    const bad = [_]u32{m31_mod.Modulus};
    const short_columns = [_][]const u32{&good};
    try std.testing.expectError(
        Error.InvalidSourceShape,
        SourceView.memoryAddress(try SparseColumns.init(&short_columns, 1), 1, 1),
    );

    const source = try SourceView.lookupWords(try LookupColumns.init(&bad, 1), 1);
    try std.testing.expectError(Error.NonCanonicalM31, source.multiplicity(2, 0, 0));
    try std.testing.expectError(Error.InvalidDescriptor, source.validateUse(&.{ 0, 1, 2, 3, 0, 0, 0 }, 2));
    try std.testing.expectError(Error.InvalidDescriptor, source.validateUse(&.{ 0, 0, 1, 0, 0, 0, 0 }, 2));

    const columns = [_][]const u32{ &good, &good };
    const big = try SourceView.memoryBig(try SparseColumns.init(&columns, 1), 1, 1, 0x3fff_ffff);
    try std.testing.expectError(Error.NonCanonicalM31, big.relationWord(3, 0, 1, 0));
}
