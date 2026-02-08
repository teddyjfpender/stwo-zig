const std = @import("std");
const accumulation = @import("accumulation.zig");
const components = @import("components.zig");
const circle = @import("../circle.zig");

const CirclePointQM31 = circle.CirclePointQM31;

/// Comptime adapter that derives both verifier and prover AIR component bindings.
///
/// Required methods on `Impl`:
/// - `nConstraints(self: *const Impl) usize`
/// - `maxConstraintLogDegreeBound(self: *const Impl) u32`
/// - `traceLogDegreeBounds(self: *const Impl, allocator: Allocator) !TraceLogDegreeBounds`
/// - `maskPoints(self: *const Impl, allocator: Allocator, point: CirclePointQM31, max_log_degree_bound: u32) !MaskPoints`
/// - `preprocessedColumnIndices(self: *const Impl, allocator: Allocator) ![]usize`
/// - `evaluateConstraintQuotientsAtPoint(...) !void`
/// - `evaluateConstraintQuotientsOnDomain(...) !void`
pub fn ComponentAdapter(
    comptime Impl: type,
    comptime ProverComponentType: type,
    comptime ProverTraceType: type,
    comptime DomainEvaluationAccumulatorType: type,
) type {
    return struct {
        pub fn asVerifierComponent(self: *const Impl) components.Component {
            return .{
                .ctx = self,
                .vtable = &.{
                    .nConstraints = nConstraints,
                    .maxConstraintLogDegreeBound = maxConstraintLogDegreeBound,
                    .traceLogDegreeBounds = traceLogDegreeBounds,
                    .maskPoints = maskPoints,
                    .preprocessedColumnIndices = preprocessedColumnIndices,
                    .evaluateConstraintQuotientsAtPoint = evaluateConstraintQuotientsAtPoint,
                },
            };
        }

        pub fn asProverComponent(self: *const Impl) ProverComponentType {
            return .{
                .ctx = self,
                .vtable = &.{
                    .nConstraints = nConstraints,
                    .maxConstraintLogDegreeBound = maxConstraintLogDegreeBound,
                    .traceLogDegreeBounds = traceLogDegreeBounds,
                    .maskPoints = maskPoints,
                    .preprocessedColumnIndices = preprocessedColumnIndices,
                    .evaluateConstraintQuotientsAtPoint = evaluateConstraintQuotientsAtPoint,
                    .evaluateConstraintQuotientsOnDomain = evaluateConstraintQuotientsOnDomain,
                },
            };
        }

        fn cast(ctx: *const anyopaque) *const Impl {
            return @ptrCast(@alignCast(ctx));
        }

        fn nConstraints(ctx: *const anyopaque) usize {
            return cast(ctx).nConstraints();
        }

        fn maxConstraintLogDegreeBound(ctx: *const anyopaque) u32 {
            return cast(ctx).maxConstraintLogDegreeBound();
        }

        fn traceLogDegreeBounds(
            ctx: *const anyopaque,
            allocator: std.mem.Allocator,
        ) anyerror!components.TraceLogDegreeBounds {
            return cast(ctx).traceLogDegreeBounds(allocator);
        }

        fn maskPoints(
            ctx: *const anyopaque,
            allocator: std.mem.Allocator,
            point: CirclePointQM31,
            max_log_degree_bound: u32,
        ) anyerror!components.MaskPoints {
            return cast(ctx).maskPoints(allocator, point, max_log_degree_bound);
        }

        fn preprocessedColumnIndices(
            ctx: *const anyopaque,
            allocator: std.mem.Allocator,
        ) anyerror![]usize {
            return cast(ctx).preprocessedColumnIndices(allocator);
        }

        fn evaluateConstraintQuotientsAtPoint(
            ctx: *const anyopaque,
            point: CirclePointQM31,
            mask: *const components.MaskValues,
            evaluation_accumulator: *accumulation.PointEvaluationAccumulator,
            max_log_degree_bound: u32,
        ) anyerror!void {
            return cast(ctx).evaluateConstraintQuotientsAtPoint(
                point,
                mask,
                evaluation_accumulator,
                max_log_degree_bound,
            );
        }

        fn evaluateConstraintQuotientsOnDomain(
            ctx: *const anyopaque,
            trace: *const ProverTraceType,
            evaluation_accumulator: *DomainEvaluationAccumulatorType,
        ) anyerror!void {
            return cast(ctx).evaluateConstraintQuotientsOnDomain(trace, evaluation_accumulator);
        }
    };
}

pub const LookupRowsError = error{
    ShapeMismatch,
    IndexOutOfBounds,
    InvalidPartitionCount,
};

/// Comptime adapter for derive-like lookup row containers.
///
/// Supported field shapes on `Rows`:
/// - `[]T`
/// - `[N][]T`
pub fn LookupRowsAdapter(comptime Rows: type) type {
    const fields = std.meta.fields(Rows);

    comptime {
        for (fields) |field| {
            assertSupportedField(field.type, field.name);
        }
    }

    return struct {
        pub const Error = LookupRowsError;
        pub const Range = struct {
            start: usize,
            end: usize,
        };

        pub const RowMut = struct {
            rows: *Rows,
            index: usize,

            pub fn get(self: @This(), comptime field_name: []const u8) FieldRefType(@FieldType(Rows, field_name)) {
                const field_type = @FieldType(Rows, field_name);
                if (comptime isSlice(field_type)) {
                    return &@field(self.rows.*, field_name)[self.index];
                }
                if (comptime isArrayOfSlices(field_type)) {
                    const info = @typeInfo(field_type).array;
                    const child = sliceChild(info.child);
                    var refs: [info.len]*child = undefined;
                    inline for (0..info.len) |i| {
                        refs[i] = &@field(self.rows.*, field_name)[i][self.index];
                    }
                    return refs;
                }
                @compileError("unsupported lookup field shape");
            }
        };

        pub const RowIterator = struct {
            rows: *Rows,
            len: usize,
            index: usize = 0,

            pub fn next(self: *@This()) ?RowMut {
                if (self.index >= self.len) return null;
                const out = RowMut{
                    .rows = self.rows,
                    .index = self.index,
                };
                self.index += 1;
                return out;
            }
        };

        pub fn allocUninitialized(allocator: std.mem.Allocator, len: usize) !Rows {
            var rows: Rows = undefined;
            var initialized_fields: usize = 0;
            errdefer deinitPrefix(allocator, &rows, initialized_fields);

            inline for (fields, 0..) |field, field_idx| {
                @field(rows, field.name) = try allocField(field.type, allocator, len);
                initialized_fields = field_idx + 1;
            }
            return rows;
        }

        pub fn deinit(allocator: std.mem.Allocator, rows: *Rows) void {
            inline for (fields) |field| {
                freeField(field.type, allocator, &@field(rows.*, field.name));
            }
            rows.* = undefined;
        }

        pub fn validateShape(rows: *const Rows, len: usize) Error!void {
            inline for (fields) |field| {
                const value = @field(rows.*, field.name);
                if (comptime isSlice(field.type)) {
                    if (value.len != len) return Error.ShapeMismatch;
                } else if (comptime isArrayOfSlices(field.type)) {
                    inline for (value) |slice| {
                        if (slice.len != len) return Error.ShapeMismatch;
                    }
                } else {
                    @compileError("unsupported lookup field shape");
                }
            }
        }

        pub fn rowMutAt(rows: *Rows, len: usize, index: usize) Error!RowMut {
            try validateShape(rows, len);
            if (index >= len) return Error.IndexOutOfBounds;
            return .{
                .rows = rows,
                .index = index,
            };
        }

        pub fn iterMut(rows: *Rows, len: usize) Error!RowIterator {
            try validateShape(rows, len);
            return .{
                .rows = rows,
                .len = len,
                .index = 0,
            };
        }

        pub fn forEachRowMut(rows: *Rows, len: usize, func: anytype) anyerror!void {
            const fn_info = @typeInfo(@TypeOf(func)).@"fn";
            const ret_ty = fn_info.return_type orelse @compileError("row callback must declare a return type");
            const is_error_union = @typeInfo(ret_ty) == .error_union;
            if (!is_error_union and ret_ty != void) {
                @compileError("row callback must return void or error union");
            }

            var iter = try iterMut(rows, len);
            var row_index: usize = 0;
            while (iter.next()) |row| : (row_index += 1) {
                if (is_error_union) {
                    try @call(.auto, func, .{ row_index, row });
                } else {
                    _ = @call(.auto, func, .{ row_index, row });
                }
            }
        }

        pub fn partitionRanges(
            allocator: std.mem.Allocator,
            len: usize,
            part_count: usize,
        ) (std.mem.Allocator.Error || Error)![]Range {
            if (part_count == 0) return Error.InvalidPartitionCount;
            const ranges = try allocator.alloc(Range, part_count);

            const base = len / part_count;
            const rem = len % part_count;
            var cursor: usize = 0;
            for (ranges, 0..) |*range, i| {
                const extra: usize = if (i < rem) 1 else 0;
                const span = base + extra;
                range.* = .{
                    .start = cursor,
                    .end = cursor + span,
                };
                cursor += span;
            }
            return ranges;
        }

        fn deinitPrefix(allocator: std.mem.Allocator, rows: *Rows, initialized_fields: usize) void {
            inline for (fields, 0..) |field, field_idx| {
                if (field_idx < initialized_fields) {
                    freeField(field.type, allocator, &@field(rows.*, field.name));
                }
            }
        }
    };
}

fn allocField(comptime FieldType: type, allocator: std.mem.Allocator, len: usize) !FieldType {
    if (comptime isSlice(FieldType)) {
        return allocator.alloc(sliceChild(FieldType), len);
    }
    if (comptime isArrayOfSlices(FieldType)) {
        const info = @typeInfo(FieldType).array;
        const child = sliceChild(info.child);
        var out: FieldType = undefined;

        var init_count: usize = 0;
        errdefer {
            var i: usize = 0;
            while (i < init_count) : (i += 1) allocator.free(out[i]);
        }
        for (&out) |*slice| {
            slice.* = try allocator.alloc(child, len);
            init_count += 1;
        }
        return out;
    }
    @compileError("unsupported lookup field shape");
}

fn freeField(comptime FieldType: type, allocator: std.mem.Allocator, field_ptr: *FieldType) void {
    if (comptime isSlice(FieldType)) {
        allocator.free(field_ptr.*);
        return;
    }
    if (comptime isArrayOfSlices(FieldType)) {
        for (field_ptr.*) |slice| allocator.free(slice);
        return;
    }
    @compileError("unsupported lookup field shape");
}

fn assertSupportedField(comptime FieldType: type, comptime name: []const u8) void {
    if (isSlice(FieldType) or isArrayOfSlices(FieldType)) return;
    @compileError("unsupported lookup field shape for '" ++ name ++ "': expected []T or [N][]T");
}

fn isSlice(comptime T: type) bool {
    const info = @typeInfo(T);
    return info == .pointer and info.pointer.size == .slice;
}

fn isArrayOfSlices(comptime T: type) bool {
    const info = @typeInfo(T);
    if (info != .array) return false;
    return isSlice(info.array.child);
}

fn sliceChild(comptime SliceType: type) type {
    const info = @typeInfo(SliceType);
    if (info != .pointer or info.pointer.size != .slice) {
        @compileError("expected slice type");
    }
    return info.pointer.child;
}

fn FieldRefType(comptime FieldType: type) type {
    if (isSlice(FieldType)) {
        return *sliceChild(FieldType);
    }
    if (isArrayOfSlices(FieldType)) {
        const info = @typeInfo(FieldType).array;
        return [info.len]*sliceChild(info.child);
    }
    @compileError("unsupported lookup field shape");
}

const AirDeriveVectorFile = struct {
    meta: struct {
        schema_version: u32,
        seed: u64,
        sample_count: usize,
    },
    mixed_row_updates: []AirDeriveMixedRowUpdateVector,
    invalid_shape_cases: []AirDeriveInvalidShapeVector,
};

const AirDeriveMixedRowUpdateVector = struct {
    len: usize,
    initial_a: []u32,
    initial_b: [2][]u16,
    expected_a: []u32,
    expected_b: [2][]u16,
};

const AirDeriveInvalidShapeVector = struct {
    len: usize,
    a_len: usize,
    b_lens: [2]usize,
    expected: []const u8,
};

fn parseAirDeriveVectors(allocator: std.mem.Allocator) !std.json.Parsed(AirDeriveVectorFile) {
    const raw = try std.fs.cwd().readFileAlloc(
        allocator,
        "vectors/air_derive.json",
        4 * 1024 * 1024,
    );
    defer allocator.free(raw);
    return std.json.parseFromSlice(AirDeriveVectorFile, allocator, raw, .{
        .ignore_unknown_fields = false,
        .allocate = .alloc_always,
    });
}

test "air derive: lookup adapter alloc+iter_mut on mixed field shapes" {
    const Rows = struct {
        a: []u32,
        b: [2][]u16,
    };
    const Adapter = LookupRowsAdapter(Rows);
    const alloc = std.testing.allocator;

    var rows = try Adapter.allocUninitialized(alloc, 6);
    defer Adapter.deinit(alloc, &rows);

    try Adapter.forEachRowMut(&rows, 6, struct {
        fn call(index: usize, row: Adapter.RowMut) void {
            row.get("a").* = @as(u32, @intCast(index * 3));
            const refs = row.get("b");
            refs[0].* = @as(u16, @intCast(index));
            refs[1].* = @as(u16, @intCast(index + 17));
        }
    }.call);

    for (rows.a, 0..) |value, i| {
        try std.testing.expectEqual(@as(u32, @intCast(i * 3)), value);
        try std.testing.expectEqual(@as(u16, @intCast(i)), rows.b[0][i]);
        try std.testing.expectEqual(@as(u16, @intCast(i + 17)), rows.b[1][i]);
    }

    var iter = try Adapter.iterMut(&rows, 6);
    var visited: usize = 0;
    while (iter.next()) |row| {
        _ = row.get("a");
        visited += 1;
    }
    try std.testing.expectEqual(@as(usize, 6), visited);
}

test "air derive: lookup adapter rejects shape mismatches and bounds" {
    const Rows = struct {
        left: []u8,
        right: [2][]u8,
    };
    const Adapter = LookupRowsAdapter(Rows);
    const alloc = std.testing.allocator;

    var rows: Rows = .{
        .left = try alloc.alloc(u8, 4),
        .right = .{
            try alloc.alloc(u8, 4),
            try alloc.alloc(u8, 3),
        },
    };
    defer {
        alloc.free(rows.left);
        alloc.free(rows.right[0]);
        alloc.free(rows.right[1]);
    }

    try std.testing.expectError(Adapter.Error.ShapeMismatch, Adapter.validateShape(&rows, 4));
    try std.testing.expectError(Adapter.Error.ShapeMismatch, Adapter.iterMut(&rows, 4));
}

test "air derive: lookup adapter partition ranges deterministic" {
    const Rows = struct {
        values: []u32,
    };
    const Adapter = LookupRowsAdapter(Rows);
    const alloc = std.testing.allocator;

    const ranges = try Adapter.partitionRanges(alloc, 10, 3);
    defer alloc.free(ranges);

    try std.testing.expectEqual(@as(usize, 3), ranges.len);
    try std.testing.expectEqual(@as(usize, 0), ranges[0].start);
    try std.testing.expectEqual(@as(usize, 4), ranges[0].end);
    try std.testing.expectEqual(@as(usize, 4), ranges[1].start);
    try std.testing.expectEqual(@as(usize, 7), ranges[1].end);
    try std.testing.expectEqual(@as(usize, 7), ranges[2].start);
    try std.testing.expectEqual(@as(usize, 10), ranges[2].end);

    try std.testing.expectError(Adapter.Error.InvalidPartitionCount, Adapter.partitionRanges(alloc, 10, 0));
}

test "air derive: vector parity mixed row updates" {
    const Rows = struct {
        a: []u32,
        b: [2][]u16,
    };
    const Adapter = LookupRowsAdapter(Rows);
    const alloc = std.testing.allocator;

    var parsed = try parseAirDeriveVectors(alloc);
    defer parsed.deinit();

    try std.testing.expect(parsed.value.meta.schema_version == 1);
    try std.testing.expect(parsed.value.mixed_row_updates.len > 0);

    for (parsed.value.mixed_row_updates) |vector| {
        var rows = try Adapter.allocUninitialized(alloc, vector.len);
        defer Adapter.deinit(alloc, &rows);

        try std.testing.expectEqual(vector.len, vector.initial_a.len);
        try std.testing.expectEqual(vector.len, vector.expected_a.len);
        try std.testing.expectEqual(vector.len, vector.initial_b[0].len);
        try std.testing.expectEqual(vector.len, vector.initial_b[1].len);
        try std.testing.expectEqual(vector.len, vector.expected_b[0].len);
        try std.testing.expectEqual(vector.len, vector.expected_b[1].len);

        @memcpy(rows.a, vector.initial_a);
        @memcpy(rows.b[0], vector.initial_b[0]);
        @memcpy(rows.b[1], vector.initial_b[1]);

        try Adapter.forEachRowMut(&rows, vector.len, struct {
            fn call(index: usize, row: Adapter.RowMut) void {
                row.get("a").* ^= @as(u32, @intCast(index * 7));
                const refs = row.get("b");
                refs[0].* +%= @as(u16, @intCast(index));
                refs[1].* ^= @as(u16, @intCast(index * 3 + 1));
            }
        }.call);

        try std.testing.expectEqualSlices(u32, vector.expected_a, rows.a);
        try std.testing.expectEqualSlices(u16, vector.expected_b[0], rows.b[0]);
        try std.testing.expectEqualSlices(u16, vector.expected_b[1], rows.b[1]);
    }
}

test "air derive: vector parity invalid shape cases" {
    const Rows = struct {
        a: []u8,
        b: [2][]u8,
    };
    const Adapter = LookupRowsAdapter(Rows);
    const alloc = std.testing.allocator;

    var parsed = try parseAirDeriveVectors(alloc);
    defer parsed.deinit();
    try std.testing.expect(parsed.value.invalid_shape_cases.len > 0);

    for (parsed.value.invalid_shape_cases) |vector| {
        try std.testing.expectEqualStrings("ShapeMismatch", vector.expected);

        var rows: Rows = .{
            .a = try alloc.alloc(u8, vector.a_len),
            .b = .{
                try alloc.alloc(u8, vector.b_lens[0]),
                try alloc.alloc(u8, vector.b_lens[1]),
            },
        };
        defer {
            alloc.free(rows.a);
            alloc.free(rows.b[0]);
            alloc.free(rows.b[1]);
        }

        try std.testing.expectError(Adapter.Error.ShapeMismatch, Adapter.validateShape(&rows, vector.len));
    }
}
