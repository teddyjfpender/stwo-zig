//! Allocation-free execution kernel for prepared typed-AIR witness writers.
//!
//! Family modules retain semantic authority: they authenticate their binding,
//! validate each source row, and provide one infallible row writer. This kernel
//! owns the shared hot-path contract: exact preallocated column geometry,
//! rejection before mutation, alias exclusion, deterministic padding, and
//! compile-time dispatch with no indirect call in the row loop.

const std = @import("std");

pub const Error = error{
    AddressOverflow,
    AliasedDestination,
    AliasedInput,
    InvalidTraceRow,
    InvalidTraceShape,
};

/// Executes a family-specific prepared writer into final column-major storage.
///
/// `protected` is the immutable prepared executor whose bytes must not overlap
/// either input or output. All validation completes before the first store;
/// after that boundary the loop is deliberately infallible and allocation-free.
pub fn generateMainInto(
    comptime Field: type,
    comptime Row: type,
    comptime column_count: usize,
    columns: *[column_count][]Field,
    rows: []const Row,
    log_size: u32,
    zero: Field,
    protected: anytype,
    comptime validateRow: anytype,
    comptime writeRow: anytype,
) Error!void {
    comptime if (column_count == 0)
        @compileError("direct witness executor requires at least one column");
    const size = try preflight(
        Field,
        Row,
        column_count,
        columns,
        rows,
        log_size,
        protected,
        validateRow,
    );

    for (columns) |column| @memset(column, zero);
    for (rows, 0..) |row, logical_row| writeRow(columns, logical_row, row);
    std.debug.assert(size == columns[0].len);
}

fn preflight(
    comptime Field: type,
    comptime Row: type,
    comptime column_count: usize,
    columns: *const [column_count][]Field,
    rows: []const Row,
    log_size: u32,
    protected: anytype,
    comptime validateRow: anytype,
) Error!usize {
    if (log_size >= @bitSizeOf(usize))
        return error.InvalidTraceShape;
    const size = @as(usize, 1) << @intCast(log_size);
    if (rows.len > size) return error.InvalidTraceShape;

    var destinations: [column_count]AddressRange = undefined;
    for (columns, 0..) |column, index| {
        if (column.len != size) return error.InvalidTraceShape;
        destinations[index] = (try rangeOf(Field, column)).?;
    }
    const descriptors = try objectRange(columns);
    const protected_storage = try objectRange(protected);
    const row_storage = try rangeOf(Row, rows);

    if (row_storage) |input| {
        if (input.overlaps(descriptors) or input.overlaps(protected_storage))
            return error.AliasedInput;
    }
    for (destinations, 0..) |destination, index| {
        if (destination.overlaps(descriptors) or
            destination.overlaps(protected_storage))
        {
            return error.AliasedDestination;
        }
        if (row_storage != null and destination.overlaps(row_storage.?))
            return error.AliasedInput;
        for (destinations[0..index]) |previous| {
            if (destination.overlaps(previous))
                return error.AliasedDestination;
        }
    }

    // Validate only after alias exclusion: adversarial slices cannot make the
    // semantic callback dereference protected or destination storage.
    for (rows) |row| try validateRow(row);
    return size;
}

const AddressRange = struct {
    start: usize,
    end: usize,

    inline fn overlaps(self: AddressRange, other: AddressRange) bool {
        return self.start < other.end and other.start < self.end;
    }
};

fn rangeOf(comptime T: type, values: []const T) Error!?AddressRange {
    if (values.len == 0) return null;
    const byte_len = std.math.mul(usize, values.len, @sizeOf(T)) catch
        return error.AddressOverflow;
    const start = @intFromPtr(values.ptr);
    const end = std.math.add(usize, start, byte_len) catch
        return error.AddressOverflow;
    return .{ .start = start, .end = end };
}

fn objectRange(pointer: anytype) Error!AddressRange {
    const info = @typeInfo(@TypeOf(pointer));
    if (info != .pointer or info.pointer.size != .one)
        @compileError("protected storage must be a single-item pointer");
    const start = @intFromPtr(pointer);
    const end = std.math.add(usize, start, @sizeOf(info.pointer.child)) catch
        return error.AddressOverflow;
    return .{ .start = start, .end = end };
}
