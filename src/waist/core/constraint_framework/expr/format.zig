//! Stable source formatting for constraint expressions.

const std = @import("std");
const expr_types = @import("types.zig");

const BaseExpr = expr_types.BaseExpr;
const ExtExpr = expr_types.ExtExpr;

pub fn formatBaseAlloc(expr: BaseExpr, allocator: std.mem.Allocator) ![]u8 {
    var out = std.ArrayList(u8).empty;
    defer out.deinit(allocator);
    try formatBaseExpr(out.writer(allocator), expr);
    return out.toOwnedSlice(allocator);
}

pub fn formatExtAlloc(expr: ExtExpr, allocator: std.mem.Allocator) ![]u8 {
    var out = std.ArrayList(u8).empty;
    defer out.deinit(allocator);
    try formatExtExpr(out.writer(allocator), expr);
    return out.toOwnedSlice(allocator);
}

fn formatBaseExpr(writer: anytype, expr: BaseExpr) !void {
    switch (expr.*) {
        .col => |col| {
            if (col.offset >= 0) {
                try writer.print(
                    "trace_{d}_column_{d}_offset_{d}",
                    .{ col.interaction, col.idx, col.offset },
                );
            } else {
                const abs_offset: usize = @intCast(-col.offset);
                try writer.print(
                    "trace_{d}_column_{d}_offset_neg_{d}",
                    .{ col.interaction, col.idx, abs_offset },
                );
            }
        },
        .constant => |value| try writer.print("m31({d}).into()", .{value.toU32()}),
        .param => |name| try writer.writeAll(name),
        .add => |pair| {
            try formatBaseExpr(writer, pair.lhs);
            try writer.writeAll(" + ");
            try formatBaseExpr(writer, pair.rhs);
        },
        .sub => |pair| {
            try formatBaseExpr(writer, pair.lhs);
            try writer.writeAll(" - (");
            try formatBaseExpr(writer, pair.rhs);
            try writer.writeAll(")");
        },
        .mul => |pair| {
            try writer.writeAll("(");
            try formatBaseExpr(writer, pair.lhs);
            try writer.writeAll(") * (");
            try formatBaseExpr(writer, pair.rhs);
            try writer.writeAll(")");
        },
        .neg => |value| {
            try writer.writeAll("-(");
            try formatBaseExpr(writer, value);
            try writer.writeAll(")");
        },
        .inv => |value| {
            try writer.writeAll("1 / (");
            try formatBaseExpr(writer, value);
            try writer.writeAll(")");
        },
    }
}

fn formatExtExpr(writer: anytype, expr: ExtExpr) !void {
    switch (expr.*) {
        .secure_col => |values| {
            if (isBaseConstZero(values[1]) and isBaseConstZero(values[2]) and isBaseConstZero(values[3])) {
                return formatBaseExpr(writer, values[0]);
            }
            try writer.writeAll("QM31Impl::from_partial_evals([");
            try formatBaseExpr(writer, values[0]);
            try writer.writeAll(", ");
            try formatBaseExpr(writer, values[1]);
            try writer.writeAll(", ");
            try formatBaseExpr(writer, values[2]);
            try writer.writeAll(", ");
            try formatBaseExpr(writer, values[3]);
            try writer.writeAll("])");
        },
        .constant => |value| {
            const arr = value.toM31Array();
            try writer.print(
                "qm31({d}, {d}, {d}, {d})",
                .{ arr[0].toU32(), arr[1].toU32(), arr[2].toU32(), arr[3].toU32() },
            );
        },
        .param => |name| try writer.writeAll(name),
        .add => |pair| {
            try formatExtExpr(writer, pair.lhs);
            try writer.writeAll(" + ");
            try formatExtExpr(writer, pair.rhs);
        },
        .sub => |pair| {
            try formatExtExpr(writer, pair.lhs);
            try writer.writeAll(" - (");
            try formatExtExpr(writer, pair.rhs);
            try writer.writeAll(")");
        },
        .mul => |pair| {
            try writer.writeAll("(");
            try formatExtExpr(writer, pair.lhs);
            try writer.writeAll(") * (");
            try formatExtExpr(writer, pair.rhs);
            try writer.writeAll(")");
        },
        .neg => |value| {
            try writer.writeAll("-(");
            try formatExtExpr(writer, value);
            try writer.writeAll(")");
        },
    }
}

fn isBaseConstZero(expr: BaseExpr) bool {
    return switch (expr.*) {
        .constant => |value| value.isZero(),
        else => false,
    };
}
