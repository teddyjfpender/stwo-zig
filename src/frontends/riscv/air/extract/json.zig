//! Serialise an extracted `model.System` into the flat IR encoding that
//! `scripts/air_uniqueness_lib/ir.py` accepts (`from_dict`, `nodes` form).
//!
//! The wire shape is owned by that module; this writer only has to keep node
//! references as arena indices, which are already a topological order.

const std = @import("std");
const symbolic = @import("symbolic.zig");
const model = @import("model.zig");

pub const MODULUS: u32 = (1 << 31) - 1;

/// What a green result does and does not establish. Emitted into every model
/// so the scope travels with the artefact instead of living only in a report.
pub const SCOPE_NOTE =
    \\Extracted from the shipped AIR by instantiating air/semantics over a
    \\recording scalar; the QM31 instantiation of the same source is what the
    \\prover evaluates, and a differential test pins the two together on random
    \\assignments.  Covered: per-row witness uniqueness of the emitted machine
    \\state, given the fetched instruction and the consumed bus values, granting
    \\that a live lookup numerator implies table membership.  NOT covered:
    \\anything cross-row or multiset -- the LogUp memory argument, clock
    \\monotonicity, state-chain telescoping, program binding, public boundary
    \\closure -- nor completeness, nor agreement with Sail.
;

pub fn write(
    writer: *std.Io.Writer,
    arena: *const symbolic.Arena,
    system: model.System,
) !void {
    try writer.print("{{\n  \"family\": \"{s}\",\n", .{@tagName(system.family)});
    try writer.print("  \"modulus\": {d},\n", .{MODULUS});
    try writer.writeAll("  \"notes\": ");
    try writeString(writer, SCOPE_NOTE);
    try writer.print(",\n  \"unmodelled_bus_requests\": {d},\n", .{system.unmodelled_bus_requests});

    try writer.writeAll("  \"columns\": [\n");
    for (system.columns, 0..) |column, index| {
        try writer.writeAll("    {\"name\": ");
        try writeString(writer, column.name);
        try writer.print(", \"role\": \"{s}\"}}", .{@tagName(column.role)});
        try writer.writeAll(if (index + 1 == system.columns.len) "\n" else ",\n");
    }
    try writer.writeAll("  ],\n  \"nodes\": [\n");
    for (arena.nodes.items, 0..) |node, index| {
        switch (node.op) {
            .constant => try writer.print("    {{\"op\": \"const\", \"value\": {d}}}", .{node.value}),
            .column => {
                try writer.writeAll("    {\"op\": \"col\", \"name\": ");
                try writeString(writer, arena.names.items[node.value]);
                try writer.writeAll("}");
            },
            .neg => try writer.print("    {{\"op\": \"neg\", \"args\": [{d}]}}", .{node.lhs}),
            else => try writer.print(
                "    {{\"op\": \"{s}\", \"args\": [{d}, {d}]}}",
                .{ @tagName(node.op), node.lhs, node.rhs },
            ),
        }
        try writer.writeAll(if (index + 1 == arena.nodes.items.len) "\n" else ",\n");
    }
    try writer.writeAll("  ],\n  \"constraints\": [");
    for (system.constraints, 0..) |node, index| {
        try writer.print("{s}{d}", .{ if (index == 0) "" else ", ", node });
    }
    try writer.writeAll("],\n  \"lookups\": [\n");
    for (system.lookups, 0..) |lookup, index| {
        try writer.writeAll("    {\"label\": ");
        try writeString(writer, lookup.label);
        try writer.print(
            ", \"domain\": \"{s}\", \"numerator\": {d}, \"tuple\": [",
            .{ @tagName(lookup.domain), lookup.numerator },
        );
        for (lookup.tuple, 0..) |node, position| {
            try writer.print("{s}{d}", .{ if (position == 0) "" else ", ", node });
        }
        try writer.writeAll("]}");
        try writer.writeAll(if (index + 1 == system.lookups.len) "\n" else ",\n");
    }
    try writer.writeAll("  ]\n}\n");
}

fn writeString(writer: *std.Io.Writer, text: []const u8) !void {
    try writer.writeByte('"');
    for (text) |byte| switch (byte) {
        '"' => try writer.writeAll("\\\""),
        '\\' => try writer.writeAll("\\\\"),
        '\n' => try writer.writeAll("\\n"),
        else => try writer.writeByte(byte),
    };
    try writer.writeByte('"');
}
