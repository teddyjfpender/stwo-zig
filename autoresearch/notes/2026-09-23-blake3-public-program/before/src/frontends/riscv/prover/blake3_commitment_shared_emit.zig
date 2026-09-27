//! One shared hash graph per independently admitted program/memory root.
const std = @import("std");
const plans = @import("blake3_commitment_plan.zig");
const Witness = @import("blake3_commitment_witness.zig").Witness;
const shared = @import("blake3_shared_path_emit.zig");
const tree = @import("../air/memory_commitment/blake3_byte_tree.zig");
const memory = @import("../recursion/air/blake3_memory_boundary.zig");
const program = @import("../recursion/air/blake3_program_boundary.zig");
const packing = @import("../recursion/air/qm31_pack_wire.zig");
const encoding = @import("../recursion/air/blake3_field_bytes.zig");
const Q = @import("stwo_core").fields.qm31.QM31;
pub fn emit(a: std.mem.Allocator, admission: plans.Admission, source: ?*const Witness, sink: anytype) !void {
    try admission.validate();
    const plan = admission.plan;
    const last = plan.programs[plan.programs.len - 1];
    var namespace = try std.math.add(u32, last.namespace, @import("../recursion/air/blake3_program_word.zig").CIRCUIT_COUNT);
    var inputs: std.ArrayList(shared.Input) = .empty;
    defer inputs.deinit(a);
    for (0..3) |group| {
        inputs.clearRetainingCapacity();
        const leaves: ?[]const tree.Leaf = if (source) |w| switch (group) {
            0 => w.program.leaves,
            1 => w.initial.leaves,
            else => w.final.leaves,
        } else null;
        if (group == 0) {
            for (plan.programs) |statement| {
                var values: [4]u32 = @splat(0);
                for (&values, 0..) |*value, i| if (leaves) |bytes| {
                    value.* = shared.valueAt(bytes, statement.address + @as(u32, @intCast(i)));
                };
                const row = if (leaves != null) try program.logicalRow(statement.schedule(), values) else try program.fixedRow(statement.schedule());
                const coordinates = Q.fromM31Array(row[0..4].*);
                try sink.append(program, &.{row});
                try sink.append(packing, &.{if (leaves != null) try packing.logicalRow(statement.packSchedule(), coordinates) else try packing.fixedRow(statement.packSchedule())});
                try sink.append(encoding, &.{if (leaves != null) try encoding.logicalRow(statement.encodingSchedule(), coordinates) else try encoding.fixedRow(statement.encodingSchedule())});
                for (0..4) |i| try inputs.append(a, .{ .address = statement.address + @as(u32, @intCast(i)), .caller = .{ .circuit = statement.namespace + 2, .wire = @intCast(i) } });
            }
        } else {
            for (plan.memories) |statement| {
                if ((group == 1) != (statement.direction == .initial)) continue;
                var values: [4]u8 = @splat(0);
                for (&values, 0..) |*value, i| if (leaves) |bytes| {
                    value.* = std.math.cast(u8, shared.valueAt(bytes, statement.address + @as(u32, @intCast(i)))) orelse return error.NonByteLeaf;
                };
                try sink.append(memory, &.{if (leaves != null) try memory.logicalRow(statement.schedule(), values) else try memory.fixedRow(statement.schedule())});
                for (0..4) |i| try inputs.append(a, .{ .address = statement.address + @as(u32, @intCast(i)), .caller = .{ .circuit = statement.source_circuit, .wire = @intCast(i) } });
            }
        }
        namespace = try shared.emit(a, inputs.items, namespace, if (group == 0) .program else .memory, plan.roots[group], leaves, sink);
    }
}
