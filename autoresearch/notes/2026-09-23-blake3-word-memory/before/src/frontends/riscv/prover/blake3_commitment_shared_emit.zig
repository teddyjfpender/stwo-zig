//! One shared hash graph per independently admitted program/memory root.
const std = @import("std");
const plans = @import("blake3_commitment_plan.zig");
const Witness = @import("blake3_commitment_witness.zig").Witness;
const shared = @import("blake3_shared_path_emit.zig");
const tree = @import("../air/memory_commitment/blake3_byte_tree.zig");
const memory = @import("../recursion/air/blake3_memory_boundary.zig");
const program = @import("../recursion/air/blake3_public_program.zig");
pub fn emit(a: std.mem.Allocator, admission: plans.Admission, source: ?*const Witness, sink: anytype) !void {
    try admission.validate();
    const plan = admission.plan;
    const last = plan.programs[plan.programs.len - 1];
    var namespace = try std.math.add(u32, last.namespace, @import("../recursion/air/blake3_program_word.zig").CIRCUIT_COUNT);
    var inputs: std.ArrayList(shared.Input) = .empty;
    defer inputs.deinit(a);
    // The complete ROM is authenticated by Plan.validate. Both proving and
    // independent verification publish the same fixed lookup tuples; no ROM
    // value is taken from witness main columns.
    for (plan.programs, 0..) |statement, i| {
        var values: [4]u32 = undefined;
        for (&values, plan.program_leaves[i * 4 ..][0..4]) |*value, leaf| value.* = leaf.value;
        try sink.append(program, &.{try program.fixedRow(statement.address, statement.multiplicity, values)});
    }
    for (1..3) |group| {
        inputs.clearRetainingCapacity();
        const leaves: ?[]const tree.Leaf = if (source) |w| if (group == 1) w.initial.leaves else w.final.leaves else null;
        for (plan.memories) |statement| {
            if ((group == 1) != (statement.direction == .initial)) continue;
            var values: [4]u8 = @splat(0);
            for (&values, 0..) |*value, i| if (leaves) |bytes| {
                value.* = std.math.cast(u8, shared.valueAt(bytes, statement.address + @as(u32, @intCast(i)))) orelse return error.NonByteLeaf;
            };
            try sink.append(memory, &.{if (leaves != null) try memory.logicalRow(statement.schedule(), values) else try memory.fixedRow(statement.schedule())});
            for (0..4) |i| try inputs.append(a, .{ .address = statement.address + @as(u32, @intCast(i)), .caller = .{ .circuit = statement.source_circuit, .wire = @intCast(i) } });
        }
        namespace = try shared.emit(a, inputs.items, namespace, .memory, plan.roots[group], leaves, sink);
    }
}
