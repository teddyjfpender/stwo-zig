//! Paired memory multiproof: accessed words change, shared frontier cannot.
const std = @import("std");
const plans = @import("blake3_commitment_plan.zig");
const Witness = @import("blake3_commitment_witness.zig").Witness;
const shared = @import("blake3_shared_path_emit.zig");
const tree = @import("../air/memory_commitment/blake3_state_tree.zig");
const memory = @import("../recursion/air/blake3_memory_boundary.zig");
const program = @import("../recursion/air/blake3_public_program.zig");
pub fn emit(a: std.mem.Allocator, admission: plans.Admission, source: ?*const Witness, sink: anytype) !void {
    try admission.validate();
    const plan = admission.plan;
    const last = plan.programs[plan.programs.len - 1];
    var namespace = try std.math.add(u32, last.namespace, @import("../recursion/air/blake3_program_word.zig").CIRCUIT_COUNT);
    var inputs: [2]std.ArrayList(shared.Input) = @splat(.empty);
    defer for (&inputs) |*items| items.deinit(a);
    // The complete ROM is authenticated by Plan.validate. Both proving and
    // independent verification publish the same fixed lookup tuples; no ROM
    // value is taken from witness main columns.
    for (plan.programs, 0..) |statement, i| {
        var values: [4]u32 = undefined;
        for (&values, plan.program_leaves[try plan.programLeafOffset(i) ..][0..4]) |*value, leaf| value.* = leaf.value;
        try sink.append(program, &.{try program.fixedRow(statement.address, statement.multiplicity, values)});
    }
    // Publish only admitted word lookup boundaries. Complete root projections
    // remain intact; untouched memory is authenticated by shared frontier wires.
    const leaves: [2]?[]const tree.Leaf = if (source) |w| .{ w.initial.leaves, w.final.leaves } else .{ null, null };
    var split: usize = 0;
    for (plan.memories) |statement| {
        const side: usize = if (statement.direction == .initial) 0 else 1;
        if (side == 0) split += 1;
        const index = try tree.memoryIndex(statement.address);
        const value = if (leaves[side]) |words| shared.valueAt(words, index) else 0;
        var values: [4]u8 = undefined;
        std.mem.writeInt(u32, &values, value, .little);
        try sink.append(memory, &.{if (source != null) try memory.logicalRow(statement.schedule(), values) else try memory.fixedRow(statement.schedule())});
    }
    const sides = .{ plan.memories[0..split], plan.memories[split..] };
    var at: [2]usize = @splat(0);
    while (at[0] < sides[0].len or at[1] < sides[1].len) {
        const left = if (at[0] < sides[0].len) sides[0][at[0]].address else std.math.maxInt(u32);
        const right = if (at[1] < sides[1].len) sides[1][at[1]].address else std.math.maxInt(u32);
        const address = @min(left, right);
        const index = try tree.memoryIndex(address);
        inline for (0..2) |side| {
            var constant_zero = false;
            const circuit = if (at[side] < sides[side].len and sides[side][at[side]].address == address) blk: {
                const item = sides[side][at[side]];
                at[side] += 1;
                break :blk item.source_circuit;
            } else blk: {
                // Public custody excludes this side from its ordinary root.
                // Its leaf is fixed zero, never an unconstrained private word.
                if (leaves[side]) |words| if (shared.valueAt(words, index) != 0) return error.InvalidExcludedMemoryLeaf;
                const circuit = namespace;
                namespace = try std.math.add(u32, namespace, 1);
                constant_zero = true;
                break :blk circuit;
            };
            try inputs[side].append(a, .{ .address = index, .caller = .{ .circuit = circuit, .wire = 0 }, .constant_zero = constant_zero });
        }
    }
    _ = try shared.emitPair(a, .{ inputs[0].items, inputs[1].items }, namespace, .{ plan.roots[1], plan.roots[2] }, leaves, sink);
}
