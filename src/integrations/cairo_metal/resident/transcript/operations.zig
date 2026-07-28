//! Resident transcript recipe construction and challenge publication.

const std = @import("std");
const arena_plan = @import("stwo_metal_backend").arena_plan;
const metal_runtime = @import("stwo_metal_backend").runtime;
const protocol_recipes = @import("stwo_metal_backend").protocol_recipes;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const schedule_bindings = @import("../../schedule_bindings.zig");
const Error = @import("../errors.zig").Error;

pub const Bindings = struct {
    allocator: std.mem.Allocator,
    state: arena_plan.Binding,
    inputs: []const schedule_bindings.OrdinalBinding,
    outputs: []const schedule_bindings.OrdinalBinding,
    quotient_tile: arena_plan.Binding,
    relation_z: arena_plan.Binding,
    relation_alpha_powers: arena_plan.Binding,
    canonical_claimed_sums: []const arena_plan.Binding,
};

pub fn prepare(
    bindings: Bindings,
    metal: *metal_runtime.Runtime,
    resident_arena: *arena_plan.ResidentArena,
) !protocol_recipes.TranscriptRecipe {
    const inputs = try bindings.allocator.alloc(protocol_recipes.TranscriptBinding, bindings.inputs.len);
    defer bindings.allocator.free(inputs);
    for (bindings.inputs, inputs) |source, *destination| destination.* = .{
        .ordinal = source.ordinal,
        .binding = source.binding,
    };
    const outputs = try bindings.allocator.alloc(protocol_recipes.TranscriptBinding, bindings.outputs.len);
    defer bindings.allocator.free(outputs);
    for (bindings.outputs, outputs) |source, *destination| destination.* = .{
        .ordinal = source.ordinal,
        .binding = source.binding,
    };
    return protocol_recipes.TranscriptRecipe.init(
        bindings.allocator,
        metal,
        resident_arena,
        bindings.state,
        try schedule_bindings.friStartLog(bindings.quotient_tile),
        inputs,
        outputs,
    );
}

pub fn restoreCommitmentRoot(
    resident_arena: *arena_plan.ResidentArena,
    schedule: []const std.json.Value,
    plan: arena_plan.Plan,
    tree_index: u32,
    root: [32]u8,
) !void {
    const transcript_ordinals = [_]u32{ 3, 20, 23, 24 };
    if (tree_index >= transcript_ordinals.len) return Error.InvalidCardinality;
    const destination = try schedule_bindings.oneOrdinal(
        schedule,
        plan,
        "TranscriptInput",
        transcript_ordinals[tree_index],
    );
    @memcpy((try resident_arena.bytes(destination))[0..32], &root);
}

pub fn materializeRelationChallenges(
    bindings: Bindings,
    resident_arena: *arena_plan.ResidentArena,
) !void {
    var drawn: ?arena_plan.Binding = null;
    for (bindings.outputs) |output| if (output.ordinal == 1) {
        drawn = output.binding;
        break;
    };
    const source = drawn orelse return Error.MissingBinding;
    const source_bytes = try resident_arena.bytes(source);
    if (source_bytes.len < 32 or bindings.relation_z.size_bytes < 16 or
        bindings.relation_alpha_powers.size_bytes % 16 != 0)
        return Error.InvalidBindingSize;
    const aligned_source: []align(4) u8 = @alignCast(source_bytes);
    const words = std.mem.bytesAsSlice(u32, aligned_source);
    if (std.process.hasEnvVarConstant("STWO_ZIG_SN2_LOG_STAGE_TIMINGS")) std.debug.print(
        "transcript_relation_challenges z={d},{d},{d},{d} alpha={d},{d},{d},{d}\n",
        .{ words[0], words[1], words[2], words[3], words[4], words[5], words[6], words[7] },
    );
    try restoreRelationChallenges(
        bindings,
        resident_arena,
        .{ words[0], words[1], words[2], words[3] },
        .{ words[4], words[5], words[6], words[7] },
    );
}

pub fn restoreRelationChallenges(
    bindings: Bindings,
    resident_arena: *arena_plan.ResidentArena,
    z: [4]u32,
    alpha_words: [4]u32,
) !void {
    const z_bytes: []align(4) u8 = @alignCast(try resident_arena.bytes(bindings.relation_z));
    const z_destination = std.mem.bytesAsSlice(u32, z_bytes);
    if (z_destination.len < 4 or bindings.relation_alpha_powers.size_bytes % 16 != 0)
        return Error.InvalidBindingSize;
    @memcpy(z_destination[0..4], &z);
    const alpha = QM31.fromU32Unchecked(alpha_words[0], alpha_words[1], alpha_words[2], alpha_words[3]);
    const powers_bytes = try resident_arena.bytes(bindings.relation_alpha_powers);
    const aligned_powers: []align(4) u8 = @alignCast(powers_bytes);
    const powers = std.mem.bytesAsSlice(u32, aligned_powers);
    var current = QM31.one();
    var index: usize = 0;
    while (index < powers.len / 4) : (index += 1) {
        const coordinates = current.toM31Array();
        inline for (0..4) |coordinate| powers[index * 4 + coordinate] = coordinates[coordinate].v;
        current = current.mul(alpha);
    }
}

pub fn publishInteractionClaim(
    bindings: Bindings,
    resident_arena: *arena_plan.ResidentArena,
    schedule: []const std.json.Value,
    plan: arena_plan.Plan,
) !void {
    const destination = try schedule_bindings.oneOrdinal(schedule, plan, "TranscriptInput", 22);
    if (destination.size_bytes != @as(u64, bindings.canonical_claimed_sums.len) * 16)
        return Error.InvalidBindingSize;
    const destination_bytes = try resident_arena.bytes(destination);
    for (bindings.canonical_claimed_sums, 0..) |source, index| {
        if (source.size_bytes != 16) return Error.InvalidBindingSize;
        @memcpy(destination_bytes[index * 16 ..][0..16], (try resident_arena.bytes(source))[0..16]);
    }
}
