//! Opt-in arena layout and digest diagnostics.

const std = @import("std");
const stwo = @import("stwo");
const arena = stwo.backends.metal.arena_plan;

pub fn logAddOpcodeCoefficientDigests(
    resident_arena: *arena.ResidentArena,
    schedule: []const std.json.Value,
    plan: arena.Plan,
    stage: []const u8,
) !void {
    for ([_]u32{ 62, 64, 65, 79, 80 }) |wanted_ordinal| {
        for (schedule) |entry| {
            const object = entry.object;
            if (!std.mem.eql(u8, object.get("purpose").?.string, "BaseCoefficients")) continue;
            const component = object.get("component") orelse continue;
            if (component != .string or !std.mem.eql(u8, component.string, "add_opcode")) continue;
            if (object.get("ordinal").?.integer != wanted_ordinal) continue;
            const binding = try plan.binding(@intCast(object.get("id").?.integer));
            const bytes = try resident_arena.bytes(binding);
            var digest: u64 = 0xcbf29ce484222325;
            for (bytes) |byte| {
                digest ^= byte;
                digest *%= 0x100000001b3;
            }
            std.debug.print(
                "native_add_opcode_coeff_digest stage={s} ordinal={} first={x:0>8} last={x:0>8} fnv64={x:0>16}\n",
                .{
                    stage,
                    wanted_ordinal,
                    std.mem.readInt(u32, bytes[0..4], .little),
                    std.mem.readInt(u32, bytes[bytes.len - 4 ..][0..4], .little),
                    digest,
                },
            );
            break;
        }
    }
}
