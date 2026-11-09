//! Opt-in arena layout and digest diagnostics.

const std = @import("std");
const stwo = @import("stwo");
const arena = stwo.backends.metal.arena_plan;

pub fn logPurposeDigests(
    resident_arena: *arena.ResidentArena,
    schedule: []const std.json.Value,
    plan: arena.Plan,
    wanted_purpose: []const u8,
) !void {
    var index: usize = 0;
    for (schedule) |entry| {
        const object = entry.object;
        if (!std.mem.eql(u8, object.get("purpose").?.string, wanted_purpose)) continue;
        const logical_id: u32 = @intCast(object.get("id").?.integer);
        const binding = try plan.binding(logical_id);
        const bytes = try resident_arena.bytes(binding);
        var digest: u64 = 0xcbf29ce484222325;
        for (bytes) |byte| {
            digest ^= byte;
            digest *%= 0x100000001b3;
        }
        const component = if (object.get("component")) |value|
            if (value == .string) value.string else ""
        else
            "";
        std.debug.print(
            "base_digest index={} id={} component={s} ordinal={} words={} first={x:0>8} last={x:0>8} fnv64={x:0>16}\n",
            .{
                index,
                logical_id,
                component,
                object.get("ordinal").?.integer,
                bytes.len / 4,
                std.mem.readInt(u32, bytes[0..4], .little),
                std.mem.readInt(u32, bytes[bytes.len - 4 ..][0..4], .little),
                digest,
            },
        );
        index += 1;
    }
}

pub fn dumpAddOpcodeCoefficients(
    resident_arena: *arena.ResidentArena,
    schedule: []const std.json.Value,
    plan: arena.Plan,
) !void {
    for ([_]u32{ 62, 64, 65, 79, 80 }) |wanted_ordinal| {
        for (schedule) |entry| {
            const object = entry.object;
            if (!std.mem.eql(u8, object.get("purpose").?.string, "BaseCoefficients")) continue;
            const component = object.get("component") orelse continue;
            if (component != .string or !std.mem.eql(u8, component.string, "add_opcode")) continue;
            if (object.get("ordinal").?.integer != wanted_ordinal) continue;
            const binding = try plan.binding(@intCast(object.get("id").?.integer));
            const path = try std.fmt.allocPrint(std.heap.page_allocator, "/tmp/sn2-metal-add-op-coeff-{}.bin", .{wanted_ordinal});
            defer std.heap.page_allocator.free(path);
            const file = try std.fs.createFileAbsolute(path, .{});
            defer file.close();
            try file.writeAll(try resident_arena.bytes(binding));
            break;
        }
    }
}

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

pub fn logPurposeLayout(
    schedule: []const std.json.Value,
    plan: arena.Plan,
    wanted_purpose: []const u8,
) !void {
    for (schedule) |entry| {
        const object = entry.object;
        if (!std.mem.eql(u8, object.get("purpose").?.string, wanted_purpose)) continue;
        const logical_id: u32 = @intCast(object.get("id").?.integer);
        const binding = try plan.binding(logical_id);
        std.debug.print(
            "arena_layout purpose={s} id={} ordinal={} offset={} end={} words={}\n",
            .{
                wanted_purpose,
                logical_id,
                object.get("ordinal").?.integer,
                binding.offset_bytes,
                binding.offset_bytes + binding.size_bytes,
                binding.size_bytes / 4,
            },
        );
    }
}

pub fn logComponentPurposeLayout(
    schedule: []const std.json.Value,
    plan: arena.Plan,
    wanted_purpose: []const u8,
    wanted_component: []const u8,
) !void {
    for (schedule) |entry| {
        const object = entry.object;
        if (!std.mem.eql(u8, object.get("purpose").?.string, wanted_purpose)) continue;
        const component_value = object.get("component") orelse continue;
        if (component_value != .string or !std.mem.eql(u8, component_value.string, wanted_component)) continue;
        const logical_id: u32 = @intCast(object.get("id").?.integer);
        const binding = try plan.binding(logical_id);
        std.debug.print(
            "arena_layout purpose={s} component={s} id={} ordinal={} offset={} end={} words={}\n",
            .{
                wanted_purpose,
                wanted_component,
                logical_id,
                object.get("ordinal").?.integer,
                binding.offset_bytes,
                binding.offset_bytes + binding.size_bytes,
                binding.size_bytes / 4,
            },
        );
    }
}
