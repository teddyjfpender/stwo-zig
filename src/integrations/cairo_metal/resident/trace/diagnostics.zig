//! Opt-in diagnostics for resident Cairo trace evaluations.

const std = @import("std");
const arena_plan = @import("stwo_metal_backend").arena_plan;
const schedule_bindings = @import("../../schedule_bindings.zig");
const Error = @import("../errors.zig").Error;

const componentName = schedule_bindings.componentName;
const logicalId = schedule_bindings.logicalId;
const ordinal = schedule_bindings.ordinal;
const purpose = schedule_bindings.purpose;

pub fn logComponentBaseEvalDigests(
    resident_arena: *arena_plan.ResidentArena,
    schedule: []const std.json.Value,
    plan: arena_plan.Plan,
    component: []const u8,
) !void {
    var local_index: usize = 0;
    for (schedule) |entry| {
        if (!std.mem.eql(u8, try purpose(entry), "BaseTrace") or
            !std.mem.eql(u8, try componentName(entry), component)) continue;
        const output = plan.binding(try logicalId(entry)) catch return Error.MissingBinding;
        const bytes = try resident_arena.bytes(output);
        if (bytes.len < 4 or bytes.len % 4 != 0 or !std.math.isPowerOfTwo(bytes.len / 4))
            return Error.InvalidBindingSize;
        var digest: u64 = 0xcbf29ce484222325;
        for (bytes) |byte| {
            digest ^= byte;
            digest *%= 0x100000001b3;
        }
        const words: []align(1) const u32 = std.mem.bytesAsSlice(u32, bytes);
        std.debug.print(
            "base_eval_digest component={s} local_index={} logical_id={} ordinal={} log_size={} first={} last={} fnv64={x:0>16}\n",
            .{
                component,
                local_index,
                output.logical_id,
                try ordinal(entry),
                std.math.log2_int(usize, words.len),
                words[0],
                words[words.len - 1],
                digest,
            },
        );
        if (std.process.hasEnvVarConstant("STWO_ZIG_SN2_DUMP_BASE_EVAL_LOGICAL_ID")) {
            const wanted_text = try std.process.getEnvVarOwned(
                std.heap.page_allocator,
                "STWO_ZIG_SN2_DUMP_BASE_EVAL_LOGICAL_ID",
            );
            defer std.heap.page_allocator.free(wanted_text);
            const wanted = std.fmt.parseInt(u32, wanted_text, 10) catch return Error.InvalidSchedule;
            if (wanted == output.logical_id) {
                const path = try std.process.getEnvVarOwned(
                    std.heap.page_allocator,
                    "STWO_ZIG_SN2_DUMP_BASE_EVAL_PATH",
                );
                defer std.heap.page_allocator.free(path);
                const file = try std.fs.createFileAbsolute(path, .{});
                defer file.close();
                try file.writeAll(bytes);
                std.debug.print(
                    "base_eval_dump logical_id={} path={s} words={}\n",
                    .{ output.logical_id, path, words.len },
                );
            }
        }
        local_index += 1;
    }
    if (local_index == 0) return Error.MissingBinding;
}
