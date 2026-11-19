//! Opt-in host/GPU diagnostics for resident Cairo interaction traces.

const std = @import("std");
const arena_plan = @import("stwo_metal_backend").arena_plan;
const schedule_bindings = @import("../../schedule_bindings.zig");
const resident_binding = @import("../binding.zig");
const Error = @import("../errors.zig").Error;
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;

const collectComponent = schedule_bindings.collectComponent;
const componentName = schedule_bindings.componentName;
const logicalId = schedule_bindings.logicalId;
const one = schedule_bindings.one;
const oneComponent = schedule_bindings.oneComponent;
const ordinal = schedule_bindings.ordinal;
const purpose = schedule_bindings.purpose;
const wordOffset = resident_binding.wordOffset;

pub fn logInteractionCoefficientDigests(
    resident_arena: *arena_plan.ResidentArena,
    schedule: []const std.json.Value,
    plan: arena_plan.Plan,
    stage: []const u8,
) !void {
    var count: usize = 0;
    for (schedule) |entry| {
        if (!std.mem.eql(u8, try purpose(entry), "InteractionCoefficients")) continue;
        const binding = plan.binding(try logicalId(entry)) catch return Error.MissingBinding;
        const bytes = try resident_arena.bytes(binding);
        if (bytes.len < 4 or bytes.len % 4 != 0 or !std.math.isPowerOfTwo(bytes.len / 4))
            return Error.InvalidBindingSize;
        const words: []align(1) const u32 = std.mem.bytesAsSlice(u32, bytes);
        var raw_digest: u64 = 0xcbf29ce484222325;
        var canonical_digest: u64 = 0xcbf29ce484222325;
        for (words) |word| {
            for (0..4) |byte_index| {
                raw_digest ^= @as(u8, @truncate(word >> @intCast(byte_index * 8)));
                raw_digest *%= 0x100000001b3;
            }
            const canonical = word % 0x7fffffff;
            for (0..4) |byte_index| {
                canonical_digest ^= @as(u8, @truncate(canonical >> @intCast(byte_index * 8)));
                canonical_digest *%= 0x100000001b3;
            }
        }
        std.debug.print(
            "interaction_coeff_digest stage={s} component={s} ordinal={} logical_id={} log_size={} first={} last={} canonical_first={} canonical_last={} raw_fnv64={x:0>16} fnv64={x:0>16}\n",
            .{
                stage,
                try componentName(entry),
                try ordinal(entry),
                binding.logical_id,
                std.math.log2_int(usize, words.len),
                words[0],
                words[words.len - 1],
                words[0] % 0x7fffffff,
                words[words.len - 1] % 0x7fffffff,
                raw_digest,
                canonical_digest,
            },
        );
        count += 1;
    }
    if (count == 0) return Error.MissingBinding;
}
