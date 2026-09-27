//! Distinct compact/public bridge public supply. Original lazy public-root
//! sources remain genuine typed sources; metadata is never a verified slot.
const std = @import("std");
const core = @import("stwo_core");
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const Owner = @import("block_v5_heterogeneous_scoped_owner_v1.zig");
const Compact = @import("block_v5_heterogeneous_scoped_source_v1.zig");
const Public = @import("block_v5_heterogeneous_scoped_public_source_v1.zig");
const Plan = @import("block_v5_heterogeneous_scoped_public_plan_v1.zig");
const Wire = @import("block_v5_heterogeneous_scoped_public_bus_v1.zig").Wire;
pub const Values = struct {
    owner: *const Owner.Owner,
    compact: *const Compact.Source,
    public: *const Public.Source,
    plan: *const Plan.Plan,
    /// Exact exported three-term fields plus four Boolean carry fields per
    /// adjacent window, all constrained from actual lower-child byte sources.
    outputs: []const Q,
    pub const complete_block_authority = false;
    pub fn validate(self: Values) !void {
        var lease = try self.owner.borrow();
        defer lease.deinit();
        const original = try self.owner.source(self.owner.cohorts.root);
        try self.compact.validate();
        if (!std.meta.eql(self.compact.seal, original.seal) or !std.meta.eql(self.compact.ref, self.owner.cohorts.root)) return error.UnpairedScopedPublicSource;
        try self.plan.validate(self.owner, self.public);
        const count = self.plan.windows.len;
        if (count == 0 or self.outputs.len != try std.math.add(usize, try std.math.mul(usize, count, 3), try std.math.mul(usize, count - 1, 4))) return error.UntrustedScopedPublicBridgeCensus;
        for (self.outputs) |value| for (value.toM31Array()) |limb| if (limb.v >= core.fields.m31.Modulus) return error.NoncanonicalScopedSummary;
        if (self.compact.span == null) return error.MissingScopedPublicNativeSpan;
        // These old compact/native protocols still reject unsupported wide
        // native spans; the full-u64 graph below cannot relabel them.
        try @import("block_v5_open_parent_public_bus_v1.zig").validateSpanBound(self.compact.span.?);
    }
    pub fn at(self: Values, wire: Wire) ![4]M {
        var bytes: [4]M = undefined;
        switch (wire.kind) {
            .child_cell => switch (wire.child) {
                0 => bytes = if (wire.coordinate < self.compact.cells.len) self.compact.cells[wire.coordinate] else return error.InvalidScopedPublicSchedule,
                1 => bytes = try self.public.fresh.normalized.cell(wire.coordinate),
                else => return error.InvalidScopedPublicSchedule,
            },
            .child_term => {
                if (wire.part != null) return error.InvalidScopedPublicSchedule;
                const terms = switch (wire.child) {
                    0 => self.compact.terms,
                    1 => self.public.terms,
                    else => return error.InvalidScopedPublicSchedule,
                };
                return if (wire.coordinate < terms.len) terms[wire.coordinate].coordinates else error.InvalidScopedPublicSchedule;
            },
            .output_slot => {
                const index = wire.coordinate / 4;
                if (index >= self.outputs.len) return error.InvalidScopedPublicSchedule;
                bytes = wordBytes(self.outputs[index].toM31Array()[wire.coordinate % 4].v);
            },
            .output_span => {
                const span = self.compact.span orelse return error.MissingScopedPublicNativeSpan;
                const words = [_]u32{ @truncate(span.first_cycle), @truncate(span.first_cycle >> 32), @truncate(span.last_cycle), @truncate(span.last_cycle >> 32), span.first_index, span.segment_count, span.initial_pc, span.final_pc };
                if (wire.coordinate >= words.len) return error.InvalidScopedPublicSchedule;
                bytes = wordBytes(words[wire.coordinate]);
            },
            .child_span => return error.InvalidScopedPublicSchedule,
        }
        return if (wire.part) |part| .{ bytes[part], M.zero(), M.zero(), M.zero() } else bytes;
    }
    pub fn mix(self: Values, channel: anytype) void {
        channel.mixU32s(&.{ 0x42354743, 0x4d503156, 1, 0, @intCast(self.plan.windows.len), @intCast(self.outputs.len) }); // OPEN source authority.
        channel.mixRoot(self.owner.pinned_identity);
        channel.mixRoot(self.owner.pins.coverage);
        channel.mixRoot(self.owner.pins.source);
        channel.mixRoot(self.plan.pinned_digest);
        channel.mixRoot(self.compact.expected_id);
        channel.mixRoot(self.compact.public_input_digest);
        channel.mixRoot(self.compact.seal);
        channel.mixRoot(self.public.expected_id);
        channel.mixRoot(self.public.fresh.normalized.public_input_digest);
        channel.mixRoot(self.public.fresh.normalization_source);
        channel.mixU32s(&.{@intFromBool(self.compact.span != null)});
        if (self.compact.span) |span| {
            channel.mixU32s(&.{ span.first_index, span.segment_count, span.initial_pc, span.final_pc });
            channel.mixU64(span.first_cycle);
            channel.mixU64(span.last_cycle);
            channel.mixRoot(span.job_id);
            channel.mixRoot(span.source_image_digest);
            channel.mixRoot(span.sealed_digest);
        }
        channel.mixFelts(self.outputs);
    }
};
fn wordBytes(value: u32) [4]M {
    var bytes: [4]M = undefined;
    for (&bytes, 0..) |*byte, part| byte.* = M.fromCanonical((value >> @as(u5, @intCast(8 * part))) & 255);
    return bytes;
}
