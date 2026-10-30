//! Every physical claim in the shared Keccak STARK, before interaction roots.
const std = @import("std");
const core = @import("stwo_core");
const Q = core.fields.qm31.QM31;
const Source = @import("block_v7_keccak_batch_source_v1.zig");
const Memory = @import("block_v7_keccak_window_memory_v1.zig");
const Lookup = @import("block_v7_keccak_window_lookup_v1.zig");
const Algebra = @import("block_v5_precompile_lookup_algebra_v1.zig");
pub const Claims = struct {
    keccak: @import("../air/guest_precompile/keccakf_component.zig").Claim,
    chi: Q,
    xor5: Q,
    controls: []const [3]Q,
    tables: [Lookup.SLOT_COUNT]Algebra.Claim,
    memory: [Memory.SLOT_COUNT]Memory.Claim,
    pub fn validate(self: *const Claims, pin: Source.Pin) !void {
        try self.keccak.validate();
        const k = self.keccak;
        const g = pin.geometry;
        if (k.log_size != g.log_size or k.n_rows != g.n_rows or k.first_call_index != g.first_call_index or k.call_count != g.call_count or self.controls.len != pin.windows.len) return error.UntrustedKeccakBatchClaims;
        for (self.memory) |claim| if (claim.active_count != pin.geometry.call_count) return error.UntrustedKeccakBatchMemoryCensus;
        // The table projection independently pins each slot's exact row count.
        for (self.tables) |claim| if (claim.row_count != @as(u32, 1) << @intCast(g.log_size)) return error.UntrustedKeccakBatchTableCensus;
    }
    pub fn record(self: *const Claims, pin: Source.Pin, entry: @import("block_v7_execution_epoch_v1.zig").Entry, ch: *core.proof_suites.Blake3.Channel) !void {
        try self.validate(pin);
        try Source.claimPrefix(ch, entry);
        ch.mixU32s(&.{ self.keccak.log_size, self.keccak.n_rows, self.keccak.first_call_index, self.keccak.call_count, @intCast(self.controls.len), Lookup.SLOT_COUNT, Memory.SLOT_COUNT });
        for (self.keccak.batch_sums) |v| try mix(ch, v);
        try mix(ch, self.keccak.component_sum);
        try mix(ch, self.chi);
        try mix(ch, self.xor5);
        for (self.controls) |frame| for (frame) |v| try mix(ch, v);
        for (self.tables) |claim| {
            ch.mixU64(claim.row_count);
            try mix(ch, claim.sum);
        }
        for (self.memory) |claim| {
            ch.mixU64(claim.active_count);
            try mix(ch, claim.transition_sum);
            for (claim.range_claims) |v| try mix(ch, v);
            try mix(ch, claim.universal_sum);
        }
    }
    /// Pure arithmetic only; proof verification must precede authority.
    pub fn open(self: *const Claims, pin: Source.Pin, slots: []const @import("block_v5_precompile_lookup_source_v1.zig").Slot) !@import("block_v7_keccak_batch_closure_v1.zig").Open {
        try self.validate(pin);
        if (slots.len != self.tables.len) return error.UntrustedKeccakBatchClaims;
        var out = @import("block_v7_keccak_batch_closure_v1.zig").Open{ .controls = self.controls, .arithmetic_sum = self.keccak.component_sum.add(self.chi).add(self.xor5), .table_requests = @splat(Q.zero()), .universal_opposite = Q.zero(), .transition_sum = Q.zero(), .byte_requests = Q.zero(), .event_count = 0 };
        for (self.tables, slots) |claim, slot| {
            if (claim.row_count != slot.n_rows) return error.UntrustedKeccakBatchTableCensus;
            out.table_requests[@intFromEnum(slot.table)] = out.table_requests[@intFromEnum(slot.table)].add(claim.sum);
        }
        for (self.memory) |claim| {
            out.universal_opposite = out.universal_opposite.add(claim.universal_sum);
            out.transition_sum = out.transition_sum.add(claim.transition_sum);
            for (claim.range_claims) |v| out.byte_requests = out.byte_requests.add(v);
            out.event_count = try std.math.add(u64, out.event_count, claim.active_count);
        }
        try @import("block_v7_keccak_batch_closure_v1.zig").requireClosed(pin, out);
        return out;
    }
};
fn mix(ch: *core.proof_suites.Blake3.Channel, v: Q) !void {
    for (v.toM31Array()) |limb| if (limb.v >= core.fields.m31.Modulus) return error.NonCanonicalM31;
    ch.mixFelts(&.{v});
}
