//! Legacy Full allocation accounting; imports the canonical integration module.
const std = @import("std");
const wire = @import("stwo_proof_wire");
const Full = @import("stwo_riscv_cpu_integration").rv64_full;
pub const Cells = struct { fixed: u64, main: u64, interaction: u64 };
pub const LegacySource = struct {
    cells: Cells,
    columns: [3]usize,
    /// Capture before MAIN transfer/INTER retirement. The first two counts are
    /// actual owned matrix lengths; INTER is the verified legacy typed roster.
    pub fn capture(setup: *const Full.PreparedSetup, trace: *const Full.Trace, cpu_interaction: usize) !LegacySource {
        const m = &setup.materials;
        if (trace.borrowed_main or trace.main_backing.len < trace.main.len) return error.InvalidLegacyMeasurementPhase;
        var fixed: u64 = m.cpu_fixed.len + m.rom_fixed.len + m.byte_table.fixed.len;
        if (m.and_table) |table| fixed += table.fixed.len;
        if (m.shift_table) |table| fixed += table.fixed.len;
        const providers = trace.main_backing.len - trace.main.len;
        const n = @as(u64, 1) << @intCast(trace.log_size);
        const interaction = try std.math.add(u64, try std.math.mul(u64, cpu_interaction, n), try std.math.mul(u64, providers, 8));
        return .{ .cells = .{ .fixed = fixed, .main = trace.main_backing.len, .interaction = interaction }, .columns = .{ setup.fixedCount(), trace.main.len / @as(usize, @intCast(n)) + setup.providerCount(), cpu_interaction + 8 * setup.providerCount() } };
    }
    /// A stale legacy width model fails loudly against the physical proof.
    pub fn validate(self: LegacySource, proof: *const wire.Proof) !void {
        const trees = proof.commitment_scheme_proof.sampled_values.items;
        if (trees.len != 4) return error.InvalidLegacyMeasurementProof;
        for (self.columns, trees[0..3]) |columns, tree| if (columns != tree.len) return error.InvalidLegacyMeasurementProof;
    }
};
