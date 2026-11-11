//! Source-derived phase admission for streamed/checkpointed truth GKR.
//! Requested bytes only: immutable FIXED setup, original capture/advice,
//! allocator metadata and thread stacks require coordinator reservations.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const A = @import("stwo_riscv_frontend").rv64_air;
const Shapes = @import("authority.zig");
const Wire = @import("../../word16_global_execution/services/wire.zig");
const Reviewed = @import("../../word16_global_execution/services/gkr_local/resource.zig");
const Numerical = engine.lookups.resource.ForField(core.fields.om31.OM31);
const Classic = @import("../../word16_global_execution/services/gkr_local/classic_witness.zig");
const GW = @import("../../word16_global_execution/services/gkr_local/truth_global_witness.zig");
fn add(x: usize, y: usize) !usize {
    return std.math.add(usize, x, y);
}
fn mul(x: usize, y: usize) !usize {
    return std.math.mul(usize, x, y);
}
pub const Plan = struct {
    padded_facts: usize = 0,
    checkpoint_bank_bytes: usize = 0,
    first_secure_checkpoint_bytes: usize = 0,
    numerical_working_bytes: usize = 0,
    numerical_metadata_bytes: usize = 0,
    child_peak_bytes: usize = 0,
    main_bytes: usize = 0,
    interaction_bytes: usize = 0,
    binding_bytes: usize = 0,
    binding_scratch_bytes: usize = 0,
    durable_metadata_bytes: usize = 0,
    main_merkle_bytes: usize = 0,
    resident_main_bytes: usize = 0,
    stage1_peak_bytes: usize = 0,
    gkr_phase_peak_bytes: usize = 0,
    binding_phase_peak_bytes: usize = 0,
    pcs_phase_payload_bytes: usize = 0,
    whole_peak_bytes: usize = 0,
    /// The numerical52B/fact bound is source-reviewed. The PCS term separately
    /// reserves source-column evaluations, coefficients, full trees, FFT batches,
    /// FRI work, sampled/opening data and32MiB packed-row workspaces. The actual
    /// worker allocator remains the final hard limit; this is not an RSS claim.
    pub fn admit(self: Plan, limits: anytype) !void {
        if (limits.live_bytes == 0 or limits.gkr_bytes == 0) return error.OpTruthLocalBudget;
        if (self.main_bytes > limits.main_bytes or self.interaction_bytes > limits.interaction_bytes or self.child_peak_bytes > limits.gkr_bytes or self.whole_peak_bytes > limits.live_bytes) return error.OpTruthLocalBudget;
    }
};
pub fn derive(d: Wire.TruthDeclaration, config: core.pcs.PcsConfig) !Plan {
    const shapes = try Shapes.shapesForDeclaration(d);
    var out = Plan{};
    var numerical = Numerical.Plan{};
    var max_log: u32 = 0;
    var columns: usize = 0;
    var max_lanes: usize = 0;
    var global_scratch: usize = 0;
    for (shapes) |shape| {
        const instance = shape.instance();
        const rows = try instance.rows();
        const facts = try instance.facts();
        const variables = try instance.variables();
        try numerical.add(.{ .kind = .multiplicities, .variables = variables });
        out.padded_facts = try add(out.padded_facts, facts);
        var height: usize = @min(2, variables);
        const first = try mul(facts >> @intCast(height), 64);
        out.first_secure_checkpoint_bytes = @max(out.first_secure_checkpoint_bytes, first);
        while (true) {
            out.checkpoint_bank_bytes = try add(out.checkpoint_bank_bytes, try mul(facts >> @intCast(height), 64));
            if (height == variables) break;
            height += if (height + 2 <= variables) @as(usize, 2) else 1;
        }
        out.main_bytes = try add(out.main_bytes, try mul(try mul(shape.widths()[1], rows), 4));
        out.interaction_bytes = try add(out.interaction_bytes, try mul(try mul(shape.widths()[2], rows), 4));
        out.binding_bytes = try add(out.binding_bytes, try mul(rows, 64));
        max_lanes = @max(max_lanes, @as(usize, 1) << @intCast(try instance.laneLog()));
        max_log = @max(max_log, instance.row_log);
        for (shape.widths()) |width| columns = try add(columns, width);
        if (shape.globalWidth() != 0) global_scratch = @max(global_scratch, try Classic.scratchByteUpperBound(instance.row_log, GW.inverseCountFor(instance)));
    }
    try numerical.finish();
    out.numerical_metadata_bytes = try add(numerical.metadata_bytes, 65536);
    out.numerical_working_bytes = try mul(out.padded_facts, Reviewed.SOURCE_CHECKPOINT_BYTES_PER_FACT);
    out.child_peak_bytes = try add(out.numerical_working_bytes, out.numerical_metadata_bytes);
    out.binding_scratch_bytes = try mul(max_lanes, 128);
    if (d.family == .keccak) {
        const policy = shapes[0].original.keccak_policy;
        const active = try mul(try std.math.divCeil(usize, d.calls, 2), policy.geometry().rowsPerPair());
        out.durable_metadata_bytes = try add(try mul(active, @sizeOf(A.crypto.keccak.trace.PackedRow)), try mul(@as(usize, 1) << @intCast(d.logs[0]), 4 * A.crypto.keccak.layout.FIXED));
        for (shapes[1..]) |shape| out.durable_metadata_bytes = try add(out.durable_metadata_bytes, try mul(try shape.instance().rows(), 40));
    } else {
        const program = A.crypto.secp256k1.program.get(if (d.family == .add) .add else .double);
        for ([_]A.crypto.secp256k1.layout.Kind{ .product, .linear }, d.logs) |kind, log| out.durable_metadata_bytes = try add(out.durable_metadata_bytes, try add(try mul(try mul(d.calls, program.rows(kind == .product)), A.crypto.secp256k1.layout.metadataByteCount(kind)), try mul(@as(usize, 1) << @intCast(log), 4 * A.crypto.secp256k1.layout.FIXED)));
        out.durable_metadata_bytes = try add(out.durable_metadata_bytes, 4096);
    }
    const merkle_log = @max(16, try std.math.add(u32, max_log, config.fri_config.log_blowup_factor));
    if (merkle_log > 30) return error.InvalidTruthGkrGeometry;
    const domain = @as(usize, 1) << @intCast(merkle_log);
    out.main_merkle_bytes = try add(try mul(try std.math.sub(usize, try mul(domain, 2), 1), 36), try mul(merkle_log + 1, 32));
    const headers = try add(65536, try mul(columns, 256));
    out.resident_main_bytes = try add(out.main_bytes, try add(out.main_merkle_bytes, try add(out.durable_metadata_bytes, headers)));
    const fft_batch = try mul(try mul(domain, 64), 8);
    out.stage1_peak_bytes = try add(out.resident_main_bytes, try add(out.main_bytes, fft_batch));
    out.gkr_phase_peak_bytes = try add(out.resident_main_bytes, out.child_peak_bytes);
    out.binding_phase_peak_bytes = try add(out.resident_main_bytes, try add(out.interaction_bytes, try add(global_scratch, try add(out.binding_scratch_bytes, out.numerical_metadata_bytes))));
    // Source rows at their own heights; two complete coset views bound all prior
    // masks. This intentionally overcounts small-table and fixed columns.
    const native_rows = @as(usize, 1) << @intCast(max_log);
    const composition = try mul(try mul(columns, native_rows), 8);
    const fri = try mul(domain, 256);
    const openings = try mul(try mul(columns, config.fri_config.n_queries), 64);
    out.pcs_phase_payload_bytes = try add(out.resident_main_bytes, try add(try mul(out.interaction_bytes, 2), try add(try mul(out.main_merkle_bytes, 2), try add(composition, try add(fft_batch, try add(fri, try add(openings, 32 << 20)))))));
    out.whole_peak_bytes = @max(@max(out.stage1_peak_bytes, out.gkr_phase_peak_bytes), @max(out.binding_phase_peak_bytes, out.pcs_phase_payload_bytes));
    return out;
}
pub const Capacity = struct { log: u32, calls: u32, plan: Plan };
pub fn maxKeccak(config: core.pcs.PcsConfig, profile_word: u32, limits: anytype) !Capacity {
    const policy = try @import("../../word16_global_execution/services/gkr_local/truth_profile.zig").fromDeclaration(.{ .family = .keccak, .first_id = 1, .calls = 1, .logs = .{ 5, profile_word } });
    var best: ?Capacity = null;
    for (5..22) |value| {
        const log: u32 = @intCast(value);
        const calls: u32 = @intCast(2 * (((@as(usize, 1) << @intCast(log)) - 1) / policy.geometry().rowsPerPair()));
        const plan = derive(.{ .family = .keccak, .first_id = 1, .calls = calls, .logs = .{ log, profile_word } }, config) catch continue;
        plan.admit(limits) catch continue;
        best = .{ .log = log, .calls = calls, .plan = plan };
    }
    return best orelse error.OpTruthLocalBudget;
}
test "OP truth local GKR resource cap derives checkpoint and whole-worker sharding" {
    const config = @import("../op_profile.zig").Profile.op_target_b4_q72_p0_fold4_v1.config();
    const limits = struct { live_bytes: usize = 8 << 30, main_bytes: usize = 2 << 30, interaction_bytes: usize = 4 << 30, gkr_bytes: usize = 12 << 30 }{};
    const large = try derive(.{ .family = .keccak, .first_id = 1, .calls = 15121, .logs = .{ 18, 0 } }, config);
    try std.testing.expectError(error.OpTruthLocalBudget, large.admit(limits));
    const cap = try maxKeccak(config, 0, limits);
    try std.testing.expectEqual(@as(u32, 16), cap.log);
    try std.testing.expectEqual(@as(u32, 4518), cap.calls);
    try cap.plan.admit(limits);
    try std.testing.expect(cap.plan.checkpoint_bank_bytes >= cap.plan.first_secure_checkpoint_bytes);
    try std.testing.expectEqual(52 * cap.plan.padded_facts, cap.plan.numerical_working_bytes);
    var tiny = limits;
    tiny.gkr_bytes = 1;
    try std.testing.expectError(error.OpTruthLocalBudget, maxKeccak(config, 0, tiny));
    std.debug.print("OP_TRUTH_GKR_CAP {any}\n", .{cap});
}
