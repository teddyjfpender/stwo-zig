//! Value-free cost and canonical SHA boundary inspection for the one-step
//! fused-SHA Bitcoin fold. This does not claim a joined native proof.
const std = @import("std");
const core = @import("stwo_core");
const circuit = @import("stwo_circuit_frontend");
const fold = @import("bitcoin_chain_fold.zig");
const anchor = @import("bitcoin_chain_anchor.zig");
const s31 = @import("stwo_s31_prototype");

const projection = @embedFile("s31_air_projection");
const reference = @embedFile("s31_fold_reference");
const Sizes = struct { eq: usize, qm31_ops: usize, m31_to_u32: usize, triple_xor: usize, blake_g: usize };
const Record = struct { fold_geometry: struct { padded_rows: Sizes } };
const checkpoint = [8]u32{ 93892305, 397617766, 1762064199, 2128125525, 211345822, 958247097, 595994426, 1074837273 };

fn targets(sizes: Sizes) circuit.common.finalize.ComponentSizes {
    return .{ .eq = sizes.eq, .qm31_ops = sizes.qm31_ops, .m31_to_u32 = sizes.m31_to_u32, .triple_xor = sizes.triple_xor, .blake_g_gate = sizes.blake_g };
}

pub fn main() !void {
    const allocator = std.heap.page_allocator;
    const parsed = try std.json.parseFromSlice(Record, allocator, reference, .{ .ignore_unknown_fields = true });
    defer parsed.deinit();
    var child_rows = parsed.value.fold_geometry.padded_rows;
    child_rows.qm31_ops *= 2;
    const child_layout = try circuit.common.preprocessed.ColumnLayout.fromComponentSizes(targets(child_rows));
    const child_pcs = core.pcs.config_v2.PcsConfigV2.fromFriAndTraceSize(
        try core.pcs.config_v2.FriConfigV2.init(26, 0, 1, 70, 4),
        child_layout.traceLogSize(),
    );
    const anchor_root = blk: {
        var anchor_ctx = try anchor.build(circuit.builder.NoValue, allocator, checkpoint, targets(child_rows));
        defer anchor_ctx.deinit();
        var pp = try circuit.common.preprocessed.PreprocessedCircuit.fromBuilderCircuit(allocator, &anchor_ctx.circuit);
        defer pp.deinit(allocator);
        break :blk try pp.preprocessedRoot(allocator, child_pcs.fri_config.log_blowup_factor);
    };
    var expected: ?[56]u32 = null;
    for ([_]u32{ 0, 1 }) |step| {
        var boundary_wires: s31.bitcoin_fold_step.ShaBoundaryWires = undefined;
        var ctx = try fold.fusedTopology(allocator, projection, child_layout, child_pcs, anchor_root, checkpoint, step, &boundary_wires);
        defer ctx.deinit();
        var addresses: [56]u32 = undefined;
        for (boundary_wires.header, 0..) |wire, i| addresses[i] = wire.idx;
        for (boundary_wires.digest, 0..) |wire, i| addresses[40 + i] = wire.idx;
        if (expected) |earlier| {
            if (!std.meta.eql(addresses, earlier)) return error.WitnessDependentFusedShaBoundary;
        } else expected = addresses;
        const raw_vars = ctx.circuit.n_vars;
        const raw = circuit.common.finalize.rawComponentSizes(.fromBuilder(&ctx.circuit));
        const padded = raw.map(circuit.common.finalize.paddedSize);
        try (circuit.common.preprocessed.ShaBoundary{ .addresses = addresses }).validate(.fromBuilder(&ctx.circuit));
        var duplicate = addresses;
        duplicate[55] = addresses[0];
        if ((circuit.common.preprocessed.ShaBoundary{ .addresses = duplicate }).validate(.fromBuilder(&ctx.circuit))) |_| {
            return error.AcceptedDuplicateFusedShaAddress;
        } else |err| if (err != error.DuplicateShaPrivateBoundary) return err;
        var public_address = addresses;
        public_address[55] = ctx.circuit.output.items[1];
        if ((circuit.common.preprocessed.ShaBoundary{ .addresses = public_address }).validate(.fromBuilder(&ctx.circuit))) |_| {
            return error.AcceptedPublicFusedShaAddress;
        } else |err| if (err != error.PublicShaPrivateBoundary) return err;
        if (padded.eq > child_rows.eq or padded.qm31_ops > child_rows.qm31_ops or
            padded.m31_to_u32 > child_rows.m31_to_u32 or padded.triple_xor > child_rows.triple_xor or
            padded.blake_g_gate > child_rows.blake_g)
            return error.FusedFoldGeometryExceedsChild;
        try circuit.common.finalize.padToTargets(circuit.builder.NoValue, &ctx, targets(child_rows));
        var pp = try circuit.common.preprocessed.PreprocessedCircuit.fromBuilderCircuitWithShaBoundary(allocator, &ctx.circuit, .{ .addresses = addresses });
        defer pp.deinit(allocator);
        const root = try pp.preprocessedRoot(allocator, child_pcs.fri_config.log_blowup_factor);
        var boundary_bytes: [56 * 4]u8 = undefined;
        for (addresses, 0..) |address, i| std.mem.writeInt(u32, boundary_bytes[4 * i ..][0..4], address, .little);
        var boundary_digest: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(&boundary_bytes, &boundary_digest, .{});
        std.debug.print("S31_FUSED_FOLD_TOPOLOGY step={d} raw_vars={d} eq={d} qm31={d} u32={d} xor={d} blake={d} anchor_root={s} fixed_root={s} boundary_sha256={s} boundary_first={d} boundary_last={d}\n", .{
            step,                                     raw_vars,                          raw.eq,                                       raw.qm31_ops, raw.m31_to_u32, raw.triple_xor, raw.blake_g_gate,
            &std.fmt.bytesToHex(anchor_root, .lower), &std.fmt.bytesToHex(root, .lower), &std.fmt.bytesToHex(boundary_digest, .lower), addresses[0], addresses[55],
        });
    }
}
