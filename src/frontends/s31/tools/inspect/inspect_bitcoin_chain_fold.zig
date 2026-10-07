//! Measure the whole candidate fold, including its in-circuit child verifier.
const std = @import("std");
const core = @import("stwo_core");
const circuit = @import("stwo_circuit_frontend");
const fold = @import("../../bitcoin/fold/bitcoin_chain_fold.zig");
const anchor = @import("../../bitcoin/fold/bitcoin_chain_anchor.zig");

const projection = @embedFile("s31_air_projection");
const reference = @embedFile("s31_fold_reference");
const Sizes = struct { eq: usize, qm31_ops: usize, m31_to_u32: usize, triple_xor: usize, blake_g: usize };
const Record = struct { fold_geometry: struct { padded_rows: Sizes } };

pub fn main() !void {
    const allocator = std.heap.page_allocator;
    const parsed = try std.json.parseFromSlice(Record, allocator, reference, .{ .ignore_unknown_fields = true });
    defer parsed.deinit();
    const baseline = parsed.value.fold_geometry.padded_rows;
    const checkpoint = [8]u32{ 93892305, 397617766, 1762064199, 2128125525, 211345822, 958247097, 595994426, 1074837273 };
    var expanded = baseline;
    expanded.qm31_ops *= 2;
    const candidate = expanded;
    const candidate_layout = try circuit.common.preprocessed.ColumnLayout.fromComponentSizes(.{
        .eq = candidate.eq,
        .qm31_ops = candidate.qm31_ops,
        .m31_to_u32 = candidate.m31_to_u32,
        .triple_xor = candidate.triple_xor,
        .blake_g_gate = candidate.blake_g,
    });
    const anchor_root = blk: {
        var anchor_ctx = try anchor.build(circuit.builder.NoValue, allocator, checkpoint, .{
            .eq = candidate.eq,
            .qm31_ops = candidate.qm31_ops,
            .m31_to_u32 = candidate.m31_to_u32,
            .triple_xor = candidate.triple_xor,
            .blake_g_gate = candidate.blake_g,
        });
        defer anchor_ctx.deinit();
        var anchor_pp = try circuit.common.preprocessed.PreprocessedCircuit.fromBuilderCircuit(allocator, &anchor_ctx.circuit);
        defer anchor_pp.deinit(allocator);
        if (!anchor_pp.layout().eql(&candidate_layout)) return error.AnchorGeometryMismatch;
        const anchor_pcs = core.pcs.config_v2.PcsConfigV2.fromFriAndTraceSize(
            try core.pcs.config_v2.FriConfigV2.init(26, 0, 1, 70, 4),
            candidate_layout.traceLogSize(),
        );
        break :blk try anchor_pp.preprocessedRoot(allocator, anchor_pcs.fri_config.log_blowup_factor);
    };
    const anchor_hex = std.fmt.bytesToHex(anchor_root, .lower);
    const Case = struct {
        name: []const u8,
        child: Sizes,
        step: u32,
        change_checkpoint: bool = false,
        change_base_root: bool = false,
    };
    const cases = [_]Case{
        .{ .name = "baseline", .child = baseline, .step = 0 },
        .{ .name = "qm31-expanded", .child = expanded, .step = 0 },
        .{ .name = "candidate-base", .child = candidate, .step = 0 },
        .{ .name = "candidate-recursive", .child = candidate, .step = 1 },
        .{ .name = "candidate-u16-carry", .child = candidate, .step = 65536 },
        .{ .name = "candidate-u32-max", .child = candidate, .step = 0xffffffff },
        .{ .name = "changed-checkpoint", .child = candidate, .step = 0, .change_checkpoint = true },
        .{ .name = "changed-base-root", .child = candidate, .step = 0, .change_base_root = true },
    };
    var candidate_root: ?[32]u8 = null;
    for (cases) |case| {
        const child_layout = try circuit.common.preprocessed.ColumnLayout.fromComponentSizes(.{
            .eq = case.child.eq,
            .qm31_ops = case.child.qm31_ops,
            .m31_to_u32 = case.child.m31_to_u32,
            .triple_xor = case.child.triple_xor,
            .blake_g_gate = case.child.blake_g,
        });
        const pcs = core.pcs.config_v2.PcsConfigV2.fromFriAndTraceSize(
            try core.pcs.config_v2.FriConfigV2.init(26, 0, 1, 70, 4),
            child_layout.traceLogSize(),
        );
        var case_checkpoint = checkpoint;
        if (case.change_checkpoint) case_checkpoint[0] ^= 1;
        var base_root = anchor_root;
        if (case.change_base_root) base_root[0] ^= 1;
        var ctx = try fold.topology(allocator, projection, child_layout, pcs, base_root, case_checkpoint, case.step);
        defer ctx.deinit();
        const raw_vars = ctx.circuit.n_vars;
        const raw = circuit.common.finalize.rawComponentSizes(circuit.common.preprocessed.CircuitView.fromBuilder(&ctx.circuit));
        const padded = raw.map(circuit.common.finalize.paddedSize);
        const fixed_point = padded.eq == case.child.eq and padded.qm31_ops == case.child.qm31_ops and
            padded.m31_to_u32 == case.child.m31_to_u32 and padded.triple_xor == case.child.triple_xor and
            padded.blake_g_gate == case.child.blake_g;
        if (std.mem.startsWith(u8, case.name, "candidate-") and !fixed_point) return error.FoldGeometryNotFixed;
        var root_field: [66]u8 = undefined;
        var root_json: []const u8 = "null";
        if (fixed_point) {
            try circuit.common.finalize.padContext(circuit.builder.NoValue, &ctx);
            var pp = try circuit.common.preprocessed.PreprocessedCircuit.fromBuilderCircuit(allocator, &ctx.circuit);
            defer pp.deinit(allocator);
            const root = try pp.preprocessedRoot(allocator, pcs.fri_config.log_blowup_factor);
            if (std.mem.startsWith(u8, case.name, "candidate-")) {
                if (candidate_root) |first| {
                    if (!std.mem.eql(u8, &root, &first)) return error.CounterChangesFoldAir;
                } else candidate_root = root;
            } else if (case.change_checkpoint or case.change_base_root) {
                const first = candidate_root orelse return error.MissingCandidateRoot;
                if (std.mem.eql(u8, &root, &first))
                    return error.FoldKeyParameterNotBound;
            }
            const hex = std.fmt.bytesToHex(root, .lower);
            root_field[0] = '"';
            @memcpy(root_field[1..65], &hex);
            root_field[65] = '"';
            root_json = &root_field;
        }
        std.debug.print(
            "{{\"schema\":\"s31-bitcoin-chain-fold-inspection-v1\",\"case\":\"{s}\",\"step\":{d},\"anchor_root\":\"{s}\",\"child_eq_rows\":{d},\"child_qm31_rows\":{d},\"child_trace_log_size\":{d},\"raw_vars\":{d},\"fixed_point\":{},\"preprocessed_root\":{s},\"raw\":{{\"eq\":{d},\"qm31_ops\":{d},\"m31_to_u32\":{d},\"triple_xor\":{d},\"blake_g\":{d}}},\"padded\":{{\"eq\":{d},\"qm31_ops\":{d},\"m31_to_u32\":{d},\"triple_xor\":{d},\"blake_g\":{d}}}}}\n",
            .{ case.name, case.step, &anchor_hex, case.child.eq, case.child.qm31_ops, child_layout.traceLogSize(), raw_vars, fixed_point, root_json, raw.eq, raw.qm31_ops, raw.m31_to_u32, raw.triple_xor, raw.blake_g_gate, padded.eq, padded.qm31_ops, padded.m31_to_u32, padded.triple_xor, padded.blake_g_gate },
        );
    }
}
