//! DEEP geometry comes from the admitted execution components, never the
//! received capture. Preserve native and typed framework mask order exactly.
const std = @import("std");
const core = @import("stwo_core");
const Q = core.fields.qm31.QM31;
const Verified = @import("../../prover/blake3_execution_capture.zig").Verified;
const deep = @import("pcs_deep_circuit.zig");
const layouts = @import("../sample_point_layout.zig");
const capture_mod = @import("../pcs_arithmetic_capture.zig");
pub const Prepared = @import("blake3_native_deep.zig").Prepared;
pub fn prepare(a: std.mem.Allocator, admitted: anytype, capture: anytype, expected: [32]u8) !Prepared {
    try capture.validate(admitted, expected);
    if (comptime @import("blake3_execution_profile.zig").isExtension(@TypeOf(capture.*))) {
        const Profile = @import("blake3_execution_profile.zig").Extension(@TypeOf(capture.*));
        const owner = try @import("blake3_extension_verifier_components.zig").ForProfile(Profile).init(a, admitted, capture, expected);
        defer owner.deinit();
        return prepareComponents(a, .{ .components = owner.assembly.active(), .n_preprocessed_columns = admitted.logs[0].len }, admitted.logs, admitted.config, &capture.proof);
    } else return prepareBase(a, admitted, capture, expected);
}
fn prepareBase(a: std.mem.Allocator, admitted: anytype, capture: *const Verified, expected: [32]u8) !Prepared {
    try capture.validate(admitted, expected);
    var scratch = std.heap.ArenaAllocator.init(a);
    defer scratch.deinit();
    const temp = scratch.allocator();
    const joined = try @import("../../prover/blake3_execution_components.zig").Owner.init(a, &admitted.shape, capture.native_claims, capture.relations, admitted.admission());
    defer joined.deinit();
    const hashes = admitted.hashes.?;
    if (admitted.range_components) |ranges| try joined.bindCompactCommitments(hashes, capture.hash_claims, ranges, capture.compact_claims) else try joined.bindCommitments(hashes, capture.hash_claims);
    var components: std.ArrayList(core.air.components.Component) = .empty;
    try components.appendSlice(temp, joined.verifying.components.active());
    try components.appendSlice(temp, &(try hashes.verifiers()));
    const all = core.air.components.Components{ .components = components.items, .n_preprocessed_columns = admitted.logs[0].len };
    return prepareComponents(a, all, admitted.logs, admitted.config, &capture.proof);
}
/// Shared component-owned geometry for execution leaves and typed parents.
pub fn prepareComponents(a: std.mem.Allocator, all: core.air.components.Components, column_logs: anytype, config: core.pcs.PcsConfig, proof: anytype) !Prepared {
    var scratch = std.heap.ArenaAllocator.init(a);
    defer scratch.deinit();
    const temp = scratch.allocator();
    const split = try all.compositionLogSplit();
    const mask_log = core.verifier_types.compositionMaskLogSize(all.compositionLogDegreeBound(), split) orelse return error.InvalidExecutionDeep;
    // A fixed valid point probes component-owned masks independently of proof data.
    const current = core.circle.SECURE_FIELD_CIRCLE_GEN;
    const step = core.poly.circle.canonic.CanonicCoset.new(mask_log).step();
    const previous = current.sub(.{ .x = Q.fromBase(step.x), .y = Q.fromBase(step.y) });
    var masks = try all.maskPoints(temp, current, mask_log, false);
    defer masks.deinitDeep(temp);
    if (masks.items.len != 3) return error.InvalidExecutionDeep;
    var trees: [4]deep.TreeProfile = undefined;
    var ordered: std.ArrayList(deep.SamplePointLayout) = .empty;
    const blowup = config.fri_config.log_blowup_factor;
    var lifting: u32 = 0;
    for (column_logs, masks.items, trees[0..3]) |logs, columns, *tree| {
        if (logs.len != columns.len) return error.InvalidExecutionDeep;
        const extended = try temp.alloc(u32, logs.len);
        for (logs, columns, extended) |log, points, *out| {
            out.* = try std.math.add(u32, log, blowup);
            if (points.len != 0) lifting = @max(lifting, out.*);
            try ordered.append(temp, try layouts.classifyColumn(points, current, previous));
        }
        tree.* = .{ .column_log_sizes = extended };
    }
    const composition_columns = core.verifier_types.compositionColumnCount(split, 4) orelse return error.InvalidExecutionDeep;
    const extended = try temp.alloc(u32, composition_columns);
    @memset(extended, try std.math.add(u32, mask_log, blowup));
    lifting = @max(lifting, extended[0]);
    for (extended) |_| try ordered.append(temp, .current);
    trees[3] = .{ .column_log_sizes = extended };
    const profile = deep.Profile{ .trees = &trees, .sample_layouts = ordered.items, .lifting_log_size = lifting, .log_blowup_factor = blowup, .query_count = std.math.cast(u32, config.fri_config.n_queries) orelse return error.InvalidExecutionDeep };
    var inputs = try capture_mod.Owned.init(a, profile, proof);
    errdefer inputs.deinit();
    var graph = try deep.build(a, profile);
    errdefer graph.deinit();
    const evaluation = try graph.evaluate(a, inputs.inputs);
    return .{ .graph = graph, .inputs = inputs, .evaluation = evaluation };
}
