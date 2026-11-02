//! Qualification sidecar only. Initial transcript state and expected artifacts
//! are public diagnostic inputs; this is not a recursive/execution receiver.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const O = core.fields.om31.OM31;
const Channel = core.channel.raw_mod_m31.Om31Channel;
const V = engine.lookups.gkr_verifier.ForField(O);
const P = engine.lookups.gkr_prover.ForField(O);
const Word = [8]u32;
fn word(v: O) Word {
    var out: Word = undefined;
    for (&out, v.toM31Array()) |*x, c| x.* = c.v;
    return out;
}
fn fields(a: std.mem.Allocator, values: []const O) ![]Word {
    const out = try a.alloc(Word, values.len);
    for (out, values) |*x, v| x.* = word(v);
    return out;
}
pub fn write(a: std.mem.Allocator, file: std.fs.File, scope: []const u8, proof: *const V.GkrBatchProof, gates: []const V.Gate, initial: Channel, terminal_inputs: ?[]const []const []const O, closure: bool) !void {
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const scratch = arena.allocator();
    var ch = initial;
    var artifact = try V.partiallyVerifyBatch(a, gates, proof, &ch);
    defer artifact.deinit(a);
    if (closure) try @import("../word16_global_execution/services/gkr_local/closure.zig").close(a, proof.output_claims_by_instance);
    const polys = try scratch.alloc([][]Word, proof.sumcheck_proofs.len);
    for (polys, proof.sumcheck_proofs) |*rounds, layer| {
        rounds.* = try scratch.alloc([]Word, layer.round_polys.len);
        for (rounds.*, layer.round_polys) |*poly, source| poly.* = try fields(scratch, source.coeffsSlice());
    }
    const masks = try scratch.alloc([][][2]Word, proof.layer_masks_by_instance.len);
    for (masks, proof.layer_masks_by_instance) |*rows, instance| {
        rows.* = try scratch.alloc([][2]Word, instance.len);
        for (rows.*, instance) |*row, mask| {
            row.* = try scratch.alloc([2]Word, mask.columns.len);
            for (row.*, mask.columns) |*pair, source| pair.* = .{ word(source[0]), word(source[1]) };
        }
    }
    const outputs = try scratch.alloc([]Word, proof.output_claims_by_instance.len);
    for (outputs, proof.output_claims_by_instance) |*row, source| row.* = try fields(scratch, source);
    const claims = try scratch.alloc([]Word, artifact.claims_to_verify_by_instance.len);
    for (claims, artifact.claims_to_verify_by_instance) |*row, source| row.* = try fields(scratch, source);
    const gate_names = try scratch.alloc([]const u8, gates.len);
    for (gate_names, gates) |*name, gate| name.* = @tagName(gate);
    const inputs: ?[][][]Word = if (terminal_inputs) |values| blk: {
        const out = try scratch.alloc([][]Word, values.len);
        for (out, values) |*cols, instance| {
            cols.* = try scratch.alloc([]Word, instance.len);
            for (cols.*, instance) |*column, source| column.* = try fields(scratch, source);
        }
        break :blk out;
    } else null;
    const data = .{ .schema = @as(u32, 1), .scope = scope, .initial = .{ .digest = initial.digestBytes(), .draws = initial.inner.n_draws }, .gates = gate_names, .sumchecks = polys, .masks = masks, .outputs = outputs, .expected = .{ .point = try fields(scratch, artifact.ood_point), .claims = claims, .variables = artifact.n_variables_by_instance, .end = .{ .digest = ch.digestBytes(), .draws = ch.inner.n_draws } }, .terminal_inputs = inputs, .require_local_closure = closure };
    const bytes = try std.json.Stringify.valueAlloc(scratch, data, .{});
    try file.writeAll(bytes);
}
pub fn fixtures(a: std.mem.Allocator, path: []const u8) !void {
    try std.fs.cwd().makeDir(path);
    var dir = try std.fs.cwd().openDir(path, .{});
    defer dir.close();
    for (0..3) |kind| {
        var gp: [8]O = undefined;
        var ds: [4]O = undefined;
        const ones: [4]O = @splat(O.one());
        for (&gp, 0..) |*v, i| {
            var coords: [8]core.fields.m31.M31 = undefined;
            for (&coords, 0..) |*c, j| c.* = core.fields.m31.M31.fromCanonical(@intCast(103 * (i + 1) + j * 71));
            v.* = if (kind == 1) O.zero() else if (kind == 2) O.one() else O.fromM31Array(coords);
        }
        for (&ds, 0..) |*v, i| {
            var coords: [8]core.fields.m31.M31 = undefined;
            for (&coords, 0..) |*c, j| c.* = core.fields.m31.M31.fromCanonical(@intCast(211 * (i + 1) + j * 31));
            v.* = O.fromM31Array(coords);
        }
        var layers: [2]P.Layer = undefined;
        layers[0] = .{ .GrandProduct = try engine.lookups.mle.MleFor(O, O).initOwned(try a.dupe(O, &gp)) };
        defer layers[0].deinit(a);
        layers[1] = .{ .LogUpSingles = .{ .denominators = try engine.lookups.mle.MleFor(O, O).initOwned(try a.dupe(O, &ds)) } };
        defer layers[1].deinit(a);
        var ch = Channel.init();
        ch.mixU32s(&.{ 0x524f5243, @intCast(kind) });
        const initial = ch;
        const n: usize = if (kind == 0) 2 else 1;
        var result = try P.proveBatch(a, &ch, layers[0..n]);
        defer result.deinit(a);
        const gates = [_]V.Gate{ .GrandProduct, .LogUp };
        const input0 = [_][]const O{&gp};
        const input1 = [_][]const O{ &ones, &ds };
        const input = [_][]const []const O{ &input0, &input1 };
        const names = [_][]const u8{ "mixed.json", "zero.json", "constant.json" };
        var file = try dir.createFile(names[kind], .{ .exclusive = true });
        defer file.close();
        try write(a, file, "native tiny numerical fixture; independent terminal arrays supplied, no PCS", &result.proof, gates[0..n], initial, input[0..n], false);
    }
}
