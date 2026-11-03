//! Complete native PCS oracle and fresh receiver for the resident GPU pipeline.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const F = @import("rv64/fri.zig");
const T = @import("rv64/trace.zig");
const IO = @import("rv64/fixture_io.zig");
const O = core.fields.om31.OM31;
const M = core.fields.m31.M31;
const H = F.H;
const Channel = core.channel.raw_mod_m31.Om31Channel;
const Point = core.circle.CirclePoint(O);
const TreeVec = core.pcs.TreeVec;
const Native = core.pcs.ForField(O);
const Cpu = @import("stwo_riscv_cpu_integration").CpuProverEngine.Backend;
const MC = struct {
    pub fn mixRoot(channel: *Channel, root: H.Hash) void {
        core.vcs_lifted.blake2_merkle.Blake2sPrefixedMerkleChannel.mixRoot(&channel.inner, root);
    }
};
const Scheme = engine.pcs.ForField(O).CommitmentSchemeProver(Cpu, H, MC);
const Verifier = Native.verifier.CommitmentSchemeVerifier(H, MC);
const a = std.heap.page_allocator;
const degrees = [_]u32{ 5, 5, 7, 7, 9, 9 };
const output_log: u32 = 11;
const group_count: u32 = 3;
fn config() core.pcs.PcsConfig {
    return .{ .pow_bits = 0, .fri_config = .{ .log_blowup_factor = 2, .log_last_layer_degree_bound = 0, .n_queries = 256, .fold_step = 4 } };
}
fn initial() Channel {
    var c = Channel.init();
    c.mixU32s(&.{ 0x52565043, 1 });
    return c;
}
fn offset(g: usize) core.circle.CirclePointM31 {
    return core.poly.circle.canonic.CanonicCoset.new(9).circleDomain().at((g + 1) * 7);
}
fn pointsFor(c: *Channel) !TreeVec([][]Point) {
    const base = try core.circle.secureFieldPointFromRandomSeedCheckedFor(O, c.drawSecureFelt());
    const trees = try a.alloc([][]Point, 1);
    errdefer a.free(trees);
    trees[0] = try a.alloc([]Point, degrees.len);
    errdefer a.free(trees[0]);
    var count: usize = 0;
    errdefer for (trees[0][0..count]) |p| a.free(p);
    for (trees[0], 0..) |*p, i| {
        const o = offset(i / 2);
        p.* = try a.dupe(Point, &.{base.add(.{ .x = O.fromBase(o.x), .y = O.fromBase(o.y) })});
        count += 1;
    }
    return TreeVec([][]Point).initOwned(trees);
}
fn bases(w: anytype, values: []const M) !void {
    for (values) |v| try IO.words(w, &.{v.v});
}
fn hashWords(w: anytype, h: H.Hash) !void {
    for (0..8) |i| try IO.words(w, &.{std.mem.readInt(u32, h[4 * i ..][0..4], .little)});
}
fn checkpoint(w: anytype, c: Channel) !void {
    try hashWords(w, c.inner.digest);
    try IO.words(w, &.{c.inner.n_draws});
}
fn friMetadata(plan: F.Plan, descriptions: *std.ArrayList(u32), twiddles: *std.ArrayList(M)) !void {
    const domain = core.poly.circle.canonic.CanonicCoset.new(plan.initial_log).circleDomain();
    var line = core.poly.line.LineDomain.fromCircleDomain(domain);
    for (plan.layers[0..plan.len], 0..) |layer, li| {
        var offsets: [4]u32 = @splat(0);
        var count = layer.count;
        for (0..layer.fold_step) |step| {
            offsets[step] = @intCast(twiddles.items.len);
            const half = count / 2;
            const values = try a.alloc(M, half);
            defer a.free(values);
            const inverses = try a.alloc(M, half);
            defer a.free(inverses);
            if (li == 0 and step == 0) {
                F.F.fillBitReversedCosetCoordinate(values, domain.half_coset, .y);
                try core.fields.batchInverseInPlace(M, values, inverses);
                for (0..(half + 3) / 4) |pair| {
                    try twiddles.append(a, if (pair * 4 + 3 < half) inverses[pair * 4 + 3] else M.zero());
                    try twiddles.append(a, inverses[pair * 4]);
                }
            } else {
                F.F.fillBitReversedCosetCoordinate(values, line.coset(), .x);
                try core.fields.batchInverseInPlace(M, values, inverses);
                try twiddles.appendSlice(a, inverses);
            }
            if (li != 0 or step != 0) line = line.double();
            count /= 2;
        }
        try descriptions.appendSlice(a, &.{ layer.count, layer.fold_step, layer.leaf_log, layer.shift });
        try descriptions.appendSlice(a, &offsets);
    }
}
fn exportFixture(dir: std.fs.Dir) !void {
    var scheme = try Scheme.init(a, config());
    var scheme_owned = true;
    defer if (scheme_owned) scheme.deinit(a);
    var channel = initial();
    var coeff: std.ArrayList(M) = .empty;
    defer coeff.deinit(a);
    var sources: std.ArrayList(u32) = .empty;
    defer sources.deinit(a);
    var terms: std.ArrayList(u32) = .empty;
    defer terms.deinit(a);
    var groups: std.ArrayList(u32) = .empty;
    defer groups.deinit(a);
    var source_groups: std.ArrayList(u32) = .empty;
    defer source_groups.deinit(a);
    var recipes: std.ArrayList(u32) = .empty;
    defer recipes.deinit(a);
    var twiddles: std.ArrayList(M) = .empty;
    defer twiddles.deinit(a);
    var rng = std.Random.DefaultPrng.init(0x1437acc);
    var columns: [degrees.len]engine.pcs.ColumnEvaluation = undefined;
    var column_count: usize = 0;
    defer for (columns[0..column_count]) |c| a.free(c.values);
    var source_eval_words: u32 = 0;
    var combined_coeff_words: u32 = 0;
    var combined_eval_words: u32 = 0;
    for (0..group_count) |g| {
        const degree = degrees[2 * g];
        const eval_log = degree + 2;
        const tw_offset: u32 = @intCast(twiddles.items.len);
        var ts = try engine.poly.twiddles.precomputeM31(a, core.poly.circle.canonic.CanonicCoset.new(eval_log).circleDomain().half_coset);
        defer engine.poly.twiddles.deinitM31(a, &ts);
        try twiddles.appendSlice(a, ts.twiddles);
        try source_groups.appendSlice(a, &.{ source_eval_words, 0, degree, eval_log, @intCast(2 * g), 2, tw_offset, @intCast(ts.twiddles.len) });
        try groups.appendSlice(a, &.{ @intCast(2 * g), @intCast(2 * g + 2), degree, eval_log, combined_coeff_words, 0, combined_eval_words, 0 });
        const o = offset(g);
        try recipes.appendSlice(a, &.{ o.x.v, o.y.v, output_log - eval_log, degree });
        combined_coeff_words += @as(u32, 8) << @intCast(degree);
        combined_eval_words += @as(u32, 8) << @intCast(eval_log);
        source_eval_words += @as(u32, 2) << @intCast(eval_log);
        for (0..2) |j| {
            const index: u32 = @intCast(2 * g + j);
            try sources.appendSlice(a, &.{ @intCast(coeff.items.len), 0, 0, degree });
            try terms.appendSlice(a, &.{ index, @intCast(g), index, 0 });
            const values = try a.alloc(M, @as(usize, 1) << @intCast(degree));
            defer a.free(values);
            for (values) |*v| v.* = M.fromCanonical(rng.random().uintLessThan(u32, core.fields.m31.Modulus));
            try coeff.appendSlice(a, values);
            const poly = try engine.poly.circle.CircleCoefficients.initBorrowed(values);
            columns[index] = .{ .log_size = degree, .values = (try poly.evaluate(a, core.poly.circle.canonic.CanonicCoset.new(degree).circleDomain())).values };
            column_count += 1;
        }
    }
    var builder = scheme.treeBuilder(a);
    defer builder.deinit();
    _ = try builder.extendColumns(&columns);
    try builder.commit(&channel);
    const expected_root = scheme.trees.items[0].commitment.root();
    const points = try pointsFor(&channel);
    scheme_owned = false;
    var extended = try scheme.proveValues(a, points, &channel);
    var extended_owned = true;
    defer if (extended_owned) extended.deinit(a);
    const proof_json = try std.json.Stringify.valueAlloc(a, extended.proof, .{});
    defer a.free(proof_json);
    try dir.writeFile(.{ .sub_path = "native-reference.json", .data = proof_json });
    var proof_hash: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(proof_json, &proof_hash, .{});
    var replay = initial();
    var verifier = try Verifier.init(a, config());
    defer verifier.deinit(a);
    try verifier.commit(a, expected_root, &degrees, &replay);
    const replay_points = try pointsFor(&replay);
    // The verifier consumes the proof, so detach it from Extended first.
    const proof = extended.proof;
    extended.aux.deinit(a);
    extended_owned = false;
    try verifier.verifyValues(a, replay_points, proof, &replay);
    if (!std.mem.eql(u8, &channel.inner.digest, &replay.inner.digest) or channel.inner.n_draws != replay.inner.n_draws) return error.NativePcsChannelMismatch;
    const plan = try F.Plan.init(9, config().fri_config);
    var descriptions: std.ArrayList(u32) = .empty;
    defer descriptions.deinit(a);
    var fri_twiddles: std.ArrayList(M) = .empty;
    defer fri_twiddles.deinit(a);
    try friMetadata(plan, &descriptions, &fri_twiddles);
    var bytes: std.ArrayList(u8) = .empty;
    defer bytes.deinit(a);
    const w = bytes.writer(a);
    try IO.words(w, &.{ 0x52565043, 1, 0, 9, output_log, 2, 256, 4, degrees.len, group_count, @intCast(plan.len), @intCast(coeff.items.len), source_eval_words, @intCast(twiddles.items.len), combined_coeff_words, combined_eval_words, @intCast(fri_twiddles.items.len), 0, 0, 0 });
    try checkpoint(w, initial());
    try IO.words(w, sources.items);
    try IO.words(w, terms.items);
    try IO.words(w, groups.items);
    try IO.words(w, source_groups.items);
    try IO.words(w, recipes.items);
    try bases(w, coeff.items);
    try bases(w, twiddles.items);
    try IO.words(w, descriptions.items);
    try bases(w, fri_twiddles.items);
    const domain = core.poly.circle.canonic.CanonicCoset.new(output_log).circleDomain();
    for (0..@as(usize, 1) << output_log) |row| {
        const p = domain.at(core.utils.bitReverseIndex(row, output_log));
        try IO.words(w, &.{ p.x.v, p.y.v });
    }
    try hashWords(w, expected_root);
    try hashWords(w, proof_hash);
    try checkpoint(w, channel);
    try dir.writeFile(.{ .sub_path = "case-0.bin", .data = bytes.items });
    std.debug.print("PASS complete native PCS reference, columns=6 groups=3 degree=9 beta=2 q=256 fold=4\n", .{});
}
const Reader = struct {
    words: []u32,
    pos: usize = 0,
    fn init(path: []const u8) !@This() {
        const bytes = try std.fs.cwd().readFileAlloc(a, path, 1 << 28);
        defer a.free(bytes);
        if (bytes.len % 4 != 0) return error.InvalidPcsReadback;
        const out = try a.alloc(u32, bytes.len / 4);
        for (out, 0..) |*v, i| v.* = std.mem.readInt(u32, bytes[4 * i ..][0..4], .little);
        return .{ .words = out };
    }
    fn deinit(self: *@This()) void {
        a.free(self.words);
    }
    fn take(self: *@This(), count: usize) ![]const u32 {
        if (count > self.words.len - self.pos) return error.TruncatedPcsReadback;
        const out = self.words[self.pos..][0..count];
        self.pos += count;
        return out;
    }
};
fn secure(words: []const u32) !O {
    if (words.len != 8) return error.InvalidPcsReadback;
    var c: [8]M = undefined;
    for (words, &c) |v, *d| {
        if (v >= core.fields.m31.Modulus) return error.NoncanonicalPcsReadback;
        d.* = M.fromCanonical(v);
    }
    return O.fromM31Array(c);
}
fn digest(words: []const u32) H.Hash {
    var out: H.Hash = undefined;
    for (words, 0..) |v, i| std.mem.writeInt(u32, out[4 * i ..][0..4], v, .little);
    return out;
}
const Capture = struct {
    root: [8]u32,
    samples: []const u32,
    nonce: u64,
    terminal: [8]u32,
    raw: []const u32,
    layers: []const F.LayerReadback,
    trace_values: []const u32,
    trace_paths: []const u32,
    fn assemble(self: @This()) !Native.CommitmentSchemeProof(H) {
        const plan = try F.Plan.init(9, config().fri_config);
        const column_logs = [_]u32{ 7, 7, 9, 9, 11, 11 };
        const order = [_]u32{ 0, 1, 2, 3, 4, 5 };
        var trace = try T.assemble(a, .{ .tree_log = output_log, .lifting_log = output_log, .column_logs = &column_logs, .column_order = &order }, self.raw, .{ .root = self.root, .values = self.trace_values, .paths = self.trace_paths });
        var trace_owned = true;
        defer if (trace_owned) trace.deinit(a);
        var fri = try F.assemble(a, plan, self.raw, self.layers, &self.terminal);
        var fri_owned = true;
        defer if (fri_owned) fri.deinit(a);
        const commitments = try a.dupe(H.Hash, &.{trace.root});
        errdefer a.free(commitments);
        const sampled = try a.alloc([]O, degrees.len);
        errdefer a.free(sampled);
        var count: usize = 0;
        errdefer for (sampled[0..count]) |v| a.free(v);
        for (sampled, 0..) |*column, i| {
            column.* = try a.dupe(O, &.{try secure(self.samples[8 * i ..][0..8])});
            count += 1;
        }
        const sampled_outer = try a.alloc([][]O, 1);
        errdefer a.free(sampled_outer);
        sampled_outer[0] = sampled;
        const queried_outer = try a.alloc([][]M, 1);
        errdefer a.free(queried_outer);
        queried_outer[0] = trace.queried_values;
        const decommitments = try a.alloc(core.vcs_lifted.verifier.MerkleDecommitmentLifted(H), 1);
        errdefer a.free(decommitments);
        decommitments[0] = trace.decommitment;
        trace_owned = false;
        fri_owned = false;
        return .{ .config = config(), .commitments = TreeVec(H.Hash).initOwned(commitments), .sampled_values = TreeVec([][]O).initOwned(sampled_outer), .decommitments = TreeVec(core.vcs_lifted.verifier.MerkleDecommitmentLifted(H)).initOwned(decommitments), .queried_values = TreeVec([][]M).initOwned(queried_outer), .proof_of_work = self.nonce, .fri_proof = fri };
    }
};
const Attack = enum { none, sample, trace_value, fri_root, terminal, nonce, trace_root };
fn verifyAttempt(capture: Capture, attack: Attack, expected_hash: [32]u8, readback_path: []const u8) !void {
    var proof = try capture.assemble();
    var owned = true;
    defer if (owned) proof.deinit(a);
    switch (attack) {
        .none => {},
        .sample => proof.sampled_values.items[0][0][0] = proof.sampled_values.items[0][0][0].add(O.one()),
        .trace_value => proof.queried_values.items[0][0][0] = proof.queried_values.items[0][0][0].add(M.one()),
        .fri_root => proof.fri_proof.first_layer.commitment[0] ^= 1,
        .terminal => {
            const c = @constCast(proof.fri_proof.last_layer_poly.coefficients());
            c[0] = c[0].add(O.one());
        },
        .nonce => proof.proof_of_work += 1,
        .trace_root => proof.commitments.items[0][0] ^= 1,
    }
    var actual_hash: [32]u8 = undefined;
    if (attack == .none) {
        const json = try std.json.Stringify.valueAlloc(a, proof, .{});
        defer a.free(json);
        std.crypto.hash.sha2.Sha256.hash(json, &actual_hash, .{});
        const path = try std.fmt.allocPrint(a, "{s}.native.json", .{readback_path});
        defer a.free(path);
        try std.fs.cwd().writeFile(.{ .sub_path = path, .data = json });
    }
    var channel = initial();
    var verifier = try Verifier.init(a, config());
    defer verifier.deinit(a);
    try verifier.commit(a, proof.commitments.items[0], &degrees, &channel);
    const points = try pointsFor(&channel);
    owned = false;
    verifier.verifyValues(a, points, proof, &channel) catch |err| {
        if (attack == .none) return err;
        std.debug.print("REJECT complete native PCS mutation={s} error={s}\n", .{ @tagName(attack), @errorName(err) });
        return;
    };
    if (attack != .none) return error.PcsMutationAccepted;
    if (!std.mem.eql(u8, &actual_hash, &expected_hash)) return error.NativePcsProofParityMismatch;
    std.debug.print("PASS complete GPU PCS proof native_verified=true native_proof_byte_parity=true\n", .{});
}
fn verifyFixture(fixture_path: []const u8, readback_path: []const u8) !void {
    var f = try Reader.init(fixture_path);
    defer f.deinit();
    var r = try Reader.init(readback_path);
    defer r.deinit();
    const h = try f.take(20);
    if (!std.mem.eql(u32, h, &.{ 0x52565043, 1, 0, 9, 11, 2, 256, 4, 6, 3, 3, h[11], h[12], h[13], h[14], h[15], h[16], 0, 0, 0 })) return error.InvalidPcsFixture;
    _ = try f.take(9 + 6 * 4 + 6 * 4 + 3 * 8 + 3 * 8 + 3 * 4 + h[11] + h[13] + 3 * 8 + h[16] + 2 * (@as(usize, 1) << output_log));
    const expected_root = try f.take(8);
    const expected_hash = digest(try f.take(8));
    const expected_channel = try f.take(9);
    if (f.pos != f.words.len) return error.InvalidPcsFixture;
    const rh = try r.take(10);
    if (!std.mem.eql(u32, rh, &.{ 0x5256504f, 1, 0, 6, 3, 3, 11, 256, 9, 13 })) return error.InvalidPcsReadback;
    const status = (try r.take(1))[0];
    const channel = try r.take(16);
    if (status != 0 or !std.mem.eql(u32, channel[0..9], expected_channel) or channel[9] != 13 or channel[10] != 0 or channel[11] != 0 or channel[12] != 30 or !std.mem.allEqual(u32, channel[13..], 0)) return error.NativePcsChannelMismatch;
    const root = try r.take(8);
    if (!std.mem.eql(u32, root, expected_root)) return error.NativePcsRootMismatch;
    const samples = try r.take(6 * 8);
    const nonce = try r.take(2);
    const terminal = try r.take(8);
    const raw = try r.take(256);
    const plan = try F.Plan.init(9, config().fri_config);
    const layers = try a.alloc(F.LayerReadback, plan.len);
    defer a.free(layers);
    for (layers, plan.layers[0..plan.len]) |*layer, shape| {
        layer.* = .{ .root = (try r.take(8))[0..8].*, .values = try r.take(shape.valueWords(256)), .paths = try r.take(shape.pathWords(256)) };
    }
    const capture = Capture{ .root = root[0..8].*, .samples = samples, .nonce = @as(u64, nonce[0]) | (@as(u64, nonce[1]) << 32), .terminal = terminal[0..8].*, .raw = raw, .layers = layers, .trace_values = try r.take(6 * 256), .trace_paths = try r.take(256 * output_log * 8) };
    if (r.pos != r.words.len) return error.InvalidPcsReadback;
    for (std.enums.values(Attack)) |attack| try verifyAttempt(capture, attack, expected_hash, readback_path);
}
pub fn main() !void {
    const args = try std.process.argsAlloc(a);
    defer std.process.argsFree(a, args);
    if (args.len == 4 and std.mem.eql(u8, args[1], "verify")) return verifyFixture(args[2], args[3]);
    if (args.len != 3 or !std.mem.eql(u8, args[1], "export")) return error.ExpectedExportDirectory;
    try std.fs.cwd().makePath(args[2]);
    var dir = try std.fs.cwd().openDir(args[2], .{});
    defer dir.close();
    try exportFixture(dir);
}
