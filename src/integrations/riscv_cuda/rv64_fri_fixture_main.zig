//! Native FRI oracle export and fresh verification of compact GPU readback.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const G = @import("rv64/fri.zig");
const IO = @import("rv64/fixture_io.zig");
const M = core.fields.m31.M31;
const O = G.O;
const H = G.H;
const F = G.F;
const Channel = core.channel.raw_mod_m31.Om31Channel;
const Cpu = @import("stwo_riscv_cpu_integration").CpuProverEngine.Backend;
const Backend = struct {
    pub const MerkleTree = Cpu.MerkleTree;
    pub const commitMerkle = Cpu.commitMerkle;
};
const MC = struct {
    pub fn mixRoot(channel: *Channel, root: H.Hash) void {
        core.vcs_lifted.blake2_merkle.Blake2sPrefixedMerkleChannel.mixRoot(&channel.inner, root);
    }
};
const P = engine.fri.ForField(O).FriProver(Backend, H, MC);
const Column = engine.secure_column.SecureColumnByCoordsFor(O);
const Case = struct {
    degree: u32,
    blowup: u32,
    fold: u32,
    queries: usize,
    fn config(c: Case) F.FriConfig {
        return .{ .log_blowup_factor = c.blowup, .log_last_layer_degree_bound = 0, .n_queries = c.queries, .fold_step = c.fold };
    }
};
const cases = [_]Case{
    .{ .degree = 8, .blowup = 2, .fold = 4, .queries = 65 },  .{ .degree = 12, .blowup = 2, .fold = 4, .queries = 256 },
    .{ .degree = 7, .blowup = 1, .fold = 4, .queries = 108 }, .{ .degree = 6, .blowup = 2, .fold = 2, .queries = 64 },
    .{ .degree = 5, .blowup = 1, .fold = 1, .queries = 32 },  .{ .degree = 17, .blowup = 2, .fold = 4, .queries = 256 },
};
const a = std.heap.page_allocator;
fn checkpoint(w: anytype, channel: Channel) !void {
    for (0..8) |i| try IO.words(w, &.{std.mem.readInt(u32, channel.inner.digest[i * 4 ..][0..4], .little)});
    try IO.words(w, &.{channel.inner.n_draws});
}
fn initialChannel(id: u32) Channel {
    var channel = Channel.init();
    channel.mixU32s(&.{ 0x52564652, 1, id });
    return channel;
}
fn hashWords(w: anytype, hash: H.Hash) !void {
    for (0..8) |i| try IO.words(w, &.{std.mem.readInt(u32, hash[i * 4 ..][0..4], .little)});
}
fn exportCase(dir: std.fs.Dir, c: Case, id: u32) !void {
    const plan = try G.Plan.init(c.degree, c.config());
    const domain = core.poly.circle.canonic.CanonicCoset.new(plan.initial_log).circleDomain();
    const n = @as(usize, 1) << @intCast(c.degree);
    var prng = std.Random.DefaultPrng.init(0xf11d001 + id);
    var coordinates: [8][]M = undefined;
    for (&coordinates) |*plane| {
        const coefficients = try a.alloc(M, n);
        defer a.free(coefficients);
        for (coefficients) |*v| v.* = M.fromU64(prng.random().int(u32));
        const poly = try engine.poly.circle.CircleCoefficients.initBorrowed(coefficients);
        plane.* = @constCast((try poly.evaluate(a, domain)).values);
    }
    const input = try Column.initOwned(coordinates);
    var input_bytes: std.ArrayList(u8) = .empty;
    defer input_bytes.deinit(a);
    for (coordinates) |plane| for (plane) |v| try IO.words(input_bytes.writer(a), &.{v.v});
    var channel = initialChannel(id);
    var prover = try P.commit(a, &channel, c.config(), domain, input);
    defer prover.deinit(a);
    if (prover.inner_layers.len + 1 != plan.len) return error.NativeFriShapeMismatch;
    var roots: std.ArrayList(H.Hash) = .empty;
    defer roots.deinit(a);
    try roots.append(a, prover.first_layer.merkle_tree.root());
    for (prover.inner_layers) |layer| try roots.append(a, layer.merkle_tree.root());
    var oracle = initialChannel(id);
    var alphas: std.ArrayList(O) = .empty;
    defer alphas.deinit(a);
    for (roots.items) |root| {
        MC.mixRoot(&oracle, root);
        try alphas.append(a, oracle.drawSecureFelt());
    }
    oracle.mixFelts(prover.last_layer_poly.coefficients());
    if (!std.mem.eql(u8, &oracle.inner.digest, &channel.inner.digest) or oracle.inner.n_draws != channel.inner.n_draws) return error.NativeFriTranscriptMismatch;
    const raw = try core.queries.drawQueries(&channel, a, plan.initial_log, c.queries);
    defer a.free(raw);
    var twiddles: std.ArrayList(M) = .empty;
    defer twiddles.deinit(a);
    var descriptions: std.ArrayList(u32) = .empty;
    defer descriptions.deinit(a);
    var line_domain = core.poly.line.LineDomain.fromCircleDomain(domain);
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
                F.fillBitReversedCosetCoordinate(values, domain.half_coset, .y);
                try core.fields.batchInverseInPlace(M, values, inverses);
                for (0..(half + 3) / 4) |pair| {
                    try twiddles.append(a, if (pair * 4 + 3 < half) inverses[pair * 4 + 3] else M.zero());
                    try twiddles.append(a, inverses[pair * 4]);
                }
            } else {
                F.fillBitReversedCosetCoordinate(values, line_domain.coset(), .x);
                try core.fields.batchInverseInPlace(M, values, inverses);
                try twiddles.appendSlice(a, inverses);
                line_domain = line_domain.double();
            }
            count /= 2;
        }
        try descriptions.appendSlice(a, &.{ layer.count, layer.fold_step, layer.leaf_log, layer.shift });
        try descriptions.appendSlice(a, &offsets);
    }
    var bytes: std.ArrayList(u8) = .empty;
    defer bytes.deinit(a);
    const w = bytes.writer(a);
    try IO.words(w, &.{ 0x52564652, 1, id, c.degree, c.blowup, c.fold, @intCast(c.queries), plan.initial_log, @intCast(plan.len), @intCast(twiddles.items.len) });
    try checkpoint(w, initialChannel(id));
    try IO.words(w, descriptions.items);
    for (twiddles.items) |v| try IO.words(w, &.{v.v});
    try w.writeAll(input_bytes.items);
    for (roots.items) |root| try hashWords(w, root);
    try IO.felts(w, alphas.items);
    try IO.felts(w, prover.last_layer_poly.coefficients());
    for (raw) |q| try IO.words(w, &.{@intCast(q)});
    try checkpoint(w, channel);
    const cursor: u32 = @intCast(plan.len * 2 + 2);
    try IO.words(w, &.{ cursor, 0, 0, 17 + cursor, 0, 0, 0 });
    const name = try std.fmt.allocPrint(a, "case-{}.bin", .{id});
    defer a.free(name);
    try dir.writeFile(.{ .sub_path = name, .data = bytes.items });
    std.debug.print("FRI case={} degree_log={} blowup_log={} fold={} queries={} layers={}\n", .{ id, c.degree, c.blowup, c.fold, c.queries, plan.len });
}
const Reader = struct {
    bytes: []const u8,
    at: usize = 0,
    fn load(allocator: std.mem.Allocator, path: []const u8) !Reader {
        return .{ .bytes = try std.fs.cwd().readFileAlloc(allocator, path, 256 << 20) };
    }
    fn words(self: *Reader, allocator: std.mem.Allocator, n: usize) ![]u32 {
        if (n > (self.bytes.len - self.at) / 4) return error.TruncatedFriReadback;
        const out = try allocator.alloc(u32, n);
        for (out) |*v| {
            v.* = std.mem.readInt(u32, self.bytes[self.at..][0..4], .little);
            self.at += 4;
        }
        return out;
    }
};
fn readValue(words: []const u32) !O {
    var limbs: [8]M = undefined;
    for (words, &limbs) |v, *out| {
        if (v >= core.fields.m31.Modulus) return error.NoncanonicalFriField;
        out.* = M.fromCanonical(v);
    }
    return O.fromM31Array(limbs);
}
fn verifyCase(allocator: std.mem.Allocator, fixtures: []const u8, outputs: []const u8, id: u32, fault: u32) !void {
    const c = cases[id];
    const plan = try G.Plan.init(c.degree, c.config());
    const file = try std.fmt.allocPrint(allocator, "{s}/case-{}.bin", .{ fixtures, id });
    var input = try Reader.load(allocator, file);
    const h = try input.words(allocator, 10);
    if (h[0] != 0x52564652 or h[1] != 1 or h[2] != id or h[3] != c.degree or h[4] != c.blowup or h[5] != c.fold or h[6] != c.queries or h[7] != plan.initial_log or h[8] != plan.len) return error.InvalidFriFixture;
    _ = try input.words(allocator, 9 + plan.len * 8 + h[9]);
    const column = try input.words(allocator, (@as(usize, 1) << @intCast(plan.initial_log)) * 8);
    const out_path = try std.fmt.allocPrint(allocator, "{s}/case-{}.bin", .{ outputs, id });
    var capture = try Reader.load(allocator, out_path);
    const ch = try capture.words(allocator, 5);
    if (ch[0] != 0x5256464f or ch[1] != 1 or ch[2] != id or ch[3] != plan.len or ch[4] != c.queries) return error.InvalidFriReadback;
    const terminal_state = try capture.words(allocator, 16);
    if ((try capture.words(allocator, 1))[0] != 0) return error.DeviceFriFailure;
    const terminal = try capture.words(allocator, 8);
    const raw = try capture.words(allocator, c.queries);
    const layers = try allocator.alloc(G.LayerReadback, plan.len);
    for (layers, plan.layers[0..plan.len]) |*layer, layout| layer.* = .{ .root = (try capture.words(allocator, 8))[0..8].*, .values = try capture.words(allocator, layout.valueWords(c.queries)), .paths = try capture.words(allocator, layout.pathWords(c.queries)) };
    if (capture.at != capture.bytes.len) return error.TrailingFriReadback;
    switch (fault) {
        1 => layers[0].root[0] ^= 1,
        2 => @constCast(layers[0].values)[0] = @intCast((@as(u64, layers[0].values[0]) + 1) % core.fields.m31.Modulus),
        3 => @constCast(layers[0].paths)[0] ^= 1,
        4 => terminal[0] = @intCast((@as(u64, terminal[0]) + 1) % core.fields.m31.Modulus),
        5 => raw[0] ^= 1,
        6 => terminal_state[0] ^= 1,
        else => {},
    }
    var proof = try G.assemble(allocator, plan, raw, layers, terminal);
    defer proof.deinit(allocator);
    switch (fault) {
        7 => proof.first_layer.fri_witness[0] = proof.first_layer.fri_witness[0].add(O.one()),
        8 => proof.first_layer.decommitment.hash_witness[0][0] ^= 1,
        9 => proof.first_layer.commitment[0] ^= 1,
        10 => std.mem.swap(F.FriLayerProof(H), &proof.inner_layers[0], &proof.inner_layers[1]),
        else => {},
    }
    var channel = initialChannel(id);
    var verifier = try F.FriVerifier(H, MC).commit(allocator, &channel, c.config(), proof, F.CirclePolyDegreeBound.init(c.degree));
    defer verifier.deinit(allocator);
    const sampled = try verifier.sampleQueryPositionsWithRaw(allocator, &channel);
    defer {
        allocator.free(sampled.raw);
        allocator.free(sampled.unique);
    }
    if (fault < 7) {
        for (sampled.raw, raw) |expected, actual| if (expected != actual) return error.FriRawQueryMismatch;
        for (0..8) |i| if (std.mem.readInt(u32, channel.inner.digest[i * 4 ..][0..4], .little) != terminal_state[i]) return error.FriTerminalChannelMismatch;
        if (channel.inner.n_draws != terminal_state[8] or terminal_state[9] != plan.len * 2 + 2 or terminal_state[10] != 0 or terminal_state[11] != 0 or terminal_state[12] != 17 + plan.len * 2 + 2 or !std.mem.allEqual(u32, terminal_state[13..], 0)) return error.FriTerminalChannelMismatch;
    }
    const rows = @as(usize, 1) << @intCast(plan.initial_log);
    const expected = try allocator.alloc(O, sampled.unique.len);
    for (sampled.unique, expected) |position, *v| {
        var words: [8]u32 = undefined;
        for (&words, 0..) |*w, k| w.* = column[k * rows + position];
        v.* = try readValue(&words);
    }
    try verifier.decommit(allocator, expected);
}
pub fn main() !void {
    const args = try std.process.argsAlloc(a);
    if (args.len == 3 and std.mem.eql(u8, args[1], "export")) {
        try std.fs.cwd().makePath(args[2]);
        var dir = try std.fs.cwd().openDir(args[2], .{});
        defer dir.close();
        for (cases, 0..) |c, id| try exportCase(dir, c, @intCast(id));
    } else if (args.len == 4 and std.mem.eql(u8, args[1], "verify")) {
        for (cases, 0..) |_, id| {
            var arena = std.heap.ArenaAllocator.init(a);
            defer arena.deinit();
            try verifyCase(arena.allocator(), args[2], args[3], @intCast(id), 0);
            std.debug.print("FRI_NATIVE_VERIFY case={} PASS\n", .{id});
        }
        for (1..11) |fault| {
            var arena = std.heap.ArenaAllocator.init(a);
            defer arena.deinit();
            if (verifyCase(arena.allocator(), args[2], args[3], 1, @intCast(fault))) |_| return error.FriTamperAccepted else |err| std.debug.print("FRI_NATIVE_TAMPER fault={} rejected={s}\n", .{ fault, @errorName(err) });
        }
    } else return error.ExpectedExportDirectoryOrVerifyFixtureAndOutputDirectories;
}
