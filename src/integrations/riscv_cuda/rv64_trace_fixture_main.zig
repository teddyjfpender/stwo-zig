//! Native lifted commitments and a fresh receiver for compact GPU openings.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const T = @import("rv64/trace.zig");
const IO = @import("rv64/fixture_io.zig");
const M = core.fields.m31.M31;
const H = T.H;
const Channel = core.channel.raw_mod_m31.Om31Channel;
const Prover = engine.vcs_lifted.prover.MerkleProverLifted(H);
const Verifier = core.vcs_lifted.verifier.MerkleVerifierLifted(H);
const a = std.heap.page_allocator;
const case_count = 6;
fn logsFor(id: u32) ![]u32 {
    const small: []const u32 = switch (id) {
        0 => &.{ 5, 3, 5, 4 },
        1 => &.{ 8, 4, 8, 3, 6 },
        2 => &.{1},
        3 => &.{ 14, 5, 10, 14 },
        4 => &.{},
        5 => &.{ 8, 3, 5 },
        else => return error.InvalidTraceCase,
    };
    if (id != 4) return a.dupe(u32, small);
    const out = try a.alloc(u32, 512);
    for (out, 0..) |*v, i| v.* = @intCast(3 + i % 6);
    return out;
}
fn hashWords(w: anytype, h: H.Hash) !void {
    for (0..8) |i| try IO.words(w, &.{std.mem.readInt(u32, h[4 * i ..][0..4], .little)});
}
fn checkpoint(w: anytype, c: Channel, full: bool) !void {
    try hashWords(w, c.inner.digest);
    try IO.words(w, &.{c.inner.n_draws});
    if (full) try IO.words(w, &.{ 2, 0, 0, 3, 0, 0, 0 });
}
fn initial(id: u32) Channel {
    var c = Channel.init();
    c.mixU32s(&.{ 0x52565452, 1, id });
    return c;
}
fn exportCase(dir: std.fs.Dir, id: u32) !void {
    const logs = try logsFor(id);
    defer a.free(logs);
    const height: u32 = if (id == 5) 10 else std.mem.max(u32, logs);
    const lifting: u32 = switch (id) {
        0 => 7,
        1 => 6,
        5 => 6,
        else => height,
    };
    const queries: u32 = if (id == 2) 65 else 256;
    const cols = try a.alloc([]const M, logs.len);
    defer a.free(cols);
    var done: usize = 0;
    defer for (cols[0..done]) |v| a.free(v);
    var rng = std.Random.DefaultPrng.init(0xfabb331 + id);
    for (logs, cols) |log, *values| {
        const n = @as(usize, 1) << @intCast(log);
        const coefficients = try a.alloc(M, @max(2, n / 4));
        defer a.free(coefficients);
        for (coefficients) |*v| v.* = M.fromCanonical(rng.random().uintLessThan(u32, core.fields.m31.Modulus));
        const poly = try engine.poly.circle.CircleCoefficients.initBorrowed(coefficients);
        const domain = core.poly.circle.canonic.CanonicCoset.new(log).circleDomain();
        values.* = (try poly.evaluate(a, domain)).values;
        done += 1;
    }
    var tree = try Prover.commitLifted(a, cols, height);
    defer tree.deinit(a);
    var channel = initial(id);
    core.vcs_lifted.blake2_merkle.Blake2sPrefixedMerkleChannel.mixRoot(&channel.inner, tree.root());
    const raw = try core.queries.drawQueries(&channel, a, lifting, queries);
    defer a.free(raw);
    const unique = try core.queries.sortedUniquePositions(a, raw);
    defer a.free(unique);
    const positions = try core.pcs.utils.prepareTreeQueryPositions(a, unique, lifting, height);
    defer a.free(positions);
    var opening = try tree.decommit(a, positions, cols);
    defer opening.deinit(a);
    const order = try a.alloc(u32, logs.len);
    defer a.free(order);
    for (order, 0..) |*v, i| v.* = @intCast(i);
    const Order = struct {
        fn less(ls: []const u32, l: u32, r: u32) bool {
            return ls[l] < ls[r] or (ls[l] == ls[r] and l < r);
        }
    };
    std.sort.heap(u32, order, logs, Order.less);
    var slab: std.ArrayList(u32) = .empty;
    defer slab.deinit(a);
    var segments: std.ArrayList(u32) = .empty;
    defer segments.deinit(a);
    var i: usize = 0;
    while (i < order.len) {
        const log = logs[order[i]];
        const rows = @as(usize, 1) << @intCast(log);
        const start = i;
        const offset = slab.items.len;
        const stride = rows + 3;
        while (i < order.len and logs[order[i]] == log) : (i += 1) {
            for (cols[order[i]]) |v| try slab.append(a, v.v);
            try slab.appendNTimes(a, 0x1234567, 3);
        }
        try segments.appendSlice(a, &.{ @truncate(offset), @truncate(@as(u64, offset) >> 32), @intCast(stride), @intCast(i - start), @intCast(rows), 0 });
    }
    var bytes: std.ArrayList(u8) = .empty;
    defer bytes.deinit(a);
    const w = bytes.writer(a);
    try IO.words(w, &.{ 0x52565452, 1, id, height, lifting, queries, @intCast(logs.len), @intCast(segments.items.len / 6), @intCast(slab.items.len), @intCast(opening.decommitment.decommitment.hash_witness.len), @intCast(unique.len) });
    try IO.words(w, logs);
    try IO.words(w, order);
    try IO.words(w, segments.items);
    try checkpoint(w, initial(id), false);
    try hashWords(w, tree.root());
    for (raw) |q| try IO.words(w, &.{@intCast(q)});
    try checkpoint(w, channel, true);
    try IO.words(w, slab.items);
    for (opening.queried_values) |column| for (column) |v| try IO.words(w, &.{v.v});
    for (opening.decommitment.decommitment.hash_witness) |h| try hashWords(w, h);
    const name = try std.fmt.allocPrint(a, "case-{}.bin", .{id});
    defer a.free(name);
    try dir.writeFile(.{ .sub_path = name, .data = bytes.items });
    std.debug.print("trace={} columns={} tree_log={} lifting_log={} native_root_and_opening=true\n", .{ id, logs.len, height, lifting });
}
const Reader = struct {
    words: []u32,
    pos: usize = 0,
    fn init(path: []const u8) !@This() {
        const bytes = try std.fs.cwd().readFileAlloc(a, path, 1 << 28);
        defer a.free(bytes);
        if (bytes.len % 4 != 0) return error.TraceReadbackAlignment;
        const words = try a.alloc(u32, bytes.len / 4);
        for (words, 0..) |*v, i| v.* = std.mem.readInt(u32, bytes[4 * i ..][0..4], .little);
        return .{ .words = words };
    }
    fn deinit(self: *@This()) void {
        a.free(self.words);
    }
    fn take(self: *@This(), n: usize) ![]const u32 {
        if (n > self.words.len - self.pos) return error.TruncatedTraceReadback;
        const out = self.words[self.pos..][0..n];
        self.pos += n;
        return out;
    }
};
fn verifyCase(fixtures: []const u8, readback: []const u8, id: u32) !void {
    const fp = try std.fmt.allocPrint(a, "{s}/case-{}.bin", .{ fixtures, id });
    defer a.free(fp);
    const rp = try std.fmt.allocPrint(a, "{s}/case-{}.bin", .{ readback, id });
    defer a.free(rp);
    var f = try Reader.init(fp);
    defer f.deinit();
    var r = try Reader.init(rp);
    defer r.deinit();
    const h = try f.take(11);
    const rh = try r.take(6);
    if (!std.mem.eql(u32, rh, &.{ 0x5256544f, 1, id, h[5], h[6], h[3] })) return error.InvalidTraceReadback;
    const logs = try f.take(h[6]);
    const order = try f.take(h[6]);
    _ = try f.take(h[7] * 6);
    _ = try f.take(9);
    const expected_root = try f.take(8);
    const expected_queries = try f.take(h[5]);
    const expected_channel = try f.take(16);
    _ = try f.take(h[8]);
    const expected_values = try f.take(@as(usize, h[6]) * h[10]);
    const expected_hashes = try f.take(h[9] * 8);
    const root = try r.take(8);
    const raw = try r.take(h[5]);
    const values = try r.take(@as(usize, h[6]) * h[5]);
    const paths = try r.take(@as(usize, h[5]) * h[3] * 8);
    const status = (try r.take(1))[0];
    const channel = try r.take(16);
    if (status != 0 or r.pos != r.words.len or f.pos != f.words.len or !std.mem.eql(u32, root, expected_root) or !std.mem.eql(u32, raw, expected_queries) or !std.mem.eql(u32, channel, expected_channel)) return error.TraceOracleMismatch;
    const sorted_logs = try a.alloc(u32, logs.len);
    defer a.free(sorted_logs);
    for (order, sorted_logs) |o, *v| v.* = logs[o];
    var proof = try T.assemble(a, .{ .tree_log = h[3], .lifting_log = h[4], .column_logs = sorted_logs, .column_order = order }, raw, .{ .root = root[0..8].*, .values = values, .paths = paths });
    defer proof.deinit(a);
    const positions0 = try a.alloc(usize, raw.len);
    defer a.free(positions0);
    for (raw, positions0) |q, *v| v.* = q;
    const unique = try core.queries.sortedUniquePositions(a, positions0);
    defer a.free(unique);
    const positions = try core.pcs.utils.prepareTreeQueryPositions(a, unique, h[4], h[3]);
    defer a.free(positions);
    var verifier = try Verifier.initWithHeight(a, proof.root, logs, h[3]);
    defer verifier.deinit(a);
    try verifier.verify(a, positions, proof.queried_values, proof.decommitment);
    for (proof.queried_values, 0..) |column, c| for (column, 0..) |v, q| if (v.v != expected_values[c * unique.len + q]) return error.NativeTraceValueMismatch;
    if (proof.decommitment.hash_witness.len != h[9]) return error.NativeTraceHashMismatch;
    for (proof.decommitment.hash_witness, 0..) |hash, i| for (0..8) |j| if (std.mem.readInt(u32, hash[4 * j ..][0..4], .little) != expected_hashes[i * 8 + j]) return error.NativeTraceHashMismatch;
    const original = proof.queried_values[0][0];
    proof.queried_values[0][0] = original.add(M.one());
    if (verifier.verify(a, positions, proof.queried_values, proof.decommitment)) |_| return error.TamperedTraceValueAccepted else |_| {}
    proof.queried_values[0][0] = original;
    verifier.root[0] ^= 1;
    if (verifier.verify(a, positions, proof.queried_values, proof.decommitment)) |_| return error.TamperedTraceRootAccepted else |_| {}
    verifier.root[0] ^= 1;
    if (proof.decommitment.hash_witness.len > 0) {
        proof.decommitment.hash_witness[0][0] ^= 1;
        if (verifier.verify(a, positions, proof.queried_values, proof.decommitment)) |_| return error.TamperedTracePathAccepted else |_| {}
        proof.decommitment.hash_witness[0][0] ^= 1;
    }
    try verifier.verify(a, positions, proof.queried_values, proof.decommitment);
    std.debug.print("PASS fresh native trace receiver case={} compact_opening_exact=true mutations_rejected=true\n", .{id});
}
pub fn main() !void {
    const args = try std.process.argsAlloc(a);
    defer std.process.argsFree(a, args);
    if (args.len == 3 and std.mem.eql(u8, args[1], "export")) {
        try std.fs.cwd().makePath(args[2]);
        var dir = try std.fs.cwd().openDir(args[2], .{});
        defer dir.close();
        for (0..case_count) |id| try exportCase(dir, @intCast(id));
    } else if (args.len == 4 and std.mem.eql(u8, args[1], "verify")) {
        for (0..case_count) |id| try verifyCase(args[2], args[3], @intCast(id));
    } else return error.ExpectedExportOrVerifyDirectories;
}
