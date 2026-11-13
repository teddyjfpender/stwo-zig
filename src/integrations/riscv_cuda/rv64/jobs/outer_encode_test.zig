//! Independent assembler oracle and adversarial tests for outer encoding.
const std = @import("std");
const G = @import("gpu_native.zig");
const Schema = @import("outer_encode.zig");
const Host = @import("outer_encode_host.zig");
const layerHeight = Host.layerHeight;

const Ref = struct {
    // Transliteration of trace.zig assemble / fri.zig layerProof+assemble /
    // pcs_assembly.assemble / family.zig writeProofWireBinary / wire.encode.
    fn encode(a: std.mem.Allocator, desc: []const u32, image: []const u32, in: Schema.Inputs) ![]u32 {
        var out: std.ArrayListUnmanaged(u32) = .empty;
        errdefer out.deinit(a);
        const im = Schema.Image.of(desc);
        const q = desc[Schema.D.queries];
        const raw = image[im.queries..][0..q];
        const h = image[0..14];
        if (h[0] != Schema.image_magic or h[7] != desc[Schema.D.trees]) return error.InvalidGpuPcsProof;
        if (image[14] != 0) return error.GpuPcsNumericalFailure;
        for (0..desc[Schema.D.trees]) |t| if (in.roots[t]) |r| if (!std.mem.eql(u32, r, image[im.roots + 8 * t ..][0..8])) return error.NativePcsTreeRootMismatch;
        var physical: std.ArrayListUnmanaged(u32) = .empty;
        defer physical.deinit(a);
        const P = struct {
            list: *std.ArrayListUnmanaged(u32),
            a: std.mem.Allocator,
            fn w(self: @This(), v: u32) !void {
                try self.list.append(self.a, v);
            }
            fn ws(self: @This(), v: []const u32) !void {
                try self.list.appendSlice(self.a, v);
            }
        };
        const p = P{ .list = &physical, .a = a };
        try p.ws(desc[Schema.D.phys_magic..][0..2]);
        try p.ws(desc[Schema.D.config..][0..6]);
        try p.w(desc[Schema.D.trees]);
        try p.ws(image[im.roots..][0 .. 8 * desc[Schema.D.trees]]);
        try p.w(desc[Schema.D.trees]);
        var cur: usize = im.samples;
        for (0..desc[Schema.D.trees]) |t| {
            const tr = Schema.tree(desc, @intCast(t));
            try p.w(tr.columns);
            for (desc[tr.table + 3 * tr.columns ..][0..tr.columns]) |c| {
                try p.w(c);
                for (image[cur..][0 .. 8 * c]) |v| if (v >= Schema.modulus) return error.NoncanonicalPcsReadback;
                try p.ws(image[cur..][0 .. 8 * c]);
                cur += 8 * c;
            }
        }
        // trace openings
        var queried: std.ArrayListUnmanaged(u32) = .empty;
        defer queried.deinit(a);
        try queried.append(a, desc[Schema.D.trees]);
        try p.w(desc[Schema.D.trees]);
        for (0..desc[Schema.D.trees]) |t| {
            const tr = Schema.tree(desc, @intCast(t));
            const tl = tr.tree_log;
            const lift = desc[Schema.D.initial_log];
            const idx = try a.alloc(usize, q);
            defer a.free(idx);
            for (idx, 0..) |*x, i| x.* = i;
            const Order = struct {
                raw: []const u32,
                fn less(self: @This(), l: usize, r: usize) bool {
                    return self.raw[l] < self.raw[r] or (self.raw[l] == self.raw[r] and l < r);
                }
            };
            std.sort.heap(usize, idx, Order{ .raw = raw }, Order.less);
            var reps: std.ArrayListUnmanaged(usize) = .empty;
            defer reps.deinit(a);
            for (idx) |i| if (reps.items.len == 0 or raw[reps.items[reps.items.len - 1]] != raw[i]) try reps.append(a, i);
            const values = image[im.tree_values[t]..];
            var seen = std.AutoHashMap(u64, u32).init(a);
            defer seen.deinit();
            const logs = desc[tr.table..][0..tr.columns];
            for (logs, 0..) |log, ci| {
                seen.clearRetainingCapacity();
                for (raw, 0..) |v, qi| {
                    const value = values[ci * q + qi];
                    if (value >= Schema.modulus) return error.NoncanonicalTraceValue;
                    const pp = Schema.position(Schema.position(v, lift, tl), tl, log);
                    if (seen.get(pp)) |old| {
                        if (old != value) return error.InconsistentTraceReadback;
                    } else try seen.put(pp, value);
                }
            }
            var hashes = std.AutoHashMap(u64, [8]u32).init(a);
            defer hashes.deinit();
            const paths = image[im.tree_paths[t]..];
            var tp = try a.alloc(u64, q);
            defer a.free(tp);
            for (raw, 0..) |v, qi| tp[qi] = Schema.position(v, lift, tl);
            for (0..q) |qi| for (0..tl) |lv| {
                const key = (@as(u64, lv) << 40) | ((tp[qi] >> @intCast(lv)) ^ 1);
                const hh = paths[(qi * tl + lv) * 8 ..][0..8].*;
                if (hashes.get(key)) |old| {
                    if (!std.mem.eql(u32, &old, &hh)) return error.InconsistentTraceReadback;
                } else try hashes.put(key, hh);
            };
            std.mem.sort(u64, tp, {}, std.sort.asc(u64));
            var current: std.ArrayListUnmanaged(u64) = .empty;
            defer current.deinit(a);
            for (tp) |v| if (current.items.len == 0 or current.items[current.items.len - 1] != v) try current.append(a, v);
            var witness: std.ArrayListUnmanaged(u32) = .empty;
            defer witness.deinit(a);
            var n_witness: u32 = 0;
            for (0..tl) |lv| {
                var next: std.ArrayListUnmanaged(u64) = .empty;
                var i: usize = 0;
                while (i < current.items.len) {
                    const first = current.items[i];
                    const paired = i + 1 < current.items.len and current.items[i + 1] == (first ^ 1);
                    if (!paired) {
                        try witness.appendSlice(a, &(hashes.get((@as(u64, lv) << 40) | (first ^ 1)) orelse return error.MissingTraceReadback));
                        n_witness += 1;
                    }
                    try next.append(a, first >> 1);
                    i += if (paired) 2 else 1;
                }
                current.deinit(a);
                current = next;
            }
            try p.w(n_witness);
            try p.ws(witness.items);
            const s2o = desc[tr.table + tr.columns ..][0..tr.columns];
            const cols = try a.alloc([]u32, tr.columns);
            defer {
                for (cols) |c| a.free(c);
                a.free(cols);
            }
            for (0..tr.columns) |s| {
                const col = try a.alloc(u32, reps.items.len);
                for (reps.items, col) |qi, *v| v.* = values[s * q + qi];
                cols[s2o[s]] = col;
            }
            try queried.append(a, tr.columns);
            for (cols) |c| {
                try queried.append(a, @intCast(c.len));
                try queried.appendSlice(a, c);
            }
        }
        try p.ws(queried.items);
        try p.ws(image[im.nonce..][0..2]);
        // FRI
        var positions: std.ArrayListUnmanaged(u64) = .empty;
        defer positions.deinit(a);
        {
            const tmp = try a.alloc(u64, q);
            defer a.free(tmp);
            for (raw, tmp) |v, *x| x.* = v;
            std.mem.sort(u64, tmp, {}, std.sort.asc(u64));
            for (tmp) |v| if (positions.items.len == 0 or positions.items[positions.items.len - 1] != v) try positions.append(a, v);
        }
        for (0..desc[Schema.D.layers]) |l| {
            const f = Schema.layer(desc, @intCast(l));
            const hgt = layerHeight(f);
            const subset: usize = @as(usize, 1) << @intCast(f.fold_step);
            const slots: usize = @as(usize, 1) << @intCast(f.fold_step - f.leaf_log);
            const vals = image[im.layer_values[l]..];
            const paths = image[im.layer_paths[l]..];
            var values = std.AutoHashMap(u64, [8]u32).init(a);
            defer values.deinit();
            var hashes = std.AutoHashMap(u64, [8]u32).init(a);
            defer hashes.deinit();
            for (raw, 0..) |v, qi| {
                const start = ((@as(u64, v) >> @intCast(f.shift)) >> @intCast(f.fold_step)) << @intCast(f.fold_step);
                for (0..subset) |off| {
                    const val = vals[(qi * subset + off) * 8 ..][0..8].*;
                    for (val) |x| if (x >= Schema.modulus) return error.NoncanonicalFriField;
                    if (values.get(start + off)) |old| {
                        if (!std.mem.eql(u32, &old, &val)) return error.InconsistentFriReadback;
                    } else try values.put(start + off, val);
                }
                for (0..slots) |slot| for (0..hgt) |lv| {
                    const leaf = (start >> @intCast(f.leaf_log)) + slot;
                    const key = (@as(u64, lv) << 40) | ((leaf >> @intCast(lv)) ^ 1);
                    const hh = paths[((qi * slots + slot) * hgt + lv) * 8 ..][0..8].*;
                    if (hashes.get(key)) |old| {
                        if (!std.mem.eql(u32, &old, &hh)) return error.InconsistentFriReadback;
                    } else try hashes.put(key, hh);
                };
            }
            var witness: std.ArrayListUnmanaged(u32) = .empty;
            defer witness.deinit(a);
            var n_fw: u32 = 0;
            var leaves: std.ArrayListUnmanaged(u64) = .empty;
            defer leaves.deinit(a);
            var cursor: usize = 0;
            while (cursor < positions.items.len) {
                const start = (positions.items[cursor] >> @intCast(f.fold_step)) << @intCast(f.fold_step);
                for (start..start + subset) |pos| {
                    const value = values.get(pos) orelse return error.MissingFriReadback;
                    if (cursor < positions.items.len and positions.items[cursor] == pos) cursor += 1 else {
                        try witness.appendSlice(a, &value);
                        n_fw += 1;
                    }
                    const leaf = pos >> @intCast(f.leaf_log);
                    if (leaves.items.len == 0 or leaves.items[leaves.items.len - 1] != leaf) try leaves.append(a, leaf);
                }
            }
            var hw: std.ArrayListUnmanaged(u32) = .empty;
            defer hw.deinit(a);
            var n_hw: u32 = 0;
            var current = try leaves.clone(a);
            defer current.deinit(a);
            for (0..hgt) |lv| {
                var next: std.ArrayListUnmanaged(u64) = .empty;
                var i: usize = 0;
                while (i < current.items.len) {
                    const first = current.items[i];
                    const sib = i + 1 < current.items.len and current.items[i + 1] == (first ^ 1);
                    if (!sib) {
                        try hw.appendSlice(a, &(hashes.get((@as(u64, lv) << 40) | (first ^ 1)) orelse return error.MissingFriReadback));
                        n_hw += 1;
                    }
                    try next.append(a, first >> 1);
                    i += if (sib) 2 else 1;
                }
                current.deinit(a);
                current = next;
            }
            if (l == 1) try p.w(desc[Schema.D.layers] - 1);
            try p.w(n_fw);
            try p.ws(witness.items);
            try p.w(n_hw);
            try p.ws(hw.items);
            try p.ws(image[im.layer_root[l]..][0..8]);
            // fold
            var w: usize = 0;
            for (0..positions.items.len) |i| {
                const folded = positions.items[i] >> @intCast(f.fold_step);
                if (w == 0 or positions.items[w - 1] != folded) {
                    positions.items[w] = folded;
                    w += 1;
                }
            }
            positions.shrinkRetainingCapacity(w);
        }
        if (desc[Schema.D.layers] == 1) try p.w(0);
        try p.w(1);
        for (image[im.terminal..][0..8]) |x| if (x >= Schema.modulus) return error.NoncanonicalFriField;
        try p.ws(image[im.terminal..][0..8]);
        if (desc[Schema.D.flags] & Schema.D.flag_envelope != 0) {
            try out.appendSlice(a, desc[Schema.D.envelope..][0..18]);
            try out.append(a, @intCast(in.outputs.len / 4));
            try out.appendSlice(a, in.outputs);
            try out.appendSlice(a, in.claims);
            try out.append(a, @intCast(physical.items.len * 4));
        }
        try out.appendSlice(a, physical.items);
        return out.toOwnedSlice(a);
    }
};

const Synth = struct {
    // Deterministic, internally consistent PCS image of a class: every value
    // and sibling hash is a function of its tree position, so duplicated
    // queries read back equal words (as a correct PCS does).
    fn mix(x: u64) u32 {
        var z = x +% 0x9e37_79b9_7f4a_7c15;
        z = (z ^ (z >> 30)) *% 0xbf58_476d_1ce4_e5b9;
        z = (z ^ (z >> 27)) *% 0x94d0_49bb_1331_11eb;
        return @as(u32, @truncate(z ^ (z >> 31))) % Schema.modulus;
    }
    fn image(a: std.mem.Allocator, desc: []const u32, raw: []const u32, seed: u64) ![]u32 {
        const im = Schema.Image.of(desc);
        const w = try a.alloc(u32, im.words);
        for (w, 0..) |*x, i| x.* = mix(seed ^ (i *% 0x1234_5678_9abc));
        const q = desc[Schema.D.queries];
        w[0..14].* = .{ Schema.image_magic, 2, 0, 0, 0, 0, 0, desc[Schema.D.trees], desc[Schema.D.samples], desc[Schema.D.layers], desc[Schema.D.initial_log], q, desc[Schema.D.degree_log], 5 };
        w[14] = 0;
        @memset(w[15..31], 0);
        w[15 + 8] = 3;
        w[15 + 9] = 5;
        w[15 + 12] = 22;
        @memcpy(w[im.queries..][0..q], raw);
        for (0..desc[Schema.D.layers]) |l| {
            const f = Schema.layer(desc, @intCast(l));
            const hgt = layerHeight(f);
            const subset: u64 = @as(u64, 1) << @intCast(f.fold_step);
            const slots: u64 = @as(u64, 1) << @intCast(f.fold_step - f.leaf_log);
            for (raw, 0..) |v, qi| {
                const start = ((@as(u64, v) >> @intCast(f.shift)) >> @intCast(f.fold_step)) << @intCast(f.fold_step);
                for (0..subset) |off| for (0..8) |k| {
                    w[im.layer_values[l] + (qi * subset + off) * 8 + k] = mix((l << 50) ^ ((start + off) << 4) ^ k ^ seed);
                };
                for (0..slots) |slot| for (0..hgt) |lv| {
                    const leaf = (start >> @intCast(f.leaf_log)) + slot;
                    const sib = (leaf >> @intCast(lv)) ^ 1;
                    for (0..8) |k| w[im.layer_paths[l] + ((qi * slots + slot) * hgt + lv) * 8 + k] = mix(0xf000_0000_0000 ^ (l << 44) ^ (lv << 38) ^ (sib << 4) ^ k ^ seed);
                };
            }
        }
        for (0..desc[Schema.D.trees]) |t| {
            const tr = Schema.tree(desc, @intCast(t));
            const logs = desc[tr.table..][0..tr.columns];
            for (raw, 0..) |v, qi| {
                const p = Schema.position(v, desc[Schema.D.initial_log], tr.tree_log);
                for (logs, 0..) |log, s| w[im.tree_values[t] + s * q + qi] = mix((t << 56) ^ (s << 30) ^ Schema.position(p, tr.tree_log, log) ^ seed);
                for (0..tr.tree_log) |lv| {
                    const sib = (p >> @intCast(lv)) ^ 1;
                    for (0..8) |k| w[im.tree_paths[t] + (qi * tr.tree_log + lv) * 8 + k] = mix(0xe000_0000_0000 ^ (t << 44) ^ (lv << 38) ^ (sib << 4) ^ k ^ seed);
                }
            }
        }
        return w;
    }
};

const TestClass = struct {
    trees: [Schema.max_trees]Schema.TreeShape,
    store: [Schema.max_trees][3][64]u32,
    n: usize,
    shape: Schema.Shape,
    fn random(self: *TestClass, r: std.Random, n_queries: u32, fold_step: u32) void {
        const degree_log: u32 = 5 + r.uintLessThan(u32, 5);
        self.n = 1 + r.uintLessThan(usize, Schema.max_trees);
        for (0..self.n) |t| {
            const cols = 1 + r.uintLessThan(usize, 12);
            const logs = self.store[t][0][0..cols];
            for (logs) |*l| l.* = 1 + r.uintLessThan(u32, degree_log);
            // sorted_to_original: argsort ascending by log (stable).
            const s2o = self.store[t][1][0..cols];
            for (s2o, 0..) |*x, i| x.* = @intCast(i);
            std.mem.sort(u32, s2o, logs, struct {
                fn less(ls: []u32, x: u32, y: u32) bool {
                    return ls[x] < ls[y] or (ls[x] == ls[y] and x < y);
                }
            }.less);
            const counts = self.store[t][2][0..cols];
            for (counts) |*c| c.* = r.uintLessThan(u32, 3);
            self.trees[t] = .{ .coefficient_logs = logs, .sorted_to_original = s2o, .sample_counts = counts };
        }
        self.shape = .{ .config = .{ .pow_bits = 20, .log_blowup = 1 + r.uintLessThan(u32, 2), .log_last_layer = 0, .n_queries = n_queries, .fold_step = fold_step, .lifting = degree_log + 2 }, .degree_log = degree_log, .trees = self.trees[0..self.n] };
    }
};

fn testEnvelope() Schema.Envelope {
    var e = Schema.Envelope{ .prefix = undefined, .n_outputs = 3, .n_claims = 11, .latches = 4 };
    @memcpy(e.prefix[0..8], "STWOCOM1");
    for (e.prefix[8..], 0..) |*b, i| b.* = @truncate(i *% 37);
    return e;
}

test "outer encode: host mirror equals the reference assembler + wire writer on random classes" {
    const t = std.testing;
    const a = t.allocator;
    var prng = std.Random.DefaultPrng.init(0x5eed_0e1c);
    const r = prng.random();
    var cases: usize = 0;
    while (cases < 160) : (cases += 1) {
        var tc: TestClass = undefined;
        const nq: u32 = 1 + r.uintLessThan(u32, 40);
        tc.random(r, nq, 1 + r.uintLessThan(u32, 4));
        const with_env = r.boolean();
        const env = testEnvelope();
        const root0: [8]u32 = .{ 1, 2, 3, 4, 5, 6, 7, 8 };
        const desc = Schema.buildDescriptor(a, tc.shape, if (with_env) env else null, root0) catch |err| switch (err) {
            error.UnsupportedFriGeometry => continue,
            else => return err,
        };
        defer a.free(desc);
        const raw = try a.alloc(u32, nq);
        defer a.free(raw);
        // Heavy duplication on purpose (few distinct rows).
        const span: u32 = @as(u32, 1) << @intCast(@min(desc[Schema.D.initial_log], 1 + r.uintLessThan(u32, desc[Schema.D.initial_log])));
        for (raw) |*x| x.* = r.uintLessThan(u32, span) << @intCast(desc[Schema.D.initial_log] - std.math.log2_int(u32, span));
        const img = try Synth.image(a, desc, raw, r.int(u64));
        defer a.free(img);
        var in = Schema.Inputs{};
        var claims: [88]u32 = undefined;
        for (&claims, 0..) |*c, i| c.* = @intCast(i * 7 + 1);
        const outputs = [_]u32{ 9, 8, 7, 6, 5, 4, 3, 2, 1, 0, 11, 12 };
        const latches = [_]u32{ 0, 0, 0, 0 };
        if (with_env) {
            in.claims = &claims;
            in.outputs = &outputs;
            in.latches = &latches;
        }
        in.roots[0] = img[Schema.Image.of(desc).roots..][0..8];
        // flag_fixed_root: the expected tree-0 root must equal the class
        // root as well; a different one is refused (detail root).
        try t.expect(desc[Schema.D.flags] & Schema.D.flag_fixed_root != 0);
        {
            if (!std.mem.eql(u32, in.roots[0].?, &root0)) {
                const probe = try a.alloc(u32, desc[Schema.D.max_payload_words] + 1);
                defer a.free(probe);
                try t.expectEqual(G.Verdict.reject(.node_pcs_status, @intFromEnum(Schema.PcsDetail.root)), (try Schema.encodeHost(a, desc, img, in, probe)).pcs);
            }
        }
        desc[Schema.D.fixed_root..][0..8].* = img[Schema.Image.of(desc).roots..][0..8].*;
        const expected = try Ref.encode(a, desc, img, in);
        defer a.free(expected);
        const out = try a.alloc(u32, desc[Schema.D.max_payload_words] + 1);
        defer a.free(out);
        const v = try Schema.encodeHost(a, desc, img, in, out);
        try t.expectEqual(G.Verdict.accepted, v.pcs);
        try t.expectEqual(G.Verdict.accepted, v.bounds);
        try t.expectEqual(@as(u32, @intCast(expected.len * 4)), out[0]);
        try t.expectEqualSlices(u32, expected, out[1..][0..expected.len]);
        // Bound is an upper bound with distinct queries too.
        try t.expect(expected.len <= desc[Schema.D.max_payload_words]);
    }
}

test "outer encode: distinct queries reach but never exceed the class bound" {
    const t = std.testing;
    const a = t.allocator;
    var prng = std.Random.DefaultPrng.init(77);
    const r = prng.random();
    for (0..40) |_| {
        var tc: TestClass = undefined;
        tc.random(r, 1 + r.uintLessThan(u32, 30), 1 + r.uintLessThan(u32, 4));
        const desc = Schema.buildDescriptor(a, tc.shape, testEnvelope(), null) catch continue;
        defer a.free(desc);
        const nq = desc[Schema.D.queries];
        const raw = try a.alloc(u32, nq);
        defer a.free(raw);
        for (raw) |*x| x.* = r.uintLessThan(u32, @as(u32, 1) << @intCast(desc[Schema.D.initial_log]));
        const img = try Synth.image(a, desc, raw, 1);
        defer a.free(img);
        var claims: [88]u32 = @splat(1);
        const outputs = [_]u32{ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12 };
        const in = Schema.Inputs{ .claims = &claims, .outputs = &outputs, .latches = &.{ 0, 0, 0, 0 } };
        const out = try a.alloc(u32, desc[Schema.D.max_payload_words] + 1);
        defer a.free(out);
        const v = try Schema.encodeHost(a, desc, img, in, out);
        try t.expectEqual(G.Verdict.accepted, v.bounds);
        const exact = try Ref.encode(a, desc, img, in);
        defer a.free(exact);
        try t.expectEqualSlices(u32, exact, out[1..][0..exact.len]);
        // Too small a region: encode_bounds rejects, length stays 0.
        const small = try a.alloc(u32, exact.len);
        defer a.free(small);
        const s = try Schema.encodeHost(a, desc, img, in, small);
        try t.expectEqual(G.Verdict.accepted, s.pcs);
        try t.expectEqual(G.Verdict.reject(.encode_bounds, 1), s.bounds);
        try t.expectEqual(@as(u32, 0), small[0]);
    }
}

test "outer encode: every corrupted input class is refused with its detail (and the reference refuses too)" {
    const t = std.testing;
    const a = t.allocator;
    var prng = std.Random.DefaultPrng.init(4242);
    const r = prng.random();
    var tc: TestClass = undefined;
    while (true) {
        tc.random(r, 24, 2);
        if (Schema.buildDescriptor(a, tc.shape, testEnvelope(), null)) |d| {
            a.free(d);
            break;
        } else |_| {}
    }
    const desc = try Schema.buildDescriptor(a, tc.shape, testEnvelope(), null);
    defer a.free(desc);
    const im = Schema.Image.of(desc);
    const raw = try a.alloc(u32, 24);
    defer a.free(raw);
    // Duplicates so consistency checks have something to compare.
    for (raw, 0..) |*x, i| x.* = @intCast((i / 3) * 5 % (@as(u32, 1) << @intCast(desc[Schema.D.initial_log])));
    const good = try Synth.image(a, desc, raw, 9);
    defer a.free(good);
    const claims: [88]u32 = @splat(3);
    const outputs = [_]u32{ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12 };
    const root1: [8]u32 = good[im.roots + 8 ..][0..8].*;
    const out = try a.alloc(u32, desc[Schema.D.max_payload_words] + 1);
    defer a.free(out);
    const Case = struct { detail: Schema.PcsDetail, word: ?u64 = null, value: u32 = 0, claims: bool = false, latch: bool = false, root: bool = false };
    const tr0 = Schema.tree(desc, 0);
    // A duplicated query's second copy (index 1 duplicates index 0).
    const cases = [_]Case{
        .{ .detail = .header, .word = 0, .value = 1 },
        .{ .detail = .numerical, .word = 14, .value = 1 },
        .{ .detail = .channel, .word = 15 + 10, .value = 1 },
        .{ .detail = .query_range, .word = im.queries + 3, .value = @as(u32, 1) << @intCast(desc[Schema.D.initial_log]) },
        .{ .detail = .noncanonical, .word = im.terminal, .value = Schema.modulus },
        .{ .detail = .noncanonical, .word = im.tree_values[0], .value = Schema.modulus + 5 },
        .{ .detail = .trace_inconsistent, .word = im.tree_values[0] + 1, .value = 17 },
        .{ .detail = .trace_inconsistent, .word = im.tree_paths[0] + @as(u64, tr0.tree_log) * 8 + 2, .value = 17 },
        .{ .detail = .fri_inconsistent, .word = im.layer_values[0] + (@as(u64, 1) << @intCast(Schema.layer(desc, 0).fold_step)) * 8, .value = 17 },
        .{ .detail = .fri_inconsistent, .word = im.layer_paths[0] + (@as(u64, 1) << @intCast(Schema.layer(desc, 0).fold_step - Schema.layer(desc, 0).leaf_log)) * layerHeight(Schema.layer(desc, 0)) * 8, .value = 17 },
        .{ .detail = .section_latch, .latch = true },
        .{ .detail = .noncanonical_public, .claims = true },
        .{ .detail = .root, .root = true },
    };
    for (cases) |c| {
        const img = try a.dupe(u32, good);
        defer a.free(img);
        if (c.word) |w| img[w] = c.value;
        var cl = claims;
        if (c.claims) cl[5] = Schema.modulus;
        var latches = [_]u32{ 0, 0, 0, 0 };
        if (c.latch) latches[2] = 1;
        var in = Schema.Inputs{ .claims = &cl, .outputs = &outputs, .latches = &latches };
        var bad_root = root1;
        if (c.root) bad_root[3] ^= 1;
        if (desc[Schema.D.trees] > 1) in.roots[1] = &bad_root;
        if (c.root and desc[Schema.D.trees] == 1) in.roots[0] = &bad_root;
        const v = try Schema.encodeHost(a, desc, img, in, out);
        t.expectEqual(G.Verdict.reject(.node_pcs_status, @intFromEnum(c.detail)), v.pcs) catch |err| {
            std.debug.print("case {s}: got 0x{x}\n", .{ @tagName(c.detail), v.pcs });
            return err;
        };
        try t.expectEqual(G.Verdict.reject(.encode_bounds, 2), v.bounds);
        try t.expectEqual(@as(u32, 0), out[0]);
        // The reference rejects the image-side corruptions as well.
        if (c.word != null and c.detail != .header and c.detail != .channel and c.detail != .query_range) {
            if (Ref.encode(a, desc, img, in)) |bytes| {
                a.free(bytes);
                std.debug.print("reference accepted case {s}\n", .{@tagName(c.detail)});
                return error.TestExpectedError;
            } else |_| {}
        }
    }
}

test "outer encode: descriptor refuses shapes the host assembler refuses" {
    const t = std.testing;
    const a = t.allocator;
    const logs = [_]u32{ 3, 2 };
    const bad_perm = [_]u32{ 0, 0 };
    const counts = [_]u32{ 1, 1 };
    const cfg = Schema.Config{ .pow_bits = 1, .log_blowup = 1, .log_last_layer = 0, .n_queries = 4, .fold_step = 2, .lifting = null };
    try t.expectError(error.InvalidPcsShape, Schema.buildDescriptor(a, .{ .config = cfg, .degree_log = 4, .trees = &.{.{ .coefficient_logs = &logs, .sorted_to_original = &bad_perm, .sample_counts = &counts }} }, null, null));
    // Not ascending after the permutation.
    try t.expectError(error.InvalidPcsShape, Schema.buildDescriptor(a, .{ .config = cfg, .degree_log = 4, .trees = &.{.{ .coefficient_logs = &logs, .sorted_to_original = &.{ 0, 1 }, .sample_counts = &counts }} }, null, null));
    var c2 = cfg;
    c2.log_last_layer = 1;
    try t.expectError(error.UnsupportedFriGeometry, Schema.buildDescriptor(a, .{ .config = c2, .degree_log = 4, .trees = &.{.{ .coefficient_logs = &logs, .sorted_to_original = &.{ 1, 0 }, .sample_counts = &counts }} }, null, null));
    const d = try Schema.buildDescriptor(a, .{ .config = cfg, .degree_log = 4, .trees = &.{.{ .coefficient_logs = &logs, .sorted_to_original = &.{ 1, 0 }, .sample_counts = &counts }} }, null, null);
    defer a.free(d);
    try t.expectEqual(@as(u32, 1), d[Schema.D.tables + 2]); // sorted_to_original[0] = 1 (logs sorted: [2+1, 3+1])
    try t.expectEqual(@as(u32, 3), d[Schema.D.tables]);
    try t.expectEqual(@as(u32, 4), d[Schema.D.tables + 1]);
    // Stale magic in a descriptor fails closed at encode.
    const bad = try a.dupe(u32, d);
    defer a.free(bad);
    bad[Schema.D.magic] ^= 1;
    var out: [4]u32 = undefined;
    const v = try Schema.encodeHost(a, bad, &.{}, .{}, &out);
    try t.expectEqual(G.Verdict.reject(.node_pcs_status, 1), v.pcs);
}
