//! Canonical host encoder: owns validation, section planning, scratch and emission.
const std = @import("std");
const G = @import("gpu_native.zig");
const Schema = @import("outer_encode.zig");
pub fn layerHeight(l: Schema.FriLayer) u32 {
    return std.math.log2_int(u32, l.count) - l.leaf_log;
}

pub fn reject(check: G.Check, detail: anytype) u32 {
    return G.Verdict.reject(check, @intFromEnum(detail));
}

const Op = struct { dst: u32, src: u32, n: u32 };

/// Host mirror of the kernel (see the file comment). `out[0]` receives the
/// byte length (0 on any rejection), `out[1..]` the payload words.
pub fn encodeHost(a: std.mem.Allocator, desc: []const u32, image: []const u32, in: Schema.Inputs, out: []u32) !Schema.Verdicts {
    var m = try Mirror.init(a, desc, image, in, out);
    defer m.deinit();
    return m.run();
}

const Mirror = struct {
    a: std.mem.Allocator,
    desc: []const u32,
    image: []const u32,
    in: Schema.Inputs,
    out: []u32,
    im: Schema.Image = undefined,
    q: u32 = 0,
    sorted: []u32 = &.{}, // raw query indices in (raw, index) order
    reps: []u32 = &.{}, // first index of each distinct raw value, ascending raw
    ops: std.ArrayListUnmanaged(Op) = .empty,
    words: u32 = 0, // payload cursor
    detail: ?Schema.PcsDetail = null,
    // Planned sections (payload offsets fixed in emit()).
    trace_witness: [Schema.max_trees]std.ArrayListUnmanaged(Op) = @splat(.empty),
    fri_values: [Schema.max_layers]std.ArrayListUnmanaged(Op) = @splat(.empty),
    fri_hashes: [Schema.max_layers]std.ArrayListUnmanaged(Op) = @splat(.empty),

    fn init(a: std.mem.Allocator, desc: []const u32, image: []const u32, in: Schema.Inputs, out: []u32) !Mirror {
        return .{ .a = a, .desc = desc, .image = image, .in = in, .out = out };
    }
    fn deinit(self: *Mirror) void {
        self.a.free(self.sorted);
        self.a.free(self.reps);
        self.ops.deinit(self.a);
        for (&self.trace_witness) |*l| l.deinit(self.a);
        for (&self.fri_values) |*l| l.deinit(self.a);
        for (&self.fri_hashes) |*l| l.deinit(self.a);
    }
    fn fail(self: *Mirror, d: Schema.PcsDetail) void {
        if (self.detail == null) self.detail = d;
    }
    fn run(self: *Mirror) !Schema.Verdicts {
        if (self.out.len == 0) return error.OuterEncodeNoRegion;
        self.out[0] = 0;
        self.validate();
        if (self.detail == null) try self.plan();
        if (self.detail) |d| return .{ .pcs = reject(.node_pcs_status, d), .bounds = reject(.encode_bounds, Schema.BoundsDetail.input_rejected), .bytes = 0 };
        if (@as(u64, self.words) + 1 > self.out.len) return .{ .pcs = G.Verdict.accepted, .bounds = reject(.encode_bounds, Schema.BoundsDetail.capacity), .bytes = 0 };
        try self.emit();
        self.out[0] = self.words * 4;
        return .{ .pcs = G.Verdict.accepted, .bounds = G.Verdict.accepted, .bytes = self.words * 4 };
    }

    fn validate(self: *Mirror) void {
        const d = self.desc;
        if (d.len < Schema.D.tables or d[Schema.D.magic] != Schema.descriptor_magic or d[Schema.D.version] != Schema.descriptor_version or d[Schema.D.words] != d.len or d[Schema.D.trees] == 0 or d[Schema.D.trees] > Schema.max_trees or d[Schema.D.queries] == 0 or d[Schema.D.queries] > Schema.max_queries or d[Schema.D.layers] == 0 or d[Schema.D.layers] > Schema.max_layers) return self.fail(.descriptor);
        for (0..d[Schema.D.layers]) |l| {
            const f = Schema.layer(d, @intCast(l));
            if (f.fold_step == 0 or f.fold_step > 4 or f.leaf_log > f.fold_step or f.count < (@as(u32, 1) << @intCast(f.fold_step)) or !std.math.isPowerOfTwo(f.count) or f.count > 1 << 28) return self.fail(.descriptor);
        }
        for (0..d[Schema.D.trees]) |t| {
            const tr = Schema.tree(d, @intCast(t));
            if (tr.columns == 0 or tr.columns > Schema.max_columns or tr.tree_log < 1 or tr.tree_log > 28 or @as(u64, tr.table) + 4 * @as(u64, tr.columns) > d.len) return self.fail(.descriptor);
        }
        const env = d[Schema.D.flags] & Schema.D.flag_envelope != 0;
        if (self.in.outputs.len != (if (env) 4 * @as(usize, d[Schema.D.outputs]) else 0) or self.in.claims.len != (if (env) 8 * @as(usize, d[Schema.D.claims]) else 0) or self.in.latches.len != (if (env) @as(usize, d[Schema.D.latches]) else 0)) return self.fail(.descriptor);
        self.im = Schema.Image.of(d);
        self.q = d[Schema.D.queries];
        if (self.image.len != self.im.words or self.im.words != d[Schema.D.image_words]) return self.fail(.image_length);
        const h = self.image[0..14];
        if (h[0] != Schema.image_magic or h[1] != 2 or h[7] != d[Schema.D.trees] or h[8] != d[Schema.D.samples] or h[9] != d[Schema.D.layers] or h[10] != d[Schema.D.initial_log] or h[11] != self.q or h[12] != d[Schema.D.degree_log]) return self.fail(.header);
        if (self.image[14] != 0) return self.fail(.numerical);
        const s = self.image[15..31];
        if (s[9] != h[13] or s[10] != 0 or s[11] != 0 or s[12] != 17 +% h[13] or !std.mem.allEqual(u32, s[13..], 0)) return self.fail(.channel);
        for (0..d[Schema.D.trees]) |t| if (self.in.roots[t]) |r| {
            if (!std.mem.eql(u32, r[0..8], self.image[self.im.roots + 8 * t ..][0..8])) return self.fail(.root);
        };
        if (d[Schema.D.flags] & Schema.D.flag_fixed_root != 0) if (self.in.roots[0]) |r| {
            if (!std.mem.eql(u32, r[0..8], d[Schema.D.fixed_root..][0..8])) return self.fail(.root);
        };
        for (self.in.latches) |w| if (w != 0) return self.fail(.section_latch);
        for (self.in.claims) |w| if (w >= Schema.modulus) return self.fail(.noncanonical_public);
        for (self.in.outputs) |w| if (w >= Schema.modulus) return self.fail(.noncanonical_public);
        const raw = self.image[self.im.queries..][0..self.q];
        for (raw) |v| if (v >= @as(u64, 1) << @intCast(d[Schema.D.initial_log])) return self.fail(.query_range);
        // Every value the host decodes as a field element.
        const canonical = struct {
            fn all(ws: []const u32) bool {
                for (ws) |w| if (w >= Schema.modulus) return false;
                return true;
            }
        }.all;
        if (!canonical(self.image[self.im.samples..][0 .. d[Schema.D.samples] * 8]) or !canonical(self.image[self.im.terminal..][0..8])) return self.fail(.noncanonical);
        for (0..d[Schema.D.layers]) |l| {
            const f = Schema.layer(d, @intCast(l));
            if (!canonical(self.image[self.im.layer_values[l]..][0 .. (@as(u64, self.q) << @intCast(f.fold_step)) * 8])) return self.fail(.noncanonical);
        }
        for (0..d[Schema.D.trees]) |t| {
            const tr = Schema.tree(d, @intCast(t));
            if (!canonical(self.image[self.im.tree_values[t]..][0 .. @as(u64, tr.columns) * self.q])) return self.fail(.noncanonical);
        }
    }

    /// Rank sort of raw query indices by (value, index), then the first index
    /// of every distinct value (trace.zig representatives).
    fn sortQueries(self: *Mirror) !void {
        const raw = self.image[self.im.queries..][0..self.q];
        self.sorted = try self.a.alloc(u32, self.q);
        for (0..self.q) |i| {
            var rank: u32 = 0;
            for (0..self.q) |j| rank += @intFromBool(raw[j] < raw[i] or (raw[j] == raw[i] and j < i));
            self.sorted[rank] = @intCast(i);
        }
        var reps: std.ArrayListUnmanaged(u32) = .empty;
        errdefer reps.deinit(self.a);
        for (self.sorted) |i| if (reps.items.len == 0 or raw[reps.items[reps.items.len - 1]] != raw[i]) try reps.append(self.a, i);
        self.reps = try reps.toOwnedSlice(self.a);
    }

    /// Ordered (node, rep) list of one Merkle level.
    const Level = struct { nodes: []u64, reps: []u32 };
    fn find(nodes: []const u64, node: u64) ?usize {
        var lo: usize = 0;
        var hi: usize = nodes.len;
        while (lo < hi) {
            const mid = (lo + hi) / 2;
            if (nodes[mid] < node) lo = mid + 1 else hi = mid;
        }
        return if (lo < nodes.len and nodes[lo] == node) lo else null;
    }

    /// The lifted-Merkle witness walk shared by trace trees and FRI layers:
    /// `level0` = sorted unique leaves with a representative path index each;
    /// `hash(rep, level)` = image word offset of that path's sibling hash.
    /// Emits one 8-word op per unpaired node; returns the per-level lists.
    fn walk(self: *Mirror, level0: Level, height: u32, comptime Ctx: type, ctx: Ctx, witness: *std.ArrayListUnmanaged(Op)) ![]Level {
        const levels = try self.a.alloc(Level, height);
        var made: usize = 0;
        errdefer {
            for (levels[0..made]) |lv| {
                self.a.free(lv.nodes);
                self.a.free(lv.reps);
            }
            self.a.free(levels);
        }
        var cur = level0;
        for (0..height) |lv| {
            levels[lv] = cur;
            made += 1;
            var nodes: std.ArrayListUnmanaged(u64) = .empty;
            var reps: std.ArrayListUnmanaged(u32) = .empty;
            errdefer nodes.deinit(self.a);
            errdefer reps.deinit(self.a);
            var i: usize = 0;
            while (i < cur.nodes.len) {
                const first = cur.nodes[i];
                const paired = i + 1 < cur.nodes.len and cur.nodes[i + 1] == (first ^ 1);
                if (!paired) try witness.append(self.a, .{ .dst = 0, .src = ctx.hash(cur.reps[i], @intCast(lv)), .n = 8 });
                try nodes.append(self.a, first >> 1);
                try reps.append(self.a, cur.reps[i]);
                i += if (paired) 2 else 1;
            }
            cur = .{ .nodes = try nodes.toOwnedSlice(self.a), .reps = try reps.toOwnedSlice(self.a) };
        }
        self.a.free(cur.nodes);
        self.a.free(cur.reps);
        return levels;
    }
    fn freeLevels(self: *Mirror, levels: []Level) void {
        for (levels) |lv| {
            self.a.free(lv.nodes);
            self.a.free(lv.reps);
        }
        self.a.free(levels);
    }

    const TraceCtx = struct {
        paths: u64,
        tree_log: u32,
        fn hash(self: TraceCtx, qi: u32, level: u32) u32 {
            return @intCast(self.paths + (@as(u64, qi) * self.tree_log + level) * 8);
        }
    };
    const FriCtx = struct {
        paths: u64,
        slots: u32,
        height: u32,
        fn hash(self: FriCtx, path: u32, level: u32) u32 {
            return @intCast(self.paths + (@as(u64, path) * self.height + level) * 8);
        }
    };

    fn plan(self: *Mirror) !void {
        const d = self.desc;
        try self.sortQueries();
        const raw = self.image[self.im.queries..][0..self.q];
        // ---- trace trees
        for (0..d[Schema.D.trees]) |t| {
            const tr = Schema.tree(d, @intCast(t));
            const tl = tr.tree_log;
            const p = try self.a.alloc(u64, self.q);
            defer self.a.free(p);
            for (raw, p) |v, *out| out.* = Schema.position(v, d[Schema.D.initial_log], tl);
            // Sorted unique tree positions, each with its first query (rank sort by (p, index)).
            const order = try self.a.alloc(u32, self.q);
            defer self.a.free(order);
            for (0..self.q) |i| {
                var rank: u32 = 0;
                for (0..self.q) |j| rank += @intFromBool(p[j] < p[i] or (p[j] == p[i] and j < i));
                order[rank] = @intCast(i);
            }
            var nodes: std.ArrayListUnmanaged(u64) = .empty;
            var nreps: std.ArrayListUnmanaged(u32) = .empty;
            for (order) |i| if (nodes.items.len == 0 or nodes.items[nodes.items.len - 1] != p[i]) {
                try nodes.append(self.a, p[i]);
                try nreps.append(self.a, i);
            };
            const ctx = TraceCtx{ .paths = self.im.tree_paths[t], .tree_log = tl };
            const levels = try self.walk(.{ .nodes = try nodes.toOwnedSlice(self.a), .reps = try nreps.toOwnedSlice(self.a) }, tl, TraceCtx, ctx, &self.trace_witness[t]);
            defer self.freeLevels(levels);
            // Hash consistency: every query's sibling at every level equals its node's representative's.
            for (0..self.q) |qi| for (0..tl) |lv| {
                const lvl = levels[lv];
                const k = find(lvl.nodes, p[qi] >> @intCast(lv)) orelse return self.fail(.trace_inconsistent);
                const a0 = ctx.hash(@intCast(qi), @intCast(lv));
                const b0 = ctx.hash(lvl.reps[k], @intCast(lv));
                if (!std.mem.eql(u32, self.image[a0..][0..8], self.image[b0..][0..8])) return self.fail(.trace_inconsistent);
            };
            // Value consistency: queries sharing a column position share its value.
            const logs = d[tr.table..][0..tr.columns];
            const values = self.image[self.im.tree_values[t]..][0 .. @as(u64, tr.columns) * self.q];
            const canon = try self.a.alloc(u32, self.q);
            defer self.a.free(canon);
            var last_log: u32 = 0;
            for (logs, 0..) |log, s| {
                if (s == 0 or log != last_log) {
                    canonicalFor(p, order, tl, log, canon);
                    last_log = log;
                }
                for (0..self.q) |qi| if (canon[qi] != qi and values[s * self.q + qi] != values[s * self.q + canon[qi]]) return self.fail(.trace_inconsistent);
            }
        }
        // ---- FRI layers
        var positions: std.ArrayListUnmanaged(u64) = .empty;
        defer positions.deinit(self.a);
        var prep: std.ArrayListUnmanaged(u32) = .empty; // representative raw index per position
        defer prep.deinit(self.a);
        for (self.reps) |i| {
            try positions.append(self.a, raw[i]);
            try prep.append(self.a, i);
        }
        for (0..d[Schema.D.layers]) |l| {
            const f = Schema.layer(d, @intCast(l));
            const h = layerHeight(f);
            const subset: u64 = @as(u64, 1) << @intCast(f.fold_step);
            const slots: u32 = @as(u32, 1) << @intCast(f.fold_step - f.leaf_log);
            const vals = self.im.layer_values[l];
            // Group representative of every raw query: the position list holds
            // q >> shift for every raw q; groups are positions >> fold_step.
            const group_rep = try self.a.alloc(u32, self.q);
            defer self.a.free(group_rep);
            for (raw, 0..) |v, qi| {
                const pos = @as(u64, v) >> @intCast(f.shift);
                const k = find(positions.items, pos).?;
                // The first position of pos's group carries the group's rep.
                var g = k;
                while (g > 0 and positions.items[g - 1] >> @intCast(f.fold_step) == pos >> @intCast(f.fold_step)) g -= 1;
                group_rep[qi] = prep.items[g];
            }
            // Value consistency.
            for (0..self.q) |qi| if (group_rep[qi] != qi) for (0..subset) |off| {
                const x = vals + (qi * subset + off) * 8;
                const y = vals + (group_rep[qi] * subset + off) * 8;
                if (!std.mem.eql(u32, self.image[x..][0..8], self.image[y..][0..8])) return self.fail(.fri_inconsistent);
            };
            // Witness values and leaves (fri.zig layerProof walk).
            var leaves: std.ArrayListUnmanaged(u64) = .empty;
            var lreps: std.ArrayListUnmanaged(u32) = .empty;
            var cursor: usize = 0;
            while (cursor < positions.items.len) {
                const start = (positions.items[cursor] >> @intCast(f.fold_step)) << @intCast(f.fold_step);
                const rep = prep.items[cursor];
                for (0..subset) |off| {
                    const pos = start + off;
                    if (cursor < positions.items.len and positions.items[cursor] == pos) cursor += 1 else try self.fri_values[l].append(self.a, .{ .dst = 0, .src = @intCast(vals + (rep * subset + off) * 8), .n = 8 });
                }
                for (0..slots) |slot| {
                    try leaves.append(self.a, (start >> @intCast(f.leaf_log)) + slot);
                    try lreps.append(self.a, rep * slots + @as(u32, @intCast(slot)));
                }
            }
            const ctx = FriCtx{ .paths = self.im.layer_paths[l], .slots = slots, .height = h };
            const levels = try self.walk(.{ .nodes = try leaves.toOwnedSlice(self.a), .reps = try lreps.toOwnedSlice(self.a) }, h, FriCtx, ctx, &self.fri_hashes[l]);
            defer self.freeLevels(levels);
            for (raw, 0..) |v, qi| {
                const start = ((@as(u64, v) >> @intCast(f.shift)) >> @intCast(f.fold_step)) << @intCast(f.fold_step);
                for (0..slots) |slot| for (0..h) |lv| {
                    const leaf = (start >> @intCast(f.leaf_log)) + slot;
                    const lvl = levels[lv];
                    const k = find(lvl.nodes, leaf >> @intCast(lv)) orelse return self.fail(.fri_inconsistent);
                    const x = ctx.hash(@intCast(qi * slots + slot), @intCast(lv));
                    const y = ctx.hash(lvl.reps[k], @intCast(lv));
                    if (!std.mem.eql(u32, self.image[x..][0..8], self.image[y..][0..8])) return self.fail(.fri_inconsistent);
                };
            }
            // Fold the positions (Queries.fold), keeping the first rep.
            var w: usize = 0;
            for (0..positions.items.len) |i| {
                const folded = positions.items[i] >> @intCast(f.fold_step);
                if (w == 0 or positions.items[w - 1] != folded) {
                    positions.items[w] = folded;
                    prep.items[w] = prep.items[i];
                    w += 1;
                }
            }
            positions.shrinkRetainingCapacity(w);
            prep.shrinkRetainingCapacity(w);
        }
        // ---- size
        self.words = self.layoutWords();
    }

    /// Canonical query of every query for a column of height `log` in a tree
    /// of `tl`: the first query in (p, index) order with the same column
    /// position (positions are runs of equal p >> (d+1), split by p & 1).
    fn canonicalFor(p: []const u64, order: []const u32, tl: u32, log: u32, canon: []u32) void {
        var run_key: u64 = std.math.maxInt(u64);
        var first: [2]?u32 = .{ null, null };
        for (order) |i| {
            const cp = Schema.position(p[i], tl, log);
            const key = cp >> 1;
            if (key != run_key) {
                run_key = key;
                first = .{ null, null };
            }
            const bit: usize = @intCast(cp & 1);
            if (first[bit] == null) first[bit] = i;
            canon[i] = first[bit].?;
        }
    }

    fn layoutWords(self: *const Mirror) u32 {
        const d = self.desc;
        var n: u64 = 0;
        if (d[Schema.D.flags] & Schema.D.flag_envelope != 0) n += 18 + 1 + 4 * @as(u64, d[Schema.D.outputs]) + 8 * @as(u64, d[Schema.D.claims]) + 1;
        n += 2 + 6 + 1 + 8 * @as(u64, d[Schema.D.trees]) + 1;
        for (0..d[Schema.D.trees]) |t| {
            const tr = Schema.tree(d, @intCast(t));
            n += 1 + tr.columns + 8 * @as(u64, tr.samples);
        }
        n += 1;
        for (0..d[Schema.D.trees]) |t| n += 1 + 8 * @as(u64, self.trace_witness[t].items.len);
        n += 1;
        for (0..d[Schema.D.trees]) |t| n += 1 + @as(u64, Schema.tree(d, @intCast(t)).columns) * (1 + self.reps.len);
        n += 2;
        for (0..d[Schema.D.layers]) |l| n += 1 + 8 * @as(u64, self.fri_values[l].items.len) + 1 + 8 * @as(u64, self.fri_hashes[l].items.len) + 8;
        n += 1 + 1 + 8;
        return @intCast(n);
    }

    fn put(self: *Mirror, at: *u32, w: u32) void {
        self.out[1 + at.*] = w;
        at.* += 1;
    }
    fn copy(self: *Mirror, at: *u32, src: u64, n: u64) void {
        @memcpy(self.out[1 + at.* ..][0..n], self.image[src..][0..n]);
        at.* += @intCast(n);
    }
    fn emitOps(self: *Mirror, at: *u32, ops: []const Op) void {
        put(self, at, @intCast(ops.len));
        for (ops) |op| self.copy(at, op.src, op.n);
    }

    fn emit(self: *Mirror) !void {
        const d = self.desc;
        var at: u32 = 0;
        var phys_len_at: ?u32 = null;
        if (d[Schema.D.flags] & Schema.D.flag_envelope != 0) {
            for (0..18) |i| self.put(&at, d[Schema.D.envelope + i]);
            self.put(&at, d[Schema.D.outputs]);
            for (self.in.outputs) |w| self.put(&at, w);
            for (self.in.claims) |w| self.put(&at, w);
            phys_len_at = at;
            self.put(&at, 0);
        }
        const phys = at;
        self.put(&at, d[Schema.D.phys_magic]);
        self.put(&at, d[Schema.D.phys_magic + 1]);
        for (0..6) |i| self.put(&at, d[Schema.D.config + i]);
        self.put(&at, d[Schema.D.trees]);
        self.copy(&at, self.im.roots, 8 * @as(u64, d[Schema.D.trees]));
        // sampled values: tree, original column, value (pcs_assembly cursor order)
        self.put(&at, d[Schema.D.trees]);
        var cursor = self.im.samples;
        for (0..d[Schema.D.trees]) |t| {
            const tr = Schema.tree(d, @intCast(t));
            self.put(&at, tr.columns);
            const counts = d[tr.table + 3 * tr.columns ..][0..tr.columns];
            for (counts) |c| {
                self.put(&at, c);
                self.copy(&at, cursor, 8 * @as(u64, c));
                cursor += 8 * @as(u64, c);
            }
        }
        self.put(&at, d[Schema.D.trees]);
        for (0..d[Schema.D.trees]) |t| self.emitOps(&at, self.trace_witness[t].items);
        // queried values: tree, original column, distinct raw query (ascending)
        self.put(&at, d[Schema.D.trees]);
        for (0..d[Schema.D.trees]) |t| {
            const tr = Schema.tree(d, @intCast(t));
            const o2s = d[tr.table + 2 * tr.columns ..][0..tr.columns];
            const base = self.im.tree_values[t];
            self.put(&at, tr.columns);
            for (o2s) |s| {
                self.put(&at, @intCast(self.reps.len));
                for (self.reps) |qi| self.put(&at, self.image[base + @as(u64, s) * self.q + qi]);
            }
        }
        self.copy(&at, self.im.nonce, 2);
        for (0..d[Schema.D.layers]) |l| {
            if (l == 1) self.put(&at, d[Schema.D.layers] - 1);
            self.emitOps(&at, self.fri_values[l].items);
            self.emitOps(&at, self.fri_hashes[l].items);
            self.copy(&at, self.im.layer_root[l], 8);
        }
        if (d[Schema.D.layers] == 1) self.put(&at, 0);
        self.put(&at, 1);
        self.copy(&at, self.im.terminal, 8);
        if (phys_len_at) |p| self.out[1 + p] = (at - phys) * 4;
        if (at != self.words) return error.OuterEncodeLayoutDrift;
    }
};
