//! Witness ledger (TENSOR_LEDGER=1 in tensor-bench): what the per-batch
//! witness commitment holds, per committed tensor and per op class, the
//! analogue of the per-opcode bits/gas table of the RV64 guest work.
//!
//! The prover fills it from `proveCore` after the proof is complete
//! (`sink`, set by the caller); it reads the committed tensors, the derived
//! LogUp relations and the witness-table layout and never touches the
//! transcript, so proofs are unchanged. Labels come from the statement
//! builder (`transformer.Builder.labels`): scope (block) / name (tensor).
//!
//! Per tensor: elements, committed bits (elements * 31, the M31 cells the
//! commitment encodes) and used bits (elements * ceil(log2(max - min + 1)),
//! a packing lower bound). Per LogUp key: leaves, the table, and whether the
//! leaf value is a committed column (`direct`, possibly shifted by a
//! constant) or an affine combination of committed columns / accumulators
//! that is never committed (`virtual`, e.g. requant remainders). Witness
//! opening bytes are attributed to tensors in proportion to their elements
//! (a queried column of the witness table holds every committed row).
const std = @import("std");
const proto = @import("protocol.zig");
const xt = @import("ext.zig");
const tf = @import("transformer.zig");

const TensorInfo = proto.TensorInfo;
pub const Label = tf.Builder.Label;

/// Set by the caller around a prove call; null (default): no ledger.
pub var sink: ?*Ledger = null;

pub fn enabled() bool {
    return if (std.posix.getenv("TENSOR_LEDGER")) |v| !std.mem.eql(u8, v, "0") else false;
}

/// TENSOR_LEDGER=noprove: ledger from the forward pass only (protocol.witnessLedger).
pub fn noProve() bool {
    return if (std.posix.getenv("TENSOR_LEDGER")) |v| std.mem.eql(u8, v, "noprove") else false;
}

pub const Layout = struct { log_total: u32, used: usize, log_rows: u32, log_cols: u32, rows_used: usize };

pub const Row = struct {
    label: Label,
    info: TensorInfo,
    elems: usize,
    min: i64,
    max: i64,
    /// multiplicity column: the table's log size, else null
    mult_log: ?u32 = null,

    pub fn bitsUsed(self: Row) u32 {
        if (self.elems == 0 or self.max <= self.min) return 0;
        const span: u64 = @intCast(self.max - self.min);
        return std.math.log2_int(u64, span) + 1;
    }
};

pub const KeyRow = struct {
    kind: []const u8,
    log_size: u32,
    table_log: u32,
    table: []const u8,
    virtual: bool,
    /// witness tensor the key is attributed to (its first committed operand)
    owner: ?u32,
};

pub const Ledger = struct {
    a: std.mem.Allocator,
    /// the builder's labels, aligned with the statement's witness tensors
    labels: []const Label = &.{},
    rows: std.ArrayList(Row) = .empty,
    keys: std.ArrayList(KeyRow) = .empty,
    table_logs: std.ArrayList(u32) = .empty,
    layout: Layout = .{ .log_total = 0, .used = 0, .log_rows = 0, .log_cols = 0, .rows_used = 0 },
    opening_bytes: usize = 0,
    captures: usize = 0,

    pub fn init(a: std.mem.Allocator) Ledger {
        return .{ .a = a };
    }

    pub fn deinit(self: *Ledger) void {
        self.rows.deinit(self.a);
        self.keys.deinit(self.a);
        self.table_logs.deinit(self.a);
    }

    fn reset(self: *Ledger) void {
        self.rows.clearRetainingCapacity();
        self.keys.clearRetainingCapacity();
        self.table_logs.clearRetainingCapacity();
    }

    /// Called by proveCore (one request / batch). Keeps the last capture.
    pub fn capture(self: *Ledger, st: proto.Statement, rel: proto.Relations, all: []const []const i32, lay: Layout, opening_bytes: usize) !void {
        self.reset();
        self.captures += 1;
        self.layout = lay;
        self.opening_bytes = opening_bytes;
        const nw = st.witness.len;
        for (all, 0..) |v, i| {
            var mn: i64 = 0;
            var mx: i64 = 0;
            if (v.len > 0) {
                mn = v[0];
                mx = v[0];
                for (v) |x| {
                    mn = @min(mn, x);
                    mx = @max(mx, x);
                }
            }
            if (i < nw) {
                const lab: Label = if (i < self.labels.len) self.labels[i] else .{ .scope = "unlabelled", .name = "raw" };
                try self.rows.append(self.a, .{ .label = lab, .info = st.witness[i], .elems = v.len, .min = mn, .max = mx });
            } else {
                const t = rel.tables[i - nw];
                try self.rows.append(self.a, .{ .label = .{ .scope = "logup", .name = "mult", .sub = tableName(t.kind) }, .info = TensorInfo.vec(t.log_size), .elems = v.len, .min = mn, .max = mx, .mult_log = t.log_size });
            }
        }
        for (rel.tables) |t| try self.table_logs.append(self.a, t.log_size);
        for (rel.keys) |k| {
            const t = rel.tables[k.table];
            var kr = KeyRow{ .kind = @tagName(k.kind), .log_size = k.log_size, .table_log = t.log_size, .table = tableName(t.kind), .virtual = false, .owner = null };
            switch (k.kind) {
                .remainder => {
                    kr.virtual = true;
                    kr.owner = coreY(st.ops[k.op]);
                },
                .y_range => kr.owner = coreY(st.ops[k.op]),
                .lookup_pair => kr.owner = st.ops[k.op].lookup.in,
                .plain_range => kr.owner = st.ops[k.op].range8.in,
                .glu_triple => kr.owner = st.ops[k.op].glu.h,
                .ext => {
                    const ek = rel.ext_keys[k.op];
                    const op = st.ext.ops[ek.op];
                    switch (ek.kind) {
                        .remainder => {
                            kr.kind = "ext.remainder";
                            kr.virtual = true;
                            kr.owner = op.einsum.y;
                        },
                        .y_range => {
                            kr.kind = "ext.y_range";
                            kr.owner = op.einsum.y;
                        },
                        .key => {
                            const ko = op.key;
                            kr.kind = if (ko.output != null) "ext.lookup" else "ext.range";
                            for (ko.input.terms) |tm| if (!tm.t.public) {
                                if (kr.owner == null) kr.owner = tm.t.id;
                            };
                            kr.virtual = ko.input.terms.len != 1;
                        },
                    }
                },
            }
            try self.keys.append(self.a, kr);
        }
    }

    fn coreY(op: proto.Op) ?u32 {
        return switch (op) {
            .matmul => |m| m.y,
            .hadamard => |h| h.y,
            else => null,
        };
    }

    fn tableName(k: proto.TableKind) []const u8 {
        return switch (k) {
            .range => |b| RANGE_NAMES[b],
            .act => "act",
            .glu => "glu",
            .ext_lookup => "xlookup",
        };
    }

    const RANGE_NAMES = blk: {
        var n: [32][]const u8 = undefined;
        for (0..32) |i| n[i] = std.fmt.comptimePrint("range{d}", .{i});
        break :blk n;
    };

    /// Class of a row: dense / moe layer part, or per-request (embed,
    /// head, logup multiplicities, io).
    pub fn part(lab: Label) []const u8 {
        if (lab.layer != null) return if (lab.moe) "moe" else "dense";
        return "request";
    }

    fn layerCount(self: *const Ledger, moe: bool) usize {
        var seen: [512]bool = [_]bool{false} ** 512;
        var n: usize = 0;
        for (self.rows.items) |r| if (r.label.layer) |l| {
            if (r.label.moe != moe or l >= seen.len) continue;
            if (!seen[l]) {
                seen[l] = true;
                n += 1;
            }
        };
        return n;
    }

    /// JSON lines: one per tensor ("tensor"), one per LogUp key ("key"),
    /// one per class ("class"), and a summary. `tokens`: the request length
    /// (per-token normalisation).
    pub fn report(self: *const Ledger, out: anytype, tokens: usize) !void {
        const n_dense = self.layerCount(false);
        const n_moe = self.layerCount(true);
        var total_elems: usize = 0;
        for (self.rows.items) |r| total_elems += r.elems;
        const table_elems = self.layout.rows_used << @intCast(self.layout.log_cols);
        const ob: f64 = @floatFromInt(self.opening_bytes);
        const te: f64 = @floatFromInt(@max(table_elems, 1));
        const tok: f64 = @floatFromInt(@max(tokens, 1));
        for (self.rows.items, 0..) |r, i| {
            try out.print("{{\"ledger\":\"tensor\",\"id\":{d},\"part\":\"{s}\",\"scope\":\"{s}\",\"name\":\"{s}\",\"sub\":\"{s}\",\"layer\":{d},\"dims\":[", .{ i, part(r.label), r.label.scope, r.label.name, r.label.sub, if (r.label.layer) |l| @as(i64, l) else -1 });
            for (r.info.log_dims[0..r.info.n_dims], 0..) |d, j| try out.print("{s}{d}", .{ if (j > 0) "," else "", d });
            try out.print("],\"elems\":{d},\"bits31\":{d},\"min\":{d},\"max\":{d},\"bits_used\":{d},\"used_bits\":{d}}}\n", .{ r.elems, r.elems * 31, r.min, r.max, r.bitsUsed(), r.elems * r.bitsUsed() });
        }
        for (self.keys.items) |k| {
            const owner_lab: Label = if (k.owner) |o| (if (o < self.rows.items.len) self.rows.items[o].label else .{ .scope = "?", .name = "?" }) else .{ .scope = "?", .name = "?" };
            try out.print("{{\"ledger\":\"key\",\"kind\":\"{s}\",\"leaves\":{d},\"table\":\"{s}\",\"table_log\":{d},\"virtual\":{},\"part\":\"{s}\",\"scope\":\"{s}\",\"name\":\"{s}\"}}\n", .{ k.kind, @as(usize, 1) << @intCast(k.log_size), k.table, k.table_log, k.virtual, part(owner_lab), owner_lab.scope, owner_lab.name });
        }
        // classes: (part, scope, name), first-seen order
        var classes: std.ArrayList(Class) = .empty;
        defer classes.deinit(self.a);
        for (self.rows.items) |r| {
            const c = try findClassSub(&classes, self.a, part(r.label), r.label.scope, r.label.name, if (r.mult_log != null) r.label.sub else "");
            c.tensors += 1;
            c.elems += r.elems;
            c.used_bits += r.elems * r.bitsUsed();
            c.max_bits = @max(c.max_bits, r.bitsUsed());
        }
        for (self.keys.items) |k| {
            const lab: Label = if (k.owner) |o| (if (o < self.rows.items.len) self.rows.items[o].label else .{ .scope = "?", .name = "?" }) else .{ .scope = "?", .name = "?" };
            const c = try findClass(&classes, self.a, part(lab), lab.scope, lab.name);
            const leaves = @as(usize, 1) << @intCast(k.log_size);
            if (k.virtual) c.leaves_virtual += leaves else c.leaves_direct += leaves;
        }
        var leaves_tables: usize = 0;
        for (self.table_logs.items) |l| leaves_tables += @as(usize, 1) << @intCast(l);
        for (classes.items) |c| {
            const nl: f64 = @floatFromInt(@max(if (std.mem.eql(u8, c.part, "dense")) n_dense else if (std.mem.eql(u8, c.part, "moe")) n_moe else 1, 1));
            const e: f64 = @floatFromInt(c.elems);
            const per_tok_layer = e / tok / nl;
            try out.print("{{\"ledger\":\"class\",\"part\":\"{s}\",\"scope\":\"{s}\",\"name\":\"{s}{s}{s}\",\"tensors\":{d},\"elems\":{d},\"bits31\":{d},\"used_bits\":{d},\"max_bits_used\":{d},\"share\":{d:.5},\"elems_per_token_layer\":{d:.3},\"bits31_per_token_layer\":{d:.2},\"used_bits_per_token_layer\":{d:.2},\"gkr_leaves_direct\":{d},\"gkr_leaves_virtual\":{d},\"opening_bytes\":{d:.0}}}\n", .{ c.part, c.scope, c.name, if (c.sub.len > 0) "." else "", c.sub, c.tensors, c.elems, c.elems * 31, c.used_bits, c.max_bits, e / @as(f64, @floatFromInt(@max(total_elems, 1))), per_tok_layer, per_tok_layer * 31, @as(f64, @floatFromInt(c.used_bits)) / tok / nl, c.leaves_direct, c.leaves_virtual, ob * e / te });
        }
        var lv: usize = 0;
        var ld: usize = 0;
        for (self.keys.items) |k| {
            const leaves = @as(usize, 1) << @intCast(k.log_size);
            if (k.virtual) lv += leaves else ld += leaves;
        }
        var used_bits: usize = 0;
        for (self.rows.items) |r| used_bits += r.elems * r.bitsUsed();
        try out.print("{{\"ledger\":\"summary\",\"captures\":{d},\"tokens\":{d},\"dense_layers\":{d},\"moe_layers\":{d},\"tensors\":{d},\"committed_elems\":{d},\"table_elems\":{d},\"padding_elems\":{d},\"log_total\":{d},\"log_rows\":{d},\"log_cols\":{d},\"bits31\":{d},\"used_bits\":{d},\"keys\":{d},\"gkr_leaves_direct\":{d},\"gkr_leaves_virtual\":{d},\"gkr_leaves_tables\":{d},\"witness_opening_bytes\":{d}}}\n", .{ self.captures, tokens, n_dense, n_moe, self.rows.items.len, total_elems, table_elems, table_elems -| total_elems, self.layout.log_total, self.layout.log_rows, self.layout.log_cols, table_elems * 31, used_bits, self.keys.items.len, ld, lv, leaves_tables, self.opening_bytes });
    }

    const Class = struct { part: []const u8, scope: []const u8, name: []const u8, sub: []const u8 = "", tensors: usize = 0, elems: usize = 0, used_bits: usize = 0, max_bits: u32 = 0, leaves_direct: usize = 0, leaves_virtual: usize = 0 };

    fn findClass(list: *std.ArrayList(Class), a: std.mem.Allocator, p: []const u8, scope: []const u8, name: []const u8) !*Class {
        return findClassSub(list, a, p, scope, name, "");
    }

    /// `sub` separates the multiplicity columns by table.
    fn findClassSub(list: *std.ArrayList(Class), a: std.mem.Allocator, p: []const u8, scope: []const u8, name: []const u8, sub: []const u8) !*Class {
        for (list.items) |*c| if (std.mem.eql(u8, c.part, p) and std.mem.eql(u8, c.scope, scope) and std.mem.eql(u8, c.name, name) and std.mem.eql(u8, c.sub, sub)) return c;
        try list.append(a, .{ .part = p, .scope = scope, .name = name, .sub = sub });
        return &list.items[list.items.len - 1];
    }
};

test "ledger: every witness tensor labelled, proofs unchanged with the ledger on" {
    const a = std.testing.allocator;
    const f = @import("field.zig");
    const digest = @import("digest.zig");
    const model = @import("model.zig");
    var pool: f.Pool = undefined;
    try pool.init(a, 2);
    defer pool.deinit();
    const cfg = tf.LayerCfg{ .log_t = 3, .log_d = 4, .log_f = 4, .log_heads = 1, .log_kv_heads = 1, .log_experts = 1, .log_capacity = 3, .router_log_cols = 4 };
    const pc = proto.Config{ .pcs = .{ .log_blowup = 2, .n_queries = 12, .pow_bits = 1 }, .weight_log_cols = 4, .witness_log_cols_max = 8, .gkr_threads = 2 };
    var sw = try tf.setupWeights(a, &pool, cfg, pc, 300);
    defer {
        sw.ws.deinit(a);
        for (sw.wdata) |w| a.free(w);
        a.free(sw.wdata);
        a.free(sw.winfos);
    }
    var b = tf.Builder.init(a, &pool);
    defer b.deinit();
    b.keep_accs = true;
    const c = try tf.initCtx(&b, cfg, &sw.ws, 1);
    const x = try model.randomInput(a, @as(usize, 1) << (cfg.log_t + cfg.log_d), 17);
    defer a.free(x);
    _ = try tf.buildStack(&b, c, x);
    const st = b.statement();
    try std.testing.expectEqual(st.witness.len, b.labels.items.len);
    const wv = try b.witnessView(a);
    defer a.free(wv);
    var tm: proto.Timings = .{};
    var p0 = try proto.prove(a, &pool, pc, st, &sw.ws, wv, &tm);
    defer p0.deinit(a);
    var lg = Ledger.init(a);
    defer lg.deinit();
    lg.labels = b.labels.items;
    sink = &lg;
    defer sink = null;
    tm = .{};
    var p1 = try proto.prove(a, &pool, pc, st, &sw.ws, wv, &tm);
    defer p1.deinit(a);
    try std.testing.expectEqualSlices(u8, &digest.fullDigest(p0), &digest.fullDigest(p1));
    try std.testing.expectEqual(@as(usize, 1), lg.captures);
    var rel = try proto.deriveRelations(a, st);
    defer rel.deinit(a);
    try std.testing.expectEqual(st.witness.len + rel.tables.len, lg.rows.items.len);
    try std.testing.expectEqual(rel.keys.len, lg.keys.items.len);
    var n_elems: usize = 0;
    for (lg.rows.items, 0..) |r, i| {
        n_elems += r.elems;
        // every tensor has a block scope (no "other"/"unlabelled" rows)
        try std.testing.expect(!std.mem.eql(u8, r.label.scope, "other"));
        try std.testing.expect(!std.mem.eql(u8, r.label.scope, "unlabelled"));
        if (i < st.witness.len) try std.testing.expectEqual(st.witness[i].size(), r.elems);
    }
    try std.testing.expectEqual(tm.witness_elems, n_elems);
    // MoE dispatch and attention scores are present and in their layer
    var saw_disp = false;
    var saw_scores = false;
    for (lg.rows.items) |r| {
        if (std.mem.eql(u8, r.label.name, "disp")) saw_disp = r.label.moe and r.label.layer.? == 0;
        if (std.mem.eql(u8, r.label.name, "scores")) saw_scores = true;
    }
    try std.testing.expect(saw_disp and saw_scores);
    // the no-prove ledger (protocol.witnessLedger) sees the same tensors
    var lg2 = Ledger.init(a);
    defer lg2.deinit();
    lg2.labels = b.labels.items;
    try proto.witnessLedger(a, &pool, pc, st, wv, b.coreAccs(), b.extAccs(), &lg2);
    try std.testing.expectEqual(lg.rows.items.len, lg2.rows.items.len);
    for (lg.rows.items, lg2.rows.items) |r1, r2| {
        try std.testing.expectEqual(r1.elems, r2.elems);
        try std.testing.expectEqual(r1.min, r2.min);
        try std.testing.expectEqual(r1.max, r2.max);
    }
    try std.testing.expectEqual(lg.layout, lg2.layout);
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(a);
    try lg.report(buf.writer(a), 8);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"ledger\":\"summary\"") != null);
}
