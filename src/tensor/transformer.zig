//! Integer Llama-style decoder layers as tensor-protocol statements.
//!
//! Exact semantics, ranges and soundness notes: design/tensor-frontend/transformer.md.
//! Every function here computes the witness with plain integer arithmetic and
//! emits the ops that constrain it; the prover additionally re-checks every
//! constraint (ext.proverInit / multiplicities) before proving.
const std = @import("std");
const f = @import("field.zig");
const proto = @import("protocol.zig");
const xt = @import("ext.zig");
const model = @import("model.zig");

const TensorInfo = proto.TensorInfo;
const Ref = xt.Ref;

const IOTA = blk: {
    var x: [64]u8 = undefined;
    for (&x, 0..) |*v, i| v.* = i;
    break :blk x;
};
const SUMS = [_]u8{xt.SUM} ** xt.MAXB;

/// Labels start, start+1, ..., start+n-1.
pub fn ids(start: u32, n: u32) []const u8 {
    return IOTA[start..][0..n];
}

pub fn sums(n: u32) []const u8 {
    return SUMS[0..n];
}

pub fn cat(parts: []const []const u8) xt.Labels {
    var buf: [xt.MAXB]u8 = undefined;
    var n: usize = 0;
    for (parts) |p| {
        @memcpy(buf[n..][0..p.len], p);
        n += p.len;
    }
    return xt.labels(buf[0..n]);
}

pub fn term(c: i64, r: Ref, parts: []const []const u8) xt.Term {
    return .{ .coeff = c, .t = r, .labels = cat(parts) };
}

/// Smallest s >= 1 with requant(acc, s) in [-2^(ob-1), 2^(ob-1)) for all entries.
pub fn chooseShiftBits(acc: []const i64, ob: u5) !u5 {
    var mx: i64 = 0;
    var mn: i64 = 0;
    for (acc) |v| {
        mx = @max(mx, v);
        mn = @min(mn, v);
    }
    const lim = @as(i64, 1) << (ob - 1);
    var s: u5 = 1;
    while (s <= xt.MAX_TABLE_BITS) : (s += 1) {
        if (proto.requant(mx, s) < lim and proto.requant(mn, s) >= -lim) return s;
    }
    return error.RequantOverflow;
}

/// model.chooseShift generalised to `bits`: smallest s >= 1 with
/// |acc| <= (2^(bits-1) - 1) 2^s - 2^(s-1) (symmetric range; bits = 8 is
/// exactly model.chooseShift).
pub fn chooseShiftSym(acc: []const i64, bits: u5) u5 {
    var mx: i64 = 0;
    for (acc) |v| mx = @max(mx, @as(i64, @intCast(@abs(v))));
    const top = (@as(i64, 1) << (bits - 1)) - 1;
    var s: u5 = 1;
    while (s < 30) : (s += 1) {
        if (mx <= (top << s) - (@as(i64, 1) << (s - 1))) break;
    }
    return s;
}

/// requant with s = 0 meaning identity.
pub fn rq(v: i64, s: u5) i64 {
    return if (s == 0) v else proto.requant(v, s);
}

/// exp table over a domain of 2^log entries (log = LayerCfg.expLog()):
/// round(256 exp(-d / 16)) for d < 256, else 0. Caller frees.
pub fn expTableN(a: std.mem.Allocator, log: u32) ![]i32 {
    const t = try a.alloc(i32, @as(usize, 1) << @intCast(log));
    for (t, 0..) |*v, d| {
        v.* = if (d < 256) @intFromFloat(@round(256.0 * @exp(-@as(f64, @floatFromInt(d)) / 16.0))) else 0;
    }
    return t;
}

pub fn expTable() [1024]i32 {
    var t: [1024]i32 = undefined;
    for (&t, 0..) |*v, d| {
        v.* = if (d < 256) @intFromFloat(@round(256.0 * @exp(-@as(f64, @floatFromInt(d)) / 16.0))) else 0;
    }
    return t;
}

pub const Builder = struct {
    a: std.mem.Allocator,
    arena: std.heap.ArenaAllocator,
    pool: *f.Pool,
    infos: std.ArrayList(TensorInfo) = .empty,
    wit: std.ArrayList([]i32) = .empty,
    ops: std.ArrayList(proto.Op) = .empty,
    xops: std.ArrayList(xt.Op) = .empty,
    publics: std.ArrayList(xt.Public) = .empty,
    xtables: std.ArrayList(xt.LookupTable) = .empty,
    tables: std.ArrayList(proto.Table) = .empty,
    weight_infos: std.ArrayList(TensorInfo) = .empty,
    /// keep the forward pass's integer accumulators (core matmul / hadamard
    /// ops, requant einsums) for proto.proveWithAllAccumulators
    keep_accs: bool = false,
    /// per core op / per ext op: kept accumulator (null when not kept)
    core_accs: std.ArrayList(?[]i64) = .empty,
    ext_accs: std.ArrayList(?[]i64) = .empty,
    /// device hook for the forward matmuls (null: CPU kernel)
    accel: ?*const @import("accel.zig").Accel = null,
    /// P2: requant shifts are part of the public model definition. Record
    /// mode (shift_plan == null): every shift the builder chooses is appended
    /// to shift_log (calibration). Replay mode: shifts come from the plan in
    /// order, and a requant output outside its range is an error (the input
    /// is outside the model).
    shift_plan: ?[]const u5 = null,
    shift_pos: usize = 0,
    /// record mode only: shift i is at least shift_floor[i] (iterated
    /// calibration, lm.calibrate: record under the current plan and widen it)
    shift_floor: ?[]const u5 = null,
    shift_log: std.ArrayList(u5) = .empty,
    /// verifier-side statement construction (statementFor): no weights, dummy
    /// witness values; only the statement is meaningful
    shape_only: bool = false,
    /// P1: public ids of the bound model input / output (buildStack)
    io_in: ?u32 = null,
    io_out: ?u32 = null,
    model_digest: ?[32]u8 = null,
    /// witness ledger (ledger.zig, TENSOR_LEDGER): one label per witness
    /// tensor, aligned with `infos`. Diagnostic only: never part of the
    /// statement or the transcript.
    labels: std.ArrayList(Label) = .empty,
    /// current ledger scope (block: "attn", "rms1", "mlp", ...)
    scope: []const u8 = "other",
    /// one-shot name for the next added tensor (overrides its op kind)
    next_name: ?[]const u8 = null,
    /// current decoder layer (null outside the layers) and whether it is MoE
    cur_layer: ?u32 = null,
    cur_moe: bool = false,

    pub const Label = struct { scope: []const u8, name: []const u8, sub: []const u8 = "", layer: ?u32 = null, moe: bool = false };

    /// Sets the ledger scope; returns the previous one (restore with defer).
    pub fn enter(self: *Builder, scope: []const u8) []const u8 {
        const prev = self.scope;
        self.scope = scope;
        return prev;
    }

    /// Names the next added witness tensor in the ledger.
    pub fn tag(self: *Builder, n: []const u8) void {
        self.next_name = n;
    }

    pub fn init(a: std.mem.Allocator, pool: *f.Pool) Builder {
        return .{ .a = a, .arena = std.heap.ArenaAllocator.init(a), .pool = pool };
    }

    pub fn deinit(self: *Builder) void {
        const a = self.a;
        for (self.wit.items) |w| a.free(w);
        self.wit.deinit(a);
        self.infos.deinit(a);
        self.ops.deinit(a);
        self.xops.deinit(a);
        self.publics.deinit(a);
        self.xtables.deinit(a);
        self.tables.deinit(a);
        self.weight_infos.deinit(a);
        self.labels.deinit(a);
        for (self.core_accs.items) |x| if (x) |v| a.free(v);
        self.core_accs.deinit(a);
        for (self.ext_accs.items) |x| if (x) |v| a.free(v);
        self.ext_accs.deinit(a);
        self.shift_log.deinit(a);
        self.arena.deinit();
    }

    pub fn replaying(self: *const Builder) bool {
        return self.shift_plan != null;
    }

    /// The next requant shift: from the plan (replay) or `chosen` (record).
    pub fn nextShift(self: *Builder, chosen: u5) !u5 {
        if (self.shift_plan) |plan| {
            if (self.shift_pos >= plan.len) return error.ShiftPlan;
            self.shift_pos += 1;
            return plan[self.shift_pos - 1];
        }
        var s = chosen;
        if (self.shift_floor) |fl| {
            if (self.shift_pos < fl.len) s = @max(s, fl[self.shift_pos]);
        }
        self.shift_pos += 1;
        try self.shift_log.append(self.a, s);
        return s;
    }

    /// Replay mode, not shape-only: error.RequantOverflow unless every
    /// value is int8 (the input is outside the calibrated model).
    pub fn checkInt8(self: *const Builder, y: []const i32) !void {
        return self.checkBits(y, 8);
    }

    /// As checkInt8 for a signed `bits`-wide range [-2^(bits-1), 2^(bits-1)).
    pub fn checkBits(self: *const Builder, y: []const i32, bits: u5) !void {
        if (self.shape_only or !self.replaying()) return;
        const lim = @as(i32, 1) << (bits - 1);
        for (y) |v| if (v < -lim or v >= lim) return error.RequantOverflow;
    }

    /// Appends a core op; takes ownership of `acc` (kept if keep_accs).
    pub fn pushOp(self: *Builder, op: proto.Op, acc: ?[]i64) !void {
        try self.core_accs.ensureUnusedCapacity(self.a, 1);
        try self.ops.append(self.a, op);
        self.core_accs.appendAssumeCapacity(if (self.keep_accs) acc else null);
        if (!self.keep_accs) if (acc) |v| self.a.free(v);
    }

    /// Appends an ext op; takes ownership of `acc` (kept if keep_accs).
    fn pushXop(self: *Builder, op: xt.Op, acc: ?[]i64) !void {
        try self.ext_accs.ensureUnusedCapacity(self.a, 1);
        try self.xops.append(self.a, op);
        self.ext_accs.appendAssumeCapacity(if (self.keep_accs) acc else null);
        if (!self.keep_accs) if (acc) |v| self.a.free(v);
    }

    /// Kept accumulators, aligned with statement().ops / .ext.ops.
    pub fn coreAccs(self: *const Builder) []const ?[]i64 {
        return self.core_accs.items;
    }
    pub fn extAccs(self: *const Builder) []const ?[]const i64 {
        return @ptrCast(self.ext_accs.items);
    }

    pub fn statement(self: *const Builder) proto.Statement {
        return .{
            .witness = self.infos.items,
            .weights = self.weight_infos.items,
            .tables = self.tables.items,
            .ops = self.ops.items,
            .ext = .{ .ops = self.xops.items, .publics = self.publics.items, .tables = self.xtables.items },
            .model_digest = self.model_digest,
        };
    }

    pub fn witnessView(self: *const Builder, a: std.mem.Allocator) ![]const []const i32 {
        const v = try a.alloc([]const i32, self.wit.items.len);
        for (self.wit.items, 0..) |w, i| v[i] = w;
        return v;
    }

    fn view(self: *const Builder) []const []const i32 {
        return @ptrCast(self.wit.items);
    }

    pub fn vals(self: *const Builder, r: Ref) []const i32 {
        return if (r.public) self.publics.items[r.id].values else self.wit.items[r.id];
    }

    /// Takes ownership of `data` (allocated with self.a).
    pub fn add(self: *Builder, info_in: TensorInfo, data: []i32) !u32 {
        return self.addKind(info_in, data, "raw", "");
    }

    /// As `add`, with the ledger kind of the producing op (the label is the
    /// current scope and the pending `name`, else `kind`).
    pub fn addKind(self: *Builder, info_in: TensorInfo, data: []i32, kind: []const u8, sub: []const u8) !u32 {
        // Zig may pass `info_in` by reference, and callers pass elements of
        // `self.infos` (which ensureUnusedCapacity may reallocate). Copy the
        // bytes explicitly before growing the list; a plain `const info =
        // info_in` can be elided into the same reference.
        var info: TensorInfo = undefined;
        @memcpy(std.mem.asBytes(&info), std.mem.asBytes(&info_in));
        std.mem.doNotOptimizeAway(&info);
        std.debug.assert(data.len == info.size());
        try self.infos.ensureUnusedCapacity(self.a, 1);
        try self.wit.ensureUnusedCapacity(self.a, 1);
        try self.labels.ensureUnusedCapacity(self.a, 1);
        self.infos.appendAssumeCapacity(info);
        self.labels.appendAssumeCapacity(.{ .scope = self.scope, .name = self.next_name orelse kind, .sub = sub, .layer = self.cur_layer, .moe = self.cur_moe });
        if (sub.len == 0 or std.mem.eql(u8, sub, "hi")) self.next_name = null;
        try self.wit.append(self.a, data);
        return @intCast(self.wit.items.len - 1);
    }

    pub fn addVec(self: *Builder, log: u32, data: []i32) !u32 {
        return self.add(TensorInfo.vec(log), data);
    }

    pub fn public(self: *Builder, log: u32, values: []const i32) !u32 {
        try self.publics.append(self.a, .{ .log_size = log, .values = try self.arena.allocator().dupe(i32, values) });
        return @intCast(self.publics.items.len - 1);
    }

    pub fn xtable(self: *Builder, log: u5, values: []const i32) !u32 {
        try self.xtables.append(self.a, .{ .log_size = log, .values = try self.arena.allocator().dupe(i32, values) });
        return @intCast(self.xtables.items.len - 1);
    }

    pub fn expr(self: *Builder, terms: []const xt.Term, c: i64) !xt.Expr {
        return .{ .terms = try self.arena.allocator().dupe(xt.Term, terms), .constant = c };
    }

    fn einsumSpec(a_: Ref, b_: Ref, n_out: u32, n_k: u32, la: []const []const u8, lb: []const []const u8) xt.Einsum {
        return .{ .a = a_, .b = b_, .y = null, .n_out = @intCast(n_out), .n_k = @intCast(n_k), .a_labels = cat(la), .b_labels = cat(lb) };
    }

    /// Y = requant_s(einsum(A, B)), s chosen (if null) so Y fits out_bits.
    pub fn einsumRequant(self: *Builder, info: TensorInfo, a_: Ref, b_: Ref, n_k: u32, la: []const []const u8, lb: []const []const u8, shift: ?u5, out_bits: u5) !u32 {
        var e = einsumSpec(a_, b_, info.logSize(), n_k, la, lb);
        const acc = try xt.einsumAcc(self.a, self.pool, e, self.vals(a_), self.vals(b_));
        var acc_owned = true;
        defer if (acc_owned) self.a.free(acc);
        const s = shift orelse if (self.replaying()) try self.nextShift(0) else try self.nextShift(try chooseShiftBits(acc, out_bits));
        const y = try self.a.alloc(i32, acc.len);
        const lim = @as(i64, 1) << (out_bits - 1);
        for (acc, y) |v, *o| {
            const q = proto.requant(v, s);
            if (!self.shape_only and (q < -lim or q >= lim)) {
                self.a.free(y);
                return error.RequantOverflow;
            }
            o.* = q;
        }
        const id = try self.addKind(info, y, "einsum.rq", "");
        e.y = id;
        e.shift = s;
        e.out_bits = out_bits;
        acc_owned = false;
        try self.pushXop(.{ .einsum = e }, acc);
        return id;
    }

    /// Y = einsum(A, B) exactly (info == null: asserts the einsum is zero).
    pub fn einsumExact(self: *Builder, info: ?TensorInfo, n_out: u32, a_: Ref, b_: Ref, n_k: u32, la: []const []const u8, lb: []const []const u8) !?u32 {
        var e = einsumSpec(a_, b_, n_out, n_k, la, lb);
        const acc = try xt.einsumAcc(self.a, self.pool, e, self.vals(a_), self.vals(b_));
        defer self.a.free(acc);
        var id: ?u32 = null;
        if (info) |inf| {
            std.debug.assert(inf.logSize() == n_out);
            const y = try self.a.alloc(i32, acc.len);
            for (acc, y) |v, *o| {
                if (v < std.math.minInt(i32) or v > std.math.maxInt(i32)) {
                    self.a.free(y);
                    return error.EinsumOverflow;
                }
                o.* = @intCast(v);
            }
            id = try self.addKind(inf, y, "einsum.exact", "");
        } else self.next_name = null;
        e.y = id;
        try self.pushXop(.{ .einsum = e }, null);
        return id;
    }

    /// Asserts einsum(A, B) == existing witness y exactly.
    pub fn einsumInto(self: *Builder, y: u32, a_: Ref, b_: Ref, n_k: u32, la: []const []const u8, lb: []const []const u8) !void {
        var e = einsumSpec(a_, b_, self.infos.items[y].logSize(), n_k, la, lb);
        const acc = try xt.einsumAcc(self.a, self.pool, e, self.vals(a_), self.vals(b_));
        defer self.a.free(acc);
        for (acc, self.wit.items[y]) |v, w| if (v != w) return error.EinsumMismatch;
        e.y = y;
        try self.pushXop(.{ .einsum = e }, null);
    }

    pub fn key(self: *Builder, n: u32, input: xt.Expr, output: ?xt.Expr, table: xt.TableRef) !void {
        try self.pushXop(.{ .key = .{ .n = @intCast(n), .input = input, .output = output, .table = table } }, null);
    }

    pub fn lineq(self: *Builder, n: u32, e: xt.Expr) !void {
        try self.pushXop(.{ .lineq = .{ .n = @intCast(n), .expr = e } }, null);
    }

    pub fn materialize(self: *Builder, e: xt.Expr, n: u32) ![]i64 {
        return xt.materializePar(self.a, self.pool, self.statement(), self.view(), e, n);
    }

    /// expr in [0, 2^bits) over {0,1}^n. Above 16 bits: committed 16-bit limbs
    /// lo, hi with expr == lo + 2^16 hi (lineq) and range keys on both.
    pub fn rangeWide(self: *Builder, n: u32, e: xt.Expr, bits: u32) !void {
        if (bits <= 16) {
            self.next_name = null;
            return self.key(n, e, null, .{ .range = @intCast(bits) });
        }
        std.debug.assert(bits <= 32);
        const v = try self.materialize(e, n);
        defer self.a.free(v);
        const lo = try self.a.alloc(i32, v.len);
        const hi = try self.a.alloc(i32, v.len);
        for (v, lo, hi) |x, *l, *h| {
            if (!self.shape_only and (x < 0 or x >= (@as(i64, 1) << @intCast(bits)))) {
                self.a.free(lo);
                self.a.free(hi);
                return error.ValueOutOfRange;
            }
            l.* = @intCast(x & 0xffff);
            h.* = @intCast(x >> 16);
        }
        if (self.next_name == null) self.next_name = "range.limb";
        const lo_id = try self.addKind(TensorInfo.vec(n), lo, "range.limb", "lo");
        const hi_id = try self.addKind(TensorInfo.vec(n), hi, "range.limb", "hi");
        try self.key(n, try self.expr(&.{term(1, Ref.w(lo_id), &.{ids(0, n)})}, 0), null, .{ .range = 16 });
        try self.key(n, try self.expr(&.{term(1, Ref.w(hi_id), &.{ids(0, n)})}, 0), null, .{ .range = @intCast(bits - 16) });
        const terms = try self.arena.allocator().alloc(xt.Term, e.terms.len + 2);
        @memcpy(terms[0..e.terms.len], e.terms);
        terms[e.terms.len] = term(-1, Ref.w(lo_id), &.{ids(0, n)});
        terms[e.terms.len + 1] = term(-65536, Ref.w(hi_id), &.{ids(0, n)});
        try self.lineq(n, .{ .terms = terms, .constant = e.constant });
    }

    /// Signed range: x + 2^(bits-1) in [0, 2^bits) (elementwise, all bits of x).
    pub fn rangeSigned(self: *Builder, x: u32, bits: u32) !void {
        const n = self.infos.items[x].logSize();
        try self.rangeWide(n, try self.expr(&.{term(1, Ref.w(x), &.{ids(0, n)})}, @as(i64, 1) << @intCast(bits - 1)), bits);
    }

    /// xs = round(x / 2^s) = floor((x + 2^(s-1)) / 2^s) as a committed int8
    /// tensor: remainder key x + 2^(s-1) - 2^s xs in [0, 2^s) and xs range.
    pub fn requantLinear(self: *Builder, x: u32, s: u5) !u32 {
        return self.requantLinearBits(x, s, 8);
    }

    /// As requantLinear with a signed `bits`-wide output (8 = int8).
    pub fn requantLinearBits(self: *Builder, x: u32, s: u5, bits: u5) !u32 {
        const info = self.infos.items[x];
        const n = info.logSize();
        const xs = try self.a.alloc(i32, info.size());
        for (self.wit.items[x], xs) |v, *o| o.* = proto.requant(v, s);
        self.checkBits(xs, bits) catch |e| {
            self.a.free(xs);
            return e;
        };
        const id = try self.addKind(info, xs, "requant.out", "");
        try self.key(n, try self.expr(&.{ term(1, Ref.w(x), &.{ids(0, n)}), term(-(@as(i64, 1) << s), Ref.w(id), &.{ids(0, n)}) }, @as(i64, 1) << (s - 1)), null, .{ .range = s });
        try self.rangeSigned(id, bits);
        return id;
    }

    // --- core ops (weights) -------------------------------------------------

    pub fn matmul(self: *Builder, ws: *const proto.WeightStore, x: u32, w: u32) !u32 {
        return self.matmulShift(ws, x, w, null);
    }

    /// As `matmul`, with a fixed requant shift (null: chosen from the data).
    pub fn matmulShift(self: *Builder, ws: *const proto.WeightStore, x: u32, w: u32, shift: ?u5) !u32 {
        return self.matmulBits(ws, x, w, shift, 8);
    }

    /// Core matmul with a signed `out_bits`-wide output (8 = the int8 op;
    /// 9..16: proto Op.matmul.out_bits, a 2^out_bits range key on Y).
    /// Data-chosen shifts use chooseShiftSym(acc, out_bits).
    pub fn matmulBits(self: *Builder, ws: *const proto.WeightStore, x: u32, w: u32, shift: ?u5, out_bits: u5) !u32 {
        const xi = self.infos.items[x];
        const n_y = @as(usize, 1) << @intCast(xi.log_dims[0] + ws.infos[w].log_dims[1]);
        const acc = if (self.shape_only) blk: {
            const z = try self.a.alloc(i64, n_y);
            @memset(z, 0);
            break :blk z;
        } else try @import("accel.zig").matmulAcc(self.accel, self.a, xi.log_dims[0], self.wit.items[x], ws.matrix(w)) orelse
            try proto.matmulAcc(self.a, self.pool, xi, self.wit.items[x], ws.matrix(w));
        var acc_owned = true;
        defer if (acc_owned) self.a.free(acc);
        // a fixed shift is part of the code-level model definition (e.g. the
        // embedding gather's rq_1): never recorded in or read from a shift plan
        const s = if (shift) |fs| fs else try self.nextShift(if (self.replaying()) 0 else chooseShiftSym(acc, out_bits));
        const y = try self.a.alloc(i32, acc.len);
        for (acc, y) |v, *o| o.* = proto.requant(v, s);
        self.checkBits(y, out_bits) catch |e| {
            self.a.free(y);
            return e;
        };
        const id = try self.addKind(TensorInfo.mat(xi.log_dims[0], ws.infos[w].log_dims[1]), y, "matmul.out", "");
        acc_owned = false;
        try self.pushOp(.{ .matmul = .{ .x = x, .w = w, .y = id, .shift = s, .out_bits = out_bits } }, acc);
        return id;
    }

    pub fn coreTable(self: *Builder, t: proto.Table) !u32 {
        try self.tables.append(self.a, t);
        return @intCast(self.tables.items.len - 1);
    }

    pub fn lookup(self: *Builder, x: u32, table: u32) !u32 {
        const out = try self.a.alloc(i32, self.wit.items[x].len);
        for (self.wit.items[x], out) |v, *o| o.* = self.tables.items[table].values[@intCast(v + 128)];
        const info = self.infos.items[x]; // copy: add() may reallocate infos
        const id = try self.addKind(info, out, "lookup.out", "");
        try self.pushOp(.{ .lookup = .{ .in = x, .out = id, .table = table } }, null);
        return id;
    }

    pub fn hadamard(self: *Builder, x: u32, y: u32) !u32 {
        const n = self.wit.items[x].len;
        const acc = try self.a.alloc(i64, n);
        var acc_owned = true;
        defer if (acc_owned) self.a.free(acc);
        for (self.wit.items[x], self.wit.items[y], acc) |p, q, *o| o.* = @as(i64, p) * q;
        const s = try self.nextShift(if (self.replaying()) 0 else model.chooseShift(acc));
        const out = try self.a.alloc(i32, n);
        for (acc, out) |v, *o| o.* = proto.requant(v, s);
        self.checkInt8(out) catch |e| {
            self.a.free(out);
            return e;
        };
        const info = self.infos.items[x]; // copy: add() may reallocate infos
        const id = try self.addKind(info, out, "hadamard.out", "");
        acc_owned = false;
        try self.pushOp(.{ .hadamard = .{ .a = x, .b = y, .y = id, .shift = s } }, acc);
        return id;
    }
};

// ---------------------------------------------------------------------------
// Layer configuration.

pub const LayerCfg = struct {
    log_t: u32,
    log_d: u32,
    log_f: u32,
    log_heads: u32,
    /// log2 of KV heads (GQA): log_kv_heads <= log_heads
    log_kv_heads: u32,
    n_layers: u32 = 1,
    /// MoE: 2^log_experts experts (0 = dense SwiGLU MLP), top-1 routing,
    /// 2^log_capacity token slots per expert.
    log_experts: u32 = 0,
    log_capacity: u32 = 0,
    /// router weight columns are padded to 2^max(log_experts, router_log_cols)
    /// (set to the weight table's column count so the core matmul applies)
    router_log_cols: u32 = 0,
    /// one fused projection W_qkv [D, 2^qkvLogCols] (Q | K | V | zero pad) with
    /// Q, K, V consumed as fixed-bit column slices; lets the weight table use
    /// 2^min(log_d, log_f) columns instead of 2^logDkv
    fused_qkv: bool = false,
    /// attention score width: S = rq(Qr . Kr) in [-2^(sb-1), 2^(sb-1)) at a
    /// fixed 1/16-nat scale (the exp table's). 8 (default) is the original
    /// int8 score; a trained model's logits need ~13 bits (accuracy.md).
    /// Masked bias 2^sb + 256 and exp-table domain 2^(sb+2) follow from it.
    score_bits: u32 = 8,
    /// activation width A (accuracy.md "Wide activations"): RMSNorm input
    /// view xs and output y, the q / k / v / gate / up projections, the
    /// SiLU table domain (2^A entries, input scale 2^-(A-4)), the gated
    /// hadamard and the attention output O are signed A-bit; RoPE outputs
    /// A + 1 bits. 8 (default) is the original int8 model, unchanged.
    act_bits: u32 = 8,
    /// residual width R: the embedding (two int8 limbs above 8 bits, lm.zig)
    /// and the residual increments o Wo, hm Wd are signed R-bit.
    resid_bits: u32 = 8,
    /// RMSNorm reciprocal precision: inv = floor(2^INV_BITS / rt)
    pub const INV_BITS = 15;
    /// act_bits > 8: inv = floor(2^INV_BITS_WIDE / rt) with rt >= 64 (eps)
    pub const INV_BITS_WIDE = 21;
    /// act_bits > 8: u = rq(xs inv, U_SHIFT_WIDE)
    pub const U_SHIFT_WIDE = 10;

    pub fn actBits(self: LayerCfg) u5 {
        return @intCast(self.act_bits);
    }
    pub fn residBits(self: LayerCfg) u5 {
        return @intCast(self.resid_bits);
    }
    /// SiLU table: 2^A entries over input g in [-2^(A-1), 2^(A-1)) at scale 2^-(A-4)
    pub fn siluFrac(self: LayerCfg) u5 {
        return @intCast(self.act_bits - 4);
    }

    /// causal mask bias: any masked D = m - S + bias is >= 256 (e = 0)
    pub fn maskBias(self: LayerCfg) i32 {
        return (@as(i32, 1) << @intCast(self.score_bits)) + 256;
    }
    /// D = m - S - Bias < 2^sb + maskBias <= 2^(sb+2)
    pub fn expLog(self: LayerCfg) u32 {
        return self.score_bits + 2;
    }

    pub fn isMoe(self: LayerCfg) bool {
        return self.log_experts > 0;
    }
    pub fn routerLogCols(self: LayerCfg) u32 {
        return @max(self.log_experts, self.router_log_cols);
    }
    pub fn qkvLogCols(self: LayerCfg) u32 {
        const w = (@as(usize, 1) << @intCast(self.log_d)) + 2 * (@as(usize, 1) << @intCast(self.logDkv()));
        return std.math.log2_int_ceil(usize, w);
    }
    fn nAttn(self: LayerCfg) u32 {
        return if (self.fused_qkv) 2 else 4;
    }
    pub fn weightsPerLayer(self: LayerCfg) u32 {
        return self.nAttn() + if (self.isMoe()) 1 + 3 * (@as(u32, 1) << @intCast(self.log_experts)) else 3;
    }
    // weight indices within a layer
    pub fn wQ(_: LayerCfg) u32 {
        return 0; // W_qkv when fused
    }
    pub fn wK(self: LayerCfg) u32 {
        std.debug.assert(!self.fused_qkv);
        return 1;
    }
    pub fn wV(self: LayerCfg) u32 {
        std.debug.assert(!self.fused_qkv);
        return 2;
    }
    pub fn wO(self: LayerCfg) u32 {
        return self.nAttn() - 1;
    }
    pub fn wGate(self: LayerCfg) u32 {
        return self.nAttn();
    }
    pub fn wUp(self: LayerCfg) u32 {
        return self.nAttn() + 1;
    }
    pub fn wDown(self: LayerCfg) u32 {
        return self.nAttn() + 2;
    }
    pub fn wRouter(self: LayerCfg) u32 {
        return self.nAttn();
    }
    pub fn wExpert(self: LayerCfg, x: u32) u32 {
        return self.nAttn() + 1 + 3 * x;
    }

    pub fn logDh(self: LayerCfg) u32 {
        return self.log_d - self.log_heads;
    }
    pub fn logDkv(self: LayerCfg) u32 {
        return self.log_kv_heads + self.logDh();
    }
    pub fn validate(self: LayerCfg) !void {
        if (self.log_heads > self.log_d or self.logDh() < 1) return error.BadConfig;
        if (self.log_kv_heads > self.log_heads) return error.BadConfig;
        // no-wrap bounds (transformer.md, "Field-size bounds")
        if (self.log_d > 14 or self.log_f > 15 or self.logDh() > 13) return error.BadConfig;
        if (self.log_heads + 2 * self.log_t > 26 or self.log_t > 12) return error.BadConfig;
        if (self.isMoe() and (self.log_experts > 6 or self.log_capacity > self.log_t)) return error.BadConfig;
        // exp-table domain 2^(sb+2) <= 2^16 (one LogUp table); sel * D sums stay < 2^(lt+16)
        if (self.score_bits < 8 or self.score_bits > 14) return error.BadConfig;
        // A-bit tables (SiLU 2^A, RoPE out A + 1 bits) stay <= 2^16 entries;
        // R-bit increments: shift + R <= 30 (bounds.zig re-derives every
        // accumulator bound from the statement, so wider widths that could
        // wrap are rejected there regardless)
        if (self.act_bits < 8 or self.act_bits > 14) return error.BadConfig;
        if (self.resid_bits < 8 or self.resid_bits > 16) return error.BadConfig;
        // wide widths are implemented for dense layers only
        if (self.isMoe() and (self.act_bits != 8 or self.resid_bits != 8)) return error.BadConfig;
    }
};

pub fn layerWeightInfos(a: std.mem.Allocator, cfg: LayerCfg) ![]TensorInfo {
    const wpl = cfg.weightsPerLayer();
    const out = try a.alloc(TensorInfo, wpl * cfg.n_layers);
    for (0..cfg.n_layers) |l| {
        const b = out[l * wpl ..];
        if (cfg.fused_qkv) {
            b[cfg.wQ()] = TensorInfo.mat(cfg.log_d, cfg.qkvLogCols());
        } else {
            b[cfg.wQ()] = TensorInfo.mat(cfg.log_d, cfg.log_d);
            b[cfg.wK()] = TensorInfo.mat(cfg.log_d, cfg.logDkv());
            b[cfg.wV()] = TensorInfo.mat(cfg.log_d, cfg.logDkv());
        }
        b[cfg.wO()] = TensorInfo.mat(cfg.log_d, cfg.log_d);
        if (cfg.isMoe()) {
            b[cfg.wRouter()] = TensorInfo.mat(cfg.log_d, cfg.routerLogCols());
            for (0..@as(u32, 1) << @intCast(cfg.log_experts)) |x| {
                const e = cfg.wExpert(@intCast(x));
                b[e] = TensorInfo.mat(cfg.log_d, cfg.log_f);
                b[e + 1] = TensorInfo.mat(cfg.log_d, cfg.log_f);
                b[e + 2] = TensorInfo.mat(cfg.log_f, cfg.log_d);
            }
        } else {
            b[cfg.wGate()] = TensorInfo.mat(cfg.log_d, cfg.log_f);
            b[cfg.wUp()] = TensorInfo.mat(cfg.log_d, cfg.log_f);
            b[cfg.wDown()] = TensorInfo.mat(cfg.log_f, cfg.log_d);
        }
    }
    return out;
}

/// RoPE rotation table R[t, i, b_out, b_in] (2^7 fixed point).
pub fn ropeTable(a: std.mem.Allocator, log_t: u32, log_dh: u32) ![]i32 {
    const T = @as(usize, 1) << @intCast(log_t);
    const half = @as(usize, 1) << @intCast(log_dh - 1);
    const dh: f64 = @floatFromInt(@as(usize, 1) << @intCast(log_dh));
    const out = try a.alloc(i32, T * half * 4);
    for (0..T) |t| for (0..half) |i| {
        const theta = @as(f64, @floatFromInt(t)) * std.math.pow(f64, 10000.0, -2.0 * @as(f64, @floatFromInt(i)) / dh);
        const c: i32 = @intFromFloat(@round(128.0 * @cos(theta)));
        const s: i32 = @intFromFloat(@round(128.0 * @sin(theta)));
        const base = (t * half + i) * 4;
        out[base + 0] = c; // (b_out 0, b_in 0)
        out[base + 1] = -s; // (0, 1)
        out[base + 2] = s; // (1, 0)
        out[base + 3] = c; // (1, 1)
    };
    return out;
}

/// Causal additive mask Bias[t, j] = 0 (j <= t) or -512 (j > t).
pub fn causalBias(a: std.mem.Allocator, log_t: u32) ![]i32 {
    return causalBiasN(a, log_t, MASK_BIAS);
}

/// Causal additive mask with bias `mask` (LayerCfg.maskBias()).
pub fn causalBiasN(a: std.mem.Allocator, log_t: u32, mask: i32) ![]i32 {
    const T = @as(usize, 1) << @intCast(log_t);
    const out = try a.alloc(i32, T * T);
    for (0..T) |t| for (0..T) |j| {
        out[t * T + j] = if (j <= t) 0 else -mask;
    };
    return out;
}

pub const MASK_BIAS = 512;

/// Shared public tensors / tables of a stack.
pub const Ctx = struct {
    cfg: LayerCfg,
    ws: *const proto.WeightStore,
    rope: u32,
    bias: u32,
    exp_table: u32,
    silu: u32,
    gammas: []u32, // 2 per layer
    tri: u32 = 0, // MoE tie-break triangle (public)
    /// act_bits > 8: SiLU as an ext lookup table over 2^A entries
    silu_x: ?u32 = null,
    /// test-only: route ties to the LAST maximiser (must be rejected)
    test_last_argmax: bool = false,
};

pub fn initCtx(b: *Builder, cfg: LayerCfg, ws: *const proto.WeightStore, seed: u64) !Ctx {
    const c = try initCtxPublics(b, cfg, ws, seed);
    const wi = try layerWeightInfos(b.a, cfg);
    defer b.a.free(wi);
    try b.weight_infos.appendSlice(b.a, wi);
    return c;
}

/// As `initCtx`, without registering the weight infos (callers with their own
/// weight layout, e.g. `lm.zig`'s interleaved dense/MoE stack, append them).
pub fn initCtxPublics(b: *Builder, cfg: LayerCfg, ws: *const proto.WeightStore, seed: u64) !Ctx {
    try cfg.validate();
    const rt = try ropeTable(b.a, cfg.log_t, cfg.logDh());
    defer b.a.free(rt);
    const rope_id = try b.public(cfg.log_t + cfg.logDh() + 1, rt);
    const cb = try causalBiasN(b.a, cfg.log_t, cfg.maskBias());
    defer b.a.free(cb);
    const bias = try b.public(2 * cfg.log_t, cb);
    const et = try expTableN(b.a, cfg.expLog());
    defer b.a.free(et);
    const exp_table = try b.xtable(@intCast(cfg.expLog()), et);
    const silu = try b.coreTable(model.siluTable());
    const gammas = try b.arena.allocator().alloc(u32, 2 * cfg.n_layers);
    var prng = std.Random.DefaultPrng.init(seed);
    const D = @as(usize, 1) << @intCast(cfg.log_d);
    const g = try b.a.alloc(i32, D);
    defer b.a.free(g);
    for (gammas) |*gid| {
        for (g) |*v| v.* = prng.random().intRangeAtMost(i32, 48, 80);
        gid.* = try b.public(cfg.log_d, g);
    }
    var tri: u32 = 0;
    if (cfg.isMoe()) {
        // Tri[x', x] = 1 iff x' > x (first-argmax tie-breaking)
        const E = @as(usize, 1) << @intCast(cfg.log_experts);
        const tv = try b.a.alloc(i32, E * E);
        defer b.a.free(tv);
        for (0..E) |xp| for (0..E) |x| {
            tv[xp * E + x] = @intFromBool(xp > x);
        };
        tri = try b.public(2 * cfg.log_experts, tv);
    }
    var silu_x: ?u32 = null;
    if (cfg.act_bits > 8) {
        const st = try siluTableWide(b.a, cfg.actBits(), cfg.siluFrac());
        defer b.a.free(st);
        silu_x = try b.xtable(cfg.actBits(), st);
    }
    return .{ .cfg = cfg, .ws = ws, .rope = rope_id, .bias = bias, .exp_table = exp_table, .silu = silu, .gammas = gammas, .tri = tri, .silu_x = silu_x };
}

/// SiLU over g in [-2^(bits-1), 2^(bits-1)) at input / output scale
/// 2^-frac, indexed by g + 2^(bits-1); round half away from zero, clamped to
/// the signed bits-wide range (bits = 8, frac = 4 is model.siluTable).
pub fn siluTableWide(a: std.mem.Allocator, bits: u5, frac: u5) ![]i32 {
    const n = @as(usize, 1) << bits;
    const half: i32 = @intCast(n / 2);
    const t = try a.alloc(i32, n);
    const sc: f64 = @floatFromInt(@as(u32, 1) << frac);
    for (t, 0..) |*o, i| {
        const v: f64 = @as(f64, @floatFromInt(@as(i32, @intCast(i)) - half)) / sc;
        const sv = v / (1.0 + @exp(-v));
        const q: i32 = @intFromFloat(@round(sv * sc));
        o.* = std.math.clamp(q, -half, half - 1);
    }
    return t;
}

/// RMSNorm parameters (transformer.md 4; accuracy.md "Wide activations").
/// rt = isqrt(((ss + ceps) << m1) >> s1), inv = floor(2^k / rt),
/// u = rq(xs inv, us). act_bits = 8: the original constants. act_bits > 8:
/// s1 - m1 = ld + 2 A - 27 keeps rt < 2^13 for |xs| <= 2^(A-1) (so rt * rt
/// and inv * rt stay below 2^29), and ceps = 2^(12 + s1 - m1) forces
/// rt >= 64 (an eps), so inv <= 2^(k-6) = 2^15 fits its 16-bit range.
pub const RmsParams = struct { s1: u5, m1: u5, ceps: i64, k: u5, us: u5, a: u5 };

pub fn rmsParams(cfg: LayerCfg) RmsParams {
    const ld: i32 = @intCast(cfg.log_d);
    if (cfg.act_bits == 8) {
        const s1: u5 = if (ld >= 8) @intCast(ld - 8) else 0;
        const m1: u5 = if (ld < 8) @intCast(8 - ld) else 0;
        return .{ .s1 = s1, .m1 = m1, .ceps = @as(i64, 1) << s1, .k = LayerCfg.INV_BITS, .us = 6, .a = 8 };
    }
    const A: i32 = @intCast(cfg.act_bits);
    const d = ld + 2 * A - 27;
    const s1: u5 = if (d >= 0) @intCast(d) else 0;
    const m1: u5 = if (d < 0) @intCast(-d) else 0;
    return .{ .s1 = s1, .m1 = m1, .ceps = @as(i64, 1) << @intCast(12 + @as(i32, s1) - @as(i32, m1)), .k = LayerCfg.INV_BITS_WIDE, .us = LayerCfg.U_SHIFT_WIDE, .a = cfg.actBits() };
}

// ---------------------------------------------------------------------------
// Blocks.

/// RMSNorm over the last dim of x [T, D] with public gamma; returns int8 y [T, D].
/// If `x_int8` the input is range-checked as int8, otherwise it is first
/// requantized to int8 (xs = round(x / 2^s0)).
pub const RmsOut = struct { y: u32, xs: u32, ss: u32, rt: u32, inv: u32, u: u32 };

pub fn rmsnorm(b: *Builder, c: Ctx, x: u32, gamma: u32, x_int8: bool) !RmsOut {
    const prev_scope = b.enter(if (std.mem.startsWith(u8, b.scope, "rms")) b.scope else "rms");
    defer b.scope = prev_scope;
    const lt = c.cfg.log_t;
    const ld = c.cfg.log_d;
    const n = lt + ld;
    const rp = rmsParams(c.cfg);
    const A = rp.a;
    const lim = @as(i64, 1) << (A - 1);
    // xs: signed A-bit view of x (A = 8: int8)
    var xs = x;
    if (x_int8) {
        b.tag("xs.range");
        try b.rangeSigned(x, A);
    } else {
        var s0: u5 = 0;
        if (!b.replaying()) for (b.wit.items[x]) |v| {
            while (rq(v, s0) < -lim or rq(v, s0) >= lim) s0 += 1;
        };
        s0 = try b.nextShift(s0);
        b.tag("xs");
        if (s0 == 0) try b.rangeSigned(x, A) else xs = try b.requantLinearBits(x, s0, A);
    }
    const xr = Ref.w(xs);
    // ss[t] = sum_d xs^2
    b.tag("ss");
    const ss = (try b.einsumExact(TensorInfo.vec(lt), lt, xr, xr, ld, &.{ids(0, n)}, &.{ids(0, n)})).?;
    // rt = max{r >= 0 : r^2 2^s1 <= (ss + c) 2^m1}
    const s1 = rp.s1;
    const m1 = rp.m1;
    const ceps: i64 = rp.ceps;
    const T = @as(usize, 1) << @intCast(lt);
    const rt = try b.a.alloc(i32, T);
    for (b.wit.items[ss], rt) |v, *o| {
        const N: u64 = @intCast((@as(i64, v) + ceps) << m1);
        o.* = @intCast(std.math.sqrt(N >> s1));
    }
    b.tag("rt");
    const rt_id = try b.addVec(lt, rt);
    const nmax: u64 = @intCast(((@as(i64, 1) << @intCast(ld + 2 * (@as(u32, A) - 1))) + ceps) << m1);
    const rtmax = std.math.sqrt(nmax >> s1);
    // rt in [0, 2^rt_bits) with 2^s1 * rt^2 < 2^30: rt2 = rt * rt cannot wrap mod p
    const rt_bits: u32 = std.math.log2_int_ceil(u64, rtmax + 1);
    if (2 * rt_bits + s1 > 30) return error.BadConfig;
    b.tag("rt.range");
    try b.rangeWide(lt, try b.expr(&.{term(1, Ref.w(rt_id), &.{ids(0, lt)})}, 0), rt_bits);
    b.tag("rt2");
    const rt2 = (try b.einsumExact(TensorInfo.vec(lt), lt, Ref.w(rt_id), Ref.w(rt_id), 0, &.{ids(0, lt)}, &.{ids(0, lt)})).?;
    const gap_bits: u32 = s1 + std.math.log2_int_ceil(u64, 2 * rtmax + 2);
    const tl = ids(0, lt);
    const p_m1 = @as(i64, 1) << m1;
    const p_s1 = @as(i64, 1) << s1;
    // lower: (ss + c) 2^m1 - 2^s1 rt2 >= 0
    b.tag("isqrt.slack_lo");
    try b.rangeWide(lt, try b.expr(&.{ term(p_m1, Ref.w(ss), &.{tl}), term(-p_s1, Ref.w(rt2), &.{tl}) }, ceps * p_m1), gap_bits);
    // upper: 2^s1 (rt2 + 2 rt + 1) - 1 - (ss + c) 2^m1 >= 0
    b.tag("isqrt.slack_hi");
    try b.rangeWide(lt, try b.expr(&.{ term(p_s1, Ref.w(rt2), &.{tl}), term(2 * p_s1, Ref.w(rt_id), &.{tl}), term(-p_m1, Ref.w(ss), &.{tl}) }, p_s1 - 1 - ceps * p_m1), gap_bits);
    // inv = floor(2^K / rt)
    const K = rp.k;
    const inv = try b.a.alloc(i32, T);
    for (rt, inv) |r, *o| o.* = @divFloor(@as(i32, 1) << K, r);
    b.tag("inv");
    const inv_id = try b.addVec(lt, inv);
    try b.rangeWide(lt, try b.expr(&.{term(1, Ref.w(inv_id), &.{tl})}, 0), 16);
    b.tag("inv_rt");
    const pr = (try b.einsumExact(TensorInfo.vec(lt), lt, Ref.w(inv_id), Ref.w(rt_id), 0, &.{tl}, &.{tl})).?;
    // 2^K - pr in [0, rt): 2^K - pr >= 0 and rt - 1 - 2^K + pr >= 0
    try b.rangeWide(lt, try b.expr(&.{term(-1, Ref.w(pr), &.{tl})}, @as(i64, 1) << K), 16);
    try b.rangeWide(lt, try b.expr(&.{ term(1, Ref.w(rt_id), &.{tl}), term(1, Ref.w(pr), &.{tl}) }, -1 - (@as(i64, 1) << K)), 16);
    // u = requant_us(xs * inv) (16-bit), y = requant(u * gamma) (A-bit)
    b.tag("u");
    const u = try b.einsumRequant(TensorInfo.mat(lt, ld), xr, Ref.w(inv_id), 0, &.{ids(0, n)}, &.{tl}, rp.us, 16);
    b.tag("y");
    const y = try b.einsumRequant(TensorInfo.mat(lt, ld), Ref.w(u), Ref.p(gamma), 0, &.{ids(0, n)}, &.{ids(lt, ld)}, null, A);
    return .{ .y = y, .xs = xs, .ss = ss, .rt = rt_id, .inv = inv_id, .u = u };
}

/// RoPE on x [T, heads * dh] (layout t, head, i, b): out[.., i, b'] =
/// requant_7(sum_b x[.., i, b] R[t, i, b', b]), 9-bit output.
pub fn rope(b: *Builder, c: Ctx, x: u32, log_heads: u32, colfix: []const u8) !u32 {
    const lt = c.cfg.log_t;
    const ldh = c.cfg.logDh();
    const n_out = lt + log_heads + ldh;
    const i_vars = ids(lt + log_heads, ldh - 1);
    const prev_scope = b.enter("rope");
    defer b.scope = prev_scope;
    b.tag(if (log_heads == c.cfg.log_heads) "q_rot" else "k_rot");
    return b.einsumRequant(
        TensorInfo.mat(lt, log_heads + ldh),
        Ref.w(x),
        Ref.p(c.rope),
        1,
        &.{ ids(0, lt), colfix, ids(lt, log_heads), i_vars, ids(n_out, 1) },
        &.{ ids(0, lt), i_vars, ids(n_out - 1, 1), ids(n_out, 1) },
        7,
        c.cfg.actBits() + 1,
    );
}

/// Attention with log_t >= this uses the factored argmax selector A (x) B
/// (2 H T^(1/2) one-hots) instead of sel[h, t, j] (H T^2).
pub const FACTORED_SEL_MIN_LOG_T = 4;

/// sel (plain, log_t < FACTORED_SEL_MIN_LOG_T) or sel_a / sel_b and the
/// partial sums ps / pb (factored); z1 = S(j*), z2 = Bias(j*). D = m - S - Bias
/// is virtual (an exp-key input expression, never committed).
pub const AttnOut = struct {
    o: u32,
    scores: u32,
    acc: u32,
    od: u32,
    m: u32,
    sel: ?u32 = null,
    sel_a: ?u32 = null,
    sel_b: ?u32 = null,
    ps: ?u32 = null,
    pb: ?u32 = null,
    z1: u32,
    z2: u32,
    e: u32,
    den: u32,
};

/// Causal GQA attention core: qr [T, H dh], kr / v [T, Hkv dh] -> O [T, H dh].
pub fn attention(b: *Builder, c: Ctx, qr: u32, kr: u32, v: u32, vfix: []const u8) !AttnOut {
    const cfg = c.cfg;
    const lt = cfg.log_t;
    const lh = cfg.log_heads;
    const lkv = cfg.log_kv_heads;
    const lg = lh - lkv;
    const ldh = cfg.logDh();
    const n3 = lh + 2 * lt; // (h, t, j)
    const n2 = lh + lt; // (h, t)
    const prev_scope = b.enter("attn");
    defer b.scope = prev_scope;
    b.tag("scores");
    // scores S[hk, g, t, j] = requant(sum_e Qr[t, hk, g, e] Kr[j, hk, e])
    const S = try b.einsumRequant(
        TensorInfo.vec(n3),
        Ref.w(qr),
        Ref.w(kr),
        ldh,
        &.{ ids(lh, lt), ids(0, lkv), ids(lkv, lg), ids(n3, ldh) },
        &.{ ids(lh + lt, lt), ids(0, lkv), ids(n3, ldh) },
        null,
        @intCast(cfg.score_bits),
    );
    const T = @as(usize, 1) << @intCast(lt);
    const H = @as(usize, 1) << @intCast(lh);
    const bias = b.vals(Ref.p(c.bias));
    const sv = b.wit.items[S];
    // rowmax over masked scores + first-argmax selector
    const m = try b.a.alloc(i32, H * T);
    const arg = try b.a.alloc(usize, H * T);
    defer b.a.free(arg);
    for (0..H * T) |row| {
        const t = row % T;
        var best: i32 = std.math.minInt(i32);
        var aj: usize = 0;
        for (0..T) |j| {
            const val = sv[row * T + j] + bias[t * T + j];
            if (val > best) {
                best = val;
                aj = j;
            }
        }
        m[row] = best;
        arg[row] = aj;
    }
    b.tag("m");
    const m_id = try b.addVec(n2, m);
    // m in S's signed range: the honest max is attained at an unmasked j
    // (j = t is never masked, and a masked S + Bias < -2^(sb-1) <= S(t, t)),
    // so |m| < 2^(sb-1). This bounds m from its own key (bounds.zig).
    b.tag("m.range");
    try b.rangeSigned(m_id, cfg.score_bits);
    const all3 = ids(0, n3);
    const bias_lab = ids(lh, 2 * lt);
    // D = m - S - Bias is NOT committed (virtual): the exp key below takes the
    // affine expression itself. Membership in the exp table's domain proves
    // D in [0, 2^expLog) as an integer (bounds.zig: |expr| + dom < p), i.e.
    // m >= S_j + Bias_j for every j. Attainment: a boolean one-hot selector
    // at some j* with z1 = S(j*), z2 = Bias(j*) (exact one-hot einsums) and
    // m = z1 + z2. Together: m = max_j (S + Bias).
    var z1: u32 = undefined;
    var z2: u32 = undefined;
    var sel_id: ?u32 = null;
    var sel_a: ?u32 = null;
    var sel_b: ?u32 = null;
    var ps_id: ?u32 = null;
    var pb_id: ?u32 = null;
    if (lt < FACTORED_SEL_MIN_LOG_T) {
        // plain selector sel[h, t, j] (H T^2), kept for toy statements
        const sel = try b.a.alloc(i32, H * T * T);
        @memset(sel, 0);
        for (arg, 0..) |j, row| sel[row * T + j] = 1;
        b.tag("sel");
        const sid = try b.addVec(n3, sel);
        sel_id = sid;
        // sel in {0,1} (sel * sel == sel: one degree-3 zero-check, cheaper than
        // a 1-bit LogUp key over H T^2), sum_j sel = 1
        try b.einsumInto(sid, Ref.w(sid), Ref.w(sid), 0, &.{all3}, &.{all3});
        try b.lineq(n2, try b.expr(&.{term(1, Ref.w(sid), &.{ ids(0, n2), sums(lt) })}, -1));
        b.tag("argmax.z1");
        z1 = (try b.einsumExact(TensorInfo.vec(n2), n2, Ref.w(sid), Ref.w(S), lt, &.{all3}, &.{all3})).?;
        b.tag("argmax.z2");
        z2 = (try b.einsumExact(TensorInfo.vec(n2), n2, Ref.w(sid), Ref.p(c.bias), lt, &.{all3}, &.{bias_lab})).?;
    } else {
        // factored selector: j = jl + 2^ljl jh, A[h, t, jh] and B[h, t, jl]
        // one-hot each (2 H T sqrt(T) instead of H T^2), sel = A (x) B
        const ljl = lt / 2;
        const ljh = lt - ljl;
        const Tl = @as(usize, 1) << @intCast(ljl);
        const Th = @as(usize, 1) << @intCast(ljh);
        const av = try b.a.alloc(i32, H * T * Th);
        const bv = try b.a.alloc(i32, H * T * Tl);
        @memset(av, 0);
        @memset(bv, 0);
        for (arg, 0..) |j, row| {
            av[row * Th + (j >> @intCast(ljl))] = 1;
            bv[row * Tl + (j & (Tl - 1))] = 1;
        }
        const na = n2 + ljh;
        const nb = n2 + ljl;
        b.tag("sel.a");
        const aid = try b.addVec(na, av);
        b.tag("sel.b");
        const bid = try b.addVec(nb, bv);
        sel_a = aid;
        sel_b = bid;
        try b.einsumInto(aid, Ref.w(aid), Ref.w(aid), 0, &.{ids(0, na)}, &.{ids(0, na)});
        try b.lineq(n2, try b.expr(&.{term(1, Ref.w(aid), &.{ ids(0, n2), sums(ljh) })}, -1));
        try b.einsumInto(bid, Ref.w(bid), Ref.w(bid), 0, &.{ids(0, nb)}, &.{ids(0, nb)});
        try b.lineq(n2, try b.expr(&.{term(1, Ref.w(bid), &.{ ids(0, n2), sums(ljl) })}, -1));
        // PS[h, t, jh] = sum_jl B S, PB[h, t, jh] = sum_jl B Bias (one-hot: exact)
        b.tag("argmax.ps");
        const ps = (try b.einsumExact(TensorInfo.vec(na), na, Ref.w(bid), Ref.w(S), ljl, &.{ ids(0, n2), ids(na, ljl) }, &.{all3})).?;
        b.tag("argmax.pb");
        const pb = (try b.einsumExact(TensorInfo.vec(na), na, Ref.w(bid), Ref.p(c.bias), ljl, &.{ ids(0, n2), ids(na, ljl) }, &.{bias_lab})).?;
        ps_id = ps;
        pb_id = pb;
        b.tag("argmax.z1");
        z1 = (try b.einsumExact(TensorInfo.vec(n2), n2, Ref.w(aid), Ref.w(ps), ljh, &.{ids(0, na)}, &.{ids(0, na)})).?;
        b.tag("argmax.z2");
        z2 = (try b.einsumExact(TensorInfo.vec(n2), n2, Ref.w(aid), Ref.w(pb), ljh, &.{ids(0, na)}, &.{ids(0, na)})).?;
    }
    // m = S(j*) + Bias(j*)
    try b.lineq(n2, try b.expr(&.{ term(1, Ref.w(m_id), &.{ids(0, n2)}), term(-1, Ref.w(z1), &.{ids(0, n2)}), term(-1, Ref.w(z2), &.{ids(0, n2)}) }, 0));
    // e = exp_table(m - S - Bias) (domain [0, 2^expLog) also range-checks D)
    const et = b.xtables.items[c.exp_table].values;
    const e = try b.a.alloc(i32, H * T * T);
    for (e, 0..) |*o, i| {
        const row = i / T;
        const t = row % T;
        const j = i % T;
        o.* = et[@intCast(m[row] - sv[i] - bias[t * T + j])];
    }
    b.tag("e");
    const e_id = try b.addVec(n3, e);
    try b.key(n3, try b.expr(&.{
        term(1, Ref.w(m_id), &.{ids(0, n2)}),
        term(-1, Ref.w(S), &.{all3}),
        term(-1, Ref.p(c.bias), &.{bias_lab}),
    }, 0), try b.expr(&.{term(1, Ref.w(e_id), &.{all3})}, 0), .{ .lookup = c.exp_table });
    // den = sum_j e
    const den = try b.a.alloc(i32, H * T);
    for (den, 0..) |*o, row| {
        var s: i32 = 0;
        for (e[row * T ..][0..T]) |x| s += x;
        o.* = s;
    }
    b.tag("den");
    const den_id = try b.addVec(n2, den);
    try b.lineq(n2, try b.expr(&.{ term(1, Ref.w(den_id), &.{ids(0, n2)}), term(-1, Ref.w(e_id), &.{ ids(0, n2), sums(lt) }) }, 0));
    // Softmax-weighted values without a reciprocal (EXT-1 / EXT-3, the
    // FlashProve-style division): acc[t, h, c] = sum_j e[h, t, j] v[j, hk, c]
    // exactly (|acc| <= 2^(lt+15)), then o = round(acc / den) per entry via
    //   0 <= 2 acc + den - 2 o den < 2 den,   o int8,
    // with od = o * den an exact einsum (|od| <= 2^(lt+15)). Every product and
    // sum stays below 2^(lt+17) <= 2^29 < p/2 (validateStatement re-derives
    // this from the statement alone), and the row is normalised up to one
    // rounding per output (no per-probability quantisation).
    const n_o = lt + lh + ldh;
    b.tag("acc");
    const acc_id = (try b.einsumExact(
        TensorInfo.mat(lt, lh + ldh),
        n_o,
        Ref.w(e_id),
        Ref.w(v),
        lt,
        &.{ ids(lt, lkv), ids(lt + lkv, lg), ids(0, lt), ids(n_o, lt) },
        &.{ ids(n_o, lt), vfix, ids(lt, lkv), ids(lt + lh, ldh) },
    )).?;
    const accv = b.wit.items[acc_id];
    const Dh = @as(usize, 1) << @intCast(lh + ldh);
    const dhn = @as(usize, 1) << @intCast(ldh);
    const ov = try b.a.alloc(i32, accv.len);
    for (ov, accv, 0..) |*o, x, i| {
        const t = i / Dh;
        const h = (i % Dh) / dhn;
        const dn: i64 = den[h * T + t];
        o.* = @intCast(@divFloor(2 * @as(i64, x) + dn, 2 * dn));
    }
    b.tag("o");
    const O = try b.add(TensorInfo.mat(lt, lh + ldh), ov);
    b.tag("o.range");
    try b.rangeSigned(O, cfg.actBits());
    const all_o = ids(0, n_o);
    const den_lab = cat(&.{ ids(lt, lh), ids(0, lt) });
    b.tag("od");
    const od = (try b.einsumExact(TensorInfo.mat(lt, lh + ldh), n_o, Ref.w(O), Ref.w(den_id), 0, &.{all_o}, &.{den_lab[0..n2]})).?;
    // 2 acc + den - 2 od in [0, 2 den): lower and upper slack, lt + 9 bits each
    b.tag("div.slack_lo");
    try b.rangeWide(n_o, try b.expr(&.{ term(2, Ref.w(acc_id), &.{all_o}), term(1, Ref.w(den_id), &.{den_lab[0..n2]}), term(-2, Ref.w(od), &.{all_o}) }, 0), lt + 9);
    b.tag("div.slack_hi");
    try b.rangeWide(n_o, try b.expr(&.{ term(1, Ref.w(den_id), &.{den_lab[0..n2]}), term(-2, Ref.w(acc_id), &.{all_o}), term(2, Ref.w(od), &.{all_o}) }, -1), lt + 9);
    return .{ .o = O, .scores = S, .acc = acc_id, .od = od, .m = m_id, .sel = sel_id, .sel_a = sel_a, .sel_b = sel_b, .ps = ps_id, .pb = pb_id, .z1 = z1, .z2 = z2, .e = e_id, .den = den_id };
}

/// z = x + y (committed, lineq).
pub fn residual(b: *Builder, x: u32, y: u32) !u32 {
    const info = b.infos.items[x];
    const n = info.logSize();
    const z = try b.a.alloc(i32, info.size());
    for (z, b.wit.items[x], b.wit.items[y]) |*o, p, q| o.* = p + q;
    b.tag("residual");
    const id = try b.add(info, z);
    try b.lineq(n, try b.expr(&.{ term(1, Ref.w(id), &.{ids(0, n)}), term(-1, Ref.w(x), &.{ids(0, n)}), term(-1, Ref.w(y), &.{ids(0, n)}) }, 0));
    return id;
}

pub const MoeOut = struct { out: u32, logits: u32, sel: u32, dr: u32, pre: u32, disp: u32, occ: u32, mo: u32, slot_of: []usize, expert_of: []usize };

/// Top-1 MoE: router logits = rq(y Wr) (int8, first E of the padded columns),
/// x*(t) = first argmax, tokens dispatched to per-expert slots, each expert
/// runs its SwiGLU MLP on its 2^log_capacity slots only, outputs combined.
pub fn moe(b: *Builder, c: Ctx, wb: u32, y: u32) !MoeOut {
    const r = try moeRoute(b, c, wb, y);
    const prev_scope = b.enter("moe.expert");
    defer b.scope = prev_scope;
    const cfg = c.cfg;
    const lt = cfg.log_t;
    const ld = cfg.log_d;
    const le = cfg.log_experts;
    const lc = cfg.log_capacity;
    const E = @as(usize, 1) << @intCast(le);
    const C = @as(usize, 1) << @intCast(lc);
    const D = @as(usize, 1) << @intCast(ld);
    const disp_id = r.disp;
    // experts: Xe_x[c, d] = sum_t Disp[x, c, t] y[t, d]; SwiGLU on C slots
    const mo_all = try b.a.alloc(i32, E * C * D);
    var mo_ids: [64]u32 = undefined;
    for (0..E) |x| {
        b.tag("xe.gather");
        const xe = (try b.einsumExact(TensorInfo.mat(lc, ld), lc + ld, Ref.w(disp_id), Ref.w(y), lt, &.{ fixesOf(x, le), ids(0, lc), ids(lc + ld, lt) }, &.{ ids(lc + ld, lt), ids(lc, ld) })).?;
        const we = wb + cfg.wExpert(@intCast(x));
        b.tag("gate");
        const g = try b.matmul(c.ws, xe, we);
        b.tag("up");
        const u = try b.matmul(c.ws, xe, we + 1);
        b.tag("silu");
        const act = try b.lookup(g, c.silu);
        b.tag("glu");
        const hm = try b.hadamard(act, u);
        b.tag("down");
        const mo = try b.matmul(c.ws, hm, we + 2);
        @memcpy(mo_all[x * C * D ..][0 .. C * D], b.wit.items[mo]);
        mo_ids[x] = mo;
    }
    // stack MO[x, c, d] = mo_x[c, d]
    const nmo = le + lc + ld;
    b.tag("mo.stack");
    const mo_st = try b.addVec(nmo, mo_all);
    for (0..E) |x| {
        try b.lineq(lc + ld, try b.expr(&.{ term(1, Ref.w(mo_st), &.{ fixesOf(x, le), ids(0, lc + ld) }), term(-1, Ref.w(mo_ids[x]), &.{ids(0, lc + ld)}) }, 0));
    }
    // combine out[t, d] = sum_{x, c} Disp[x, c, t] MO[x, c, d]
    const n_out = lt + ld;
    b.tag("combine");
    const out = (try b.einsumExact(TensorInfo.mat(lt, ld), n_out, Ref.w(disp_id), Ref.w(mo_st), le + lc, &.{ ids(n_out, le + lc), ids(0, lt) }, &.{ ids(n_out, le + lc), ids(lt, ld) })).?;
    return .{ .out = out, .logits = r.logits, .sel = r.sel, .dr = r.dr, .pre = r.pre, .disp = disp_id, .occ = r.occ, .mo = mo_st, .slot_of = r.slot_of, .expert_of = r.expert_of };
}

pub const MoeRoute = struct { logits: u32, sel: u32, dr: u32, pre: u32, disp: u32, occ: u32, slot_of: []usize, expert_of: []usize };

/// Top-1 routing of an MoE layer: router logits, first-argmax selection and
/// the dispatch tensor Disp[x, c, t] with its slot constraints (see moe()).
pub fn moeRoute(b: *Builder, c: Ctx, wb: u32, y: u32) !MoeRoute {
    const cfg = c.cfg;
    const lt = cfg.log_t;
    const le = cfg.log_experts;
    const lc = cfg.log_capacity;
    const lrc = cfg.routerLogCols();
    const T = @as(usize, 1) << @intCast(lt);
    const E = @as(usize, 1) << @intCast(le);
    const C = @as(usize, 1) << @intCast(lc);
    const Ncol = @as(usize, 1) << @intCast(lrc);
    const ar = b.arena.allocator();
    const prev_scope = b.enter("moe.route");
    defer b.scope = prev_scope;
    b.tag("logits");
    const logits = try b.matmul(c.ws, y, wb + cfg.wRouter());
    const lg = b.wit.items[logits];
    // routing (first argmax; test hook: last)
    const nr = lt + le; // vars (t, x)
    const m = try b.a.alloc(i32, T);
    const sel = try b.a.alloc(i32, T * E);
    @memset(sel, 0);
    const expert_of = try ar.alloc(usize, T);
    for (0..T) |t| {
        var best: i32 = std.math.minInt(i32);
        var arg: usize = 0;
        for (0..E) |x| {
            const v = lg[t * Ncol + x];
            if (v > best or (c.test_last_argmax and v == best)) {
                best = v;
                arg = x;
            }
        }
        m[t] = best;
        sel[t * E + arg] = 1;
        expert_of[t] = arg;
    }
    b.tag("m");
    const m_id = try b.addVec(lt, m);
    b.tag("sel");
    const sel_id = try b.addVec(nr, sel);
    const dr = try b.a.alloc(i32, T * E);
    for (0..T) |t| for (0..E) |x| {
        dr[t * E + x] = m[t] - lg[t * Ncol + x];
    };
    b.tag("dr");
    const dr_id = try b.addVec(nr, dr);
    const tv = ids(0, lt);
    const xv = ids(lt, le);
    const lg_lab: []const []const u8 = &.{ tv, fixes(0, lrc - le), xv };
    // Dr = m - L (L = real-expert slice of the padded logits)
    try b.lineq(nr, try b.expr(&.{ term(1, Ref.w(dr_id), &.{ tv, xv }), term(-1, Ref.w(m_id), &.{tv}), term(1, Ref.w(logits), lg_lab) }, 0));
    try b.key(nr, try b.expr(&.{term(1, Ref.w(dr_id), &.{ tv, xv })}, 0), null, .{ .range = 8 });
    try b.einsumInto(sel_id, Ref.w(sel_id), Ref.w(sel_id), 0, &.{ids(0, nr)}, &.{ids(0, nr)});
    try b.lineq(lt, try b.expr(&.{term(1, Ref.w(sel_id), &.{ tv, sums(le) })}, -1));
    _ = try b.einsumExact(null, lt, Ref.w(sel_id), Ref.w(dr_id), le, &.{ tv, ids(lt, le) }, &.{ tv, ids(lt, le) });
    // first argmax: pre[t, x] = sum_{x' > x} sel[t, x'];  Dr - pre >= 0
    b.tag("pre");
    const pre = (try b.einsumExact(TensorInfo.vec(nr), nr, Ref.w(sel_id), Ref.p(c.tri), le, &.{ tv, ids(nr, le) }, &.{ ids(nr, le), xv })).?;
    try b.key(nr, try b.expr(&.{ term(1, Ref.w(dr_id), &.{ tv, xv }), term(-1, Ref.w(pre), &.{ tv, xv }) }, 0), null, .{ .range = 8 });
    // dispatch Disp[x, c, t]
    const nd = le + lc + lt;
    const disp = try b.a.alloc(i32, E * C * T);
    @memset(disp, 0);
    const fill = try b.a.alloc(usize, E);
    defer b.a.free(fill);
    @memset(fill, 0);
    const slot_of = try ar.alloc(usize, T);
    for (0..T) |t| {
        const x = expert_of[t];
        if (fill[x] >= C) {
            if (b.shape_only) { // dummy values: any slot (statement unaffected)
                slot_of[t] = 0;
                continue;
            }
            b.a.free(disp);
            return error.CapacityExceeded;
        }
        slot_of[t] = fill[x];
        disp[(x * C + fill[x]) * T + t] = 1;
        fill[x] += 1;
    }
    b.tag("disp");
    const disp_id = try b.addVec(nd, disp);
    try b.einsumInto(disp_id, Ref.w(disp_id), Ref.w(disp_id), 0, &.{ids(0, nd)}, &.{ids(0, nd)});
    // sum_c Disp[x, c, t] = sel[t, x]   (vars: x, t)
    try b.lineq(le + lt, try b.expr(&.{ term(1, Ref.w(disp_id), &.{ ids(0, le), sums(lc), ids(le, lt) }), term(-1, Ref.w(sel_id), &.{ ids(le, lt), ids(0, le) }) }, 0));
    // occ[x, c] = sum_t Disp in {0, 1}
    const occ = try b.a.alloc(i32, E * C);
    @memset(occ, 0);
    for (0..E) |x| for (0..fill[x]) |cc| {
        occ[x * C + cc] = 1;
    };
    b.tag("occ");
    const occ_id = try b.addVec(le + lc, occ);
    try b.lineq(le + lc, try b.expr(&.{ term(1, Ref.w(occ_id), &.{ids(0, le + lc)}), term(-1, Ref.w(disp_id), &.{ ids(0, le + lc), sums(lt) }) }, 0));
    try b.einsumInto(occ_id, Ref.w(occ_id), Ref.w(occ_id), 0, &.{ids(0, le + lc)}, &.{ids(0, le + lc)});
    return .{ .logits = logits, .sel = sel_id, .dr = dr_id, .pre = pre, .disp = disp_id, .occ = occ_id, .slot_of = slot_of, .expert_of = expert_of };
}

const FIX0S = [_]u8{xt.FIX0} ** xt.MAXB;

/// FIX labels selecting the column block [off, off + 2^width_log) of a
/// 2^total_log-wide index (off a multiple of the block width).
pub fn sliceFix(buf: *[xt.MAXB]u8, total_log: u32, off: usize, width_log: u32) []const u8 {
    const n = total_log - width_log;
    const blk = off >> @intCast(width_log);
    std.debug.assert(blk << @intCast(width_log) == off);
    for (0..n) |i| buf[i] = if ((blk >> @intCast(n - 1 - i)) & 1 == 1) xt.FIX1 else xt.FIX0;
    return buf[0..n];
}

pub fn fixes(_: u32, n: u32) []const u8 {
    return FIX0S[0..n];
}

/// Fixed labels spelling x in `n` bits (MSB-first); arena-free static storage.
pub fn fixesOf(x: usize, n: u32) []const u8 {
    const S = struct {
        threadlocal var buf: [8][xt.MAXB]u8 = undefined;
        threadlocal var next: usize = 0;
    };
    const slot = &S.buf[S.next % 8];
    S.next += 1;
    for (0..n) |i| slot[i] = if ((x >> @intCast(n - 1 - i)) & 1 == 1) xt.FIX1 else xt.FIX0;
    return slot[0..n];
}

pub const LayerOut = struct { out: u32, h: u32, attn: AttnOut, rms1: RmsOut, rms2: RmsOut, q: u32, qr: u32, moe: ?MoeOut = null };

/// One Llama-style decoder layer: x -> x + Attn(RMSNorm(x)) -> h + MLP(RMSNorm(h)).
pub fn decoderLayer(b: *Builder, c: Ctx, layer: u32, x: u32, x_int8: bool) !LayerOut {
    return decoderLayerAt(b, c, layer, layer * c.cfg.weightsPerLayer(), x, x_int8);
}

/// `decoderLayer` with an explicit first weight index `wb` (layers of
/// different kinds, e.g. dense and MoE, interleaved in one weight store).
pub fn decoderLayerAt(b: *Builder, c: Ctx, layer: u32, wb: u32, x: u32, x_int8: bool) !LayerOut {
    const ab = try attnBlock(b, c, layer, wb, x, x_int8);
    const h = ab.h;
    const at = ab.attn;
    const r1 = ab.rms1;
    const r2 = ab.rms2;
    const q = ab.q;
    const qr = ab.qr;
    const cfg = c.cfg;
    const prev_scope = b.enter("residual");
    defer b.scope = prev_scope;
    if (cfg.isMoe()) {
        const mo = try moe(b, c, wb, r2.y);
        return .{ .out = try residual(b, h, mo.out), .h = h, .attn = at, .rms1 = r1, .rms2 = r2, .q = q, .qr = qr, .moe = mo };
    }
    const mo = try denseMlp(b, c, wb, r2.y);
    return .{ .out = try residual(b, h, mo), .h = h, .attn = at, .rms1 = r1, .rms2 = r2, .q = q, .qr = qr };
}

/// Dense SwiGLU MLP on y [T, D]: rq(SiLU(y Wg) (.) (y Wu)) Wd. int8
/// (act_bits = 8): core matmuls, core lookup and hadamard, as before. Wide:
/// A-bit gate / up / hadamard outputs, the SiLU as an ext lookup over 2^A
/// entries (its key also range-checks g), the hadamard as a requant einsum
/// (A-bit, symmetric data-chosen shift) and an R-bit down projection.
pub fn denseMlp(b: *Builder, c: Ctx, wb: u32, y: u32) !u32 {
    const cfg = c.cfg;
    const prev_scope = b.enter("mlp");
    defer b.scope = prev_scope;
    if (cfg.act_bits == 8) {
        b.tag("gate");
        const g = try b.matmul(c.ws, y, wb + cfg.wGate());
        b.tag("up");
        const u = try b.matmul(c.ws, y, wb + cfg.wUp());
        b.tag("silu");
        const act = try b.lookup(g, c.silu);
        b.tag("glu");
        const hm = try b.hadamard(act, u);
        b.tag("down");
        return b.matmulBits(c.ws, hm, wb + cfg.wDown(), null, cfg.residBits());
    }
    const A = cfg.actBits();
    b.tag("gate");
    const g = try b.matmulBits(c.ws, y, wb + cfg.wGate(), null, A);
    b.tag("up");
    const u = try b.matmulBits(c.ws, y, wb + cfg.wUp(), null, A);
    const n = b.infos.items[g].logSize();
    const half = @as(i64, 1) << (A - 1);
    const tab = b.xtables.items[c.silu_x.?].values;
    const av = try b.a.alloc(i32, b.wit.items[g].len);
    for (b.wit.items[g], av) |v, *o| o.* = tab[@intCast(v + half)];
    const info = b.infos.items[g];
    b.tag("silu");
    const act = try b.add(info, av);
    try b.key(n, try b.expr(&.{term(1, Ref.w(g), &.{ids(0, n)})}, half), try b.expr(&.{term(1, Ref.w(act), &.{ids(0, n)})}, 0), .{ .lookup = c.silu_x.? });
    // hadamard shift: chooseShiftSym(act * u, A) in record mode (the plan's
    // entry in replay), as model.chooseShift for the int8 core hadamard
    var sh: u5 = 0;
    if (!b.replaying()) {
        const acc = try b.a.alloc(i64, av.len);
        defer b.a.free(acc);
        for (av, b.wit.items[u], acc) |p, q, *o| o.* = @as(i64, p) * q;
        sh = chooseShiftSym(acc, A);
    }
    sh = try b.nextShift(sh);
    b.tag("glu");
    const hm = try b.einsumRequant(info, Ref.w(act), Ref.w(u), 0, &.{ids(0, n)}, &.{ids(0, n)}, sh, A);
    b.tag("down");
    return b.matmulBits(c.ws, hm, wb + cfg.wDown(), null, cfg.residBits());
}

pub const AttnBlockOut = struct { h: u32, attn: AttnOut, rms1: RmsOut, rms2: RmsOut, q: u32, qr: u32 };

/// First half of a decoder layer: h = x + Attn(RMSNorm(x)), and the MLP's
/// input RMSNorm(h) (rms2.y). Weights wb + wQ.. wb + wO.
pub fn attnBlock(b: *Builder, c: Ctx, layer: u32, wb: u32, x: u32, x_int8: bool) !AttnBlockOut {
    const cfg = c.cfg;
    const prev_scope = b.enter("rms1");
    defer b.scope = prev_scope;
    const r1 = try rmsnorm(b, c, x, c.gammas[2 * layer], x_int8);
    b.scope = "attn.proj";
    const y1 = r1.y;
    var q: u32 = undefined;
    var k: u32 = undefined;
    var v: u32 = undefined;
    var qf: [xt.MAXB]u8 = undefined;
    var kf: [xt.MAXB]u8 = undefined;
    var vf: [xt.MAXB]u8 = undefined;
    var qfix: []const u8 = &.{};
    var kfix: []const u8 = &.{};
    var vfix: []const u8 = &.{};
    if (cfg.fused_qkv) {
        // columns: Q [0, D), K [D, D + Dkv), V [D + Dkv, D + 2 Dkv)
        b.tag("qkv");
        const qkv = try b.matmulBits(c.ws, y1, wb + cfg.wQ(), null, cfg.actBits());
        const D = @as(usize, 1) << @intCast(cfg.log_d);
        const Dkv = @as(usize, 1) << @intCast(cfg.logDkv());
        const lq = cfg.qkvLogCols();
        qfix = sliceFix(&qf, lq, 0, cfg.log_d);
        kfix = sliceFix(&kf, lq, D, cfg.logDkv());
        vfix = sliceFix(&vf, lq, D + Dkv, cfg.logDkv());
        q = qkv;
        k = qkv;
        v = qkv;
    } else {
        b.tag("q");
        q = try b.matmulBits(c.ws, y1, wb + cfg.wQ(), null, cfg.actBits());
        b.tag("k");
        k = try b.matmulBits(c.ws, y1, wb + cfg.wK(), null, cfg.actBits());
        b.tag("v");
        v = try b.matmulBits(c.ws, y1, wb + cfg.wV(), null, cfg.actBits());
    }
    const qr = try rope(b, c, q, cfg.log_heads, qfix);
    const kr = try rope(b, c, k, cfg.log_kv_heads, kfix);
    const at = try attention(b, c, qr, kr, v, vfix);
    b.tag("wo");
    const ao = try b.matmulBits(c.ws, at.o, wb + cfg.wO(), null, cfg.residBits());
    b.scope = "residual";
    const h = try residual(b, x, ao);
    b.scope = "rms2";
    const r2 = try rmsnorm(b, c, h, c.gammas[2 * layer + 1], false);
    return .{ .h = h, .attn = at, .rms1 = r1, .rms2 = r2, .q = q, .qr = qr };
}

/// Stack of cfg.n_layers decoder layers on int8 input x [T, D].
/// The model input and the final output are bound to public tensors (P1):
/// b.io_in / b.io_out, lineqs witness == public.
pub fn buildStack(b: *Builder, c: Ctx, x_in: []const i32) !LayerOut {
    const n_in = c.cfg.log_t + c.cfg.log_d;
    const prev_scope = b.enter("input");
    b.tag("x");
    var x = try b.add(TensorInfo.mat(c.cfg.log_t, c.cfg.log_d), try b.a.dupe(i32, x_in));
    b.scope = prev_scope;
    b.io_in = try b.public(n_in, x_in);
    try b.lineq(n_in, try b.expr(&.{ term(1, Ref.w(x), &.{ids(0, n_in)}), term(-1, Ref.p(b.io_in.?), &.{ids(0, n_in)}) }, 0));
    var o: LayerOut = undefined;
    for (0..c.cfg.n_layers) |l| {
        b.cur_layer = @intCast(l);
        b.cur_moe = c.cfg.isMoe();
        defer b.cur_layer = null;
        o = try decoderLayer(b, c, @intCast(l), x, l == 0);
        x = o.out;
    }
    const n_out = b.infos.items[o.out].logSize();
    b.io_out = try b.public(n_out, b.wit.items[o.out]);
    try b.lineq(n_out, try b.expr(&.{ term(1, Ref.w(o.out), &.{ids(0, n_out)}), term(-1, Ref.p(b.io_out.?), &.{ids(0, n_out)}) }, 0));
    return o;
}

/// Public model definition (P2): layer shapes, the RMSNorm gammas (derived
/// from ctx_seed by initCtx) and every requant shift, in builder order. The
/// shifts are a model-definition decision, calibrated offline (`calibrate`)
/// and fixed for every input; tables (exp, silu, RoPE, mask) are functions
/// of the shapes. Its digest is mixed into the statement, and the verifier
/// rebuilds the statement from (ModelConfig, public input, claimed output)
/// with `statementFor`.
pub const ModelConfig = struct {
    cfg: LayerCfg,
    ctx_seed: u64,
    shifts: []const u5,

    pub fn digest(self: ModelConfig) [32]u8 {
        var h = std.crypto.hash.blake2.Blake2s256.init(.{});
        h.update("stwo-tensor-layer-config-v1");
        const c = self.cfg;
        const hdr = [_]u64{ c.log_t, c.log_d, c.log_f, c.log_heads, c.log_kv_heads, c.n_layers, c.log_experts, c.log_capacity, c.router_log_cols, @intFromBool(c.fused_qkv), LayerCfg.INV_BITS, self.ctx_seed, self.shifts.len };
        h.update(std.mem.sliceAsBytes(&hdr));
        if (c.score_bits != 8) h.update(std.mem.asBytes(&@as(u64, c.score_bits)));
        // widths: tagged, only when not the int8 default (pinned digests keep)
        if (c.act_bits != 8 or c.resid_bits != 8) {
            h.update("wide");
            h.update(std.mem.sliceAsBytes(&[_]u64{ c.act_bits, c.resid_bits }));
        }
        h.update(std.mem.sliceAsBytes(self.shifts));
        var out: [32]u8 = undefined;
        h.final(&out);
        return out;
    }
};

/// Calibration: records the builder's shift choices on `samples` (each
/// sample must replay under the result; shifts only grow). Caller frees
/// the returned shifts with `a`.
pub fn calibrate(a: std.mem.Allocator, pool: *f.Pool, ws: *const proto.WeightStore, cfg: LayerCfg, ctx_seed: u64, samples: []const []const i32) !ModelConfig {
    if (samples.len == 0) return error.CalibrationFailed;
    var plan: ?[]u5 = null;
    errdefer if (plan) |p| a.free(p);
    var round: usize = 0;
    while (round < 8) : (round += 1) {
        var all_ok = true;
        for (samples) |x| {
            if (plan) |p| {
                var b = Builder.init(a, pool);
                defer b.deinit();
                b.shift_plan = p;
                const c = try initCtx(&b, cfg, ws, ctx_seed);
                if (buildStack(&b, c, x)) |_| continue else |e| if (e != error.RequantOverflow) return e;
            }
            // record on this sample and widen the plan
            all_ok = false;
            var r = Builder.init(a, pool);
            defer r.deinit();
            const cr = try initCtx(&r, cfg, ws, ctx_seed);
            _ = try buildStack(&r, cr, x);
            const rec = r.shift_log.items;
            if (plan) |p| {
                if (p.len != rec.len) return error.ShiftPlan;
                for (p, rec) |*u, v| u.* = @max(u.*, v);
            } else plan = try a.dupe(u5, rec);
        }
        if (all_ok) return .{ .cfg = cfg, .ctx_seed = ctx_seed, .shifts = plan.? };
    }
    return error.CalibrationFailed;
}

/// Prover: the stack on x under the fixed model definition.
pub fn buildWith(b: *Builder, mc: ModelConfig, ws: *const proto.WeightStore, x_in: []const i32) !LayerOut {
    b.shift_plan = mc.shifts;
    b.shift_pos = 0;
    b.model_digest = mc.digest();
    const c = try initCtx(b, mc.cfg, ws, mc.ctx_seed);
    const o = try buildStack(b, c, x_in);
    if (b.shift_pos != mc.shifts.len) return error.ShiftPlan;
    return o;
}

/// Verifier: the statement of `mc` on public input x with claimed output y,
/// built without weights (shape-only builder on dummy values; the public
/// input / output tensors are then set to x and y). The returned builder
/// owns the statement (b.statement()).
pub fn statementFor(a: std.mem.Allocator, pool: *f.Pool, mc: ModelConfig, x: []const i32, y: []const i32) !Builder {
    const winfos = try layerWeightInfos(a, mc.cfg);
    defer a.free(winfos);
    // shapes only: matmul reads ws.infos, never the (absent) weights
    const offsets = [_]usize{};
    const ws = proto.WeightStore{ .infos = winfos, .offsets = @constCast(&offsets), .table = &.{}, .log_rows = 0, .log_cols = 0, .rows_used = 0, .com = undefined };
    var b = Builder.init(a, pool);
    errdefer b.deinit();
    b.shape_only = true;
    const n_in = @as(usize, 1) << @intCast(mc.cfg.log_t + mc.cfg.log_d);
    if (x.len != n_in) return error.StatementShape;
    const zeros = try a.alloc(i32, n_in);
    defer a.free(zeros);
    @memset(zeros, 0);
    _ = try buildWith(&b, mc, &ws, zeros);
    const pin = &b.publics.items[b.io_in.?];
    const pout = &b.publics.items[b.io_out.?];
    if (y.len != pout.values.len) return error.StatementShape;
    pin.values = try b.arena.allocator().dupe(i32, x);
    pout.values = try b.arena.allocator().dupe(i32, y);
    return b;
}

// ---------------------------------------------------------------------------
// Tests.

const testing = std.testing;

pub const TestSetup = struct {
    pool: f.Pool,
    ws: proto.WeightStore,
    wdata: [][]i8,
    winfos: []TensorInfo,
    pc: proto.Config,

    pub fn deinit(self: *TestSetup, a: std.mem.Allocator) void {
        self.ws.deinit(a);
        for (self.wdata) |w| a.free(w);
        a.free(self.wdata);
        a.free(self.winfos);
        self.pool.deinit();
    }
};

pub const WeightSetup = struct { ws: proto.WeightStore, wdata: [][]i8, winfos: []TensorInfo };

pub fn setupWeights(a: std.mem.Allocator, pool: *f.Pool, cfg: LayerCfg, pc: proto.Config, seed: u64) !WeightSetup {
    return setupWeightsWith(a, pool, cfg, pc, seed, false);
}

/// tie_router: copy router column 0 into column 1 (test: tied experts 0 / 1).
pub fn setupWeightsWith(a: std.mem.Allocator, pool: *f.Pool, cfg: LayerCfg, pc: proto.Config, seed: u64, tie_router: bool) !WeightSetup {
    const winfos = try layerWeightInfos(a, cfg);
    const wdata = try a.alloc([]i8, winfos.len);
    const wv = try a.alloc([]const i8, winfos.len);
    defer a.free(wv);
    for (wdata, 0..) |*w, i| {
        w.* = try model.randomWeights(a, winfos[i].size(), seed + i, -8, 7);
        wv[i] = w.*;
    }
    if (tie_router and cfg.isMoe()) {
        for (0..cfg.n_layers) |l| {
            const r = wdata[l * cfg.weightsPerLayer() + cfg.wRouter()];
            const ncol = @as(usize, 1) << @intCast(cfg.routerLogCols());
            for (0..r.len / ncol) |row| r[row * ncol + 1] = r[row * ncol];
        }
    }
    const ws = try proto.commitWeights(a, pool, pc, winfos, wv);
    return .{ .ws = ws, .wdata = wdata, .winfos = winfos };
}

fn testCfg() proto.Config {
    return .{ .pcs = .{ .log_blowup = 2, .n_queries = 12, .pow_bits = 1 }, .weight_log_cols = 4, .witness_log_cols_max = 8, .gkr_threads = 2 };
}

fn proveVerify(a: std.mem.Allocator, pool: *f.Pool, pc: proto.Config, b: *const Builder, ws: *const proto.WeightStore) !proto.Proof {
    const st = b.statement();
    const wv = try b.witnessView(a);
    defer a.free(wv);
    var tm: proto.Timings = .{};
    var proof = try proto.prove(a, pool, pc, st, ws, wv, &tm);
    errdefer proof.deinit(a);
    try proto.verify(a, pc, st, proto.weightKey(ws), &proof);
    return proof;
}

fn expectReject(a: std.mem.Allocator, pc: proto.Config, st: proto.Statement, ws: *const proto.WeightStore, proof: *const proto.Proof) !void {
    if (proto.verify(a, pc, st, proto.weightKey(ws), proof)) |_| {
        return error.TamperAccepted;
    } else |_| {}
}

test "decoder layer (GQA attention, RoPE, softmax, RMSNorm, SwiGLU) proves and verifies; tampering rejected" {
    const a = testing.allocator;
    var pool: f.Pool = undefined;
    try pool.init(a, 4);
    defer pool.deinit();
    const cfg = LayerCfg{ .log_t = 3, .log_d = 5, .log_f = 6, .log_heads = 2, .log_kv_heads = 1 };
    const pc = testCfg();
    var sw = try setupWeights(a, &pool, cfg, pc, 300);
    defer {
        sw.ws.deinit(a);
        for (sw.wdata) |w| a.free(w);
        a.free(sw.wdata);
        a.free(sw.winfos);
    }
    var b = Builder.init(a, &pool);
    defer b.deinit();
    const c = try initCtx(&b, cfg, &sw.ws, 1);
    const x = try model.randomInput(a, @as(usize, 1) << (cfg.log_t + cfg.log_d), 17);
    defer a.free(x);
    _ = try buildStack(&b, c, x);

    var proof = try proveVerify(a, &pool, pc, &b, &sw.ws);
    defer proof.deinit(a);
    const st = b.statement();
    // tamper each ext proof component
    {
        const sv = proof.ext.values[3];
        proof.ext.values[3] = sv.add(f.QM31.one());
        try expectReject(a, pc, st, &sw.ws, &proof);
        proof.ext.values[3] = sv;
    }
    {
        const last = proof.ext.values.len - 1;
        const sv = proof.ext.values[last];
        proof.ext.values[last] = sv.add(f.QM31.one());
        try expectReject(a, pc, st, &sw.ws, &proof);
        proof.ext.values[last] = sv;
    }
    for (0..proof.ext.finals.len) |i| {
        if (i % 3 != 0) continue;
        const sv = proof.ext.finals[i];
        proof.ext.finals[i][0] = sv[0].add(f.QM31.one());
        try expectReject(a, pc, st, &sw.ws, &proof);
        proof.ext.finals[i] = sv;
        proof.ext.finals[i][1] = sv[1].add(f.QM31.one());
        try expectReject(a, pc, st, &sw.ws, &proof);
        proof.ext.finals[i] = sv;
    }
    for (proof.ext.sumchecks) |*p| {
        if (p.rounds.len == 0) continue;
        const sv = p.rounds[0].evals[0];
        p.rounds[0].evals[0] = sv.add(f.QM31.one());
        try expectReject(a, pc, st, &sw.ws, &proof);
        p.rounds[0].evals[0] = sv;
    }
    // statement tamper: different mask bias / gamma / shift must be rejected
    {
        const pubs = try a.dupe(xt.Public, st.ext.publics);
        defer a.free(pubs);
        const nb = try a.dupe(i32, pubs[c.bias].values);
        defer a.free(nb);
        nb[1] = 0; // unmask (t=0, j=1)
        pubs[c.bias].values = nb;
        var st2 = st;
        st2.ext.publics = pubs;
        try expectReject(a, pc, st2, &sw.ws, &proof);
    }
    {
        const xops = try a.dupe(xt.Op, st.ext.ops);
        defer a.free(xops);
        for (xops) |*op| if (op.* == .einsum and op.einsum.shift > 0) {
            op.einsum.shift += 1;
            break;
        };
        var st2 = st;
        st2.ext.ops = xops;
        try expectReject(a, pc, st2, &sw.ws, &proof);
    }
    // malformed statement is rejected, not a crash
    {
        const xops = try a.dupe(xt.Op, st.ext.ops);
        defer a.free(xops);
        for (xops) |*op| if (op.* == .einsum) {
            op.einsum.a_labels[0] = 31;
            break;
        };
        var st2 = st;
        st2.ext.ops = xops;
        try expectReject(a, pc, st2, &sw.ws, &proof);
    }
    try proto.verify(a, pc, st, proto.weightKey(&sw.ws), &proof);
}

test "two-layer stack proves and verifies" {
    const a = testing.allocator;
    var pool: f.Pool = undefined;
    try pool.init(a, 4);
    defer pool.deinit();
    const cfg = LayerCfg{ .log_t = 2, .log_d = 4, .log_f = 5, .log_heads = 1, .log_kv_heads = 0, .n_layers = 2 };
    var pc = testCfg();
    pc.weight_log_cols = 3;
    var sw = try setupWeights(a, &pool, cfg, pc, 500);
    defer {
        sw.ws.deinit(a);
        for (sw.wdata) |w| a.free(w);
        a.free(sw.wdata);
        a.free(sw.winfos);
    }
    var b = Builder.init(a, &pool);
    defer b.deinit();
    const c = try initCtx(&b, cfg, &sw.ws, 2);
    const x = try model.randomInput(a, @as(usize, 1) << (cfg.log_t + cfg.log_d), 23);
    defer a.free(x);
    _ = try buildStack(&b, c, x);
    var proof = try proveVerify(a, &pool, pc, &b, &sw.ws);
    defer proof.deinit(a);
}

const SmallCfg = LayerCfg{ .log_t = 2, .log_d = 4, .log_f = 5, .log_heads = 2, .log_kv_heads = 1 };

const Fixture = struct {
    sw: WeightSetup,
    b: Builder,
    c: Ctx,
    out: LayerOut,

    fn init(a: std.mem.Allocator, pool: *f.Pool, cfg: LayerCfg, pc: proto.Config, seed: u64) !*Fixture {
        const fx = try a.create(Fixture);
        errdefer a.destroy(fx);
        fx.sw = try setupWeights(a, pool, cfg, pc, seed);
        fx.b = Builder.init(a, pool);
        fx.c = try initCtx(&fx.b, cfg, &fx.sw.ws, seed + 1);
        const x = try model.randomInput(a, @as(usize, 1) << @intCast(cfg.log_t + cfg.log_d), seed + 2);
        defer a.free(x);
        fx.out = try buildStack(&fx.b, fx.c, x);
        return fx;
    }

    fn deinit(fx: *Fixture, a: std.mem.Allocator) void {
        fx.b.deinit();
        fx.sw.ws.deinit(a);
        for (fx.sw.wdata) |w| a.free(w);
        a.free(fx.sw.wdata);
        a.free(fx.sw.winfos);
        a.destroy(fx);
    }
};

test "decoder layer witness matches a direct integer reference (RoPE, GQA scores, causal softmax, PV, RMSNorm)" {
    const a = testing.allocator;
    var pool: f.Pool = undefined;
    try pool.init(a, 2);
    defer pool.deinit();
    const cfg = LayerCfg{ .log_t = 3, .log_d = 5, .log_f = 6, .log_heads = 2, .log_kv_heads = 1 };
    var pc = testCfg();
    pc.weight_log_cols = 4;
    const fx = try Fixture.init(a, &pool, cfg, pc, 40);
    defer fx.deinit(a);
    const b = &fx.b;
    const at = fx.out.attn;
    const T = @as(usize, 1) << @intCast(cfg.log_t);
    const H = @as(usize, 1) << @intCast(cfg.log_heads);
    const G = @as(usize, 1) << @intCast(cfg.log_heads - cfg.log_kv_heads);
    const dh = @as(usize, 1) << @intCast(cfg.logDh());
    const D = H * dh;
    const Dkv = D / G;
    const rt = try ropeTable(a, cfg.log_t, cfg.logDh());
    defer a.free(rt);
    // RoPE on q: qr[t, h, 2i + bo] = rq(sum_bi q[t, h, 2i + bi] R[t, i, bo, bi], 7)
    const q = b.wit.items[fx.out.q];
    const qr = b.wit.items[fx.out.qr];
    for (0..T) |t| for (0..H) |h| for (0..dh / 2) |i| for (0..2) |bo| {
        var s: i64 = 0;
        for (0..2) |bi| s += @as(i64, q[t * D + h * dh + 2 * i + bi]) * rt[((t * dh / 2 + i) * 2 + bo) * 2 + bi];
        try testing.expectEqual(rq(s, 7), qr[t * D + h * dh + 2 * i + bo]);
    };
    // scores with GQA: kv head = h / G (MSB part of the head index)
    var sops: ?xt.Einsum = null;
    for (b.xops.items) |op| if (op == .einsum and op.einsum.y != null and op.einsum.y.? == at.scores) {
        sops = op.einsum;
    };
    const kr_id = sops.?.b.id;
    const kr = b.wit.items[kr_id];
    const S = b.wit.items[at.scores];
    for (0..H) |h| for (0..T) |t| for (0..T) |j| {
        var s: i64 = 0;
        for (0..dh) |e| s += @as(i64, qr[t * D + h * dh + e]) * kr[j * Dkv + (h / G) * dh + e];
        try testing.expectEqual(rq(s, sops.?.shift), S[(h * T + t) * T + j]);
    };
    // causal softmax-PV: o[t, h, c] = round(sum_j e v / sum_j e), exact
    // division (normalised up to one rounding per output)
    var oops: ?xt.Einsum = null;
    for (b.xops.items) |op| if (op == .einsum and op.einsum.y != null and op.einsum.y.? == at.acc) {
        oops = op.einsum;
    };
    const V = b.wit.items[oops.?.b.id];
    const O = b.wit.items[at.o];
    const et = expTable();
    for (0..H) |h| for (0..T) |t| {
        var mx: i64 = std.math.minInt(i64);
        for (0..t + 1) |j| mx = @max(mx, S[(h * T + t) * T + j]);
        var den: i64 = 0;
        for (0..t + 1) |j| den += et[@intCast(mx - S[(h * T + t) * T + j])];
        try testing.expectEqual(den, b.wit.items[at.den][h * T + t]);
        for (0..dh) |e| {
            var s: i64 = 0;
            for (0..t + 1) |j| s += @as(i64, et[@intCast(mx - S[(h * T + t) * T + j])]) * V[j * Dkv + (h / G) * dh + e];
            const o = O[t * D + h * dh + e];
            try testing.expectEqual(@divFloor(2 * s + den, 2 * den), o);
            // |o - s / den| <= 1/2
            try testing.expect(@abs(2 * (@as(i64, o) * den - s)) <= den);
        }
    };
    // RMSNorm: rt = isqrt((ss + 2^s1) 2^m1 / 2^s1), inv = 2^15 / rt
    const r1 = fx.out.rms1;
    const xs = b.wit.items[r1.xs];
    for (0..T) |t| {
        var ss: i64 = 0;
        for (0..D) |d| ss += @as(i64, xs[t * D + d]) * xs[t * D + d];
        try testing.expectEqual(ss, b.wit.items[r1.ss][t]);
        const rtv: i64 = b.wit.items[r1.rt][t];
        const N = (ss + 1) * 8; // ld = 5: s1 = 0, m1 = 3
        try testing.expect(rtv * rtv <= N and (rtv + 1) * (rtv + 1) > N);
        try testing.expectEqual(@divFloor(@as(i64, 1 << 15), rtv), b.wit.items[r1.inv][t]);
    }
}

const Cheat = enum { sel_nonbinary, acc_plus_one, sel_moved, m_lowered, m_raised, rt_plus_one, residual, exp_value, masked_exp, score, ss_value };

/// Factored-selector cheats (log_t >= FACTORED_SEL_MIN_LOG_T).
const FCheat = enum { m_lowered, m_raised, a_not_one_hot, b_two_hot, a_moved, ps_forged };

/// log_t = 4: the factored argmax selector (ljh = ljl = 2).
const FactCfg = LayerCfg{ .log_t = 4, .log_d = 4, .log_f = 5, .log_heads = 1, .log_kv_heads = 0 };

/// Lower m of `row` to the (masked) score at some j2 < max, keeping m = z1 + z2
/// attained at j2 (z1, z2 consistent) and e recomputed wherever the new D is
/// in the exp domain: only the exp key at the true argmax (D < 0) can fail.
fn lowerMax(b: *Builder, at: AttnOut, c: Ctx, row: usize) !usize {
    const T = @as(usize, 1) << @intCast(c.cfg.log_t);
    const t = row % T;
    const bias = b.vals(Ref.p(c.bias));
    const S = b.wit.items[at.scores];
    const m = b.wit.items[at.m];
    var jlow: ?usize = null;
    for (0..T) |j| if (S[row * T + j] + bias[t * T + j] < m[row]) {
        jlow = j;
    };
    const j2 = jlow orelse return error.NoLowerScore;
    const nm = S[row * T + j2] + bias[t * T + j2];
    m[row] = nm;
    b.wit.items[at.z1][row] = S[row * T + j2];
    b.wit.items[at.z2][row] = bias[t * T + j2];
    const et = b.xtables.items[c.exp_table].values;
    for (0..T) |j| {
        const d = nm - S[row * T + j] - bias[t * T + j];
        if (d >= 0 and d < et.len) b.wit.items[at.e][row * T + j] = et[@intCast(d)];
    }
    return j2;
}

fn cheatCase(a: std.mem.Allocator, cheat: Cheat) !void {
    var pool: f.Pool = undefined;
    try pool.init(a, 2);
    defer pool.deinit();
    var pc = testCfg();
    pc.weight_log_cols = 3;
    const fx = try Fixture.init(a, &pool, SmallCfg, pc, 77);
    defer fx.deinit(a);
    const b = &fx.b;
    const at = fx.out.attn;
    const T = @as(usize, 1) << @intCast(SmallCfg.log_t);
    const bias = b.vals(Ref.p(fx.c.bias));
    const S = b.wit.items[at.scores];
    const sel = b.wit.items[at.sel.?];
    const m = b.wit.items[at.m];
    const row = T - 1; // head 0, last token: all positions unmasked
    var jstar: usize = 0;
    for (0..T) |j| if (sel[row * T + j] == 1) {
        jstar = j;
    };
    // a position whose masked score is strictly below the max
    var jlow: ?usize = null;
    for (0..T) |j| if (S[row * T + j] + bias[(T - 1) * T + j] < m[row]) {
        jlow = j;
    };
    switch (cheat) {
        .sel_moved => {
            sel[row * T + jstar] = 0;
            sel[row * T + jlow.?] = 1;
        },
        .m_lowered => {
            // claim the max is a smaller score, attained (sel, z1, z2) consistently
            const j2 = try lowerMax(b, at, fx.c, row);
            sel[row * T + jstar] = 0;
            sel[row * T + j2] = 1;
        },
        .m_raised => {
            // m above every score: D >= 1 everywhere (in the exp domain), not attained
            m[row] += 1;
            const et = b.xtables.items[fx.c.exp_table].values;
            for (0..T) |j| b.wit.items[at.e][row * T + j] = et[@intCast(m[row] - S[row * T + j] - bias[(T - 1) * T + j])];
        },
        .acc_plus_one => b.wit.items[at.acc][0] += 1,
        .sel_nonbinary => {
            // non-binary selector that keeps sum_j sel = 1
            sel[row * T + jstar] = 2;
            sel[row * T + jlow.?] = -1;
        },
        .rt_plus_one => {
            const r = fx.out.rms1;
            b.wit.items[r.rt][0] += 1;
        },
        .residual => b.wit.items[fx.out.h][0] += 1,
        .exp_value => b.wit.items[at.e][row * T + jstar] -= 1,
        .masked_exp => b.wit.items[at.e][1] = 3, // (t = 0, j = 1) is masked
        .score => S[row * T] += 1,
        .ss_value => b.wit.items[fx.out.rms2.ss][0] += 1,
    }
    xt.test_unchecked_prover = true;
    defer xt.test_unchecked_prover = false;
    const st = b.statement();
    const wv = try b.witnessView(a);
    defer a.free(wv);
    var tm: proto.Timings = .{};
    var proof = try proto.prove(a, &pool, pc, st, &fx.sw.ws, wv, &tm);
    defer proof.deinit(a);
    try expectReject(a, pc, st, &fx.sw.ws, &proof);
}

test "verifier rejects invalid attention / softmax / RMSNorm / residual witnesses (unchecked prover)" {
    inline for (@typeInfo(Cheat).@"enum".fields) |fld| {
        cheatCase(testing.allocator, @enumFromInt(fld.value)) catch |err| {
            std.debug.print("cheat case {s} failed: {}\n", .{ fld.name, err });
            return err;
        };
    }
}

fn fcheatCase(a: std.mem.Allocator, cheat: FCheat) !void {
    var pool: f.Pool = undefined;
    try pool.init(a, 2);
    defer pool.deinit();
    var pc = testCfg();
    pc.weight_log_cols = 3;
    const fx = try Fixture.init(a, &pool, FactCfg, pc, 78);
    defer fx.deinit(a);
    const b = &fx.b;
    const at = fx.out.attn;
    try testing.expect(at.sel == null);
    const T = @as(usize, 1) << @intCast(FactCfg.log_t);
    const ljl = FactCfg.log_t / 2;
    const Tl = @as(usize, 1) << @intCast(ljl);
    const Th = T / Tl;
    const A = b.wit.items[at.sel_a.?];
    const B = b.wit.items[at.sel_b.?];
    const row = T - 1; // head 0, last token: all positions unmasked
    var jh: usize = 0;
    var jl: usize = 0;
    for (0..Th) |x| if (A[row * Th + x] == 1) {
        jh = x;
    };
    for (0..Tl) |x| if (B[row * Tl + x] == 1) {
        jl = x;
    };
    // the honest selector is the first argmax split into bits
    const S = b.wit.items[at.scores];
    try testing.expectEqual(S[row * T + jh * Tl + jl], b.wit.items[at.z1][row]);
    switch (cheat) {
        .m_lowered => {
            // m lowered to S(j2) and attained by A (x) B at j2, with PS, PB,
            // z1, z2 recomputed consistently: only the virtual-D exp key at
            // the true argmax (D < 0) can fail
            const j2 = try lowerMax(b, at, fx.c, row);
            const bias = b.vals(Ref.p(fx.c.bias));
            const h2 = j2 / Tl;
            const l2 = j2 % Tl;
            A[row * Th + jh] = 0;
            A[row * Th + h2] = 1;
            B[row * Tl + jl] = 0;
            B[row * Tl + l2] = 1;
            for (0..Th) |x| {
                b.wit.items[at.ps.?][row * Th + x] = S[row * T + x * Tl + l2];
                b.wit.items[at.pb.?][row * Th + x] = bias[(T - 1) * T + x * Tl + l2];
            }
        },
        .a_moved => {
            // A moved to another jh, z1 / z2 following PS / PB there; m kept:
            // the attained value differs from m (no tie at this seed)
            const o = (jh + 1) % Th;
            A[row * Th + jh] = 0;
            A[row * Th + o] = 1;
            b.wit.items[at.z1][row] = b.wit.items[at.ps.?][row * Th + o];
            b.wit.items[at.z2][row] = b.wit.items[at.pb.?][row * Th + o];
            try testing.expect(b.wit.items[at.z1][row] + b.wit.items[at.z2][row] != b.wit.items[at.m][row]);
        },
        .m_raised => {
            b.wit.items[at.m][row] += 1;
            const bias = b.vals(Ref.p(fx.c.bias));
            const et = b.xtables.items[fx.c.exp_table].values;
            for (0..T) |j| b.wit.items[at.e][row * T + j] = et[@intCast(b.wit.items[at.m][row] - S[row * T + j] - bias[(T - 1) * T + j])];
        },
        .a_not_one_hot => {
            // non-binary A keeping sum_jh A = 1
            const o = (jh + 1) % Th;
            A[row * Th + jh] = 2;
            A[row * Th + o] = -1;
        },
        .b_two_hot => B[row * Tl + (jl + 1) % Tl] = 1,
        .ps_forged => b.wit.items[at.ps.?][row * Th + jh] += 1,
    }
    xt.test_unchecked_prover = true;
    defer xt.test_unchecked_prover = false;
    const st = b.statement();
    const wv = try b.witnessView(a);
    defer a.free(wv);
    var tm: proto.Timings = .{};
    var proof = try proto.prove(a, &pool, pc, st, &fx.sw.ws, wv, &tm);
    defer proof.deinit(a);
    try expectReject(a, pc, st, &fx.sw.ws, &proof);
}

test "verifier rejects forged factored argmax selectors / virtual-D maxima (unchecked prover)" {
    inline for (@typeInfo(FCheat).@"enum".fields) |fld| {
        fcheatCase(testing.allocator, @enumFromInt(fld.value)) catch |err| {
            std.debug.print("factored cheat case {s} failed: {}\n", .{ fld.name, err });
            return err;
        };
    }
}

test "honest prover refuses invalid witnesses" {
    const a = testing.allocator;
    var pool: f.Pool = undefined;
    try pool.init(a, 2);
    defer pool.deinit();
    var pc = testCfg();
    pc.weight_log_cols = 3;
    const fx = try Fixture.init(a, &pool, SmallCfg, pc, 91);
    defer fx.deinit(a);
    fx.b.wit.items[fx.out.h][0] += 1;
    const wv = try fx.b.witnessView(a);
    defer a.free(wv);
    var tm: proto.Timings = .{};
    try testing.expectError(error.LinEqViolated, proto.prove(a, &pool, pc, fx.b.statement(), &fx.sw.ws, wv, &tm));
}

const MoeCfg = LayerCfg{ .log_t = 3, .log_d = 4, .log_f = 5, .log_heads = 1, .log_kv_heads = 0, .log_experts = 2, .log_capacity = 3, .router_log_cols = 3 };

fn moePc() proto.Config {
    var pc = testCfg();
    pc.weight_log_cols = 3;
    return pc;
}

fn buildMoeFixture(a: std.mem.Allocator, pool: *f.Pool, seed: u64, tie: bool, last_argmax: bool) !*Fixture {
    const fx = try a.create(Fixture);
    errdefer a.destroy(fx);
    fx.sw = try setupWeightsWith(a, pool, MoeCfg, moePc(), seed, tie);
    fx.b = Builder.init(a, pool);
    fx.c = try initCtx(&fx.b, MoeCfg, &fx.sw.ws, seed + 1);
    fx.c.test_last_argmax = last_argmax;
    const x = try model.randomInput(a, @as(usize, 1) << @intCast(MoeCfg.log_t + MoeCfg.log_d), seed + 2);
    defer a.free(x);
    fx.out = try buildStack(&fx.b, fx.c, x);
    return fx;
}

test "MoE top-1 layer: routing / dispatch / combine match reference; proves and verifies" {
    const a = testing.allocator;
    var pool: f.Pool = undefined;
    try pool.init(a, 2);
    defer pool.deinit();
    const fx = try buildMoeFixture(a, &pool, 600, false, false);
    defer fx.deinit(a);
    const b = &fx.b;
    const mo = fx.out.moe.?;
    const T = 8;
    const E = 4;
    const C = 8;
    const D = 16;
    const ncol = 8;
    const lg = b.wit.items[mo.logits];
    var used = [_]usize{0} ** E;
    for (0..T) |t| {
        // first argmax over the real experts
        var best: i32 = std.math.minInt(i32);
        var arg: usize = 0;
        for (0..E) |x| if (lg[t * ncol + x] > best) {
            best = lg[t * ncol + x];
            arg = x;
        };
        try testing.expectEqual(arg, mo.expert_of[t]);
        used[arg] += 1;
        for (0..D) |d| {
            try testing.expectEqual(b.wit.items[mo.mo][(arg * C + mo.slot_of[t]) * D + d], b.wit.items[mo.out][t * D + d]);
        }
    }
    var proof = try proveVerify(a, &pool, moePc(), b, &fx.sw.ws);
    defer proof.deinit(a);
}

const MoeCheat = enum { wrong_expert, drop_token, dup_slot, combine_out, last_argmax_tie };

fn moeCheatCase(a: std.mem.Allocator, cheat: MoeCheat) !void {
    var pool: f.Pool = undefined;
    try pool.init(a, 2);
    defer pool.deinit();
    const tie = cheat == .last_argmax_tie;
    const fx = try buildMoeFixture(a, &pool, 610, tie, tie);
    defer fx.deinit(a);
    const b = &fx.b;
    const mo = fx.out.moe.?;
    const T = 8;
    const E = 4;
    const C = 8;
    switch (cheat) {
        .wrong_expert => {
            // token 0 to another expert in sel only
            const x = mo.expert_of[0];
            b.wit.items[mo.sel][x] = 0;
            b.wit.items[mo.sel][(x + 1) % E] = 1;
        },
        .drop_token => {
            const x = mo.expert_of[0];
            b.wit.items[mo.disp][(x * C + mo.slot_of[0]) * T + 0] = 0;
        },
        .dup_slot => {
            // token 1 also written into token 0's slot (different expert ok)
            const x = mo.expert_of[0];
            b.wit.items[mo.disp][(x * C + mo.slot_of[0]) * T + 1] = 1;
        },
        .combine_out => b.wit.items[mo.out][3] += 1,
        .last_argmax_tie => {
            // the witness is fully consistent with last-maximiser routing;
            // only the first-argmax constraint (Dr - pre >= 0) is violated
            var differs = false;
            for (0..T) |t| {
                const lg = b.wit.items[mo.logits];
                if (lg[t * 8] == lg[t * 8 + 1] and mo.expert_of[t] == 1) {
                    var best: i32 = std.math.minInt(i32);
                    for (0..E) |x| best = @max(best, lg[t * 8 + x]);
                    if (best == lg[t * 8]) differs = true;
                }
            }
            try testing.expect(differs);
        },
    }
    xt.test_unchecked_prover = true;
    defer xt.test_unchecked_prover = false;
    const st = b.statement();
    const wv = try b.witnessView(a);
    defer a.free(wv);
    var tm: proto.Timings = .{};
    var proof = try proto.prove(a, &pool, moePc(), st, &fx.sw.ws, wv, &tm);
    defer proof.deinit(a);
    try expectReject(a, moePc(), st, &fx.sw.ws, &proof);
}

test "MoE: verifier rejects wrong routing, dropped / duplicated tokens, combine tamper, last-argmax ties" {
    inline for (@typeInfo(MoeCheat).@"enum".fields) |fld| {
        moeCheatCase(testing.allocator, @enumFromInt(fld.value)) catch |err| {
            std.debug.print("moe cheat case {s} failed: {}\n", .{ fld.name, err });
            return err;
        };
    }
}

test "MoE with tied router columns: first-argmax routing verifies" {
    const a = testing.allocator;
    var pool: f.Pool = undefined;
    try pool.init(a, 2);
    defer pool.deinit();
    const fx = try buildMoeFixture(a, &pool, 610, true, false);
    defer fx.deinit(a);
    var proof = try proveVerify(a, &pool, moePc(), &fx.b, &fx.sw.ws);
    defer proof.deinit(a);
}

test "fused QKV projection (fixed-bit slices) proves and verifies; RoPE reads the right slice" {
    const a = testing.allocator;
    var pool: f.Pool = undefined;
    try pool.init(a, 2);
    defer pool.deinit();
    inline for (.{ @as(u32, 1), @as(u32, 2) }) |lkv| { // GQA (2 Dkv < D) and MHA (3 D -> 4 D)
        const cfg = LayerCfg{ .log_t = 3, .log_d = 4, .log_f = 5, .log_heads = 2, .log_kv_heads = lkv, .fused_qkv = true };
        var pc = testCfg();
        pc.weight_log_cols = 4; // = log_d: no longer capped by logDkv
        const fx = try a.create(Fixture);
        defer a.destroy(fx);
        fx.sw = try setupWeights(a, &pool, cfg, pc, 700);
        fx.b = Builder.init(a, &pool);
        fx.c = try initCtx(&fx.b, cfg, &fx.sw.ws, 701);
        const x = try model.randomInput(a, @as(usize, 1) << @intCast(cfg.log_t + cfg.log_d), 702);
        defer a.free(x);
        fx.out = try buildStack(&fx.b, fx.c, x);
        defer {
            fx.b.deinit();
            fx.sw.ws.deinit(a);
            for (fx.sw.wdata) |w| a.free(w);
            a.free(fx.sw.wdata);
            a.free(fx.sw.winfos);
        }
        // q = qkv[:, 0:D] fed RoPE: compare against the direct rotation
        const T = 8;
        const D = 16;
        const dh = 4;
        const W = @as(usize, 1) << @intCast(cfg.qkvLogCols());
        const qkv = fx.b.wit.items[fx.out.q];
        const qr = fx.b.wit.items[fx.out.qr];
        const rt = try ropeTable(a, cfg.log_t, cfg.logDh());
        defer a.free(rt);
        for (0..T) |t| for (0..D / 2) |hi| for (0..2) |bo| {
            const h = hi / (dh / 2);
            const i = hi % (dh / 2);
            var sum: i64 = 0;
            for (0..2) |bi| sum += @as(i64, qkv[t * W + h * dh + 2 * i + bi]) * rt[((t * dh / 2 + i) * 2 + bo) * 2 + bi];
            try testing.expectEqual(rq(sum, 7), qr[t * D + h * dh + 2 * i + bo]);
        };
        var proof = try proveVerify(a, &pool, pc, &fx.b, &fx.sw.ws);
        proof.deinit(a);
    }
}

// ---------------------------------------------------------------------------
// Golden proof digests of a decoder layer (stream `speed`): recorded on the
// unmodified prover (base 61ba1ce6c + the Builder.add aliasing fix). Every
// prover optimisation must reproduce these bytes. The shapes reach the GEMM
// einsum accumulator (score and PV contractions of 2^4 terms), the split-eq
// einsum sumcheck (selector zero-checks, one-hot argmax einsums) and the
// split-eq MLE evaluations.
//
// Repinned (codex/tensor-wv-attn-virtual-d-sel): commit 1 attn/d removed
// (the exp key takes m - S - Bias as a virtual input; m = z1 + z2 attained
// by one-hot einsums, m range-keyed): flat 8424c4b6..., pcs2_moe 79360fbd...;
// commit 2 attn/sel -> 2 sqrt(T) one-hots A (x) B at log_t >=
// FACTORED_SEL_MIN_LOG_T (this shape: log_t = 4): the pins below. Before
// both: flat 837b19ac..., pcs2_moe 0d99b4e3....

const GOLDEN_LAYER_FLAT = "a2bcc5c766a04bf0d67cd9916f261cb298c11297312fe2d39126ceefbb414584";
const GOLDEN_LAYER_PCS2_MOE = "4dd2827981e3781644d05607975ff6a5f7eb3e40bc0f68b4ec5c81a72e9cd795";

fn layerDigest(cfg: LayerCfg, pc_in: proto.Config, threads: usize) ![32]u8 {
    return layerDigestOpt(cfg, pc_in, threads, false);
}

/// keep: prove from the forward pass's kept accumulators.
fn layerDigestOpt(cfg: LayerCfg, pc_in: proto.Config, threads: usize, keep: bool) ![32]u8 {
    const a = testing.allocator;
    var pool: f.Pool = undefined;
    try pool.init(a, threads);
    defer pool.deinit();
    var pc = pc_in;
    pc.gkr_threads = threads;
    const fx = try a.create(Fixture);
    defer a.destroy(fx);
    fx.sw = try setupWeights(a, &pool, cfg, pc, 4242);
    defer {
        fx.sw.ws.deinit(a);
        for (fx.sw.wdata) |w| a.free(w);
        a.free(fx.sw.wdata);
        a.free(fx.sw.winfos);
    }
    fx.b = Builder.init(a, &pool);
    defer fx.b.deinit();
    fx.b.keep_accs = keep;
    fx.c = try initCtx(&fx.b, cfg, &fx.sw.ws, 4242 + 1);
    const x = try model.randomInput(a, @as(usize, 1) << @intCast(cfg.log_t + cfg.log_d), 4242 + 2);
    defer a.free(x);
    fx.out = try buildStack(&fx.b, fx.c, x);
    const st = fx.b.statement();
    const wv = try fx.b.witnessView(a);
    defer a.free(wv);
    var tm: proto.Timings = .{};
    var proof = if (keep)
        try proto.proveWithAllAccumulators(a, &pool, pc, st, &fx.sw.ws, wv, fx.b.coreAccs(), fx.b.extAccs(), &tm)
    else
        try proto.prove(a, &pool, pc, st, &fx.sw.ws, wv, &tm);
    defer proof.deinit(a);
    try proto.verify(a, pc, st, proto.weightKey(&fx.sw.ws), &proof);
    return @import("digest.zig").fullDigest(proof);
}

fn checkGolden(name: []const u8, golden: []const u8, d: [32]u8) !void {
    const hx = std.fmt.bytesToHex(d, .lower);
    if (golden.len == 0) {
        std.debug.print("GOLDEN {s} = {s}\n", .{ name, hx });
        return;
    }
    try testing.expectEqualStrings(golden, &hx);
}

test "golden decoder layer digests (flat; pcs2 + batched matmuls + MoE), 1 vs 5 threads" {
    // QM31 digests; the -Dchallenge=om31 build pins none (sec128_test.zig)
    if (f.IS_OM31) return error.SkipZigTest;
    const cfg = LayerCfg{ .log_t = 4, .log_d = 6, .log_f = 7, .log_heads = 2, .log_kv_heads = 1, .fused_qkv = true };
    var pc = testCfg();
    pc.weight_log_cols = 6;
    const d1 = try layerDigest(cfg, pc, 1);
    try checkGolden("flat", GOLDEN_LAYER_FLAT, d1);
    try testing.expectEqualSlices(u8, &d1, &(try layerDigest(cfg, pc, 5)));
    // forward-pass accumulators (core + ext) give the same proof
    try testing.expectEqualSlices(u8, &d1, &(try layerDigestOpt(cfg, pc, 5, true)));
    // GKR key inputs allocated and faulted at the GKR stage (no prefault): same proof
    var pc_np = pc;
    pc_np.prefault_gkr_inputs = false;
    try testing.expectEqualSlices(u8, &d1, &(try layerDigest(cfg, pc_np, 5)));
    // GKR layer blocks warmed (allocated, touched, freed) during the commitment: same proof
    var pc_w = pc;
    pc_w.warm_gkr_layers = true;
    try testing.expectEqualSlices(u8, &d1, &(try layerDigest(cfg, pc_w, 5)));

    var cfg2 = cfg;
    cfg2.log_experts = 1;
    cfg2.log_capacity = 4;
    cfg2.router_log_cols = 6;
    var pc2 = testCfg();
    pc2.weight_log_cols = 6;
    pc2.batch_matmuls = true;
    pc2.two_level = .{ .outer = pc2.pcs, .depth = 2, .inner = .{ .log_blowup = 2, .n_queries = 12, .pow_bits = 1 } };
    const d2 = try layerDigest(cfg2, pc2, 1);
    try checkGolden("pcs2_moe", GOLDEN_LAYER_PCS2_MOE, d2);
    try testing.expectEqualSlices(u8, &d2, &(try layerDigest(cfg2, pc2, 5)));
    try testing.expectEqualSlices(u8, &d2, &(try layerDigestOpt(cfg2, pc2, 1, true)));
    var pc2_np = pc2;
    pc2_np.prefault_gkr_inputs = false;
    try testing.expectEqualSlices(u8, &d2, &(try layerDigest(cfg2, pc2_np, 5)));
    pc2_np.warm_gkr_layers = true;
    try testing.expectEqualSlices(u8, &d2, &(try layerDigest(cfg2, pc2_np, 1)));
}

test "forward-pass ext accumulators are untrusted: wrong values refused or rejected, bad shapes refused" {
    const a = testing.allocator;
    var pool: f.Pool = undefined;
    try pool.init(a, 2);
    defer pool.deinit();
    const cfg = LayerCfg{ .log_t = 3, .log_d = 5, .log_f = 6, .log_heads = 2, .log_kv_heads = 1, .fused_qkv = true };
    var pc = testCfg();
    pc.weight_log_cols = 5;
    var sw = try setupWeights(a, &pool, cfg, pc, 77);
    defer {
        sw.ws.deinit(a);
        for (sw.wdata) |w| a.free(w);
        a.free(sw.wdata);
        a.free(sw.winfos);
    }
    var b = Builder.init(a, &pool);
    defer b.deinit();
    b.keep_accs = true;
    const c = try initCtx(&b, cfg, &sw.ws, 78);
    const x = try model.randomInput(a, @as(usize, 1) << (cfg.log_t + cfg.log_d), 79);
    defer a.free(x);
    _ = try buildStack(&b, c, x);
    const st = b.statement();
    const wv = try b.witnessView(a);
    defer a.free(wv);
    var tm: proto.Timings = .{};
    // an off-by-one accumulator entry of every requant einsum (one at a time):
    // the remainder leaves its range (refused) or the einsum sumcheck fails
    var n_tested: usize = 0;
    for (b.ext_accs.items) |slot| if (slot) |v| {
        v[3] += 1;
        defer v[3] -= 1;
        n_tested += 1;
        if (proto.proveWithAllAccumulators(a, &pool, pc, st, &sw.ws, wv, b.coreAccs(), b.extAccs(), &tm)) |proof_c| {
            var proof = proof_c;
            defer proof.deinit(a);
            if (proto.verify(a, pc, st, proto.weightKey(&sw.ws), &proof)) |_| return error.WrongAccumulatorAccepted else |_| {}
        } else |_| {}
    };
    try testing.expect(n_tested >= 5);
    // a remainder kept in range by a consistent shift of 2^s: still rejected
    for (b.ext_accs.items, st.ext.ops) |slot, op| if (slot) |v| {
        const sh = op.einsum.shift;
        // pick an index whose remainder stays in range after +1
        const y = wv[op.einsum.y.?];
        var j: usize = 0;
        while (j < v.len) : (j += 1) {
            const r = v[j] + (@as(i64, 1) << (sh - 1)) - (@as(i64, y[j]) << sh);
            if (r + 1 < (@as(i64, 1) << sh)) break;
        }
        if (j == v.len) continue;
        v[j] += 1;
        defer v[j] -= 1;
        var proof = try proto.proveWithAllAccumulators(a, &pool, pc, st, &sw.ws, wv, b.coreAccs(), b.extAccs(), &tm);
        defer proof.deinit(a);
        if (proto.verify(a, pc, st, proto.weightKey(&sw.ws), &proof)) |_| return error.WrongAccumulatorAccepted else |_| {}
        break;
    };
    // wrong lengths are refused
    const short = try a.alloc(?[]const i64, st.ext.ops.len - 1);
    defer a.free(short);
    for (short, 0..) |*o, i| o.* = b.extAccs()[i];
    try testing.expectError(error.AccumulatorShape, proto.proveWithAllAccumulators(a, &pool, pc, st, &sw.ws, wv, b.coreAccs(), short, &tm));
    const ea = try a.dupe(?[]const i64, b.extAccs());
    defer a.free(ea);
    for (ea) |*o| if (o.*) |v| {
        o.* = v[0 .. v.len / 2];
        break;
    };
    try testing.expectError(error.AccumulatorShape, proto.proveWithAllAccumulators(a, &pool, pc, st, &sw.ws, wv, b.coreAccs(), ea, &tm));
}
