//! Statement-level magnitude analysis (verifier side, no witness).
//!
//! The protocol proves field identities. They mean integer identities only
//! when no product or sum can wrap mod p, so `validateStatement` (here)
//! derives, from the public statement alone, a bound
//!
//!     bound[t] = b   =>   every entry of witness tensor t, as the signed
//!                         representative in (-p/2, p/2), has |t[i]| <= 2^b
//!
//! from proved relations, and rejects any statement in which an operand of
//! a multiplication or a term of a range / lookup / linear relation is not
//! bounded or can wrap. See design/tensor-frontend/transformer.md, section 4
//! ("Statement-level bounds").
//!
//! Bound sources (each a theorem about any accepted witness):
//! * core matmul / hadamard / glu outputs, lookup in/out, range8: int8 (7);
//! * ext requant einsum: Y + 2^(ob-1) in [0, 2^ob)  ->  ob - 1;
//! * ext key whose input (or output) is a single +-1 term over plain,
//!   pairwise-distinct variable labels covering every bit of the tensor
//!   (no SUM, no FIX: every entry is checked): the table's range;
//! * boolean selector: exact einsum y = y (.) y with identity labels: y in
//!   {0, 1} (0);
//! * exact einsum y = sum_k a b with bounded operands: ba + bb + n_k, or bb
//!   alone when a is boolean and one-hot over the contracted bits (at most one
//!   nonzero term), and symmetrically;
//! * lineq: a term with coefficient +-1 whose tensor appears nowhere else in
//!   the expression is solved for; plain labels bound the whole tensor, FIX
//!   labels bound a slice, and slices covering the tensor bound it.
//! One-hot facts come from `sum_S a = 1` and `sum_S a = s` (s boolean)
//! lineqs over boolean a, including nesting (sum_c a = s with s one-hot over x
//! makes a one-hot over (c, x)).
//!
//! Bounds are derived to a fixpoint (each derivation uses bounds already
//! established, so the result is sound by induction), then every check runs
//! on the final bounds. Unknown is 255; derived bounds above 30 are dropped.
const std = @import("std");
const proto = @import("protocol.zig");
const xt = @import("ext.zig");

const Statement = proto.Statement;
const UNB: u8 = 255;
const P: u128 = (1 << 31) - 1;
/// largest bound of an exact einsum output / zero-check: |y| <= 2^29 < p / 2
pub const EXACT_MAX_BITS = 29;
/// largest accumulator bound of a requant einsum (and shift + out_bits <= 30)
pub const REQUANT_MAX_BITS = 29;
const MAX_TENSORS = 4096;
const MAX_PUBLICS = 1024;
const MAX_SLICES = 4096;
const MAX_ONEHOT = 1024;

fn log2Ceil(m: u128) u8 {
    if (m <= 1) return 0;
    return @intCast(128 - @clz(m - 1));
}

fn checkInfo(t: proto.TensorInfo) !void {
    if (t.n_dims > proto.MAX_DIMS) return error.StatementShape;
    var s: u32 = 0;
    for (t.log_dims[0..t.n_dims]) |d| {
        if (d > xt.MAXB) return error.StatementShape;
        s += d;
    }
    if (s > xt.MAXB) return error.StatementShape;
}

const Slice = struct { t: u32, mask: u32, val: u32, b: u8 };
const OneHot = struct { t: u32, mask: u32 };

const State = struct {
    st: Statement,
    bound: []u8,
    boolean: []bool,
    pub_bound: []const u8,
    slices: [MAX_SLICES]Slice = undefined,
    n_slices: usize = 0,
    onehot: [MAX_ONEHOT]OneHot = undefined,
    n_onehot: usize = 0,
    changed: bool = false,

    fn setb(self: *State, t: u32, v: u8) void {
        if (v > 30) return;
        if (t < self.bound.len and v < self.bound[t]) {
            self.bound[t] = v;
            self.changed = true;
        }
    }

    fn refBound(self: *const State, r: xt.Ref) u8 {
        return if (r.public) self.pub_bound[r.id] else self.bound[r.id];
    }

    fn addOneHot(self: *State, t: u32, mask: u32) void {
        if (mask == 0) return;
        for (self.onehot[0..self.n_onehot]) |o| if (o.t == t and o.mask & mask == mask) return;
        if (self.n_onehot == MAX_ONEHOT) return; // fail closed: fact not recorded
        self.onehot[self.n_onehot] = .{ .t = t, .mask = mask };
        self.n_onehot += 1;
        self.changed = true;
    }

    fn isOneHotOver(self: *const State, t: u32, mask: u32) bool {
        for (self.onehot[0..self.n_onehot]) |o| if (o.t == t and o.mask & mask == mask) return true;
        return false;
    }
};

/// Bit positions (MSB-first index p -> bit 1 << p) of an operand.
fn posBit(p: usize) u32 {
    return @as(u32, 1) << @intCast(p);
}

/// Labels of a term over nb bits are plain, pairwise-distinct variables (no
/// SUM, no FIX): every entry of the tensor is reached.
fn plainCover(lab: xt.Labels, nb: u32) bool {
    var seen: u64 = 0;
    for (lab[0..nb]) |l| {
        if (l >= xt.MAXB) return false; // SUM / FIX / NONE
        const bit = @as(u64, 1) << @intCast(l);
        if (seen & bit != 0) return false;
        seen |= bit;
    }
    return true;
}

fn nSum(lab: xt.Labels, nb: u32) u32 {
    var n: u32 = 0;
    for (lab[0..nb]) |l| n += @intFromBool(l == xt.SUM);
    return n;
}

/// |sum of terms except `skip`| + |constant|, or null if a term is unbounded.
fn exprMagnitude(s: *const State, e: xt.Expr, skip: ?usize) ?u128 {
    var tot: u128 = @abs(e.constant);
    for (e.terms, 0..) |t, i| {
        if (skip != null and skip.? == i) continue;
        const b = s.refBound(t.t);
        if (b == UNB) return null;
        const nb = bits(s.st, t.t);
        const sh: u32 = @as(u32, b) + nSum(t.labels, nb);
        if (sh > 64) return std.math.maxInt(u128);
        tot +|= @as(u128, @abs(t.coeff)) << @intCast(sh);
    }
    return tot;
}

fn bits(st: Statement, r: xt.Ref) u32 {
    return if (r.public) st.ext.publics[r.id].log_size else st.witness[r.id].logSize();
}

/// Single +-1 witness term over plain labels covering all its bits.
fn coveringTerm(st: Statement, e: xt.Expr) ?xt.Term {
    if (e.terms.len != 1) return null;
    const t = e.terms[0];
    if (t.t.public or (t.coeff != 1 and t.coeff != -1)) return null;
    if (!plainCover(t.labels, st.witness[t.t.id].logSize())) return null;
    return t;
}

fn tableMaxAbs(st: Statement, id: u32) u128 {
    var m: u128 = 0;
    for (st.ext.tables[id].values) |v| m = @max(m, @abs(v));
    return m;
}

fn tableDomain(st: Statement, tr: xt.TableRef) u128 {
    return switch (tr) {
        .range => |b| @as(u128, 1) << b,
        .lookup => |id| @as(u128, 1) << st.ext.tables[id].log_size,
    };
}

/// Boolean structural rule: y = y (.) y with identity labels over all bits.
fn isBooleanEinsum(st: Statement, e: xt.Einsum) bool {
    const y = e.y orelse return false;
    if (e.a.public or e.b.public or e.a.id != y or e.b.id != y or e.n_k != 0) return false;
    const nb = st.witness[y].logSize();
    if (e.n_out != nb) return false;
    for (0..nb) |p| if (e.a_labels[p] != p or e.b_labels[p] != p) return false;
    return true;
}

/// Mask of an operand's bit positions driven by contracted variables.
fn contractedMask(lab: xt.Labels, nb: u32, n_out: u8) u32 {
    var m: u32 = 0;
    for (lab[0..nb], 0..) |l, p| if (l < xt.MAXB and l >= n_out) {
        m |= posBit(p);
    };
    return m;
}

fn einsumBound(s: *const State, e: xt.Einsum) ?u8 {
    const ba = s.refBound(e.a);
    const bb = s.refBound(e.b);
    // one-hot selector: at most one nonzero term per output
    if (!e.a.public and s.boolean[e.a.id] and bb != UNB) {
        const cm = contractedMask(e.a_labels, bits(s.st, e.a), e.n_out);
        if (cm == 0 or s.isOneHotOver(e.a.id, cm)) return bb;
    }
    if (!e.b.public and s.boolean[e.b.id] and ba != UNB) {
        const cm = contractedMask(e.b_labels, bits(s.st, e.b), e.n_out);
        if (cm == 0 or s.isOneHotOver(e.b.id, cm)) return ba;
    }
    if (ba == UNB or bb == UNB) return null;
    return @intCast(@min(254, @as(u32, ba) + bb + e.n_k));
}

fn deriveLineq(s: *State, l: xt.LinEq) void {
    const st = s.st;
    // solve for a +-1 term whose tensor appears once
    for (l.expr.terms, 0..) |t, i| {
        if (t.t.public or (t.coeff != 1 and t.coeff != -1)) continue;
        var once = true;
        for (l.expr.terms, 0..) |u, j| if (j != i and !u.t.public and u.t.id == t.t.id) {
            once = false;
        };
        if (!once) continue;
        const nb = st.witness[t.t.id].logSize();
        // plain + FIX labels (no SUM), plain ones pairwise distinct
        var fmask: u32 = 0;
        var fval: u32 = 0;
        var seen: u64 = 0;
        var ok = true;
        for (t.labels[0..nb], 0..) |lb, p| {
            if (lb == xt.SUM) {
                ok = false;
            } else if (xt.isFix(lb)) {
                fmask |= posBit(p);
                if (lb == xt.FIX1) fval |= posBit(p);
            } else {
                const bit = @as(u64, 1) << @intCast(lb);
                if (seen & bit != 0) ok = false;
                seen |= bit;
            }
        }
        if (!ok) continue;
        const m = exprMagnitude(s, l.expr, i) orelse continue;
        const b = log2Ceil(m);
        if (fmask == 0) {
            s.setb(t.t.id, b);
        } else if (b <= 30) {
            var dup = false;
            for (s.slices[0..s.n_slices]) |*x| if (x.t == t.t.id and x.mask == fmask and x.val == fval) {
                dup = true;
                if (b < x.b) x.b = b;
            };
            if (!dup and s.n_slices < MAX_SLICES) {
                s.slices[s.n_slices] = .{ .t = t.t.id, .mask = fmask, .val = fval, .b = b };
                s.n_slices += 1;
            }
        }
    }
    // one-hot facts: sum_S a = 1, or sum_S a - s = 0 with s boolean (and nested)
    const terms = l.expr.terms;
    for (terms, 0..) |t, i| {
        if (t.t.public or !s.boolean[t.t.id]) continue;
        const nb = st.witness[t.t.id].logSize();
        var smask: u32 = 0;
        var ok = true;
        var seen: u64 = 0;
        for (t.labels[0..nb], 0..) |lb, p| {
            if (lb == xt.SUM) {
                smask |= posBit(p);
            } else if (xt.isFix(lb) or lb >= xt.MAXB) {
                ok = false;
            } else {
                const bit = @as(u64, 1) << @intCast(lb);
                if (seen & bit != 0) ok = false;
                seen |= bit;
            }
        }
        if (!ok or smask == 0) continue;
        if (terms.len == 1 and (t.coeff == 1 or t.coeff == -1) and l.expr.constant == -t.coeff) {
            s.addOneHot(t.t.id, smask);
        } else if (terms.len == 2 and l.expr.constant == 0) {
            const o = terms[1 - i];
            if (o.t.public or !s.boolean[o.t.id] or o.coeff != -t.coeff) continue;
            const ob = st.witness[o.t.id].logSize();
            if (!plainCover(o.labels, ob)) continue;
            s.addOneHot(t.t.id, smask);
            // nesting: s one-hot over M' (s positions) -> a one-hot over smask + map(M')
            var k: usize = 0;
            while (k < s.n_onehot) : (k += 1) {
                const oh = s.onehot[k];
                if (oh.t != o.t.id) continue;
                var mm = smask;
                var all = true;
                for (0..ob) |q| if (oh.mask & posBit(q) != 0) {
                    const v = o.labels[q];
                    var found = false;
                    for (t.labels[0..nb], 0..) |lb, p| if (lb == v) {
                        mm |= posBit(p);
                        found = true;
                    };
                    if (!found) all = false;
                };
                if (all) s.addOneHot(t.t.id, mm);
            }
        }
    }
}

/// Slices with the same FIX mask that cover a tensor bound it.
fn applySlices(s: *State) void {
    for (s.slices[0..s.n_slices], 0..) |x, i| {
        var first = true;
        for (s.slices[0..i]) |y| if (y.t == x.t and y.mask == x.mask) {
            first = false;
        };
        if (!first) continue;
        var count: usize = 0;
        var mx: u8 = 0;
        for (s.slices[i..s.n_slices]) |y| if (y.t == x.t and y.mask == x.mask) {
            count += 1;
            mx = @max(mx, y.b);
        };
        if (count == @as(usize, 1) << @intCast(@popCount(x.mask))) s.setb(x.t, mx);
    }
}

fn exprCheck(s: *const State, e: xt.Expr, slack: u128) !void {
    const m = exprMagnitude(s, e, null) orelse return error.StatementUnboundedOperand;
    if (m +| slack >= P) return error.StatementAccumulatorBound;
}

pub fn validateStatement(st: Statement) !void {
    const n = st.witness.len;
    if (n > MAX_TENSORS or st.ext.publics.len > MAX_PUBLICS) return error.StatementTooLarge;
    // shape pass first: nothing below indexes an unchecked id (PROTO-4)
    for (st.witness) |t| try checkInfo(t);
    for (st.weights) |t| {
        try checkInfo(t);
        if (t.n_dims != 2) return error.StatementShape;
    }
    for (st.ops) |op| switch (op) {
        .matmul => |m| {
            if (m.x >= n or m.y >= n or m.w >= st.weights.len) return error.StatementShape;
            if (m.shift < 1 or m.shift > 22) return error.StatementShift;
            const xi = st.witness[m.x];
            const wi = st.weights[m.w];
            if (xi.n_dims != 2) return error.StatementShape;
            if (xi.log_dims[1] != wi.log_dims[0]) return error.StatementShape;
            if (st.witness[m.y].logSize() != xi.log_dims[0] + wi.log_dims[1]) return error.StatementShape;
        },
        .hadamard => |h| {
            if (h.a >= n or h.b >= n or h.y >= n) return error.StatementShape;
            if (h.shift < 1 or h.shift > 22) return error.StatementShift;
            const ls = st.witness[h.y].logSize();
            if (st.witness[h.a].logSize() != ls or st.witness[h.b].logSize() != ls) return error.StatementShape;
        },
        .lookup => |l| {
            if (l.in >= n or l.out >= n or l.table >= st.tables.len) return error.StatementShape;
            if (st.witness[l.in].logSize() != st.witness[l.out].logSize()) return error.StatementShape;
        },
        .range8 => |r| if (r.in >= n) return error.StatementShape,
        .product => |q| if (q.a >= n or q.b >= n or q.c >= n) return error.StatementShape,
        .glu => |g| {
            if (g.g >= n or g.u >= n or g.h >= n or g.table >= st.tables.len) return error.StatementShape;
            if (g.shift < 1 or g.shift > 22) return error.StatementShift;
            const ls = st.witness[g.h].logSize();
            if (st.witness[g.g].logSize() != ls or st.witness[g.u].logSize() != ls) return error.StatementShape;
        },
    };
    try xt.validate(st); // ext ids, labels, tables

    var bound_buf: [MAX_TENSORS]u8 = undefined;
    var bool_buf: [MAX_TENSORS]bool = undefined;
    var pub_buf: [MAX_PUBLICS]u8 = undefined;
    for (st.ext.publics, 0..) |p, i| {
        var m: u128 = 0;
        for (p.values) |v| m = @max(m, @abs(v));
        pub_buf[i] = log2Ceil(m);
    }
    var s: State = .{ .st = st, .bound = bound_buf[0..n], .boolean = bool_buf[0..n], .pub_bound = pub_buf[0..st.ext.publics.len] };
    @memset(s.bound, UNB);
    @memset(s.boolean, false);
    for (st.ops) |op| switch (op) {
        .matmul => |m| s.setb(m.y, 7),
        .hadamard => |h| s.setb(h.y, 7),
        .lookup => |l| {
            s.setb(l.out, 7);
            s.setb(l.in, 7); // table domain is int8
        },
        .range8 => |r| s.setb(r.in, 7),
        .product => {},
        .glu => |g| {
            s.setb(g.h, 7);
            s.setb(g.g, 7);
            s.setb(g.u, 7);
        },
    };
    for (st.ext.ops) |op| switch (op) {
        .einsum => |e| if (isBooleanEinsum(st, e)) {
            s.boolean[e.y.?] = true;
            s.setb(e.y.?, 0);
        } else if (e.shift > 0) {
            s.setb(e.y.?, e.out_bits - 1);
        },
        .key => |k| {
            const dom = tableDomain(st, k.table);
            if (coveringTerm(st, k.input)) |t| {
                // coeff * T + c in [0, dom)  =>  |T| <= max(|c|, |dom - 1 - c|)
                const c: i128 = k.input.constant;
                const hi: i128 = @as(i128, @intCast(dom)) - 1 - c;
                s.setb(t.t.id, log2Ceil(@max(@abs(c), @abs(hi))));
            }
            if (k.output) |o| if (coveringTerm(st, o)) |t| {
                s.setb(t.t.id, log2Ceil(tableMaxAbs(st, k.table.lookup) + @abs(o.constant)));
            };
        },
        .lineq => {},
    };
    // fixpoint over the relations that depend on other bounds
    var iters: usize = 0;
    while (true) : (iters += 1) {
        s.changed = false;
        s.n_slices = 0;
        for (st.ext.ops) |op| switch (op) {
            .einsum => |e| if (e.shift == 0 and e.y != null and !isBooleanEinsum(st, e)) {
                if (einsumBound(&s, e)) |b| if (b <= EXACT_MAX_BITS) s.setb(e.y.?, b);
            },
            .lineq => |l| deriveLineq(&s, l),
            .key => {},
        };
        applySlices(&s);
        if (!s.changed or iters > st.ext.ops.len + 2) break;
    }

    // checks on the final bounds
    for (st.ops) |op| switch (op) {
        .matmul => |m| {
            // |acc| <= 2^(bx + 7 + logK) <= 2^30 (weights int8 by the key proof):
            // the requant remainder identity is an integer identity
            if (s.bound[m.x] == UNB) return error.StatementUnboundedOperand;
            if (@as(u32, s.bound[m.x]) + 7 + st.witness[m.x].log_dims[1] > 30) return error.StatementAccumulatorBound;
        },
        .hadamard => |h| {
            if (s.bound[h.a] == UNB or s.bound[h.b] == UNB) return error.StatementUnboundedOperand;
            if (@as(u32, s.bound[h.a]) + s.bound[h.b] > 30) return error.StatementAccumulatorBound;
        },
        else => {},
    };
    for (st.ext.ops) |op| switch (op) {
        .einsum => |e| {
            if (isBooleanEinsum(st, e)) continue; // a field identity: y in {0, 1}
            const b = einsumBound(&s, e) orelse return error.StatementUnboundedOperand;
            if (e.shift > 0) {
                if (b > REQUANT_MAX_BITS or @as(u32, e.shift) + e.out_bits > 30) return error.StatementAccumulatorBound;
            } else if (b > EXACT_MAX_BITS) return error.StatementAccumulatorBound;
        },
        .key => |k| {
            const dom = tableDomain(st, k.table);
            if (coveringTerm(st, k.input) == null) try exprCheck(&s, k.input, dom);
            if (k.output) |o| if (coveringTerm(st, o) == null) try exprCheck(&s, o, tableMaxAbs(st, k.table.lookup));
        },
        .lineq => |l| {
            // all terms bounded: the field identity must be an integer identity
            if (exprMagnitude(&s, l.expr, null)) |m| if (m >= P) return error.StatementAccumulatorBound;
        },
    };
}

