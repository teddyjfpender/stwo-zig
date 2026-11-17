//! Seed execution owner: bounded host fill, cap authentication and statement binding.
const std = @import("std");
const Enc = @import("outer_encode.zig");
const Schema = @import("outer_seed_device.zig");
fn reject(check: u16, detail: anytype) u32 {
    return (@as(u32, check) << 16) | @intFromEnum(detail);
}
const seed_check: u16 = 0x0305;
const bind_check: u16 = 0x0306;

/// Seed fill: `out` = n_seeds records of 5 words {var, limb0..3}; `scratch`
/// = P.scratch_words. Child k's region is `children[k]` (length word, wire
/// words, then the image at C.image). Returns the seed_tape verdict; the
/// records are all written only when it accepts.
pub fn fillHost(program: Schema.Program, children: []const []const u32, scratch_in: []u32, out: []u32) u32 {
    const w = program.words;
    if (w.len < Schema.P.header_words or scratch_in.len < w[Schema.P.scratch_words]) return reject(seed_check, Schema.SeedDetail.program);
    const scratch = scratch_in[0..w[Schema.P.scratch_words]];
    if (w.len < Schema.P.header_words or w[Schema.P.magic] != Schema.program_magic or w[Schema.P.version] != Schema.program_version or w[Schema.P.words] != w.len or children.len != w[Schema.P.n_children] or out.len < 5 * @as(usize, w[Schema.P.n_seeds]) or scratch.len < w[Schema.P.scratch_words]) return reject(seed_check, Schema.SeedDetail.program);
    var worst: u16 = 0xffff;
    const rank = struct {
        fn note(worst_: *u16, d: Schema.SeedDetail) void {
            worst_.* = @min(worst_.*, @intFromEnum(d));
        }
    };
    // Region / image geometry and header.
    for (children, 0..) |region, k| {
        const e = program.child(k);
        if (region.len < @as(usize, e[Schema.C.image]) + e[Schema.C.image_words] or region[0] == 0) {
            rank.note(&worst, .region);
            continue;
        }
        const img = region[e[Schema.C.image]..][0..e[Schema.C.image_words]];
        if (img[0] != Schema.image_magic or img[1] != 2) rank.note(&worst, .image_header);
    }
    if (worst != 0xffff) return (@as(u32, seed_check) << 16) | worst;
    // Caps.
    for (program.caps()) |c| {
        const e = program.child(c.child);
        const img = children[c.child][e[Schema.C.image]..][0..e[Schema.C.image_words]];
        const n_cap = @as(usize, 1) << @intCast(c.cl);
        var known: [64]bool = @splat(false);
        const cap = scratch[c.scratch..][0 .. n_cap * 8];
        var bad = false;
        for (0..c.nq) |qi| {
            const q = img[c.queries + qi];
            if (c.kind == 0 and q >= (@as(u32, 1) << @intCast(c.from_log))) {
                rank.note(&worst, .query_range);
                bad = true;
                continue;
            }
            var node: Schema.Hash = undefined;
            var pos: u32 = undefined;
            if (c.kind == 0) {
                var row: [Enc.max_columns]u32 = undefined;
                for (0..c.width) |ci| {
                    const v = img[c.values + ci * c.nq + qi];
                    if (v >= Schema.modulus) rank.note(&worst, .noncanonical);
                    row[ci] = v;
                }
                node = Schema.leafHash(row[0..c.width]);
                pos = Schema.position(q, c.from_log, c.to_log);
            } else {
                node = groupRoot(img[c.values + qi * c.width * 8 ..][0 .. c.width * 8], c.pack != 0, c.to_log, &worst);
                pos = (q >> @intCast(c.from_log)) >> @intCast(c.to_log);
            }
            const walk = c.height - c.cl;
            const path = img[c.paths + qi * c.path_stride ..];
            for (0..walk) |level| {
                const sib = path[level * 8 ..][0..8].*;
                node = if ((pos >> @intCast(level)) & 1 == 1) Schema.nodeHash(sib, node) else Schema.nodeHash(node, sib);
            }
            if (c.cl == 0) {
                if (!std.mem.eql(u32, &node, img[c.root..][0..8])) rank.note(&worst, .cap_root);
                continue;
            }
            const at: usize = pos >> @intCast(walk);
            if (at >= n_cap) {
                rank.note(&worst, .query_range);
                bad = true;
                continue;
            }
            const pairs = [2]struct { i: usize, h: Schema.Hash }{ .{ .i = at, .h = node }, .{ .i = at ^ 1, .h = path[walk * 8 ..][0..8].* } };
            for (pairs) |p| {
                if (known[p.i]) {
                    if (!std.mem.eql(u32, cap[p.i * 8 ..][0..8], &p.h)) rank.note(&worst, .cap_mismatch);
                } else {
                    @memcpy(cap[p.i * 8 ..][0..8], &p.h);
                    known[p.i] = true;
                }
            }
        }
        if (bad or c.cl == 0) continue;
        for (known[0..n_cap]) |k| if (!k) rank.note(&worst, .cap_uncovered);
        var layer: [64]Schema.Hash = undefined;
        for (0..n_cap) |i| layer[i] = cap[i * 8 ..][0..8].*;
        var n = n_cap;
        while (n > 1) {
            n /= 2;
            for (0..n) |i| layer[i] = Schema.nodeHash(layer[2 * i], layer[2 * i + 1]);
        }
        if (!std.mem.eql(u32, &layer[0], img[c.root..][0..8])) rank.note(&worst, .cap_root);
    }
    // Gather.
    const n_const = w[Schema.P.n_constants];
    const vars = w[w[Schema.P.vars]..][0..w[Schema.P.n_seeds]];
    for (0..n_const) |i| {
        out[5 * i] = vars[i];
        @memcpy(out[5 * i + 1 ..][0..4], w[w[Schema.P.constants] + 4 * i ..][0..4]);
    }
    for (program.ops()) |o| {
        const kind: Schema.Kind = @enumFromInt(o.kind);
        const src: []const u32 = switch (@as(Schema.Area, @enumFromInt(o.area))) {
            .region => children[o.child],
            .image => blk: {
                const e = program.child(o.child);
                break :blk children[o.child][e[Schema.C.image]..][0..e[Schema.C.image_words]];
            },
            .scratch => scratch,
        };
        var d: usize = o.dst;
        for (0..o.rows) |r| for (0..o.count) |u| {
            const s = o.offset + r * o.row_stride + u * o.stride;
            const n_src = Schema.Op.wordsPerUnit(kind);
            if (s + n_src > src.len) {
                rank.note(&worst, .program);
                return (@as(u32, seed_check) << 16) | worst;
            }
            const x = src[s..][0..n_src];
            switch (kind) {
                .hash => for (x) |v| {
                    put(out, vars, d, .{ v & 0xffff, 0, 0, 0 });
                    put(out, vars, d + 1, .{ v >> 16, 0, 0, 0 });
                    d += 2;
                },
                .word => {
                    put(out, vars, d, .{ x[0] & 0xffff, 0, 0, 0 });
                    put(out, vars, d + 1, .{ x[0] >> 16, 0, 0, 0 });
                    d += 2;
                },
                .m31 => {
                    if (x[0] >= Schema.modulus) rank.note(&worst, .noncanonical);
                    put(out, vars, d, .{ x[0], 0, 0, 0 });
                    d += 1;
                },
                .om31 => {
                    for (x) |v| if (v >= Schema.modulus) rank.note(&worst, .noncanonical);
                    put(out, vars, d, x[0..4].*);
                    put(out, vars, d + 1, x[4..8].*);
                    d += 2;
                },
                .q => {
                    for (x) |v| if (v >= Schema.modulus) rank.note(&worst, .noncanonical);
                    put(out, vars, d, x[0..4].*);
                    d += 1;
                },
            }
        };
    }
    return if (worst == 0xffff) 0 else (@as(u32, seed_check) << 16) | worst;
}
fn put(out: []u32, vars: []const u32, i: usize, v: [4]u32) void {
    out[5 * i] = vars[i];
    @memcpy(out[5 * i + 1 ..][0..4], &v);
}
/// proof.zig friGroupRoot: packed leaves of 4 OM31 (when `pack`), then the
/// in-coset node levels up to the coset's group root.
fn groupRoot(values: []const u32, pack: bool, step: u32, worst: *u16) Schema.Hash {
    for (values) |v| if (v >= Schema.modulus) {
        worst.* = @min(worst.*, @intFromEnum(Schema.SeedDetail.noncanonical));
    };
    const width: usize = if (pack) 4 else 1;
    const n_leaves = (values.len / 8) / width;
    var level: [16]Schema.Hash = undefined;
    for (0..n_leaves) |i| level[i] = Schema.leafHash(values[i * width * 8 ..][0 .. width * 8]);
    const nfolds = step - (if (pack) @as(u32, 2) else 0);
    var n = n_leaves;
    for (0..nfolds) |_| {
        n /= 2;
        for (0..n) |i| level[i] = Schema.nodeHash(level[2 * i], level[2 * i + 1]);
    }
    return level[0];
}

/// Fold statement mirror: the node's outputs (4 words each) and its
/// transcript checkpoint (9 words) from the children's regions; returns the
/// child_binding verdict.
pub fn statementHost(program: Schema.Program, children: []const []const u32, outputs: []u32, checkpoint: *[9]u32) u32 {
    const w = program.words;
    const kind = w[Schema.P.statement];
    if (kind != 1 and kind != 2) return reject(bind_check, Schema.BindDetail.region);
    var worst: u16 = 0xffff;
    const n_self = w[Schema.P.n_outputs];
    if (outputs.len < 4 * @as(usize, n_self)) return reject(bind_check, Schema.BindDetail.region);
    if (kind == 2) {
        const r = children[0];
        const at = w[Schema.P.outputs_at];
        if (r.len < @as(usize, at) + 4 * n_self) return reject(bind_check, Schema.BindDetail.region);
        for (r[at..][0 .. 4 * n_self]) |v| if (v >= Schema.modulus) {
            worst = @min(worst, @intFromEnum(Schema.BindDetail.noncanonical));
        };
        @memcpy(outputs[0 .. 4 * n_self], r[at..][0 .. 4 * n_self]);
    } else {
        var msg: std.ArrayListUnmanaged(u32) = .empty;
        const a = std.heap.page_allocator;
        defer msg.deinit(a);
        msg.appendSlice(a, &.{ w[Schema.P.domain], w[Schema.P.version_word] }) catch return reject(bind_check, Schema.BindDetail.region);
        const profile = w[w[Schema.P.profile]..][0..8];
        for (children, 0..) |region, k| {
            const e = program.child(k);
            const n_out = e[Schema.C.n_outputs];
            if (region.len < @as(usize, e[Schema.C.image]) + e[Schema.C.image_words] or region[0] < 4 * (19 + 4 * n_out) or e[Schema.C.image] < 20 + 4 * n_out) {
                worst = @min(worst, @intFromEnum(Schema.BindDetail.region));
                continue;
            }
            if (region[1] != Schema.wire_magic[0] or region[2] != Schema.wire_magic[1]) worst = @min(worst, @intFromEnum(Schema.BindDetail.magic));
            if (!std.mem.eql(u32, region[3..11], profile)) worst = @min(worst, @intFromEnum(Schema.BindDetail.profile));
            if (!std.mem.eql(u32, region[11..19], e[Schema.C.identity..][0..8])) worst = @min(worst, @intFromEnum(Schema.BindDetail.identity));
            if (region[19] != n_out) worst = @min(worst, @intFromEnum(Schema.BindDetail.outputs));
            const img = region[e[Schema.C.image]..];
            const roots_at: usize = 14 + 1 + 16;
            if (!std.mem.eql(u32, img[roots_at..][0..8], e[Schema.C.fixed_root..][0..8])) worst = @min(worst, @intFromEnum(Schema.BindDetail.fixed_root));
            for (region[20..][0 .. 4 * n_out]) |v| if (v >= Schema.modulus) {
                worst = @min(worst, @intFromEnum(Schema.BindDetail.noncanonical));
            };
            msg.appendSlice(a, region[11..19]) catch {};
            msg.appendSlice(a, img[roots_at..][0..8]) catch {};
            msg.append(a, n_out) catch {};
            msg.appendSlice(a, region[20..][0 .. 4 * n_out]) catch {};
        }
        const digest = Schema.blakeWords(&.{msg.items});
        for (0..n_self) |i| {
            const v = if (i < 8) digest[i] else 0;
            outputs[4 * i ..][0..4].* = .{ v & 0xffff, v >> 16, 0, 0 };
        }
    }
    const self_key = w[w[Schema.P.self_key]..][0..16];
    var head: [9]u32 = undefined;
    @memcpy(head[0..8], self_key[0..8]);
    head[8] = n_self;
    const d1 = Schema.blakeWords(&.{ w[w[Schema.P.prefix]..][0..8], &head, outputs[0 .. 4 * n_self] });
    const d2 = Schema.blakeWords(&.{ &d1, self_key[8..16] });
    @memcpy(checkpoint[0..8], &d2);
    checkpoint[8] = 0;
    return if (worst == 0xffff) 0 else (@as(u32, bind_check) << 16) | worst;
}

// ---------------------------------------------------------------------------
// Recorded real data (outer_seed_record.zig) for the piece harness
// ---------------------------------------------------------------------------
