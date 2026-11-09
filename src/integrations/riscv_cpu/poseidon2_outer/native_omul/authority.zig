//! Explicit R6 six-component source authority. R5 construction stays separate.
const std = @import("std");
const Core = @import("stwo_core");
const Circuit = @import("stwo_circuit_frontend");
const A = @import("../authority.zig");
const C = @import("../context.zig");
const L = @import("../layout.zig");
const P2Row = @import("../row.zig");
const R = @import("row.zig");
const OldAir = @import("stwo_circuit_cpu_integration").air;
const OldProve = @import("stwo_circuit_cpu_integration").om31.prove;
const M = A.M;
pub const FIXED_START = A.FIXED_COUNT;
pub const MAIN_START = A.MAIN_COUNT;
pub const INTER_START = A.INTER_COUNT;
pub const FIXED_COUNT = FIXED_START + R.FIXED;
pub const MAIN_COUNT = MAIN_START + R.MAIN;
pub const INTER_COUNT = INTER_START + R.INTER;
const OLD_SLOTS = A.OLD_SLOTS;
const NEW_SLOTS = A.NEW_SLOTS;
const FIXED_BASE = A.FIXED_START;
const MAIN_BASE = A.MAIN_START;
const INTER_BASE = A.INTER_START;
pub fn columns(a: std.mem.Allocator, tree: usize, logs: [5]u32, mul_log: u32) !A.Columns {
    const total: usize = switch (tree) {
        0 => FIXED_COUNT,
        1 => MAIN_COUNT,
        2 => INTER_COUNT,
        else => return error.InvalidR6Tree,
    };
    const values = try a.alloc(A.Col, total);
    var made: usize = 0;
    errdefer {
        for (values[0..made]) |column| a.free(column.values);
        a.free(values);
    }
    for (logs, L.FACTS) |log, fact| {
        const width: usize = switch (tree) {
            0 => fact.fixed,
            1 => fact.main,
            2 => fact.classic_interaction,
            else => unreachable,
        };
        for (0..width) |_| {
            const data = try a.alloc(M, @as(usize, 1) << @intCast(log));
            @memset(data, M.zero());
            values[made] = .{ .log_size = log, .values = data };
            made += 1;
        }
    }
    const width: usize = switch (tree) {
        0 => R.FIXED,
        1 => R.MAIN,
        2 => R.INTER,
        else => unreachable,
    };
    for (0..width) |_| {
        const data = try a.alloc(M, @as(usize, 1) << @intCast(mul_log));
        @memset(data, M.zero());
        values[made] = .{ .log_size = mul_log, .values = data };
        made += 1;
    }
    return .{ .allocator = a, .values = values };
}
pub const Key = struct {
    base: A.Authority,
    mul_log: u32,
    mul_rows: usize,
    mul_raw: usize,
    pub fn deinit(self: *Key) void {
        self.base.deinit();
        self.* = undefined;
    }
    pub fn init(a: std.mem.Allocator, ctx: *const C.Context, profile: A.Profile) !Key {
        if (!ctx.finalized or ctx.poisoned or ctx.usage == null or ctx.mixed_census_only) return error.PoseidonContextNotFinalized;
        var counts = try ctx.sourceMultiplicities(a);
        defer counts.deinit(a);
        for (counts.n_yields) |n| if (n != 1) return error.PoseidonMissingProducer;
        if (!std.mem.eql(u32, counts.n_uses, ctx.usage.?.counts)) return error.PoseidonSourceUsageMismatch;
        const gate_counts = ctx.base.gate_counts;
        const raw64 = [5]u64{ gate_counts.eq, gate_counts.qm31_ops, gate_counts.m31_to_u32, ctx.calls.items.len, 1 << 16 };
        var raw: [5]usize = undefined;
        var rows: [5]usize = undefined;
        var logs: [5]u32 = undefined;
        for (raw64, &raw, &rows, &logs, 0..) |count, *out, *r, *log, i| {
            out.* = std.math.cast(usize, count) orelse return error.InvalidR6Geometry;
            r.* = try std.math.ceilPowerOfTwo(usize, @max(if (i == 4) @as(usize, 1) << 16 else 16, out.*));
            log.* = @intCast(std.math.log2_int(usize, r.*));
        }
        const mul_rows = try std.math.ceilPowerOfTwo(usize, @max(16, ctx.native_mul_calls.items.len));
        const mul_log: u32 = @intCast(std.math.log2_int(usize, mul_rows));
        if (mul_log > 26 or ctx.base.circuit.n_vars >= Core.fields.m31.Modulus) return error.InvalidR6Geometry;
        const qpad = rows[1] - raw[1];
        const mpad = rows[2] - raw[2];
        const usage = try a.alloc(u32, try std.math.add(usize, counts.n_uses.len, try std.math.add(usize, qpad, mpad)));
        errdefer a.free(usage);
        @memset(usage, 0);
        @memcpy(usage[0..counts.n_uses.len], counts.n_uses);
        usage[0] = try std.math.add(u32, usage[0], @intCast(2 * (rows[0] - raw[0]) + mpad));
        usage[1] = try std.math.add(u32, usage[1], @intCast(2 * qpad));
        var total: u64 = 0;
        var maximum: u32 = 0;
        for (usage) |n| {
            total = try std.math.add(u64, total, n);
            maximum = @max(maximum, n);
        }
        const checked = try L.validateUsage(.{ .counts = usage, .max_per_wire = maximum, .max_total = total });
        var mass: u64 = @intCast(ctx.base.circuit.output.items.len);
        for (rows[0..4], [_]u64{ 2, 3, 5, 48 }) |r, n| mass = try std.math.add(u64, mass, try std.math.mul(u64, r, n));
        mass = try std.math.add(u64, mass, try std.math.mul(u64, mul_rows, 6));
        if (mass >= Core.fields.m31.Modulus or usage.len >= Core.fields.m31.Modulus) return error.PoseidonCharacteristicBound;
        var fixed = try columns(a, 0, logs, mul_log);
        errdefer fixed.deinit();
        const c = &ctx.base.circuit;
        for (0..rows[0]) |r| {
            const g: Circuit.builder.circuit.EqGate = if (r < c.eq.items.len) c.eq.items[r] else .{ .in0 = 0, .in1 = 0 };
            fixed.put(0, r, M.fromCanonical(g.in0));
            fixed.put(1, r, M.fromCanonical(g.in1));
        }
        var at: usize = 0;
        inline for (.{ c.add.items, c.sub.items, c.mul.items, c.pointwise_mul.items }, 0..) |gates, op| for (gates) |g| {
            fixed.put(2 + op, at, M.one());
            fixed.put(6, at, M.fromCanonical(g.in0));
            fixed.put(7, at, M.fromCanonical(g.in1));
            fixed.put(8, at, M.fromCanonical(g.out));
            fixed.put(9, at, M.fromCanonical(usage[g.out]));
            at += 1;
        };
        if (at != raw[1]) return error.InvalidPoseidonGraphShape;
        for (at..rows[1]) |r| {
            fixed.put(2, r, M.one());
            fixed.put(6, r, M.one());
            fixed.put(7, r, M.one());
            fixed.put(8, r, M.fromCanonical(@intCast(c.n_vars + r - at)));
        }
        for (0..rows[2]) |r| {
            const input = if (r < c.m31_to_u32.items.len) c.m31_to_u32.items[r].input else 0;
            const output = if (r < c.m31_to_u32.items.len) c.m31_to_u32.items[r].out else c.n_vars + qpad + r - raw[2];
            fixed.put(10, r, M.fromCanonical(input));
            fixed.put(11, r, M.fromCanonical(@intCast(output)));
            fixed.put(12, r, M.fromCanonical(usage[output]));
        }
        for (0..rows[3]) |r| {
            const f = if (r < ctx.calls.items.len) try L.fixedForValidated(ctx.calls.items[r], checked) else L.paddingFixed();
            for (f, 0..) |v, j| fixed.put(13 + j, r, v);
        }
        for (0..rows[4]) |r| fixed.put(86, r, M.fromCanonical(@intCast(r)));
        const sizes: Circuit.common.finalize.ComponentSizes = .{ .eq = rows[0], .qm31_ops = rows[1], .m31_to_u32 = rows[2], .triple_xor = 16, .blake_g_gate = 16 };
        const old_layout = try Circuit.common.preprocessed.ColumnLayout.fromComponentSizes(sizes);
        const old_logs = try Circuit.common.component_list.circuitComponentLogSizes(&old_layout);
        const bytes = try std.fs.cwd().readFileAlloc(a, OldAir.bundle_path, 64 << 20);
        defer a.free(bytes);
        var template = try OldProve.parsePinnedAir(a, bytes);
        defer template.deinit();
        var bound = try OldAir.bind(a, &template, old_logs, &old_layout);
        errdefer bound.deinit();
        const pp = Circuit.common.preprocessed;
        inline for (OLD_SLOTS, NEW_SLOTS) |old, new| {
            const captured = &bound.components[old];
            for (captured.trace_spans) |*s| if (s.tree == 1) {
                s.start = MAIN_BASE[new];
                s.end = s.start + L.FACTS[new].main;
            } else if (s.tree == 2) {
                s.start = INTER_BASE[new] / 2;
                s.end = s.start + L.FACTS[new].classic_interaction / 2;
            };
            for (captured.preprocessed_indices) |*index| {
                const id = old_layout.entries[index.*].id;
                const names = switch (new) {
                    0 => &pp.EQ_COLUMN_IDS,
                    1 => &pp.QM31_OPS_COLUMN_IDS,
                    2 => &pp.M31_TO_U32_COLUMN_IDS,
                    4 => &[_][]const u8{"seq_16"},
                    else => unreachable,
                };
                index.* = for (names, 0..) |name, j| {
                    if (std.mem.eql(u8, id, name)) break @intCast(FIXED_BASE[new] + j);
                } else return error.InvalidPoseidonFixedRebase;
            }
        }
        for (0..mul_rows) |r| {
            const row = if (r < ctx.native_mul_calls.items.len) try R.fixedFor(ctx.native_mul_calls.items[r], usage) else R.paddingFixed();
            for (row, 0..) |value, j| fixed.put(FIXED_START + j, r, value);
        }
        var scheme = try A.E.init(a, profile.config());
        defer scheme.deinit(a);
        scheme.reuse_bounded_merkle_tail = true;
        var channel = A.MC.Channel.init();
        try scheme.commitBorrowedStreaming(a, fixed.values, 64, &channel);
        const root = scheme.trees.items[0].root();
        try scheme.trees.items[0].share(a);
        var tree = scheme.trees.items[0].retainShared();
        errdefer tree.deinit(a);
        var hash = std.crypto.hash.sha2.Sha256.init(.{});
        hash.update("opstack/outer-R6-native-om31-mul/v1");
        hash.update(profile.domain());
        hash.update(&A.MC.identity());
        hash.update(OldAir.bundle_sha256);
        hash.update(&P2Row.sourceIdentity());
        hash.update(&R.semanticIdentity());
        hash.update(&root);
        var geometry_bytes: [8]u8 = undefined;
        for (logs) |log| {
            std.mem.writeInt(u64, &geometry_bytes, log, .little);
            hash.update(&geometry_bytes);
        }
        std.mem.writeInt(u64, &geometry_bytes, mul_log, .little);
        hash.update(&geometry_bytes);
        // Explicit native heights remain authoritative even when zero columns
        // share a lifted root. Every tree's complete ordered geometry enters.
        for (0..3) |t| for (fixedWidths(t), 0..) |width, slot| {
            const log = if (slot < 5) logs[slot] else mul_log;
            std.mem.writeInt(u64, &geometry_bytes, width, .little);
            hash.update(&geometry_bytes);
            for (0..width) |_| {
                std.mem.writeInt(u64, &geometry_bytes, log, .little);
                hash.update(&geometry_bytes);
            }
        };
        std.mem.writeInt(u64, &geometry_bytes, c.output.items.len - 1, .little);
        hash.update(&geometry_bytes);
        const base = A.Authority{ .allocator = a, .profile = profile, .logs = logs, .rows = rows, .raw = raw, .n_outputs = c.output.items.len - 1, .original_vars = c.n_vars, .usage = usage, .fixed = fixed, .fixed_tree = tree, .bound = bound, .fixed_root = root, .identity = hash.finalResult(), .gather_mass = mass };
        return .{ .base = base, .mul_log = mul_log, .mul_rows = mul_rows, .mul_raw = ctx.native_mul_calls.items.len };
    }
    pub fn treeLogs(self: *const Key, a: std.mem.Allocator, tree: usize) ![]u32 {
        const widths = fixedWidths(tree);
        var total: usize = 0;
        for (widths) |width| total += width;
        const out = try a.alloc(u32, total);
        var at: usize = 0;
        for (widths, 0..) |width, i| {
            @memset(out[at..][0..width], if (i < 5) self.base.logs[i] else self.mul_log);
            at += width;
        }
        return out;
    }
    pub fn maxLog(self: *const Key) u32 {
        var out = self.mul_log;
        for (self.base.logs) |log| out = @max(out, log);
        return out;
    }
};
fn fixedWidths(tree: usize) [6]usize {
    var out: [6]usize = undefined;
    for (L.FACTS, 0..) |fact, i| out[i] = switch (tree) {
        0 => fact.fixed,
        1 => fact.main,
        2 => fact.classic_interaction,
        else => unreachable,
    };
    out[5] = switch (tree) {
        0 => R.FIXED,
        1 => R.MAIN,
        2 => R.INTER,
        else => unreachable,
    };
    return out;
}
