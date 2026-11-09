//! Source-derived five-roster geometry. No proof-supplied topology, usages,
//! degree or FIXED commitment is accepted. CPU reference suite is P2 OM31 v2.
const std = @import("std");
const Core = @import("stwo_core");
const Engine = @import("stwo_prover_engine");
const Circuit = @import("stwo_circuit_frontend");
const OldAir = @import("stwo_circuit_cpu_integration").air;
const OldProve = @import("stwo_circuit_cpu_integration").om31.prove;
const C = @import("context.zig");
const L = @import("layout.zig");
const Row = @import("row.zig");
pub const M = Core.fields.m31.M31;
pub const O = Core.fields.om31.OM31;
pub const Q = Core.fields.qm31.QM31;
pub const MC = Core.vcs_lifted.poseidon2_profile.Om31V2;
pub const H = MC.MerkleHasher;
pub const E = Engine.engine.ForField(O).ProverEngine(@import("stwo_cpu_backend").CpuBackend, H, MC, MC.Channel);
pub const Col = Engine.pcs.ColumnEvaluation;
pub const FIXED_START = [5]usize{ 0, 2, 10, 13, 86 };
pub const MAIN_START = [5]usize{ 0, 4, 16, 20, 496 };
pub const INTER_START = [5]usize{ 0, 8, 24, 48, 240 };
pub const FIXED_COUNT = 87;
pub const MAIN_COUNT = 497;
pub const INTER_COUNT = 248;
pub const OLD_SLOTS = [4]usize{ 0, 1, 3, 10 };
pub const NEW_SLOTS = [4]usize{ 0, 1, 2, 4 };
pub const Profile = @import("op_profile.zig").Profile;
pub fn config() !Core.pcs.ForField(O).PcsConfig {
    // Reference correctness gate only. Production security policy is separate.
    return .{ .pow_bits = 0, .fri_config = try Core.fri.ForField(O).FriConfig.init(0, 1, 24) };
}
pub const Columns = struct {
    allocator: std.mem.Allocator,
    values: []Col,
    pub fn init(a: std.mem.Allocator, tree: enum { fixed, main, inter }, logs: [5]u32) !Columns {
        const out = try a.alloc(Col, switch (tree) {
            .fixed => FIXED_COUNT,
            .main => MAIN_COUNT,
            .inter => INTER_COUNT,
        });
        var made: usize = 0;
        errdefer {
            for (out[0..made]) |c| a.free(c.values);
            a.free(out);
        }
        for (logs, L.FACTS) |log, fact| {
            const width = switch (tree) {
                .fixed => fact.fixed,
                .main => fact.main,
                .inter => fact.classic_interaction,
            };
            for (0..width) |_| {
                const values = try a.alloc(M, @as(usize, 1) << @intCast(log));
                @memset(values, M.zero());
                out[made] = .{ .log_size = log, .values = values };
                made += 1;
            }
        }
        return .{ .allocator = a, .values = out };
    }
    pub fn deinit(self: *Columns) void {
        for (self.values) |c| self.allocator.free(c.values);
        self.allocator.free(self.values);
        self.* = undefined;
    }
    pub fn put(self: *Columns, column: usize, row: usize, value: M) void {
        @constCast(self.values[column].values)[row] = value;
    }
};
pub const Authority = struct {
    allocator: std.mem.Allocator,
    profile: Profile = .reference_b2_q24_p0,
    logs: [5]u32,
    rows: [5]usize,
    raw: [5]usize,
    n_outputs: usize,
    original_vars: usize,
    usage: []u32,
    fixed: Columns,
    fixed_tree: ?E.Scheme.CommittedTree,
    bound: OldAir.Bundle,
    fixed_root: H.Hash,
    identity: [32]u8,
    gather_mass: u64,
    pub fn init(a: std.mem.Allocator, ctx: *const C.Context) !Authority {
        return initForProfile(a, ctx, .reference_b2_q24_p0);
    }
    pub fn initForProfile(a: std.mem.Allocator, ctx: *const C.Context, profile: Profile) !Authority {
        if (!ctx.finalized or ctx.poisoned or ctx.usage == null or ctx.mixed_census_only) return error.PoseidonContextNotFinalized;
        // Recompute topology counts rather than trusting the Context's cached
        // Usage payload. This includes every P2 sidecar consumer and producer.
        var counts = try ctx.base.circuit.computeMultiplicities(a);
        defer counts.deinit(a);
        for (ctx.calls.items) |gate| {
            for (gate.inputs) |input| {
                if (input >= counts.n_uses.len) return error.InvalidPoseidonPortAddress;
                counts.n_uses[input] = try std.math.add(u32, counts.n_uses[input], 1);
            }
            for (gate.outputs) |output| {
                if (output >= counts.n_yields.len or counts.n_yields[output] != 0) return error.PoseidonProducerConflict;
                counts.n_yields[output] = 1;
            }
        }
        for (counts.n_yields) |yields| if (yields != 1) return error.PoseidonMissingProducer;
        if (!std.mem.eql(u32, counts.n_uses, ctx.usage.?.counts)) return error.PoseidonSourceUsageMismatch;
        if (ctx.base.circuit.blake_g_gate.items.len != 0 or ctx.base.circuit.triple_xor.items.len != 0 or ctx.base.circuit.permutation.len() != 0) return error.UnsupportedPoseidonRosterOperation;
        const raw64 = try ctx.rawCounts();
        const census = try ctx.census(false);
        var rows: [5]usize = undefined;
        var raw: [5]usize = undefined;
        var logs: [5]u32 = undefined;
        for (census.rows, raw64, &rows, &raw, &logs) |n, r, *nn, *rr, *ll| {
            nn.* = @intCast(n);
            rr.* = @intCast(r);
            ll.* = std.math.log2_int(u64, n);
        }
        const qpad = rows[1] - raw[1];
        const mpad = rows[2] - raw[2];
        const usage = try a.alloc(u32, counts.n_uses.len + qpad + mpad);
        errdefer a.free(usage);
        @memset(usage, 0);
        @memcpy(usage[0..counts.n_uses.len], counts.n_uses);
        usage[0] = try std.math.add(u32, usage[0], @intCast(2 * (rows[0] - raw[0]) + mpad));
        usage[1] = try std.math.add(u32, usage[1], @intCast(2 * qpad));
        var total: u64 = 0;
        var max: u32 = 0;
        for (usage) |u| {
            total = try std.math.add(u64, total, u);
            max = @max(max, u);
        }
        const checked = try L.validateUsage(.{ .counts = usage, .max_per_wire = max, .max_total = total });
        // Every gather entry is conservatively counted positive, including
        // negative providers. This bounds both variable and range relations.
        var mass: u64 = @intCast(ctx.base.circuit.output.items.len);
        for (rows[0..4], [_]u64{ 2, 3, 5, 48 }) |r, n| mass = try std.math.add(u64, mass, try std.math.mul(u64, r, n));
        if (mass >= Core.fields.m31.Modulus or usage.len >= Core.fields.m31.Modulus) return error.PoseidonCharacteristicBound;
        var fixed = try Columns.init(a, .fixed, logs);
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
                s.start = MAIN_START[new];
                s.end = s.start + L.FACTS[new].main;
            } else if (s.tree == 2) {
                s.start = INTER_START[new] / 2;
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
                    if (std.mem.eql(u8, id, name)) break @intCast(FIXED_START[new] + j);
                } else return error.InvalidPoseidonFixedRebase;
            }
        }
        var scheme = try E.init(a, profile.config());
        defer scheme.deinit(a);
        var channel = MC.Channel.init();
        const control = try @import("op_profile.zig").monolithicControl();
        if (control) try scheme.commit(a, fixed.values, &channel) else try scheme.commitBorrowedStreaming(a, fixed.values, 64, &channel);
        const root = scheme.trees.items[0].root();
        var fixed_tree: ?E.Scheme.CommittedTree = null;
        if (!control) {
            try scheme.trees.items[0].share(a);
            fixed_tree = scheme.trees.items[0].retainShared();
        }
        errdefer if (fixed_tree) |*tree| tree.deinit(a);
        var h = std.crypto.hash.sha2.Sha256.init(.{});
        h.update(profile.domain());
        h.update(&MC.identity());
        h.update(&Row.sourceIdentity());
        h.update(OldAir.bundle_sha256);
        h.update(@embedFile("authority.zig"));
        h.update(@embedFile("op_profile.zig"));
        h.update(@embedFile("component.zig"));
        h.update(@embedFile("witness.zig"));
        h.update(@embedFile("proof.zig"));
        h.update(&root);
        for (logs) |l| {
            var b: [4]u8 = undefined;
            std.mem.writeInt(u32, &b, l, .little);
            h.update(&b);
        }
        var b: [8]u8 = undefined;
        std.mem.writeInt(u64, &b, ctx.base.circuit.output.items.len - 1, .little);
        h.update(&b);
        return .{ .allocator = a, .profile = profile, .logs = logs, .rows = rows, .raw = raw, .n_outputs = ctx.base.circuit.output.items.len - 1, .original_vars = c.n_vars, .usage = usage, .fixed = fixed, .fixed_tree = fixed_tree, .bound = bound, .fixed_root = root, .identity = h.finalResult(), .gather_mass = mass };
    }
    pub fn deinit(self: *Authority) void {
        if (self.fixed_tree) |*tree| tree.deinit(self.allocator);
        self.fixed.deinit();
        self.bound.deinit();
        self.allocator.free(self.usage);
        self.* = undefined;
    }
    pub fn treeLogs(self: *const Authority, a: std.mem.Allocator, tree: u8) ![]u32 {
        const out = try a.alloc(u32, switch (tree) {
            0 => FIXED_COUNT,
            1 => MAIN_COUNT,
            2 => INTER_COUNT,
            else => return error.InvalidPoseidonTree,
        });
        var at: usize = 0;
        for (L.FACTS, self.logs) |f, log| {
            const n = switch (tree) {
                0 => f.fixed,
                1 => f.main,
                2 => f.classic_interaction,
                else => unreachable,
            };
            @memset(out[at..][0..n], log);
            at += n;
        }
        return out;
    }
};
