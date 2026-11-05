//! Complete mixed-height LogUp-GKR traversal on one borrowed device arena.
//! Geometry is CPU control data; all claims and Fiat-Shamir values stay resident.
//! This is not physical MAIN/PCS admission.
const std = @import("std");
const R = @import("resident.zig");
const B = @import("batch.zig");
const S = @import("sumcheck.zig");
const A = @import("abi.zig");
const Slice = @import("stwo_cuda_backend").runtime.column.DeviceSlice(u32);
const Region = @import("plan.zig").Region;
pub const max_variables = 28;
pub const max_instances = A.batch_max_oracles;
const Pair = struct { n: Region, d: Region, count: u32 };
pub const Mode = enum { retained_tree, recomputed_frontier };
const Oracle = struct {
    frontier: ?Region = null,
    tree: [max_variables]Pair = undefined,
    scratch_a: Region,
    scratch_b: Region,
    sums: Region,
};
pub const Layer = struct { active: u32, records: Region, masks: Region };
pub const Plan = struct {
    mode: Mode = .retained_tree,
    variables: [max_instances]u32 = @splat(0),
    count: u32,
    layers: u32 = 0,
    oracles: [max_instances]Oracle = undefined,
    layer: [max_variables]Layer = undefined,
    state: Region,
    batch_state: Region,
    roots: Region,
    projected: Region,
    eq: Region,
    total_words: usize,
    /// At top-down `remaining`, the current gate input is tree[remaining-2]
    /// (or the immutable raw input at one). Smaller tree levels have already
    /// completed their gate proofs and their claims are retained in GKR state.
    /// Reuse only those consumed levels as alternating sumcheck fold banks.
    /// Roots were copied before traversal; original fractions are never reused.
    pub fn foldingBanks(self: *const Plan, oracle: usize, remaining: u32) ![2]Pair {
        if (oracle >= self.count or remaining == 0 or remaining > self.variables[oracle]) return error.InvalidGeometry;
        const height = self.variables[oracle];
        if (self.mode == .recomputed_frontier and remaining <= 2) {
            var cursor = self.oracles[oracle].frontier.?.offset_words;
            const count = (@as(u32, 1) << @intCast(height)) >> @intCast(remaining - 1);
            if (remaining != 1) _ = try pair(&cursor, count);
            return .{ try pair(&cursor, @max(1, count / 2)), try pair(&cursor, @max(1, count / 4)) };
        }
        return .{ self.oracles[oracle].tree[remaining - 1], self.oracles[oracle].tree[@min(remaining, height - 1)] };
    }
    /// At depth>=2, Eq fits in the next consumed tree pair of a maximum-
    /// height oracle. The current input and two fold banks occupy r-2,r-1,r;
    /// r+1 has already closed and its roots/masks have independent custody.
    /// The N/D alignment gap is also dead owned arena storage. It is safe to
    /// use it provided the contiguous Eq view ends within that complete pair.
    pub fn equalityWorkspace(self: *const Plan, remaining: u32) !Region {
        if (remaining == 0 or remaining > self.layers) return error.InvalidGeometry;
        const depth = self.layers - remaining;
        if (self.mode == .recomputed_frontier) {
            if (remaining != 1) return self.eq;
            for (self.variables[0..self.count], 0..) |height, i| {
                if (height != self.layers) continue;
                const banks = try self.foldingBanks(i, remaining);
                var cursor = banks[1].d.offset_words + banks[1].d.words;
                return append(&cursor, @as(u64, 8) << @intCast(depth -| 1));
            }
            return error.InvalidFrontierEqualityBank;
        }
        if (depth < 2) return self.eq;
        for (self.variables[0..self.count], 0..) |height, i| {
            if (height != self.layers) continue;
            const consumed = self.oracles[i].tree[remaining + 1];
            const words = @as(u64, 8) << @intCast(depth - 1);
            if (consumed.n.offset_words + words > consumed.d.offset_words + consumed.d.words) return error.InvalidConsumedEqualityBank;
            return .{ .offset_words = consumed.n.offset_words, .words = words };
        }
        return error.InvalidConsumedEqualityBank;
    }
    pub fn frontierSource(self: *const Plan, oracle: usize, remaining: u32) !Pair {
        if (self.mode != .recomputed_frontier or oracle >= self.count or remaining <= 1 or remaining > self.variables[oracle]) return error.InvalidGeometry;
        if (remaining >= 3) return self.oracles[oracle].tree[remaining - 2];
        var cursor = self.oracles[oracle].frontier.?.offset_words;
        return pair(&cursor, (@as(u32, 1) << @intCast(self.variables[oracle])) >> @intCast(remaining - 1));
    }
    pub fn frontierBuildBank(self: *const Plan, oracle: usize, bank: usize, count: u32) !Pair {
        if (self.mode != .recomputed_frontier or oracle >= self.count or bank > 1) return error.InvalidGeometry;
        var cursor = self.oracles[oracle].frontier.?.offset_words;
        if (bank == 1) _ = try pair(&cursor, (@as(u32, 1) << @intCast(self.variables[oracle])) / 2);
        return pair(&cursor, count);
    }
    /// Requested workspace payload only: excludes input fractions, MAIN/PCS,
    /// driver allocations and diagnostics. Reject before any device mutation.
    pub fn init(variables: []const u32, byte_cap: usize) !Plan {
        return initMode(variables, byte_cap, .retained_tree);
    }
    /// Recomputed-frontier mode owns only a phase-reused source/folding
    /// frontier. Only the omitted largest product level is rebuilt from
    /// immutable fractions, after all smaller product levels have closed.
    /// Challenges and proof order stay exact.
    pub fn initMode(variables: []const u32, byte_cap: usize, mode: Mode) !Plan {
        if (variables.len == 0 or variables.len > max_instances) return error.InvalidGeometry;
        var out: Plan = undefined;
        out.mode = mode;
        out.variables = @splat(0);
        out.count = @intCast(variables.len);
        out.layers = 0;
        for (variables, 0..) |v, i| {
            if (v == 0 or v > max_variables) return error.InvalidGeometry;
            out.variables[i] = v;
            out.layers = @max(out.layers, v);
        }
        var cursor: u64 = 0;
        out.state = try append(&cursor, A.gkr_state_words);
        out.batch_state = try append(&cursor, A.batch_state_words);
        out.roots = try append(&cursor, 16 * variables.len);
        out.projected = try append(&cursor, 8 * variables.len);
        // Only the first two tiny layers need independent Eq storage.
        out.eq = try append(&cursor, if (mode == .retained_tree) 64 else @max(64, @as(u64, 1) << @intCast(out.layers)));
        for (variables, 0..) |v, i| {
            const n = @as(u32, 1) << @as(u5, @intCast(v));
            var o: Oracle = undefined;
            o.frontier = null;
            if (mode == .retained_tree) {
                for (0..v) |level| o.tree[level] = try pair(&cursor, n >> @as(u5, @intCast(level + 1)));
            } else {
                o.frontier = try append(&cursor, try frontierWords(v));
                var retained = o.frontier.?.offset_words;
                if (v == 1) o.tree[0] = try pair(&retained, 1) else for (1..v) |level| {
                    o.tree[level] = try pair(&retained, n >> @intCast(level + 1));
                }
            }
            const groups = @max(1, (n / 4 + 127) / 128);
            o.scratch_a = try append(&cursor, 16 * @as(u64, groups));
            o.scratch_b = try append(&cursor, 16 * @as(u64, groups));
            o.sums = try append(&cursor, 16);
            out.oracles[i] = o;
        }
        for (0..out.layers) |depth| {
            var active: u32 = 0;
            for (variables) |v| active += @intFromBool(v >= out.layers - depth);
            out.layer[depth] = .{ .active = active, .records = try append(&cursor, depth * A.round_record_words), .masks = try append(&cursor, 32 * @as(u64, active)) };
        }
        out.total_words = std.math.cast(usize, cursor) orelse return error.SizeOverflow;
        if (try std.math.mul(usize, out.total_words, 4) > byte_cap) return error.GkrWorkspaceBudgetExceeded;
        return out;
    }
};
fn frontierWords(height: u32) !u64 {
    const n = @as(u32, 1) << @intCast(height);
    var build: u64 = 0;
    _ = try pair(&build, n / 2);
    _ = try pair(&build, @max(1, n / 4));
    var maximum = build;
    for (1..height + 1) |remaining| {
        const count = n >> @intCast(remaining - 1);
        var cursor: u64 = 0;
        if (remaining != 1) _ = try pair(&cursor, count);
        _ = try pair(&cursor, @max(1, count / 2));
        _ = try pair(&cursor, @max(1, count / 4));
        if (remaining == 1) _ = try append(&cursor, @max(8, @as(u64, 2) * n));
        maximum = @max(maximum, cursor);
    }
    return maximum;
}
/// Skip materializing the largest product level by fusing its two levels
/// at ingress. Smaller levels remain resident until their gate proofs close.
fn buildFrontierTrees(commands: anytype, plan: *const Plan, inputs: []const R.Fraction, arena: Slice) !void {
    for (inputs, 0..) |input, i| {
        const first: usize = if (plan.variables[i] == 1) 0 else 1;
        var current = try fraction(arena, plan.oracles[i].tree[first]);
        try commands.layer(input, @intCast(first + 1), current);
        for (first + 1..plan.variables[i]) |level| {
            const next = try fraction(arena, plan.oracles[i].tree[level]);
            try commands.layer(current, 1, next);
            current = next;
        }
    }
}
fn append(cursor: *u64, words: u64) !Region {
    const at = (try std.math.add(u64, cursor.*, 63)) & ~@as(u64, 63);
    cursor.* = try std.math.add(u64, at, words);
    return .{ .offset_words = at, .words = words };
}
fn pair(cursor: *u64, count: u32) !Pair {
    return .{ .n = try append(cursor, 8 * @as(u64, count)), .d = try append(cursor, 8 * @as(u64, count)), .count = count };
}
fn region(arena: Slice, r: Region) !Slice {
    return arena.sub(std.math.cast(usize, r.offset_words) orelse return error.SizeOverflow, std.math.cast(usize, r.words) orelse return error.SizeOverflow);
}
fn plane(arena: Slice, r: Region, count: u32) !R.Plane {
    return .{ .data = try region(arena, r), .stride = count, .coordinates = 8 };
}
fn fraction(arena: Slice, p: Pair) !R.Fraction {
    return .{ .n = try plane(arena, p.n, p.count), .d = try plane(arena, p.d, p.count), .count = p.count };
}
fn buildTreesSerial(commands: anytype, plan: *const Plan, inputs: []const R.Fraction, arena: Slice) !void {
    for (inputs, 0..) |input, i| {
        var current = input;
        for (0..plan.variables[i]) |level| {
            const next = try fraction(arena, plan.oracles[i].tree[level]);
            try commands.layer(current, 1, next);
            current = next;
        }
    }
}
fn buildTrees(commands: anytype, plan: *const Plan, inputs: []const R.Fraction, arena: Slice) !void {
    if (comptime @hasDecl(@TypeOf(commands.*), "layerBatch")) {
        if (commands.batched_trees) {
            var height = plan.layers;
            while (height != 0) : (height -= 1) {
                var jobs: [max_instances]R.BatchFold = undefined;
                var count: usize = 0;
                for (inputs, 0..) |input, i| {
                    if (plan.variables[i] < height) continue;
                    const level = plan.variables[i] - height;
                    jobs[count] = .{
                        .input = if (level == 0) input else try fraction(arena, plan.oracles[i].tree[level - 1]),
                        .output = try fraction(arena, plan.oracles[i].tree[level]),
                    };
                    count += 1;
                }
                try commands.layerBatch(jobs[0..count]);
            }
            return;
        }
    }
    try buildTreesSerial(commands, plan, inputs, arena);
}
pub const ProofLayer = struct { records: Slice, masks: Slice, active: u32 };
pub const Enqueued = struct {
    state: Slice,
    roots: Slice,
    proof: [max_variables]ProofLayer,
    layers: u32,
    count: u32,
    chain: u64,
    requested_workspace_bytes: usize,
};
pub const Header = extern struct {
    channel: @import("channel.zig").Snapshot,
    layers: u32,
    count: u32,
    next_layer: u32,
    phase: u32,
    pub fn validate(self: Header, expected: Enqueued) !void {
        try self.channel.validate(2 * expected.layers, expected.chain);
        if (self.layers != expected.layers or self.count != expected.count or self.next_layer != expected.layers or self.phase != 2 or self.channel.draws != 1) return error.IncompleteGkrTraversal;
    }
};
comptime {
    if (@sizeOf(Header) != 80) @compileError("GKR parent header ABI mismatch");
}
/// Input projections and the seed must be initialized on the assigned stream
/// before this call. A single generation-checked arena owns all tree and scratch
/// regions; one reservation validates the entire job before its first launch.
pub fn enqueue(commands: anytype, inputs: []const R.Fraction, seed: Slice, arena: Slice, byte_cap: usize, chain: u64) !Enqueued {
    return enqueueImpl(commands, inputs, seed, arena, byte_cap, chain, null, .retained_tree);
}
/// Caller chooses a source-admitted mode before allocation. This entry point
/// never raises a workspace cap or changes the proof transcript.
pub fn enqueueMode(commands: anytype, inputs: []const R.Fraction, seed: Slice, arena: Slice, byte_cap: usize, chain: u64, mode: Mode) !Enqueued {
    return enqueueImpl(commands, inputs, seed, arena, byte_cap, chain, null, mode);
}
pub const ClosureEnqueued = struct {
    traversal: Enqueued,
    verdict: Slice,
    /// Called only after joined device completion and verdict readback. This
    /// validates traversal/closure, not physical MAIN binding or PCS proofs.
    pub fn validate(self: @This(), header: Header, status: u32) !void {
        if (status != 0) return error.LocalGkrClosureRejected;
        try header.validate(self.traversal);
    }
};
/// Production traversal requires zero rational root sum and rejects every
/// pole, including zero-weight 0/0. The raw enqueue remains a numerical tool.
pub fn enqueueWithClosure(commands: anytype, inputs: []const R.Fraction, seed: Slice, arena: Slice, byte_cap: usize, chain: u64, verdict: Slice) !ClosureEnqueued {
    return .{ .traversal = try enqueueImpl(commands, inputs, seed, arena, byte_cap, chain, verdict, .retained_tree), .verdict = verdict };
}
fn enqueueImpl(commands: anytype, inputs: []const R.Fraction, seed: Slice, arena: Slice, byte_cap: usize, chain: u64, verdict: ?Slice, mode: Mode) !Enqueued {
    if (commands.poisoned) return error.JobPoisoned;
    if (comptime @hasDecl(@TypeOf(commands.*), "requireBatchedOracles")) {
        if (commands.batched_oracles) try commands.requireBatchedOracles();
    }
    if (comptime @hasDecl(@TypeOf(commands.*), "requireBatchedTrees")) {
        if (commands.batched_trees) try commands.requireBatchedTrees();
    }
    if (inputs.len == 0 or inputs.len > max_instances) return error.InvalidGeometry;
    var variables: [max_instances]u32 = undefined;
    for (inputs, 0..) |input, i| {
        if (input.count < 2 or input.count > 1 << max_variables or !std.math.isPowerOfTwo(input.count)) return error.InvalidGeometry;
        variables[i] = std.math.log2_int(u32, input.count);
    }
    const plan = try Plan.initMode(variables[0..inputs.len], byte_cap, mode);
    var reservations = S.ReservationSet(3 + 18 * max_instances){};
    try reservations.slice(commands.context, arena, plan.total_words, true);
    try reservations.slice(commands.context, seed, 9, false);
    for (inputs) |input| {
        if (input.projected != null) {
            const borrowed = input.projected.?.borrowed;
            if (borrowed.len == 0 or borrowed.len > 16) return error.InvalidProjectedSource;
            for (borrowed) |span| try reservations.slice(commands.context, span, span.len, false);
            if (comptime @hasDecl(@TypeOf(commands.*), "validateProjection")) try commands.validateProjection(input) else return error.ProjectedSourceUnavailable;
        } else try reservations.fraction(commands.context, input, input.count, false);
    }
    if (verdict) |status| try reservations.slice(commands.context, status, 1, true);
    const state = try region(arena, plan.state);
    const point = try state.sub(A.gkr_point_word, 8 * plan.layers);
    const lambda = try state.sub(A.gkr_lambda_word, 8);
    const alpha = try state.sub(A.gkr_alpha_word, 8);
    const layer_seed = try state.sub(A.gkr_seed_word, 9);
    const projected = try region(arena, plan.projected);
    const roots = try region(arena, plan.roots);
    var root_sources: [max_instances]R.Fraction = undefined;
    if (mode == .retained_tree) {
        try buildTrees(commands, &plan, inputs, arena);
        for (inputs, 0..) |_, i| root_sources[i] = try fraction(arena, plan.oracles[i].tree[variables[i] - 1]);
    } else {
        try buildFrontierTrees(commands, &plan, inputs, arena);
        for (inputs, 0..) |_, i| root_sources[i] = try fraction(arena, plan.oracles[i].tree[variables[i] - 1]);
    }
    try commands.packRoots(root_sources[0..inputs.len], roots);
    if (verdict) |status| try commands.closeLocalRoots(roots, plan.count, status);
    try commands.initGkr(state, seed, variables[0..inputs.len], plan.layers, chain);
    var result = Enqueued{ .state = state, .roots = roots, .proof = undefined, .layers = plan.layers, .count = plan.count, .chain = chain, .requested_workspace_bytes = plan.total_words * 4 };
    for (0..plan.layers) |depth| {
        const remaining = plan.layers - depth;
        const l = plan.layer[depth];
        const masks = try region(arena, l.masks);
        const records = try region(arena, l.records);
        var sources: [max_instances]R.Fraction = undefined;
        var work: [max_instances]B.OracleWorkspace = undefined;
        var active: usize = 0;
        for (inputs, 0..) |input, i| {
            if (variables[i] < remaining) continue;
            const o = plan.oracles[i];
            sources[active] = if (remaining == 1) input else if (mode == .retained_tree) try fraction(arena, o.tree[remaining - 2]) else try fraction(arena, try plan.frontierSource(i, @intCast(remaining)));
            if (mode == .recomputed_frontier and remaining == 2) try commands.layer(input, 1, sources[active]);
            const banks = try plan.foldingBanks(i, @intCast(remaining));
            const bank0 = try fraction(arena, banks[0]);
            const bank1 = try fraction(arena, banks[1]);
            if (bank0.count != @max(1, sources[active].count / 2) or bank1.count != @max(1, sources[active].count / 4)) return error.InvalidConsumedTreeBank;
            work[active] = .{ .banks = .{ bank0, bank1 }, .scratch_a = try plane(arena, o.scratch_a, @intCast(o.scratch_a.words / 8)), .scratch_b = try plane(arena, o.scratch_b, @intCast(o.scratch_b.words / 8)), .sums = try plane(arena, o.sums, 2), .terminal_mask = try masks.sub(32 * active, 32) };
            active += 1;
        }
        try commands.beginGkr(state, @intCast(depth), plan.count, l.active, roots, projected);
        const equality = try plan.equalityWorkspace(@intCast(remaining));
        _ = try B.enqueue(commands, .{ .oracles = sources[0..active], .point = point, .lambda = lambda, .alpha = alpha, .claims = projected, .seed = layer_seed }, .{ .oracles = work[0..active], .eq = try plane(arena, equality, @intCast(equality.words / 8)), .state = try region(arena, plan.batch_state), .records = records });
        try commands.closeGkr(state, try region(arena, plan.batch_state), records, masks, @intCast(depth), plan.count, l.active);
        result.proof[depth] = .{ .records = records, .masks = masks, .active = l.active };
    }
    return result;
}
