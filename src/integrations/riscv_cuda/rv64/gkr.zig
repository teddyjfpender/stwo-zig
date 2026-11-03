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
const Oracle = struct {
    tree: [max_variables]Pair = undefined,
    scratch_a: Region,
    scratch_b: Region,
    sums: Region,
};
pub const Layer = struct { active: u32, records: Region, masks: Region };
pub const Plan = struct {
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
        return .{ self.oracles[oracle].tree[remaining - 1], self.oracles[oracle].tree[@min(remaining, height - 1)] };
    }
    /// Requested workspace payload only: excludes input fractions, MAIN/PCS,
    /// driver allocations and diagnostics. Reject before any device mutation.
    pub fn init(variables: []const u32, byte_cap: usize) !Plan {
        if (variables.len == 0 or variables.len > max_instances) return error.InvalidGeometry;
        var out: Plan = undefined;
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
        const eq_count = @as(u32, 1) << @as(u5, @intCast(out.layers -| 2));
        out.eq = try append(&cursor, 8 * @as(u64, eq_count));
        for (variables, 0..) |v, i| {
            const n = @as(u32, 1) << @as(u5, @intCast(v));
            var o: Oracle = undefined;
            for (0..v) |level| o.tree[level] = try pair(&cursor, n >> @as(u5, @intCast(level + 1)));
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
    return enqueueImpl(commands, inputs, seed, arena, byte_cap, chain, null);
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
    return .{ .traversal = try enqueueImpl(commands, inputs, seed, arena, byte_cap, chain, verdict), .verdict = verdict };
}
fn enqueueImpl(commands: anytype, inputs: []const R.Fraction, seed: Slice, arena: Slice, byte_cap: usize, chain: u64, verdict: ?Slice) !Enqueued {
    if (commands.poisoned) return error.JobPoisoned;
    if (comptime @hasDecl(@TypeOf(commands.*), "requireBatchedOracles")) {
        if (commands.batched_oracles) try commands.requireBatchedOracles();
    }
    if (inputs.len == 0 or inputs.len > max_instances) return error.InvalidGeometry;
    var variables: [max_instances]u32 = undefined;
    for (inputs, 0..) |input, i| {
        if (input.count < 2 or input.count > 1 << max_variables or !std.math.isPowerOfTwo(input.count)) return error.InvalidGeometry;
        variables[i] = std.math.log2_int(u32, input.count);
    }
    const plan = try Plan.init(variables[0..inputs.len], byte_cap);
    var reservations = S.ReservationSet(3 + 2 * max_instances){};
    try reservations.slice(commands.context, arena, plan.total_words, true);
    try reservations.slice(commands.context, seed, 9, false);
    for (inputs) |input| try reservations.fraction(commands.context, input, input.count, false);
    if (verdict) |status| try reservations.slice(commands.context, status, 1, true);
    const state = try region(arena, plan.state);
    const point = try state.sub(A.gkr_point_word, 8 * plan.layers);
    const lambda = try state.sub(A.gkr_lambda_word, 8);
    const alpha = try state.sub(A.gkr_alpha_word, 8);
    const layer_seed = try state.sub(A.gkr_seed_word, 9);
    const projected = try region(arena, plan.projected);
    const roots = try region(arena, plan.roots);
    var root_sources: [max_instances]R.Fraction = undefined;
    for (inputs, 0..) |input, i| {
        var current = input;
        for (0..variables[i]) |level| {
            const next = try fraction(arena, plan.oracles[i].tree[level]);
            try commands.layer(current, 1, next);
            current = next;
        }
        root_sources[i] = current;
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
            sources[active] = if (remaining == 1) input else try fraction(arena, o.tree[remaining - 2]);
            const banks = try plan.foldingBanks(i, @intCast(remaining));
            const bank0 = try fraction(arena, banks[0]);
            const bank1 = try fraction(arena, banks[1]);
            if (bank0.count != @max(1, sources[active].count / 2) or bank1.count != @max(1, sources[active].count / 4)) return error.InvalidConsumedTreeBank;
            work[active] = .{ .banks = .{ bank0, bank1 }, .scratch_a = try plane(arena, o.scratch_a, @intCast(o.scratch_a.words / 8)), .scratch_b = try plane(arena, o.scratch_b, @intCast(o.scratch_b.words / 8)), .sums = try plane(arena, o.sums, 2), .terminal_mask = try masks.sub(32 * active, 32) };
            active += 1;
        }
        try commands.beginGkr(state, @intCast(depth), plan.count, l.active, roots, projected);
        _ = try B.enqueue(commands, .{ .oracles = sources[0..active], .point = point, .lambda = lambda, .alpha = alpha, .claims = projected, .seed = layer_seed }, .{ .oracles = work[0..active], .eq = try plane(arena, plan.eq, @intCast(plan.eq.words / 8)), .state = try region(arena, plan.batch_state), .records = records });
        try commands.closeGkr(state, try region(arena, plan.batch_state), records, masks, @intCast(depth), plan.count, l.active);
        result.proof[depth] = .{ .records = records, .masks = masks, .active = l.active };
    }
    return result;
}
