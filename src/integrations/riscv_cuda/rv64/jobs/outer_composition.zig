//! Enqueue-only outer composition (RC) for OuterNodeJob. Same kernels, same
//! order, same words as resident_composition.zig Job.run on the deployed
//! outer configuration (STWO_RV64_COMPOSITION_ENQUEUE=1, direct extension,
//! no role workspace, no selected columns, no auxiliary columns, no sparse
//! role): for each catalogue role in order,
//!   LDE of every source column straight from its coefficient buffer
//!   (n2b_columns, eval_log = trace_log + 1 for every outer component),
//!   the AOT role kernel accumulating into the per-height quotient bucket,
//! then the finish kernel (bucket fold + interpolation + split), the commit
//! LDE and the Merkle tree. Differences are custody only: parameters and
//! powers come from device memory (z, alpha, claims, coefficient never reach
//! the host), every static table comes from the class region, and the root
//! stays in the tree buffer for the device channel.
const std = @import("std");
const Abi = @import("../abi.zig");
const K = @import("outer_kernels.zig");
const St = @import("outer_staged.zig");

pub const Role = *const @TypeOf(Abi.stwo_rv64_composition_role_on);
pub const Finish = *const @TypeOf(Abi.stwo_rv64_composition_finish_on);
pub const Params = *const fn (*anyopaque, u32, [*]const u32, u32, [*]const u32, [*]const u32, [*]u32, [*]u32) callconv(.c) c_int;

pub const Kernels = struct {
    role: Role,
    finish: Finish,
    params: Params,
    pub fn load(base: *std.DynLib, jobs: *std.DynLib) !Kernels {
        return .{
            .role = base.lookup(Role, "stwo_circuit_om31_composition_role_on") orelse return error.MissingOuterCompositionKernel,
            .finish = base.lookup(Finish, "stwo_rv64_composition_finish_on") orelse return error.MissingOuterCompositionKernel,
            .params = jobs.lookup(Params, "stwo_rv64_outer_rc_parameters_v1_on") orelse return error.MissingOuterCompositionKernel,
        };
    }
};

/// One RC source column: tree 0 FIXED (class coefficient region), 1 MAIN,
/// 2 INTER (job coefficient buffers), by original column index.
pub const Source = struct { tree: u8, index: u32 };

/// Class-static description of one catalogue role.
pub const RoleStatic = struct {
    id: u32,
    trace_log: u32,
    eval_log: u32,
    widths: [3]u32,
    sources: []const Source,
    roots: u32,
    /// u64 mask offsets (input.column * n), 2 words each.
    masks: St.Range,
    mask_count: u32,
    denominators: St.Range,
    /// Per-column LDE source log (eval_log - 1), read by n2b_columns.
    logs: St.Range,
    /// Parameters of this role: entries [param_first, +param_count) of the
    /// class table and of the node's parameter output (8 words each).
    param_count: u32,
    param_first: u32,
};

pub const Static = struct {
    roles: []const RoleStatic,
    log: u32,
    split: u32,
    total: u32,
    beta: u32,
    param_total: u32,
    /// Parameter table of all roles, in role order (16 words per entry).
    param_table: St.Range,
    /// Commit descriptors (one chunk log per output column).
    commit_logs: St.Range,
    /// Original-order offsets of FIXED coefficient columns in `fixed`.
    fixed: St.Range,
    fixed_offsets: []const u64,
    pub fn chunkLog(self: *const Static) u32 {
        return self.log - self.split;
    }
    pub fn outputColumns(self: *const Static) u32 {
        return @as(u32, 8) << @intCast(self.split);
    }
    pub fn commitLog(self: *const Static) u32 {
        return self.chunkLog() + self.beta;
    }
    pub fn coefficientWords(self: *const Static) u64 {
        return @as(u64, 8) << @intCast(self.log);
    }
    pub fn treeWords(self: *const Static) u64 {
        return ((@as(u64, 2) << @intCast(self.commitLog())) - 1) * 8;
    }
    pub fn rootOffset(self: *const Static) u64 {
        return self.treeWords() - 8;
    }
};

/// Device inputs of one node's composition.
pub const Inputs = struct {
    bases: St.Bases,
    /// Twiddle-region trees per height (staged image).
    twiddles: *const [29]St.Range,
    itwiddles: *const [29]St.Range,
    main: [*]const u32,
    main_offsets: []const u64,
    inter: [*]const u32,
    inter_offsets: [*]const u64,
    lookup: [*]const u32,
    claims: [*]const u32,
    powers: [*]const u32,
    /// Node parameter output (param_total * 8 words), job lifetime.
    parameters: [*]u32,
    /// Composition coefficients (coefficientWords, kept for PCS) and tree.
    output: K.Buffer,
    tree: K.Buffer,
    status: [*]u32,
};

fn source(st: *const Static, in: *const Inputs, s: Source) [*]const u32 {
    return switch (s.tree) {
        0 => in.bases.at(st.fixed) + @as(usize, @intCast(st.fixed_offsets[s.index])),
        1 => in.main + @as(usize, @intCast(in.main_offsets[s.index])),
        else => in.inter + @as(usize, @intCast(in.inter_offsets[s.index])),
    };
}

pub fn enqueue(device: *K.Device, kernels: *const Kernels, st: *const Static, in: *const Inputs) !void {
    const n2b = device.kernels.n2b_columns;
    if (st.beta != 1) return error.UnsupportedOuterJobBlowup;
    if (in.output.words < st.coefficientWords() or in.tree.words < st.treeWords()) return error.OuterCompositionBufferTooSmall;
    // Parameters of every role from the device challenges and claims.
    try device.check(kernels.params(device.ctx, K.lane, in.bases.at(st.param_table), st.param_total, in.lookup, in.claims, in.parameters, in.status));
    var buckets: [29]?K.Buffer = @splat(null);
    defer {
        var i: usize = buckets.len;
        while (i > 0) {
            i -= 1;
            if (buckets[i]) |b| device.free(b);
        }
    }
    // Buckets first (LIFO: they outlive every role arena).
    for (st.roles) |role| if (buckets[role.eval_log] == null) {
        const n = @as(u64, 1) << @intCast(role.eval_log);
        buckets[role.eval_log] = try device.alloc(@intCast(8 * n));
        try device.clear(buckets[role.eval_log].?.ptr, 8 * n);
    };
    var next: u32 = st.total;
    for (st.roles) |role| {
        const el = role.eval_log;
        const n = @as(u64, 1) << @intCast(el);
        const columns: u64 = role.widths[0] + role.widths[1] + role.widths[2];
        if (role.sources.len != columns or role.trace_log + 1 != el) return error.UnsupportedOuterCompositionRole;
        const arena = try device.alloc(@intCast(columns * n));
        defer device.free(arena);
        const tw = in.bases.at(in.twiddles[el]);
        const tw_words = in.twiddles[el].words;
        if (tw_words < n / 2) return error.InvalidOuterTwiddles;
        var c: usize = 0;
        while (c < role.sources.len) {
            // Merge columns whose coefficient sources are adjacent (one LDE call).
            const first = source(st, in, role.sources[c]);
            var end = c + 1;
            while (end < role.sources.len and source(st, in, role.sources[end]) == first + (end - c) * (n / 2)) : (end += 1) {}
            var launches: u32 = 0;
            try device.check(n2b(first, @intCast(n / 2), in.bases.at(role.logs) + c, arena.ptr + c * n, @intCast(n), el, @intCast(end - c), tw + (tw_words - n / 2), @intCast(n / 2), @intCast(n / 2), device.stream, &launches));
            device.counters.internal += launches -| 1;
            c = end;
        }
        if (role.roots > next) return error.NotEnoughCoefficients;
        next -= role.roots;
        const w = role.widths;
        const packet = Abi.CompositionRole{
            .role = role.id,
            .trace_log = role.trace_log,
            .eval_log = el,
            .first_row = 0,
            .row_count = @intCast(n),
            .trees = .{ arena.ptr, arena.ptr + w[0] * n, arena.ptr + (w[0] + w[1]) * n },
            .tree_words = .{ @max(1, w[0] * n), @max(1, w[1] * n), @max(1, w[2] * n) },
            .column_offsets = @ptrCast(@alignCast(in.bases.at(role.masks))),
            .mask_count = role.mask_count,
            .parameters = in.parameters + 8 * @as(usize, role.param_first),
            .parameter_count = role.param_count,
            .powers = in.powers + 8 * @as(usize, next),
            .constraint_count = role.roots,
            .denominator_inverses = in.bases.at(role.denominators),
            .output = buckets[el].?.ptr,
        };
        var launches: u32 = 0;
        try device.check(kernels.role(device.ctx, K.lane, &packet, &launches));
        device.counters.internal += launches -| 1;
    }
    if (next != 0) return error.UnusedCompositionCoefficients;
    // Finish: fold buckets, interpolate, split into coefficient chunks.
    var list: [29]Abi.CompositionBucket = undefined;
    var listed: u32 = 0;
    for (buckets, 0..) |bucket, log| if (bucket) |b| {
        list[listed] = .{ .words = b.ptr, .log = @intCast(log) };
        listed += 1;
    };
    const accumulator = try device.alloc(@intCast(st.coefficientWords()));
    defer device.free(accumulator);
    var launches: u32 = 0;
    try device.check(kernels.finish(device.ctx, K.lane, &list, listed, accumulator.ptr, in.output.ptr, st.log, st.split, in.bases.at(in.itwiddles[st.log]), @intCast(in.itwiddles[st.log].words), &launches));
    // Commit: LDE of the split coefficients, one Merkle segment.
    const count = st.outputColumns();
    const commit_log = st.commitLog();
    const rows = @as(u64, 1) << @intCast(commit_log);
    const scratch = try device.alloc(@intCast(count * rows));
    defer device.free(scratch);
    launches = 0;
    try device.check(n2b(in.output.ptr, @as(usize, 1) << @intCast(st.chunkLog()), in.bases.at(st.commit_logs), scratch.ptr, @intCast(rows), commit_log, count, in.bases.at(in.twiddles[commit_log]), @intCast(in.twiddles[commit_log].words), @intCast(rows / 2), device.stream, &launches));
    device.counters.internal += launches -| 1;
    const segment = Abi.MixedSegment{ .columns = scratch.ptr, .stride_words = rows, .capacity_words = count * rows, .source_size = @intCast(rows) };
    try device.check(device.kernels.tree(device.ctx, K.lane, @ptrCast(&segment), 1, commit_log, in.tree.ptr, st.treeWords()));
}

test "composition geometry follows resident_composition.zig finish/commit sizing" {
    var st: Static = undefined;
    st.log = 21;
    st.split = 1;
    st.beta = 1;
    try std.testing.expectEqual(@as(u32, 20), st.chunkLog());
    try std.testing.expectEqual(@as(u32, 16), st.outputColumns());
    try std.testing.expectEqual(@as(u32, 21), st.commitLog());
    try std.testing.expectEqual(@as(u64, 8) << 21, st.coefficientWords());
    try std.testing.expectEqual(((@as(u64, 2) << 21) - 1) * 8, st.treeWords());
}
