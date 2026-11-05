//! Host-only allocation plan for a frozen trace-commit schedule. The caller
//! must use selected_stream_budget without owner-thread adaptive shrinking.
const std = @import("std");
const S = @import("trace_stream_plan.zig");
const A = @import("global_admission.zig");
pub const Format = enum { legacy_blake32_m31, poseidon2_w24_v1 };
pub const Input = struct {
    format: Format = .legacy_blake32_m31,
    logs: []const u32,
    beta: u32,
    separate_coefficients: bool,
    stream_budget: ?usize = null,
    exact_prefix_banks: bool = false,
};
pub const Plan = struct {
    format: Format = .legacy_blake32_m31,
    allocations: [4]u64 = @splat(0),
    allocation_count: usize = 0,
    selected_stream_budget: ?usize = null,
    coefficient_words: u64,
    /// Diagnostic conservative bound only; per-allocation host lifetime audit
    /// remains required before this can set Demand.host_known.
    host_peak_bytes: u64,
    host_cost_known: bool = false,
    pub fn bytes(self: *const Plan) []const u64 {
        return self.allocations[0..self.allocation_count];
    }
    pub fn footprint(self: *const Plan) !A.Footprint {
        return A.Footprint.allocations(self.bytes());
    }
    fn addWords(self: *Plan, words: u64) !void {
        if (words == 0) return;
        if (self.allocation_count == self.allocations.len) return error.InvalidTraceAllocationPlan;
        self.allocations[self.allocation_count] = try std.math.mul(u64, words, 4);
        self.allocation_count += 1;
    }
};
pub fn init(a: std.mem.Allocator, input: Input) !Plan {
    if (input.format != .legacy_blake32_m31) return error.AllocationCostFormatUnavailable;
    if (input.logs.len == 0 or input.logs.len > 65535 or input.beta < 1 or input.beta > 4) return error.InvalidTraceCommitGeometry;
    if (input.separate_coefficients and input.beta != 1) return error.InvalidTraceCommitGeometry;
    const rows = try a.alloc(u32, input.logs.len);
    defer a.free(rows);
    var coefficient_words: u64 = 0;
    var max_log: u32 = 0;
    for (input.logs, rows) |log, *row| {
        if (log == 0 or log > 28 - input.beta) return error.InvalidTraceCommitGeometry;
        coefficient_words = try std.math.add(u64, coefficient_words, @as(u64, 1) << @intCast(log));
        row.* = @as(u32, 1) << @intCast(log + input.beta);
        max_log = @max(max_log, log);
    }
    std.mem.sort(u32, rows, {}, std.sort.asc(u32));
    const eval_log = max_log + input.beta;
    const tw_words = @as(u64, 1) << @intCast(eval_log - 1);
    const eval_words = try std.math.mul(u64, coefficient_words, @as(u64, 1) << @intCast(input.beta));
    // Cold forward+inverse arrays. All per-column order/offset/descriptors,
    // plan list spare capacity, returned-column headers and allocation slack
    // are bounded independently of the numerical source row count.
    const per_column = 16 + 8 + 28 + 64 + 4 * @sizeOf(S.Call) + 128;
    const host_metadata = try std.math.add(u64, try std.math.mul(u64, input.logs.len, per_column), 256 << 10);
    var out = Plan{ .coefficient_words = coefficient_words, .host_peak_bytes = try std.math.add(u64, try std.math.mul(u64, tw_words, 8), host_metadata) };
    if (input.separate_coefficients) try out.addWords(coefficient_words);
    if (input.separate_coefficients) if (input.stream_budget) |budget| {
        var stream = try S.plan(a, rows, budget);
        defer stream.deinit(a);
        const selection_aux = try std.math.add(u64, 2 * tw_words, 7 * input.logs.len);
        if (S.alignUp(@intCast(selection_aux)) + stream.scratchWords() < S.legacyScratchWords(rows, @intCast(selection_aux))) {
            const aux = S.alignUp(@intCast(try std.math.add(u64, 2 * tw_words, input.logs.len)));
            try out.addWords(try std.math.add(u64, aux, @max(stream.chunk_words, 1)));
            for (stream.bank_words) |words| try out.addWords(words);
            out.selected_stream_budget = budget;
            return out;
        }
    };
    const tw_base = try std.math.add(u64, if (input.separate_coefficients) 0 else coefficient_words, eval_words);
    const desc_base = std.mem.alignForward(u64, try std.math.add(u64, tw_base, 2 * tw_words), 2);
    const arena_words = try std.math.add(u64, desc_base, 7 * input.logs.len);
    try out.addWords(arena_words);
    const tree_words = S.treeWords(rows[rows.len - 1]);
    var prefix_words: u64 = 0;
    if (input.exact_prefix_banks) {
        var evaluations: u64 = 0;
        for (rows) |r| evaluations += r;
        prefix_words = S.legacyScratchWords(rows, 0) - evaluations - tree_words;
    } else {
        var previous_height: u32 = 0;
        for (rows[0 .. rows.len - 1], rows[1..]) |current, next| if (current != next) {
            previous_height = @max(previous_height, current);
        };
        prefix_words = 48 * @as(u64, previous_height);
    }
    try out.addWords(try std.math.add(u64, tree_words, prefix_words));
    if (!input.separate_coefficients) try out.addWords(coefficient_words);
    return out;
}

test "legacy commit charges separately retained coefficients and exact prefix banks" {
    const p = try init(std.testing.allocator, .{ .logs = &.{ 4, 5, 6 }, .beta = 2, .separate_coefficients = false, .exact_prefix_banks = true });
    try std.testing.expectEqual(@as(usize, 3), p.allocation_count);
    try std.testing.expectEqual(@as(u64, 112), p.coefficient_words);
    // eval448 + coeff112 + forward128 + inverse128 + descriptors21.
    try std.testing.expectEqual(@as(u64, 4 * (448 + 112 + 256 + 21)), p.allocations[0]);
    try std.testing.expectEqual(@as(u64, 4 * ((2 * 256 - 1) * 8 + 24 * (64 + 128))), p.allocations[1]);
    try std.testing.expectEqual(@as(u64, 448), p.allocations[2]);
    try std.testing.expectEqual(@as(u64, 38912), (try p.footprint()).small);
}

test "stream commit allocation list matches the frozen numerical plan" {
    const logs = [_]u32{16} ** 128;
    const p = try init(std.testing.allocator, .{ .logs = &logs, .beta = 1, .separate_coefficients = true, .stream_budget = 1 << 20, .exact_prefix_banks = true });
    try std.testing.expectEqual(@as(?usize, 1 << 20), p.selected_stream_budget);
    try std.testing.expectEqual(@as(usize, 4), p.allocation_count);
    const rows = [_]u32{1 << 17} ** 128;
    var stream = try S.plan(std.testing.allocator, &rows, 1 << 20);
    defer stream.deinit(std.testing.allocator);
    try std.testing.expectEqual(4 * @as(u64, S.alignUp((1 << 17) + 128) + stream.chunk_words), p.allocations[1]);
    try std.testing.expectEqual(4 * @as(u64, stream.bank_words[0]), p.allocations[2]);
    try std.testing.expectEqual(4 * @as(u64, stream.bank_words[1]), p.allocations[3]);
    try std.testing.expectError(error.InvalidTraceCommitGeometry, init(std.testing.allocator, .{ .logs = &.{27}, .beta = 2, .separate_coefficients = false }));
}

test "new hash ABI cannot reuse legacy trace allocation costs" {
    try std.testing.expectError(error.AllocationCostFormatUnavailable, init(std.testing.allocator, .{ .format = .poseidon2_w24_v1, .logs = &.{4}, .beta = 1, .separate_coefficients = true }));
}

test "D2 trace uses legacy LDE arena then independently retained final coefficients" {
    const logs = [_]u32{ 5, 7, 6, 7 };
    // A stream budget alone cannot enable the beta1-only separate-coefficients
    // ABI. D2 retains source + LDE arena + tree while final coeffs are copied.
    const p = try init(std.testing.allocator, .{ .logs = &logs, .beta = 2, .separate_coefficients = false, .stream_budget = 1 << 20, .exact_prefix_banks = true });
    const no_stream = try init(std.testing.allocator, .{ .logs = &logs, .beta = 2, .separate_coefficients = false, .exact_prefix_banks = true });
    try std.testing.expect(p.selected_stream_budget == null);
    try std.testing.expectEqualSlices(u64, no_stream.bytes(), p.bytes());
    try std.testing.expectEqual(@as(usize, 3), p.allocation_count);
    const coeff: u64 = 32 + 128 + 64 + 128;
    try std.testing.expectEqual(coeff, p.coefficient_words);
    try std.testing.expectEqual(@as(u64, 4 * (coeff * 5 + 2 * 256 + 7 * logs.len)), p.allocations[0]);
    // Coefficient copy is a distinct allocation AFTER the tree; no aliasing of
    // the old evaluations/arena is admitted by this numerical allocation plan.
    try std.testing.expectEqual(4 * coeff, p.allocations[2]);
    try std.testing.expect(!p.host_cost_known);
    try std.testing.expectError(error.InvalidTraceCommitGeometry, init(std.testing.allocator, .{ .logs = &logs, .beta = 2, .separate_coefficients = true, .stream_budget = 1 << 20 }));
}
