//! Shared bounded global LogUp producer. Providers fill only one row of secure
//! denominators/numerators; no tuple planes, root challenges or wide MAIN copies.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const A = @import("stwo_riscv_frontend").rv64_air;
const O = core.fields.om31.OM31;
const M = core.fields.m31.M31;
const Commit = @import("../../../word16_execution/main_ownership.zig").Commit;
pub const MAX_TERMS = 32;
pub const MAX_GROUPS = 4;
pub const ROW_CHUNK = 256;
pub const Group = struct { inverses: u16 };
pub const Numerator = union(enum) {
    base: M,
    secure: O,
    pub fn multiply(self: @This(), inverse: O) O {
        return switch (self) {
            .base => |v| inverse.mulM31(v),
            .secure => |v| inverse.mul(v),
        };
    }
};
/// Shared task-admission and runtime scratch ceiling. Parallel workers divide
/// this same former serial allowance; increasing concurrency cannot borrow
/// unadmitted memory from the rest of the frontend task.
pub fn scratchByteUpperBound(log: u32, terms: usize) !usize {
    if (log < 5 or log > 22 or terms > 640) return error.InvalidClassicWitnessShape;
    const rows = @as(usize, 1) << @intCast(log);
    return std.math.mul(usize, try std.math.mul(usize, @min(rows, ROW_CHUNK), terms), 2 * @sizeOf(O) + @sizeOf(Numerator));
}
pub const Witness = struct {
    allocator: std.mem.Allocator,
    log_size: u32,
    groups: [MAX_GROUPS]Group,
    group_count: usize,
    data: []M,
    claims: [MAX_GROUPS]O,
    pub fn width(self: *const Witness) usize {
        var n: usize = 0;
        for (self.groups[0..self.group_count]) |g| n += 8 * (@as(usize, g.inverses) + 1);
        return n;
    }
    pub fn claimSlice(self: *const Witness) []const O {
        return self.claims[0..self.group_count];
    }
    pub fn init(allocator: std.mem.Allocator, log: u32, groups: []const Group, provider: anytype, budget: usize) !Witness {
        return initBounded(MAX_TERMS, allocator, log, groups, provider, budget);
    }
    /// Explicit separately admitted wide truth catalog; CPU callers retain32.
    pub fn initTruth(allocator: std.mem.Allocator, log: u32, groups: []const Group, provider: anytype, budget: usize) !Witness {
        return initBounded(640, allocator, log, groups, provider, budget);
    }
    fn initBounded(comptime max_terms: usize, allocator: std.mem.Allocator, log: u32, groups: []const Group, provider: anytype, budget: usize) !Witness {
        if (log < 5 or log > 22 or groups.len == 0 or groups.len > MAX_GROUPS) return error.InvalidClassicWitnessShape;
        var terms: usize = 0;
        var width_: usize = 0;
        for (groups) |g| {
            if (g.inverses == 0) return error.InvalidClassicWitnessShape;
            terms += g.inverses;
            width_ += 8 * (@as(usize, g.inverses) + 1);
        }
        if (terms > max_terms) return error.InvalidClassicWitnessShape;
        const rows = @as(usize, 1) << @intCast(log);
        const cells = try std.math.mul(usize, width_, rows);
        const scratch_terms = try std.math.mul(usize, @min(rows, ROW_CHUNK), terms);
        const output_bytes = try std.math.mul(usize, cells, @sizeOf(M));
        const ProviderType = if (@typeInfo(@TypeOf(provider)) == .pointer) @typeInfo(@TypeOf(provider)).pointer.child else @TypeOf(provider);
        if (comptime @hasDecl(ProviderType, "PARALLEL_SAFE") and ProviderType.PARALLEL_SAFE) {
            const generated = try @import("classic_witness_parallel.zig").generate(allocator, log, groups, provider, budget);
            var stored: [MAX_GROUPS]Group = @splat(.{ .inverses = 0 });
            @memcpy(stored[0..groups.len], groups);
            return .{ .allocator = allocator, .log_size = log, .groups = stored, .group_count = groups.len, .data = generated.data, .claims = generated.claims };
        }
        const scratch_bytes = try scratchByteUpperBound(log, terms);
        if (try std.math.add(usize, output_bytes, scratch_bytes) > budget) return error.ClassicWitnessBudgetExceeded;
        const data = try allocator.alloc(M, cells);
        errdefer allocator.free(data);
        const d = try allocator.alloc(O, scratch_terms);
        defer allocator.free(d);
        const inverses = try allocator.alloc(O, scratch_terms);
        defer allocator.free(inverses);
        const numerators = try allocator.alloc(Numerator, scratch_terms);
        defer allocator.free(numerators);
        var claims: [MAX_GROUPS]O = @splat(O.zero());
        var start: usize = 0;
        while (start < rows) : (start += ROW_CHUNK) {
            const end = @min(start + ROW_CHUNK, rows);
            const count = (end - start) * terms;
            @memset(d[0..count], O.zero());
            @memset(numerators[0..count], .{ .base = M.zero() });
            for (start..end) |logical| {
                const offset = (logical - start) * terms;
                // Missing slots fail the strict inverse, including zero-weight
                // queries. No tuple planes are retained across this chunk.
                try provider.fill(logical, d[offset..][0..terms], numerators[offset..][0..terms]);
            }
            // One extension-field inversion per bounded row chunk, not per row.
            try core.fields.batchInverseInPlace(O, d[0..count], inverses[0..count]);
            for (start..end) |logical| {
                const row = A.witness.physical(logical, log);
                var term: usize = (logical - start) * terms;
                var column: usize = 0;
                for (groups, 0..) |g, index| {
                    for (0..g.inverses) |_| {
                        for (inverses[term].toM31Array(), 0..) |v, c| data[(column + c) * rows + row] = v;
                        claims[index] = claims[index].add(numerators[term].multiply(inverses[term]));
                        term += 1;
                        column += 8;
                    }
                    for (claims[index].toM31Array(), 0..) |v, c| data[(column + c) * rows + row] = v;
                    column += 8;
                }
            }
        }
        var column: usize = 0;
        for (groups, 0..) |g, index| {
            column += 8 * @as(usize, g.inverses);
            for (claims[index].toM31Array(), 0..) |v, c| for (data[(column + c) * rows ..][0..rows]) |*cell| {
                cell.* = cell.sub(v);
            };
            column += 8;
        }
        var stored: [MAX_GROUPS]Group = @splat(.{ .inverses = 0 });
        @memcpy(stored[0..groups.len], groups);
        return .{ .allocator = allocator, .log_size = log, .groups = stored, .group_count = groups.len, .data = data, .claims = claims };
    }
    pub fn deinit(self: *Witness) void {
        self.allocator.free(self.data);
        self.* = undefined;
    }
    pub fn columns(self: *const Witness, allocator: std.mem.Allocator) ![]engine.pcs.ColumnEvaluation {
        const rows = @as(usize, 1) << @intCast(self.log_size);
        const width_ = self.width();
        if (self.data.len != width_ * rows) return error.InvalidClassicWitnessPhase;
        const result = try allocator.alloc(engine.pcs.ColumnEvaluation, width_);
        for (result, 0..) |*column, c| column.* = .{ .log_size = self.log_size, .values = self.data[c * rows ..][0..rows] };
        return result;
    }
    pub fn take(self: *Witness) !Commit {
        const result = try self.columns(self.allocator);
        errdefer self.allocator.free(result);
        const backing = try self.allocator.alloc([]M, 1);
        backing[0] = self.data;
        self.data = &.{};
        return .{ .columns = result, .backings = backing };
    }
};
