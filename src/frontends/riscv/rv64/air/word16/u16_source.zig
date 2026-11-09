//! Canonical U16 material and per-proof counts. The AIR authority is shared
//! unchanged with the thin CPU range provider, not duplicated here.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const E = @import("../evaluation.zig");
const Range = @import("../providers/scalar_range.zig");
const Bus = @import("function_bus.zig");
const physical = @import("../witness.zig").physical;
const M = core.fields.m31.M31;
const Q = E.Q;
pub const LOG = 16;
pub const SIZE = 65536;
pub const Challenges = Range.Challenges;
pub const Setup = struct {
    allocator: std.mem.Allocator,
    fixed: []M,
    pub fn init(a: std.mem.Allocator) !Setup {
        const fixed = try a.alloc(M, 3 * SIZE);
        @memset(fixed, M.zero());
        for (0..SIZE) |i| fixed[physical(i, LOG)] = M.fromCanonical(@intCast(i));
        fixed[SIZE + physical(0, LOG)] = M.one();
        fixed[2 * SIZE + physical(SIZE - 1, LOG)] = M.one();
        return .{ .allocator = a, .fixed = fixed };
    }
    pub fn deinit(self: *Setup) void {
        self.allocator.free(self.fixed);
        self.* = undefined;
    }
};
pub const Source = struct {
    allocator: std.mem.Allocator,
    fixed: []const M,
    counts: []const u64,
    main: []M,
    interaction: []M = &.{},
    dictionary: []Q = &.{},
    claim: ?Q = null,
    /// Setup/counts remain borrowed through generate; MAIN can be released.
    pub fn init(a: std.mem.Allocator, setup: *const Setup, counts: []const u64) !Source {
        if (counts.len != SIZE or setup.fixed.len != 3 * SIZE) return error.InvalidU16Source;
        _ = try Bus.admitPositiveMass(counts);
        const main = try a.alloc(M, SIZE);
        for (counts, 0..) |count, i| main[physical(i, LOG)] = M.fromCanonical(@intCast(count));
        return .{ .allocator = a, .fixed = setup.fixed, .counts = counts, .main = main };
    }
    pub fn deinit(self: *Source) void {
        self.releaseMain();
        self.allocator.free(self.interaction);
        self.allocator.free(self.dictionary);
        self.* = undefined;
    }
    pub fn releaseMain(self: *Source) void {
        self.allocator.free(self.main);
        self.main = &.{};
    }
    pub fn columns(self: *const Source, a: std.mem.Allocator, tree: u2) ![]engine.pcs.ColumnEvaluation {
        const data = switch (tree) {
            0 => self.fixed,
            1 => self.main,
            2 => self.interaction,
            else => return error.InvalidU16Tree,
        };
        if (data.len == 0) return error.InvalidU16Phase;
        const result = try a.alloc(engine.pcs.ColumnEvaluation, data.len / SIZE);
        for (result, 0..) |*v, c| v.* = .{ .log_size = LOG, .values = data[c * SIZE ..][0..SIZE] };
        return result;
    }
    pub fn generate(self: *Source, ch: Challenges) !Q {
        if (self.interaction.len != 0 or self.dictionary.len != 0) return error.InvalidU16Phase;
        if (self.counts.len != SIZE) return error.InvalidU16Source;
        _ = try Bus.admitPositiveMass(self.counts);
        const a = self.allocator;
        const output = try a.alloc(M, 8 * SIZE);
        errdefer a.free(output);
        const dictionary = try a.alloc(Q, SIZE);
        errdefer a.free(dictionary);
        const scratch = try a.alloc(Q, 4096);
        defer a.free(scratch);
        var start: usize = 0;
        while (start < SIZE) : (start += 4096) {
            var i: usize = 0;
            while (i < 4096) : (i += E.LANES) {
                var lanes: [E.LANES]M = undefined;
                for (&lanes, 0..) |*value, lane| value.* = M.fromCanonical(@intCast(start + i + lane));
                const values = ch.denominatorFor(E.PackedBase, E.PackedBase.fromLanes(lanes));
                for (0..E.LANES) |lane| scratch[i + lane] = values.lane(lane);
            }
            try core.fields.batchInverseInPlace(Q, scratch, dictionary[start..][0..4096]);
        }
        var claim = Q.zero();
        for (self.counts, dictionary) |count, inverse| claim = claim.sub(inverse.mulM31(M.fromCanonical(@intCast(count))));
        var sum = claim.neg();
        for (self.counts, dictionary, 0..) |count, inverse, i| {
            sum = sum.sub(inverse.mulM31(M.fromCanonical(@intCast(count))));
            const row = physical(i, LOG);
            for (inverse.toM31Array(), 0..) |value, c| output[c * SIZE + row] = value;
            for (sum.toM31Array(), 0..) |value, c| output[(4 + c) * SIZE + row] = value;
        }
        std.debug.assert(sum.isZero());
        self.interaction = output;
        self.dictionary = dictionary;
        self.claim = claim;
        return claim;
    }
};
