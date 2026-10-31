//! Native UNIT JALR composite advice. SUM is advice, not trusted arithmetic:
//! physical ADD/AND providers must close the positive support requests.
const std = @import("std");
const core = @import("stwo_core");
const front = @import("stwo_riscv_frontend");
const X = front.rv64_air.word16_execution;
const J = X.jalr_equations;
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
pub const Fact = struct { op: u8 = 10, a: u64, b: u64, c: u64 };
pub const Source = struct {
    allocator: std.mem.Allocator,
    facts: []Fact,
    fixed: []M,
    main: []M,
    interaction: []M = &.{},
    rows: u32,
    log_size: u32,
    claim: ?Q = null,
    pub fn init(a: std.mem.Allocator, facts: []const Fact, log: u32) !Source {
        if (log < 5 or log > 22 or facts.len > @as(usize, 1) << @intCast(log)) return error.InvalidJalrGeometry;
        for (facts) |fact| if (fact.op != 10) return error.InvalidJalrFact;
        const owned = try a.dupe(Fact, facts);
        errdefer a.free(owned);
        const n = @as(usize, 1) << @intCast(log);
        const fixed = try a.alloc(M, 2 * n);
        errdefer a.free(fixed);
        @memset(fixed, M.zero());
        fixed[X.layout.physical(0, log)] = M.one();
        fixed[n + X.layout.physical(n - 1, log)] = M.one();
        const main = try a.alloc(M, J.MAIN * n);
        errdefer a.free(main);
        const source = Source{ .allocator = a, .facts = owned, .fixed = fixed, .main = main, .rows = @intCast(facts.len), .log_size = log };
        for (0..n) |physical| {
            const logical = core.utils.circleDomainIndexToCosetIndex(core.utils.bitReverseIndex(physical, log), log);
            const row = source.rowValues(logical);
            for (row, 0..) |value, c| main[c * n + physical] = value;
        }
        return source;
    }
    pub fn deinit(self: *Source) void {
        self.allocator.free(self.interaction);
        self.allocator.free(self.main);
        self.allocator.free(self.fixed);
        self.allocator.free(self.facts);
        self.* = undefined;
    }
    pub fn releaseMain(self: *Source) void {
        self.allocator.free(self.main);
        self.main = &.{};
    }
    pub fn size(self: *const Source) usize {
        return @as(usize, 1) << @intCast(self.log_size);
    }
    pub fn rowValues(self: *const Source, logical: usize) [J.MAIN]M {
        var row: [J.MAIN]M = @splat(M.zero());
        if (logical < self.facts.len) {
            const fact = self.facts[logical];
            X.features.put(&row, 0, fact.a);
            X.features.put(&row, 4, fact.b);
            X.features.put(&row, 8, fact.c);
            X.features.put(&row, 12, fact.a +% fact.b);
            row[J.ACTIVE] = M.one();
            row[J.WEIGHT] = M.one();
        }
        return row;
    }
    pub fn aluFacts(self: *const Source, a: std.mem.Allocator) ![]front.rv64_air.word16_v1.operations.AluFact {
        const out = try a.alloc(front.rv64_air.word16_v1.operations.AluFact, self.facts.len);
        for (out, self.facts) |*value, fact| value.* = .{ .op = .add, .a = fact.a, .b = fact.b, .c = fact.a +% fact.b };
        return out;
    }
    pub fn binaryFacts(self: *const Source, a: std.mem.Allocator) ![]front.rv64_air.word16_v1.binary_source.Fact {
        const out = try a.alloc(front.rv64_air.word16_v1.binary_source.Fact, self.facts.len);
        for (out, self.facts) |*value, fact| value.* = .{ .op = .and_, .a = fact.a +% fact.b, .b = ~@as(u64, 1), .c = fact.c };
        return out;
    }
    pub fn generate(self: *Source, ch: X.types.FunctionChallenges) !Q {
        if (self.claim != null or self.interaction.len != 0) return error.InvalidJalrPhase;
        const a = self.allocator;
        const n = self.size();
        const out = try a.alloc(M, J.INTERACTION * n);
        errdefer a.free(out);
        const contributions = try a.alloc(Q, self.facts.len);
        defer a.free(contributions);
        const pad = self.rowValues(n);
        var pad_inverse: [2]Q = undefined;
        if (self.facts.len < n) {
            const pd = J.nativeDenominators(&pad, ch);
            pad_inverse = .{ try pd.request.inv(), try pd.add.mul(pd.and_).inv() };
        }
        var claim = Q.zero();
        for (0..n) |logical| {
            const row = self.rowValues(logical);
            const inverse = if (logical < self.facts.len) blk: {
                const ds = J.nativeDenominators(&row, ch);
                const values = [_]Q{ try ds.request.inv(), try ds.add.mul(ds.and_).inv() };
                contributions[logical] = J.contributionFor(Q, ds, Q.one(), values[0], values[1]);
                claim = claim.add(contributions[logical]);
                break :blk values;
            } else pad_inverse;
            const physical = X.layout.physical(logical, self.log_size);
            for (inverse, 0..) |value, column| for (value.toM31Array(), 0..) |limb, i| {
                out[(4 * column + i) * n + physical] = limb;
            };
        }
        var sum = claim.neg();
        for (0..n) |logical| {
            if (logical < self.facts.len) sum = sum.add(contributions[logical]);
            const physical = X.layout.physical(logical, self.log_size);
            for (sum.toM31Array(), 0..) |limb, c| out[(8 + c) * n + physical] = limb;
        }
        std.debug.assert(sum.isZero());
        self.interaction = out;
        self.claim = claim;
        return claim;
    }
};
