//! One-pass durable metadata projection. Only N (M31) and D (OM31) vectors are
//! retained: no tuple planes, wide MAIN rows, coefficients or FFT expansion.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const M = core.fields.m31.M31;
const O = core.fields.om31.OM31;
const GP = engine.lookups.gkr_prover.ForField(O);
const Mle = engine.lookups.mle.MleFor;
const Fractions = @import("fractions.zig");
const Frame = @import("frame.zig");
const Work = engine.lookups.row_work;
const Challenges = @import("challenges.zig").For(O);
pub const RowSink = struct {
    challenges: *const Challenges,
    numerator: []M = &.{},
    denominator: []O = &.{},
    /// Explicit terminal-projection mode; retains no N/D matrix. Canonicality
    /// and original provider tuple authority remain exactly the same.
    projection: ?*@import("prepared_projection.zig").For(O).Projection = null,
    catalog: ?[]Fractions.Relation = null,
    count: usize = 0,
    invalid: bool = false,
    pub fn emit(self: *RowSink, relation: Fractions.Relation, tuple: anytype, weight: O) void {
        if (self.count >= (if (self.projection) |p| p.prepared.entries.len else self.numerator.len)) {
            self.invalid = true;
            return;
        }
        const coordinates = weight.toM31Array();
        for (coordinates[1..]) |c| if (!c.isZero()) {
            self.invalid = true;
            return;
        };
        var base: [tuple.len]M = undefined;
        for (tuple, &base) |value, *out| {
            const c = value.toM31Array();
            for (c[1..]) |v| if (!v.isZero()) {
                self.invalid = true;
                return;
            };
            out.* = c[0];
        }
        self.emitBase(relation, base, coordinates[0]);
    }
    pub fn emitBase(self: *RowSink, relation: Fractions.Relation, tuple: anytype, weight: M) void {
        if (self.count >= (if (self.projection) |p| p.prepared.entries.len else self.numerator.len)) {
            self.invalid = true;
            return;
        }
        if (weight.v >= core.fields.m31.Modulus) {
            self.invalid = true;
            return;
        }
        for (tuple) |value| if (value.v >= core.fields.m31.Modulus) {
            self.invalid = true;
            return;
        };
        if (self.catalog) |relations| {
            if (self.count >= relations.len) {
                self.invalid = true;
                return;
            }
            relations[self.count] = relation;
        }
        if (self.projection) |p| p.emitBase(relation, tuple, weight) else {
            self.numerator[self.count] = weight;
            self.denominator[self.count] = self.challenges.denominatorBase(relation, tuple);
        }
        self.count += 1;
    }
};
pub const Inputs = struct {
    allocator: std.mem.Allocator,
    layers: []GP.Layer,
    pub fn init(a: std.mem.Allocator, instances: []const Frame.Instance, challenges: *const Challenges, provider: anytype) !Inputs {
        return initWithOptions(a, instances, challenges, provider, .{});
    }
    pub fn initWithOptions(a: std.mem.Allocator, instances: []const Frame.Instance, challenges: *const Challenges, provider: anytype, options: Work.RangeOptions) !Inputs {
        const layers = try a.alloc(GP.Layer, instances.len);
        var done: usize = 0;
        errdefer {
            for (layers[0..done]) |*layer| layer.deinit(a);
            a.free(layers);
        }
        for (instances, layers) |instance, *layer| {
            const facts = try instance.facts();
            const n = try a.alloc(M, facts);
            errdefer a.free(n);
            const d = try a.alloc(O, facts);
            errdefer a.free(d);
            const lane_count: usize = @as(usize, 1) << @intCast(try instance.laneLog());
            const Context = struct {
                instance: Frame.Instance,
                challenges: *const Challenges,
                provider: @TypeOf(provider),
                n: []M,
                d: []O,
                lanes: usize,
                errors: [Work.MAX_SHARDS]?anyerror = @splat(null),
                pub fn runRange(self: *@This(), ordinal: usize, start: usize, end: usize) void {
                    for (start..end) |physical| {
                        const at = physical * self.lanes;
                        // Initialize padding with the row that first touches its
                        // pages. No serial whole-vector pass before projection.
                        @memset(self.n[at..][0..self.lanes], M.zero());
                        @memset(self.d[at..][0..self.lanes], O.one());
                        const logical = core.utils.circleDomainIndexToCosetIndex(core.utils.bitReverseIndex(physical, self.instance.row_log), self.instance.row_log);
                        var sink = RowSink{ .challenges = self.challenges, .numerator = self.n[at..][0..self.instance.terms], .denominator = self.d[at..][0..self.instance.terms] };
                        self.provider.emit(self.instance, logical, &sink) catch |err| {
                            self.errors[ordinal] = err;
                            return;
                        };
                        if (sink.invalid or sink.count != self.instance.terms) {
                            self.errors[ordinal] = error.LocalGkrMetadataShape;
                            return;
                        }
                    }
                }
            };
            var context = Context{ .instance = instance, .challenges = challenges, .provider = provider, .n = n, .d = d, .lanes = lane_count };
            const shards = Work.forEachRange(try instance.rows(), &context, options);
            for (context.errors[0..shards]) |err| if (err) |failure| return failure;
            layer.* = .{ .LogUpMultiplicities = .{ .numerators = try Mle(O, M).initOwned(n), .denominators = try Mle(O, O).initOwned(d) } };
            done += 1;
        }
        return .{ .allocator = a, .layers = layers };
    }
    /// Transfers the heap layer descriptors AND their MLE owners. The caller
    /// must pass the result to a consuming GKR API even on failure.
    pub fn takeLayers(self: *Inputs) []GP.Layer {
        const out = self.layers;
        self.layers = &.{};
        return out;
    }
    pub fn deinit(self: *Inputs) void {
        for (self.layers) |*layer| layer.deinit(self.allocator);
        self.allocator.free(self.layers);
        self.* = undefined;
    }
};
