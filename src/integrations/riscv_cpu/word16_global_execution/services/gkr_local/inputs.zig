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
const Challenges = @import("challenges.zig").For(O);
pub const RowSink = struct {
    challenges: *const Challenges,
    numerator: []M,
    denominator: []O,
    count: usize = 0,
    invalid: bool = false,
    pub fn emit(self: *RowSink, relation: Fractions.Relation, tuple: anytype, weight: O) void {
        if (self.count >= self.numerator.len) {
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
        self.numerator[self.count] = coordinates[0];
        self.denominator[self.count] = self.challenges.denominatorBase(relation, base);
        self.count += 1;
    }
    pub fn emitBase(self: *RowSink, relation: Fractions.Relation, tuple: anytype, weight: M) void {
        if (self.count >= self.numerator.len) {
            self.invalid = true;
            return;
        }
        self.numerator[self.count] = weight;
        self.denominator[self.count] = self.challenges.denominatorBase(relation, tuple);
        self.count += 1;
    }
};
pub const Inputs = struct {
    allocator: std.mem.Allocator,
    layers: []GP.Layer,
    pub fn init(a: std.mem.Allocator, instances: []const Frame.Instance, challenges: *const Challenges, provider: anytype) !Inputs {
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
            @memset(n, M.zero());
            @memset(d, O.one());
            const lane_count: usize = @as(usize, 1) << @intCast(try instance.laneLog());
            for (0..try instance.rows()) |physical| {
                const logical = core.utils.circleDomainIndexToCosetIndex(core.utils.bitReverseIndex(physical, instance.row_log), instance.row_log);
                const at = physical * lane_count;
                var sink = RowSink{ .challenges = challenges, .numerator = n[at..][0..instance.terms], .denominator = d[at..][0..instance.terms] };
                try provider.emit(instance, logical, &sink);
                if (sink.invalid or sink.count != instance.terms) return error.LocalGkrMetadataShape;
            }
            layer.* = .{ .LogUpMultiplicities = .{ .numerators = try Mle(O, M).initOwned(n), .denominators = try Mle(O, O).initOwned(d) } };
            done += 1;
        }
        return .{ .allocator = a, .layers = layers };
    }
    pub fn deinit(self: *Inputs) void {
        for (self.layers) |*layer| layer.deinit(self.allocator);
        self.allocator.free(self.layers);
        self.* = undefined;
    }
};
