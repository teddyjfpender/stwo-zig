//! Admitted row-major truth fact vectors. Only N(M31) and D(OM31) survive;
//! scratch is one callback tuple, with unused lanes exactly0/1.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const O = core.fields.om31.OM31;
const M = core.fields.m31.M31;
const GP = engine.lookups.gkr_prover.ForField(O);
const Mle = engine.lookups.mle.MleFor;
const F = @import("truth_fractions.zig");
const Frame = @import("truth_frame.zig");
const Metadata = @import("truth_metadata.zig");
const RowSink = struct {
    challenges: *const F.ChallengesFor(O),
    n: []M,
    d: []O,
    count: usize = 0,
    invalid: bool = false,
    pub fn emitBase(self: *@This(), relation: F.Relation, tuple: anytype, weight: M) void {
        if (self.count >= self.n.len) {
            self.invalid = true;
            return;
        }
        self.n[self.count] = weight;
        self.d[self.count] = self.challenges.denominatorBase(relation, tuple);
        self.count += 1;
    }
};
pub const Inputs = struct {
    allocator: std.mem.Allocator,
    layers: []GP.Layer,
    pub fn init(allocator: std.mem.Allocator, provider: *const Metadata.Provider, challenges: *const F.ChallengesFor(O), budget: usize) !Inputs {
        _ = try Frame.Plan.admit(&provider.frames, budget); // No allocations before admission.
        const layers = try allocator.alloc(GP.Layer, provider.frames.len);
        errdefer allocator.free(layers);
        var done: usize = 0;
        errdefer for (layers[0..done]) |*layer| layer.deinit(allocator);
        for (provider.frames, layers) |instance, *layer| {
            const facts = try instance.facts();
            const rows = try instance.rows();
            const n = try allocator.alloc(M, facts);
            errdefer allocator.free(n);
            const d = try allocator.alloc(O, facts);
            errdefer allocator.free(d);
            @memset(n, M.zero());
            @memset(d, O.one());
            const width = @as(usize, 1) << @intCast(try instance.laneLog());
            for (0..rows) |physical| {
                const logical = core.utils.circleDomainIndexToCosetIndex(core.utils.bitReverseIndex(physical, instance.row_log), instance.row_log);
                const at = physical * width;
                var sink = RowSink{ .challenges = challenges, .n = n[at..][0..instance.queries], .d = d[at..][0..instance.queries] };
                try provider.emit(instance, logical, &sink);
                if (sink.invalid or sink.count != instance.queries) return error.TruthGkrQueryCountMismatch;
            }
            layer.* = .{ .LogUpMultiplicities = .{ .numerators = try Mle(O, M).initOwned(n), .denominators = try Mle(O, O).initOwned(d) } };
            done += 1;
        }
        return .{ .allocator = allocator, .layers = layers };
    }
    pub fn deinit(self: *Inputs) void {
        for (self.layers) |*layer| layer.deinit(self.allocator);
        self.allocator.free(self.layers);
        self.* = undefined;
    }
};
