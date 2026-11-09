//! One bounded streaming metadata pass builds Eq + projected prefix planes.
//! No row×query matrix, second wide MAIN witness or retained provider ownership.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const M = core.fields.m31.M31;
const O = core.fields.om31.OM31;
const V = engine.lookups.gkr_verifier.ForField(O);
const Work = engine.lookups.row_work;
const Shared = @import("../../word16_global_execution/services/gkr_local/witness.zig");
const Frame = @import("../../word16_global_execution/services/gkr_local/truth_frame.zig");
const TF = @import("../../word16_global_execution/services/gkr_local/truth_fractions.zig");
const Native = @import("native.zig");
const Shapes = @import("authority.zig");
fn get(data: []const M, rows: usize, offset: usize, p: usize) O {
    var v: [8]M = undefined;
    for (&v, 0..) |*x, i| x.* = data[(offset + i) * rows + p];
    return O.fromM31Array(v);
}
fn set(data: []M, rows: usize, offset: usize, p: usize, v: O) void {
    for (v.toM31Array(), 0..) |x, i| data[(offset + i) * rows + p] = x;
}
pub const Witness = struct {
    allocator: std.mem.Allocator,
    columns: [3][]M,
    pub fn init(a: std.mem.Allocator, shapes: [3]Shapes.Shape, challenges: *const Native.Challenges, provider: anytype, artifact: *const V.GkrArtifact, eta: O) !Witness {
        return initWithOptions(a, shapes, challenges, provider, artifact, eta, .{});
    }
    pub fn initWithOptions(a: std.mem.Allocator, shapes: [3]Shapes.Shape, challenges: *const Native.Challenges, provider: anytype, artifact: *const V.GkrArtifact, eta: O, options: Work.RangeOptions) !Witness {
        try Shapes.validate(shapes);
        if (artifact.claims_to_verify_by_instance.len != 3 or artifact.n_variables_by_instance.len != 3) return error.LocalGkrProjectionShape;
        var out: Witness = .{ .allocator = a, .columns = undefined };
        var done: usize = 0;
        errdefer for (out.columns[0..done]) |data| a.free(data);
        for (shapes, 0..) |shape, index| {
            const instance = shape.instance();
            const point = try Native.splitPoint(instance, artifact.ood_point, artifact.n_variables_by_instance[index]);
            const claims = artifact.claims_to_verify_by_instance[index];
            if (claims.len != 2) return error.LocalGkrProjectionShape;
            const rows = try instance.rows();
            const lanes = @as(usize, 1) << @intCast(try instance.laneLog());
            const data = try a.alloc(M, try std.math.mul(usize, rows, 16));
            errdefer a.free(data);
            try Shared.eqIntoWithOptions(data, rows, point.row, options);
            const lane_planes = try a.alloc(M, 8 * lanes);
            defer a.free(lane_planes);
            try Shared.eqInto(lane_planes, lanes, point.lane);
            const weights = try a.alloc(O, lanes);
            defer a.free(weights);
            for (weights, 0..) |*w, i| w.* = get(lane_planes, lanes, 0, i);
            const target = claims[0].add(eta.mul(claims[1])).mulM31(try M.fromCanonical(@intCast(rows)).inv());
            const Context = struct {
                data: []M,
                rows: usize,
                instance: Frame.Instance,
                challenges: *const Native.Challenges,
                provider: @TypeOf(provider),
                weights: []const O,
                eta: O,
                target: O,
                errors: [Work.MAX_SHARDS]?anyerror = @splat(null),
                const Outer = @This();
                const Sink = struct {
                    ctx: *const Outer,
                    used: usize = 0,
                    n: O = .zero(),
                    d: O = .zero(),
                    invalid: bool = false,
                    pub fn emitBase(self: *@This(), relation: TF.Relation, tuple: anytype, weight: M) void {
                        if (self.used >= self.ctx.instance.queries) {
                            self.invalid = true;
                            return;
                        }
                        const eq = self.ctx.weights[self.used];
                        self.n = self.n.add(eq.mulM31(weight));
                        self.d = self.d.add(eq.mul(self.ctx.challenges.denominatorBase(relation, tuple)));
                        self.used += 1;
                    }
                };
                pub fn runRange(self: *@This(), ordinal: usize, start: usize, end: usize) void {
                    self.fillRange(start, end) catch |err| {
                        self.errors[ordinal] = err;
                    };
                }
                fn fillRange(self: *@This(), start: usize, end: usize) !void {
                    for (start..end) |p| {
                        const logical = core.utils.circleDomainIndexToCosetIndex(core.utils.bitReverseIndex(p, self.instance.row_log), self.instance.row_log);
                        var sink = Sink{ .ctx = self };
                        try self.provider.emitRange(self.instance, logical, 0, self.instance.queries, &sink);
                        if (sink.invalid or sink.used != self.instance.queries) return error.LocalGkrProjectionShape;
                        for (self.weights[self.instance.queries..]) |w| sink.d = sink.d.add(w);
                        const projection = sink.n.add(self.eta.mul(sink.d));
                        set(self.data, self.rows, 8, p, get(self.data, self.rows, 0, p).mul(projection).sub(self.target));
                    }
                }
            };
            var ctx = Context{ .data = data, .rows = rows, .instance = instance, .challenges = challenges, .provider = provider, .weights = weights, .eta = eta, .target = target };
            // The pool's standard error propagation joins every metadata reader.
            const shards = Work.forEachRange(rows, &ctx, options);
            for (ctx.errors[0..shards]) |err| if (err) |e| return e;
            try Shared.prefixProjectedWithOptions(data, rows, instance.row_log, options);
            out.columns[index] = data;
            done += 1;
        }
        return out;
    }
    pub fn deinit(self: *Witness) void {
        for (self.columns) |data| self.allocator.free(data);
        self.* = undefined;
    }
};
