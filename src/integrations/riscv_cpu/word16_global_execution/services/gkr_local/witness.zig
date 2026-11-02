//! Eq and N+eta*D prefix witness in16 column-major base planes. Optional
//! deferred storage owns only eight unweighted projection planes; immutable
//! metadata replay and finalization share the original tuple/prefix authority.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const M = core.fields.m31.M31;
const O = core.fields.om31.OM31;
const V = engine.lookups.gkr_verifier.ForField(O);
const Frame = @import("frame.zig");
const Work = engine.lookups.row_work;
const Input = @import("inputs.zig").Inputs;
fn get(data: []const M, rows: usize, offset: usize, p: usize) O {
    var coordinates: [8]M = undefined;
    for (&coordinates, 0..) |*v, i| v.* = data[(offset + i) * rows + p];
    return O.fromM31Array(coordinates);
}
fn set(data: []M, rows: usize, offset: usize, p: usize, value: O) void {
    for (value.toM31Array(), 0..) |v, i| data[(offset + i) * rows + p] = v;
}
pub fn eqInto(data: []M, rows: usize, point: []const O) !void {
    return eqIntoWithOptions(data, rows, point, .{});
}
pub fn eqIntoWithOptions(data: []M, rows: usize, point: []const O, options: Work.RangeOptions) !void {
    if (data.len < 8 * rows or rows != @as(usize, 1) << @intCast(point.len)) return error.LocalGkrEqShape;
    set(data, rows, 0, 0, O.one());
    // Reverse variables with contiguous halves: each job replaces only its own
    // old slots and appends disjoint new slots. No in-place scatter dependency.
    const Expansion = struct {
        data: []M,
        rows: usize,
        len: usize,
        r: O,
        complement: O,
        pub fn runRange(self: *@This(), _: usize, start: usize, end: usize) void {
            for (start..end) |i| {
                const value = get(self.data, self.rows, 0, i);
                set(self.data, self.rows, 0, i, value.mul(self.complement));
                set(self.data, self.rows, 0, self.len + i, value.mul(self.r));
            }
        }
    };
    var len: usize = 1;
    var k = point.len;
    while (k > 0) {
        k -= 1;
        var expansion = Expansion{ .data = data, .rows = rows, .len = len, .r = point[k], .complement = O.one().sub(point[k]) };
        _ = Work.forEachRange(len, &expansion, options);
        len *= 2;
    }
}
// Each row's lane values are contiguous. Reduce native packs directly, keeping
// the original scalar tail for short families; no extra projected plane or
// ownership transition is needed. Field addition is exact, so regrouping lanes
// preserves the authenticated scalar projection.
fn projectLanes(weights: []const O, numerators: []const M, denominators: []const O) struct { n: O, d: O } {
    const Packed = engine.lookups.packed_rows.ForField(O);
    var pn = Packed.splat(O.zero());
    var pd = Packed.splat(O.zero());
    var i: usize = 0;
    while (i + engine.lookups.packed_rows.WIDTH <= weights.len) : (i += engine.lookups.packed_rows.WIDTH) {
        const w = Packed.load(weights, i, 1);
        pn = pn.add(w.mulBase(Packed.base(numerators, i, 1)));
        pd = pd.add(Packed.mul(w, Packed.load(denominators, i, 1)));
    }
    var n = Packed.sum(pn);
    var d = Packed.sum(pd);
    for (weights[i..], numerators[i..], denominators[i..]) |weight, numerator, denominator| {
        n = n.add(weight.mulM31(numerator));
        d = d.add(weight.mul(denominator));
    }
    return .{ .n = n, .d = d };
}
// Projection fills physical rows contiguously. Prefix wave one uses logical
// ranges, then a joined carry wave adjusts disjoint physical slots in place.
fn projectAndPrefix(comptime projection_ready: bool, data: []M, rows: usize, row_log: u32, lanes: usize, weights: []const O, numerators: []const M, denominators: []const O, eta: O, uniform: O, options: Work.RangeOptions) !void {
    const Context = struct {
        data: []M,
        rows: usize,
        row_log: u32,
        lanes: usize,
        weights: []const O,
        numerators: []const M,
        denominators: []const O,
        eta: O,
        uniform: O,
        partial: [Work.MAX_SHARDS]O = undefined,
        carries: [Work.MAX_SHARDS]O = undefined,
        shards: usize = 1,
        pub fn runRange(self: *@This(), _: usize, start: usize, end: usize) void {
            for (start..end) |p| {
                const start_lane = p * self.lanes;
                const end_lane = start_lane + self.lanes;
                const projection = projectLanes(self.weights, self.numerators[start_lane..end_lane], self.denominators[start_lane..end_lane]);
                set(self.data, self.rows, 8, p, get(self.data, self.rows, 0, p).mul(projection.n.add(self.eta.mul(projection.d))).sub(self.uniform));
            }
        }
        pub fn prefixRange(self: *@This(), ordinal: usize, start: usize, end: usize) void {
            var sum = O.zero();
            for (start..end) |logical| {
                const p = @import("stwo_riscv_frontend").rv64_air.witness.physical(logical, self.row_log);
                sum = sum.add(get(self.data, self.rows, 8, p));
                set(self.data, self.rows, 8, p, sum);
            }
            self.partial[ordinal] = sum;
        }
        pub fn carryRange(self: *@This(), _: usize, start: usize, end: usize) void {
            const width = self.rows / self.shards;
            const extra = self.rows % self.shards;
            const wide_end = (width + 1) * extra;
            for (start..end) |p| {
                const logical = core.utils.circleDomainIndexToCosetIndex(core.utils.bitReverseIndex(p, self.row_log), self.row_log);
                const ordinal = if (logical < wide_end) logical / (width + 1) else extra + (logical - wide_end) / width;
                set(self.data, self.rows, 8, p, get(self.data, self.rows, 8, p).add(self.carries[ordinal]));
            }
        }
    };
    var context = Context{ .data = data, .rows = rows, .row_log = row_log, .lanes = lanes, .weights = weights, .numerators = numerators, .denominators = denominators, .eta = eta, .uniform = uniform };
    if (!projection_ready) _ = Work.forEachRange(rows, &context, options);
    const Prefix = struct {
        context: *Context,
        pub fn runRange(self: *@This(), i: usize, start: usize, end: usize) void {
            self.context.prefixRange(i, start, end);
        }
    };
    var prefix = Prefix{ .context = &context };
    context.shards = Work.forEachRange(rows, &prefix, options);
    var sum = O.zero();
    for (context.partial[0..context.shards], 0..) |value, i| {
        context.carries[i] = sum;
        sum = sum.add(value);
    }
    if (!sum.isZero()) return error.UnboundLocalGkrInput;
    if (context.shards > 1) {
        const Carry = struct {
            context: *Context,
            pub fn runRange(self: *@This(), i: usize, start: usize, end: usize) void {
                self.context.carryRange(i, start, end);
            }
        };
        var carry = Carry{ .context = &context };
        _ = Work.forEachRange(rows, &carry, options);
    }
}
pub const Witness = struct {
    allocator: std.mem.Allocator,
    columns: [][]M,
    pub fn init(a: std.mem.Allocator, instances: []const Frame.Instance, inputs: *const Input, artifact: *const V.GkrArtifact, eta: O) !Witness {
        return initWithOptions(a, instances, inputs, artifact, eta, .{});
    }
    pub fn initWithOptions(a: std.mem.Allocator, instances: []const Frame.Instance, inputs: *const Input, artifact: *const V.GkrArtifact, eta: O, options: Work.RangeOptions) !Witness {
        if (instances.len != inputs.layers.len or instances.len != artifact.claims_to_verify_by_instance.len) return error.LocalGkrProjectionShape;
        const out = try a.alloc([]M, instances.len);
        var done: usize = 0;
        errdefer {
            for (out[0..done]) |v| a.free(v);
            a.free(out);
        }
        for (instances, inputs.layers, artifact.claims_to_verify_by_instance, 0..) |instance, layer, claims, index| {
            if (claims.len != 2 or layer != .LogUpMultiplicities) return error.LocalGkrProjectionShape;
            const point = try Frame.splitPoint(instance, artifact.ood_point, artifact.n_variables_by_instance[index]);
            const rows = try instance.rows();
            const lanes: usize = @as(usize, 1) << @intCast(try instance.laneLog());
            const data = try a.alloc(M, try std.math.mul(usize, rows, 16));
            errdefer a.free(data);
            try eqIntoWithOptions(data, rows, point.rows, options);
            var lane_planes: [8 * Frame.MAX_LOCAL_TERMS]M = undefined;
            try eqInto(lane_planes[0 .. 8 * lanes], lanes, point.lanes);
            var lane_weights: [Frame.MAX_LOCAL_TERMS]O = undefined;
            for (lane_weights[0..lanes], 0..) |*v, i| v.* = get(&lane_planes, lanes, 0, i);
            const target = claims[0].add(eta.mul(claims[1]));
            const uniform = target.mulM31(try M.fromCanonical(@intCast(rows)).inv());
            const vectors = layer.LogUpMultiplicities;
            try projectAndPrefix(false, data, rows, instance.row_log, lanes, lane_weights[0..lanes], vectors.numerators.evals, vectors.denominators.evals, eta, uniform, options);
            out[index] = data;
            done += 1;
        }
        return .{ .allocator = a, .columns = out };
    }
    /// Replays original narrow metadata into the exact terminal linear form.
    /// No numerator/denominator planes or MAIN columns are retained/rebuilt.
    /// Scratch coefficients are explicitly charged to the numerical allocator;
    /// output planes remain parent-owned and externally reserved by Child.
    pub fn initFromProvider(a: std.mem.Allocator, scratch: std.mem.Allocator, instances: []const Frame.Instance, challenges: *const @import("challenges.zig").For(O), provider: anytype, artifact: *const V.GkrArtifact, eta: O) !Witness {
        return initFromProviderImpl(false, a, scratch, instances, challenges, provider, artifact, eta);
    }
    /// Retain only the unweighted terminal projection P=N+etaD in eight
    /// physical base-coordinate planes. No provider pointer escapes this call.
    /// Eq multiplication, target subtraction and prefix run at finalization.
    pub fn initProjectionFromProvider(a: std.mem.Allocator, scratch: std.mem.Allocator, instances: []const Frame.Instance, challenges: *const @import("challenges.zig").For(O), provider: anytype, artifact: *const V.GkrArtifact, eta: O) !Witness {
        return initFromProviderImpl(true, a, scratch, instances, challenges, provider, artifact, eta);
    }
    fn initFromProviderImpl(comptime projection_only: bool, a: std.mem.Allocator, scratch: std.mem.Allocator, instances: []const Frame.Instance, challenges: *const @import("challenges.zig").For(O), provider: anytype, artifact: *const V.GkrArtifact, eta: O) !Witness {
        if (instances.len != artifact.claims_to_verify_by_instance.len or instances.len != artifact.n_variables_by_instance.len) return error.LocalGkrProjectionShape;
        const out = try a.alloc([]M, instances.len);
        var done: usize = 0;
        errdefer {
            for (out[0..done]) |values| a.free(values);
            a.free(out);
        }
        for (instances, artifact.claims_to_verify_by_instance, 0..) |instance, claims, index| {
            if (claims.len != 2 or instance.terms > Frame.MAX_LOCAL_TERMS) return error.LocalGkrProjectionShape;
            const point = try Frame.splitPoint(instance, artifact.ood_point, artifact.n_variables_by_instance[index]);
            const rows = try instance.rows();
            const lanes: usize = @as(usize, 1) << @intCast(try instance.laneLog());
            if (lanes > Frame.MAX_LOCAL_TERMS) return error.LocalGkrProjectionShape;
            const data = try a.alloc(M, try std.math.mul(usize, rows, if (projection_only) @as(usize, 8) else 16));
            errdefer a.free(data);
            if (!projection_only) try eqInto(data, rows, point.rows);
            var lane_planes: [8 * Frame.MAX_LOCAL_TERMS]M = undefined;
            try eqInto(lane_planes[0 .. 8 * lanes], lanes, point.lanes);
            var lane_weights: [Frame.MAX_LOCAL_TERMS]O = undefined;
            for (lane_weights[0..lanes], 0..) |*v, j| v.* = get(&lane_planes, lanes, 0, j);
            var relations: [Frame.MAX_LOCAL_TERMS]@import("fractions.zig").Relation = undefined;
            var n: [Frame.MAX_LOCAL_TERMS]M = undefined;
            var d: [Frame.MAX_LOCAL_TERMS]O = undefined;
            var catalog = @import("inputs.zig").RowSink{ .challenges = challenges, .numerator = n[0..instance.terms], .denominator = d[0..instance.terms], .catalog = relations[0..instance.terms] };
            try provider.emit(instance, 0, &catalog);
            if (catalog.invalid or catalog.count != instance.terms) return error.LocalGkrProjectionShape;
            var prepared = try @import("prepared_projection.zig").For(O).init(scratch, relations[0..instance.terms], challenges, lane_weights[0..lanes]);
            defer prepared.deinit();
            const target = claims[0].add(eta.mul(claims[1]));
            const uniform = target.mulM31(try M.fromCanonical(@intCast(rows)).inv());
            const Context = struct {
                data: []M,
                rows: usize,
                instance: Frame.Instance,
                challenges: *const @import("challenges.zig").For(O),
                provider: @TypeOf(provider),
                prepared: *const @import("prepared_projection.zig").For(O),
                eta: O,
                uniform: O,
                errors: [Work.MAX_SHARDS]?anyerror = @splat(null),
                pub fn runRange(self: *@This(), ordinal: usize, start: usize, end: usize) void {
                    for (start..end) |p| {
                        const logical = core.utils.circleDomainIndexToCosetIndex(core.utils.bitReverseIndex(p, self.instance.row_log), self.instance.row_log);
                        var projection = self.prepared.projection();
                        var sink = @import("inputs.zig").RowSink{ .challenges = self.challenges, .projection = &projection };
                        self.provider.emit(self.instance, logical, &sink) catch |err| {
                            self.errors[ordinal] = err;
                            return;
                        };
                        if (sink.invalid or sink.count != self.instance.terms) {
                            self.errors[ordinal] = error.LocalGkrProjectionShape;
                            return;
                        }
                        projection.finish() catch |err| {
                            self.errors[ordinal] = err;
                            return;
                        };
                        const projected = projection.combine(self.eta);
                        if (projection_only) set(self.data, self.rows, 0, p, projected) else set(self.data, self.rows, 8, p, get(self.data, self.rows, 0, p).mul(projected).sub(self.uniform));
                    }
                }
            };
            var context = Context{ .data = data, .rows = rows, .instance = instance, .challenges = challenges, .provider = provider, .prepared = &prepared, .eta = eta, .uniform = uniform };
            const shards = Work.forEachRange(rows, &context, .{});
            for (context.errors[0..shards]) |err| if (err) |e| return e;
            if (!projection_only) try projectAndPrefix(true, data, rows, instance.row_log, 0, &.{}, &.{}, &.{}, eta, uniform, .{});
            out[index] = data;
            done += 1;
        }
        return .{ .allocator = a, .columns = out };
    }

    /// Expand immutable projected planes into the original authenticated
    /// Eq/prefix witness. The source remains owned and retryable on every OOM
    /// or validation failure. Caller accounts old32+new64 bytes per row.
    pub fn finalizeProjection(self: *const Witness, a: std.mem.Allocator, instances: []const Frame.Instance, artifact: *const V.GkrArtifact, eta: O) !Witness {
        if (self.columns.len != instances.len or instances.len != artifact.claims_to_verify_by_instance.len or instances.len != artifact.n_variables_by_instance.len) return error.LocalGkrProjectionShape;
        // Validate the whole source before any finalization work or allocation.
        for (instances, self.columns, artifact.claims_to_verify_by_instance, 0..) |instance, values, claims, i| {
            const rows = try instance.rows();
            if (claims.len != 2 or values.len != try std.math.mul(usize, rows, 8)) return error.LocalGkrProjectionShape;
            _ = try Frame.splitPoint(instance, artifact.ood_point, artifact.n_variables_by_instance[i]);
        }
        const out = try a.alloc([]M, instances.len);
        var done: usize = 0;
        errdefer {
            for (out[0..done]) |values| a.free(values);
            a.free(out);
        }
        for (instances, self.columns, artifact.claims_to_verify_by_instance, 0..) |instance, projected, claims, i| {
            const rows = try instance.rows();
            const point = try Frame.splitPoint(instance, artifact.ood_point, artifact.n_variables_by_instance[i]);
            const data = try a.alloc(M, try std.math.mul(usize, rows, 16));
            errdefer a.free(data);
            try eqInto(data, rows, point.rows);
            const uniform = claims[0].add(eta.mul(claims[1])).mulM31(try M.fromCanonical(@intCast(rows)).inv());
            const Context = struct {
                data: []M,
                projected: []const M,
                rows: usize,
                uniform: O,
                pub fn runRange(ctx: *@This(), _: usize, first: usize, end: usize) void {
                    for (first..end) |p| set(ctx.data, ctx.rows, 8, p, get(ctx.data, ctx.rows, 0, p).mul(get(ctx.projected, ctx.rows, 0, p)).sub(ctx.uniform));
                }
            };
            var context = Context{ .data = data, .projected = projected, .rows = rows, .uniform = uniform };
            _ = Work.forEachRange(rows, &context, .{});
            try projectAndPrefix(true, data, rows, instance.row_log, 0, &.{}, &.{}, &.{}, eta, uniform, .{});
            out[i] = data;
            done += 1;
        }
        return .{ .allocator = a, .columns = out };
    }

    /// Header allocation and all shape checks precede the transfer. On any
    /// error the original witness remains owned and retryable. Both descriptors
    /// and backing planes use this witness's parent allocator.
    pub fn takeCommit(self: *Witness, instances: []const Frame.Instance) !@import("../../../word16_execution/main_ownership.zig").Commit {
        if (self.columns.len == 0 or self.columns.len != instances.len) return error.LocalGkrBindingUnavailable;
        for (self.columns, instances) |values, instance| if (values.len != 16 * try instance.rows()) return error.LocalGkrProjectionShape;
        const headers = try self.allocator.alloc(engine.pcs.ColumnEvaluation, try std.math.mul(usize, 16, instances.len));
        errdefer self.allocator.free(headers);
        for (self.columns, instances, 0..) |values, instance, index| {
            const rows = try instance.rows();
            for (headers[16 * index ..][0..16], 0..) |*column, c| column.* = .{ .log_size = instance.row_log, .values = values[c * rows ..][0..rows] };
        }
        const backings = self.columns;
        self.columns = &.{};
        return .{ .columns = headers, .backings = backings };
    }
    pub fn deinit(self: *Witness) void {
        for (self.columns) |v| self.allocator.free(v);
        self.allocator.free(self.columns);
        self.* = undefined;
    }
};

fn denseTestValue(seed: usize) O {
    var values: [8]M = undefined;
    for (&values, 0..) |*v, i| v.* = M.fromCanonical(@intCast((seed + 1) * (i + 3) + i * i));
    return O.fromM31Array(values);
}
test "bounded Eq projection and two-wave prefix match serial authority in every coordinate" {
    const a = std.testing.allocator;
    const log = 14;
    const rows = 1 << log;
    const serial = try a.alloc(M, 16 * rows);
    defer a.free(serial);
    const parallel = try a.alloc(M, 16 * rows);
    defer a.free(parallel);
    var point: [log]O = undefined;
    for (&point, 0..) |*v, i| v.* = denseTestValue(i);
    // Independent old interleaved expansion is the ordering reference.
    set(serial, rows, 0, 0, O.one());
    var len: usize = 1;
    for (point) |r| {
        var i = len;
        while (i > 0) {
            i -= 1;
            const value = get(serial, rows, 0, i);
            set(serial, rows, 0, 2 * i + 1, value.mul(r));
            set(serial, rows, 0, 2 * i, value.mul(O.one().sub(r)));
        }
        len *= 2;
    }
    const lanes = 8;
    const n = try a.alloc(M, lanes * rows);
    defer a.free(n);
    const d = try a.alloc(O, lanes * rows);
    defer a.free(d);
    for (n, d, 0..) |*nv, *dv, i| {
        nv.* = M.fromCanonical(@intCast(i % 101));
        dv.* = denseTestValue(i % 313);
    }
    const eta = denseTestValue(31);
    var weights: [lanes]O = undefined;
    for (&weights, 0..) |*weight, lane| weight.* = denseTestValue(14 + lane);
    var total = O.zero();
    for (0..rows) |p| {
        var nsum = O.zero();
        var dsum = O.zero();
        for (weights, 0..) |weight, lane| {
            nsum = nsum.add(weight.mulM31(n[lanes * p + lane]));
            dsum = dsum.add(weight.mul(d[lanes * p + lane]));
        }
        const contribution = get(serial, rows, 0, p).mul(nsum.add(eta.mul(dsum)));
        set(serial, rows, 8, p, contribution);
        total = total.add(contribution);
    }
    const uniform = total.mulM31(try M.fromCanonical(rows).inv());
    var sum = O.zero();
    for (0..rows) |logical| {
        const p = @import("stwo_riscv_frontend").rv64_air.witness.physical(logical, log);
        sum = sum.add(get(serial, rows, 8, p)).sub(uniform);
        set(serial, rows, 8, p, sum);
    }
    try std.testing.expect(sum.isZero());
    const Pools = engine.work_pool;
    for ([_]usize{ 1, 2, 4 }) |workers| {
        var pool: Pools.WorkPool = undefined;
        try pool.initInPlaceWithOptions(.{ .worker_count = workers });
        defer pool.deinit();
        var binding = try Pools.ScopedPoolBinding.init(&pool);
        defer binding.deinit();
        try eqIntoWithOptions(parallel, rows, &point, .{});
        try projectAndPrefix(false, parallel, rows, log, lanes, &weights, n, d, eta, uniform, .{});
        try std.testing.expectEqualSlices(M, serial, parallel);
        try std.testing.expectError(error.UnboundLocalGkrInput, projectAndPrefix(false, parallel, rows, log, lanes, &weights, n, d, eta, uniform.add(O.one()), .{}));
    }
}

test "packed local binding projection matches independent scalar lanes including tails" {
    var weights: [129]O = undefined;
    var numerators: [129]M = undefined;
    var denominators: [129]O = undefined;
    for (&weights, &numerators, &denominators, 0..) |*w, *n, *d, i| {
        w.* = denseTestValue(i + 17);
        n.* = M.fromCanonical(@intCast((i * 19) % 103));
        d.* = denseTestValue(i + 79);
    }
    for ([_]usize{ 1, 2, 3, 4, 5, 8, 13, 32, 128, 129 }) |count| {
        var n = O.zero();
        var d = O.zero();
        for (weights[0..count], numerators[0..count], denominators[0..count]) |w, nv, dv| {
            n = n.add(w.mulM31(nv));
            d = d.add(w.mul(dv));
        }
        const actual = projectLanes(weights[0..count], numerators[0..count], denominators[0..count]);
        try std.testing.expectEqual(n, actual.n);
        try std.testing.expectEqual(d, actual.d);
    }
}

const DeferredTestProvider = struct {
    fail: bool = false,
    pub fn emit(self: @This(), instance: Frame.Instance, logical: usize, sink: anytype) !void {
        if (self.fail and logical == 5) return error.DeferredTestProviderFailure;
        for (0..instance.terms) |term| sink.emitBase(.range16, [1]M{M.fromCanonical(@intCast(17 * logical + 3 * term))}, M.fromCanonical(@intCast(1 + term)));
    }
};
fn deferredProjectionCase(allocator: std.mem.Allocator, finalizer: bool) !void {
    const a = std.testing.allocator;
    const instances = [_]Frame.Instance{
        .{ .origin = .{ .core = .alu }, .row_log = 5, .terms = 3, .fixed_offset = 0, .main_offset = 0 },
        .{ .origin = .{ .core = .range16 }, .row_log = 6, .terms = 1, .fixed_offset = 0, .main_offset = 0 },
    };
    var ch = core.channel.raw_mod_m31.Om31Channel.init();
    const challenges = @import("challenges.zig").For(O).draw(&ch);
    const eta = ch.drawSecureFelt();
    var point: [7]O = undefined;
    for (&point, 0..) |*v, i| v.* = denseTestValue(31 + i);
    var inputs = try Input.init(a, &instances, &challenges, DeferredTestProvider{});
    defer inputs.deinit();
    var claims: [2][2]O = undefined;
    var claim_slices: [2][]O = undefined;
    var variables: [2]usize = undefined;
    for (instances, inputs.layers, 0..) |instance, layer, i| {
        variables[i] = try instance.variables();
        const local = point[point.len - variables[i] ..];
        const vectors = layer.LogUpMultiplicities;
        claims[i] = .{ try vectors.numerators.evalAtPoint(a, local), try vectors.denominators.evalAtPoint(a, local) };
        claim_slices[i] = &claims[i];
    }
    const artifact = V.GkrArtifact{ .ood_point = &point, .claims_to_verify_by_instance = &claim_slices, .n_variables_by_instance = &variables };
    var expected = try Witness.initFromProvider(a, a, &instances, &challenges, DeferredTestProvider{}, &artifact, eta);
    defer expected.deinit();
    var projected = try Witness.initProjectionFromProvider(if (finalizer) a else allocator, if (finalizer) a else allocator, &instances, &challenges, DeferredTestProvider{}, &artifact, eta);
    defer projected.deinit();
    var snapshots: [2][]M = undefined;
    var done: usize = 0;
    defer for (snapshots[0..done]) |values| a.free(values);
    for (projected.columns, 0..) |values, i| {
        try std.testing.expectEqual(@as(usize, 8) * try instances[i].rows(), values.len);
        snapshots[i] = try a.dupe(M, values);
        done += 1;
    }
    defer for (snapshots, projected.columns) |before, after| std.testing.expectEqualSlices(M, before, after) catch @panic("deferred source mutated");
    var actual = try projected.finalizeProjection(if (finalizer) allocator else a, &instances, &artifact, eta);
    defer actual.deinit();
    for (expected.columns, actual.columns) |x, y| try std.testing.expectEqualSlices(M, x, y);
    try std.testing.expectError(error.DeferredTestProviderFailure, Witness.initProjectionFromProvider(a, a, &instances, &challenges, DeferredTestProvider{ .fail = true }, &artifact, eta));
    var bad = instances;
    bad[0].row_log += 1;
    try std.testing.expectError(error.LocalGkrProjectionShape, projected.finalizeProjection(a, &bad, &artifact, eta));
    try std.testing.expectError(error.UnboundLocalGkrInput, projected.finalizeProjection(a, &instances, &artifact, eta.add(O.one())));
}
test "deferred eight-plane projection finalizes to exact mixed-height Eq prefix and stays immutable" {
    try deferredProjectionCase(std.testing.allocator, true);
    const Pools = engine.work_pool;
    var pool: Pools.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{ .worker_count = 3 });
    defer pool.deinit();
    var binding = try Pools.ScopedPoolBinding.init(&pool);
    defer binding.deinit();
    try deferredProjectionCase(std.testing.allocator, false);
}
test "deferred projection construction and finalization are failure atomic at every allocation" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, deferredProjectionCase, .{true});
    try std.testing.checkAllAllocationFailures(std.testing.allocator, deferredProjectionCase, .{false});
}
