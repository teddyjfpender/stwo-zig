//! CPU construction of the existing M7 witness. Original lookup tuples are
//! the authority; no synthetic inputs or producer-chosen terminal claims.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const circuit = @import("stwo_circuit_frontend");
const Outer = @import("stwo_circuit_cpu_integration").om31;
const P = @import("profile.zig");
const S = @import("section.zig");
const H = @import("hybrid_air.zig");
const Legacy = @import("binding.zig");
const O = core.fields.om31.OM31;
const M = core.fields.m31.M31;
const T = circuit.witness.trace;
const L = engine.air.logup_columns.ForField(O);
const Col = engine.pcs.ColumnEvaluation;

const Fill = struct {
    raw: *const T.RawLookupRows,
    class: *const P.Class,
    inputs: *S.Inputs,
    elements: *const Outer.witness.Elements,
    kind: P.Component,
    mutex: std.Thread.Mutex = .{},
    failure: ?anyerror = null,
    pub fn runRange(self: *@This(), _: usize, first: usize, end: usize) void {
        self.fill(first, end) catch |err| {
            self.mutex.lock();
            defer self.mutex.unlock();
            self.failure = err;
        };
    }
    fn fill(self: *@This(), first: usize, end: usize) !void {
        const rows = @as(usize, 1) << @intCast(self.class.row_logs[@intFromEnum(self.kind)]);
        for (first..end) |row| {
            var storage: [T.RawLookupRows.MAX_LOOKUPS]circuit.witness.components.Lookup = undefined;
            const lookups = try self.raw.fill(@enumFromInt(@intFromEnum(self.kind)), row, &storage);
            var start: usize = 0;
            for (self.class.instances, 0..) |inst, group| {
                if (inst.component != self.kind) continue;
                for (0..inst.lanes_used) |lane| {
                    const lookup = lookups[start + lane];
                    const index = lane * rows + row;
                    self.inputs.numerators[group][index] = lookup.numerator;
                    self.inputs.denominators[group][index] = self.elements.combine(lookup.values());
                }
                start += inst.lanes_used;
            }
            if (start != lookups.len) return error.OuterGkrTupleShape;
        }
    }
};

pub fn inputs(a: std.mem.Allocator, class: *const P.Class, raw: *const T.RawLookupRows, elements: *const Outer.witness.Elements) !S.Inputs {
    try class.validate();
    var out = S.Inputs{ .numerators = try a.alloc([]M, class.instances.len), .denominators = undefined };
    errdefer a.free(out.numerators);
    out.denominators = try a.alloc([]O, class.instances.len);
    errdefer a.free(out.denominators);
    var made: usize = 0;
    errdefer for (out.numerators[0..made], out.denominators[0..made]) |n, d| {
        a.free(n);
        a.free(d);
    };
    for (class.instances, 0..) |inst, i| {
        const count = @as(usize, 1) << @intCast(inst.variables());
        const n = try a.alloc(M, count);
        errdefer a.free(n);
        const d = try a.alloc(O, count);
        @memset(n, M.zero());
        @memset(d, O.one());
        out.numerators[i] = n;
        out.denominators[i] = d;
        made += 1;
    }
    for (0..P.N_COMPONENTS) |i| {
        const kind: P.Component = @enumFromInt(i);
        if (!P.gkrBound(kind)) continue;
        var fill = Fill{ .raw = raw, .class = class, .inputs = &out, .elements = elements, .kind = kind };
        _ = engine.lookups.row_work.forEachRange(@as(usize, 1) << @intCast(class.row_logs[i]), &fill, .{ .min_rows_per_shard = 512 });
        if (fill.failure) |err| return err;
    }
    return out;
}

const ClassicRow = struct {
    raw: *const T.RawLookupRows,
    kind: P.Component,
    elements: *const Outer.witness.Elements,
    fn fill(self: @This(), row: usize, out: []L.Fraction) !void {
        var storage: [T.RawLookupRows.MAX_LOOKUPS]circuit.witness.components.Lookup = undefined;
        try Outer.witness.pairFractions(self.elements, try self.raw.fill(@enumFromInt(@intFromEnum(self.kind)), row, &storage), out);
    }
};
pub const Classic = struct {
    columns: [P.N_COMPONENTS]?L.Output = @splat(null),
    claims: Outer.witness.Claims,
    pub fn deinit(self: *@This(), a: std.mem.Allocator) void {
        for (self.columns) |maybe| if (maybe) |part| T.freeColumns(a, part.columns);
        self.columns = @splat(null);
    }
};
pub fn classic(a: std.mem.Allocator, class: *const P.Class, raw: *const T.RawLookupRows, elements: *const Outer.witness.Elements) !Classic {
    var out = Classic{ .claims = Outer.witness.Claims.fromArray(@splat(O.zero())) };
    errdefer out.deinit(a);
    var claims: [P.N_COMPONENTS]O = @splat(O.zero());
    for (0..P.N_COMPONENTS) |i| {
        const kind: P.Component = @enumFromInt(i);
        if (P.gkrBound(kind)) continue;
        const row = ClassicRow{ .raw = raw, .kind = kind, .elements = elements };
        const result = try L.build(a, class.row_logs[i], (P.FACTS[i].lookups + 1) / 2, row, ClassicRow.fill);
        out.columns[i] = result;
        claims[i] = result.claimed_sum;
    }
    out.claims = Outer.witness.Claims.fromArray(claims);
    return out;
}

/// Does not consume the classic owner; returned columns own independent values.
pub fn interaction(a: std.mem.Allocator, class: *const P.Class, source: *const S.Inputs, verified: *const S.Verified, ch: *const Legacy.Challenges, original: *const Classic) ![]Col {
    const out = try a.alloc(Col, H.interactionColumns());
    @memset(out, .{ .log_size = 0, .values = &.{} });
    errdefer T.freeColumns(a, out);
    for (0..P.N_COMPONENTS) |i| {
        const kind: P.Component = @enumFromInt(i);
        const start = H.interactionStart(kind);
        if (!P.gkrBound(kind)) {
            const part = original.columns[i] orelse return error.MissingHybridClassicWitness;
            if (part.columns.len != H.interactionWidth(kind)) return error.InvalidOm31InteractionWidth;
            for (part.columns, out[start..][0..part.columns.len]) |column, *destination| destination.* = .{ .log_size = column.log_size, .values = try a.dupe(M, column.values) };
            continue;
        }
        const point = verified.artifact.ood_point;
        const log = class.row_logs[i];
        const projection = try @import("cpu_projection.zig").project(a, class, kind, point, source, ch);
        defer a.free(projection);
        var target = O.zero();
        for (class.instances, 0..) |inst, g| if (inst.component == kind) {
            const pair = verified.artifact.claims_to_verify_by_instance[g];
            target = target.add(ch.rho[g].mul(pair[0].add(ch.gamma.mul(pair[1]))));
        };
        var columns = try @import("cpu_binding.zig").columns(a, point[point.len - log ..], projection, target);
        defer columns.deinit(a);
        for (0..16) |coordinate| {
            const values = try a.alloc(M, projection.len);
            out[start + coordinate] = .{ .log_size = log, .values = values };
            const secure = if (coordinate < 8) columns.eq else columns.prefix;
            for (values, secure) |*v, value| v.* = value.toM31Array()[coordinate % 8];
        }
    }
    return out;
}
