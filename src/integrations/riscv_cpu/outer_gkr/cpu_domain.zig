//! CPU evaluation of receiver-derived hybrid IR. Public Eq auxiliaries are
//! reconstructed from the verified GKR point, never read from committed masks.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const Outer = @import("stwo_circuit_cpu_integration").om31;
const HC = @import("hybrid_component.zig");
const H = @import("hybrid_air.zig");
const P = @import("profile.zig");
const MP = @import("../logup_gkr/mle_point.zig");
const Aux = @import("../word16_global_execution/services/gkr_local/public_aux.zig");
const O = core.fields.om31.OM31;
const M = core.fields.m31;
const Pack = core.fields.packed_om31;
const F = Pack.PackedOM31;
const PA = engine.air.component_prover.ForField(O);
const DA = engine.air.accumulation.ForField(O);
const IR = engine.air.secure_polynomial_program_v2;
pub var test_failure: ?P.Component = null;
const Col = struct { polynomial: PA.Poly = undefined, offset: i8 = 0, carry: ?[8][]const M.M31 = null, zero: bool = false };
const Work = struct {
    component: *const HC.Component,
    reads: []const Col,
    sorts: []const IR.Sort,
    constants: []const F,
    parameters: []const F,
    scratch: [][]F,
    accumulator: DA.ColumnAccumulator,
    mutex: std.Thread.Mutex = .{},
    failure: ?anyerror = null,

    pub fn runRange(self: *@This(), shard: usize, first: usize, end: usize) void {
        self.run(shard, first, end) catch |err| {
            self.mutex.lock();
            defer self.mutex.unlock();
            self.failure = err;
        };
    }
    fn run(self: *@This(), shard: usize, first: usize, end: usize) !void {
        const c = self.component;
        const log = c.source.trace_log_size;
        const values = self.scratch[shard];
        const program = &c.artifact.program;
        for (first..end) |tile| {
            const row = tile * M.PACK_WIDTH;
            for (program.nodes, values) |node, *value| value.* = switch (node.op) {
                .constant => self.constants[node.value],
                .parameter => self.parameters[node.value],
                .input => blk: {
                    const read = self.reads[node.value];
                    var coordinates: [8]M.PackedM31 = @splat(@splat(0));
                    if (read.carry) |carry| {
                        inline for (0..8) |coordinate| coordinates[coordinate] = M.loadPacked(carry[coordinate][row..].ptr);
                    } else if (!read.zero) {
                        inline for (0..M.PACK_WIDTH) |lane| {
                            const at = core.utils.offsetBitReversedCircleDomainIndex(row + lane, log, log + 1, read.offset);
                            coordinates[0][lane] = (try read.polynomial.valueAtLiftingPosition(log + 1, at)).v;
                        }
                    }
                    break :blk Pack.fromCoordinates(coordinates);
                },
                .add => values[node.lhs].add(values[node.rhs]),
                .sub => values[node.lhs].sub(values[node.rhs]),
                .neg => values[node.lhs].neg(),
                .mul => if (self.sorts[node.lhs] == .base) values[node.rhs].mulBase(values[node.lhs].c0.c0.a) else if (self.sorts[node.rhs] == .base) values[node.lhs].mulBase(values[node.rhs].c0.c0.a) else Pack.mul(values[node.lhs], values[node.rhs]),
                .fraction, .range_fraction => unreachable,
            };
            var total = Pack.splat(O.zero());
            for (program.roots, 0..) |root, i| {
                const coefficient = Pack.splat(self.accumulator.random_coeff_powers[program.roots.len - 1 - i]);
                total = total.add(if (self.sorts[root] == .base) coefficient.mulBase(values[root].c0.c0.a) else Pack.mul(coefficient, values[root]));
            }
            const inverse = c.source.denominator_inverses[row >> @intCast(log)];
            total = total.mulBase(@as(M.PackedM31, @splat(inverse)));
            inline for (0..M.PACK_WIDTH) |lane| self.accumulator.accumulate(row + lane, Pack.lane(total, lane));
        }
    }
};
pub fn evaluate(c: *const HC.Component, trace: *const PA.Trace, acc: *DA.DomainEvaluationAccumulator) !void {
    if (@import("builtin").is_test) if (test_failure) |kind| if (kind == c.artifact.component) return error.InjectedHybridDomainFailure;
    const a = acc.allocator;
    const log = c.source.trace_log_size;
    if (log < 4 or c.source.evaluation_log_size != log + 1) return error.InvalidHybridMaskGeometry;
    var aux: [10]?engine.poly.circle.CircleEvaluation = @splat(null);
    defer for (aux) |maybe| if (maybe) |evaluation| a.free(evaluation.values);
    if (P.gkrBound(c.artifact.component)) {
        const point = c.verified.artifact.ood_point;
        const row_point = try MP.MleEvalPointFor(O).init(point[point.len - log ..]);
        var coefficients = try Aux.initWithLogBound(a, &row_point, log, P.MAX_VARIABLES, engine.work_pool.currentScopedPool());
        defer for (&coefficients) |*coefficient| coefficient.deinit(a);
        for (coefficients, &aux) |coefficient, *evaluation| evaluation.* = try coefficient.evaluate(a, core.poly.circle.canonic.CanonicCoset.new(log + 1).circleDomain());
    }
    const program = &c.artifact.program;
    const reads = try a.alloc(Col, program.inputs.len);
    defer a.free(reads);
    for (program.inputs, reads) |input, *read| {
        if (P.gkrBound(c.artifact.component) and input.tree == 2 and input.column >= 16) {
            if (input.column >= 26 or input.offset != 0) return error.InvalidHybridInteractionMask;
            read.* = switch (input.column) {
                16, 17 => .{ .polynomial = .{ .log_size = log + 1, .values = aux[8 + input.column - 16].?.values } },
                18 => blk: {
                    var carry: [8][]const M.M31 = undefined;
                    for (&carry, aux[0..8]) |*column, evaluation| column.* = evaluation.?.values;
                    break :blk .{ .carry = carry };
                },
                else => .{ .zero = true },
            };
        } else {
            const index = switch (input.tree) {
                0 => c.source.preprocessed_indices[input.column],
                1 => (try Outer.geometry.span(c.source.*, 1)).start + input.column,
                2 => H.interactionStart(c.artifact.component) + input.column,
                else => return error.InvalidHybridMaskTree,
            };
            if (input.tree >= trace.polys.items.len or index >= trace.polys.items[input.tree].len) return error.MissingHybridMask;
            const polynomial = trace.polys.items[input.tree][index];
            if (polynomial.values.len == 0 or polynomial.device != null) return error.HybridCpuRequiresHostLde;
            read.* = .{ .polynomial = polynomial, .offset = input.offset };
        }
    }
    const sorts = try program.sorts(a);
    defer a.free(sorts);
    // The IR's ordinary inputs are physical M31 coordinates. Public carry
    // input18 is instead one receiver-derived OM31 polynomial; propagate that
    // distinction through its users rather than treating it as a base value.
    for (program.nodes, sorts) |node, *sort| switch (node.op) {
        .input => sort.* = if (reads[node.value].carry != null) .secure else .base,
        .add, .sub, .mul => sort.* = if (sorts[node.lhs] == .secure or sorts[node.rhs] == .secure) .secure else .base,
        .neg => sort.* = sorts[node.lhs],
        else => {},
    };
    const constants = try a.alloc(F, program.constants.len);
    defer a.free(constants);
    for (constants, 0..) |*constant, i| constant.* = Pack.splat(program.constantValue(@intCast(i)));
    const parameters = try a.alloc(F, c.parameters.len);
    defer a.free(parameters);
    for (parameters, c.parameters) |*out, value| out.* = Pack.splat(value);
    var scratch: [engine.lookups.row_work.MAX_SHARDS][]F = undefined;
    var made: usize = 0;
    defer for (scratch[0..made]) |values| a.free(values);
    for (&scratch) |*values| {
        values.* = try a.alloc(F, program.nodes.len);
        made += 1;
    }
    const columns = try acc.columns(a, &.{.{ .log_size = log + 1, .n_cols = program.roots.len }});
    defer a.free(columns);
    columns[0].next_fresh_index = null;
    var work = Work{ .component = c, .reads = reads, .sorts = sorts, .constants = constants, .parameters = parameters, .scratch = &scratch, .accumulator = columns[0] };
    _ = engine.lookups.row_work.forEachRange((@as(usize, 1) << @intCast(log + 1)) / M.PACK_WIDTH, &work, .{ .min_rows_per_shard = 256 });
    if (work.failure) |err| return err;
}
