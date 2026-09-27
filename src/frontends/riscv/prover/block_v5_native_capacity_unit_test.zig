//! Nonproving capacity custody, original equation parity and body codegen.
//! No native trace execution, commitment, STARK, FRI or recursive proof runs.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const Protocol = @import("block_v5_native_capacity_protocol_v1.zig");
const Activity = @import("block_v5_native_capacity_activity_v1.zig");
const Component = @import("block_v5_native_capacity_component_v1.zig").Component;
const Proof = @import("block_v5_native_capacity_proof_v1.zig");
const Public = @import("block_v5_native_public_admission_v1.zig");
const Seal = @import("block_v5_source_seal_v1.zig");
const Statement = @import("../air/statement.zig");
const Joined = @import("block_v5_native_components_v3.zig");
const Q = core.fields.qm31.QM31;
const M = core.fields.m31.M31;
const config = @import("../recursion/blake3_execution_parent_protocol.zig").PCS_CONFIG;
fn shape(rows: u32) Statement.Blake3ExecutionStatement {
    var result = std.mem.zeroes(Statement.Blake3ExecutionStatement);
    result.initializeDescriptorStorage();
    result.n_components = 1;
    result.component_descs[0] = .{ .family = .base_alu_imm, .log_size = @max(1, std.math.log2_int_ceil(u32, rows)), .n_rows = rows, .n_columns = @intCast(@import("../runner/trace.zig").nColumnsForFamily(.base_alu_imm)) };
    result.total_steps = rows;
    result.public_data = .{ .initial_pc = 0, .final_pc = 0, .clock = rows, .initial_regs = @splat(0), .final_regs = @splat(0), .reg_last_clock = @splat(0), .program_root = .{ .bytes = @splat(3) }, .initial_rw_root = null, .final_rw_root = null, .completion = @import("../air/public_data.zig").Completion.canonicalSelfLoop(0), .io_entries = .{ .input_start = 0x2000, .input_len = 0, .input_words = &.{}, .output_len = 0, .output_len_addr = 0x3004, .output_data_addr = 0x3008, .output_words = &.{} } };
    return result;
}
fn context(rows: u32) Public.Context {
    return .{ .job_id = @splat(1), .source_image_digest = @splat(2), .program_root = @splat(3), .program_plan_digest = @splat(4), .memory_plan_digest = @splat(5), .initial_source_plan_digest = @splat(6), .rw_endpoint_plan_digest = @splat(7), .execution_index = 0, .first_cycle = 1, .last_cycle = rows };
}
fn anyNonzero(values: []const Q) bool {
    for (values) |value| if (!value.isZero()) return true;
    return false;
}
fn cell(values: []const M, logical: usize, log: u32) Q {
    return Q.fromBase(values[core.utils.bitReverseIndex(core.utils.cosetIndexToCircleDomainIndex(logical, log), log)]);
}

test "native capacity prefix counts powers tails and catches holes last count and nonboolean selectors" {
    const a = std.testing.allocator;
    // Include full capacity, one active event, odd tail and two power edges.
    for ([_]u32{ 1, 2, 3, 4, 5, 7, 8, 9, 31, 32, 33 }) |rows| {
        var statement = shape(rows);
        const plan = try Protocol.Plan.fromShape(&statement, 0);
        const columns = try Activity.columns(a, &plan);
        defer Protocol.freeColumns(a, columns);
        const shard = plan.shards[0];
        const size = columns[0].values.len;
        const canonical = try @import("../infra_trace.zig").BitReversalTable.init(a, shard.log_size);
        defer canonical.deinit(a);
        for (0..size) |logical| {
            const previous = (logical + size - 1) % size;
            // Independently generated native placement and actual circle
            // predecessor must agree with both newly committed columns.
            const physical = canonical.map(logical);
            try std.testing.expectEqual(canonical.map(previous), core.utils.previousBitReversedCircleDomainIndex(physical, shard.log_size, shard.log_size));
            try std.testing.expectEqualDeep(if (logical < rows) M.one() else M.zero(), columns[0].values[physical]);
            try std.testing.expectEqualDeep(M.fromCanonical(@intCast(@min(logical + 1, rows))), columns[1].values[physical]);
            const checks = Activity.evaluate(Q, if (logical == 0) Q.one() else Q.zero(), cell(columns[0].values, logical, shard.log_size), cell(columns[0].values, previous, shard.log_size), cell(columns[1].values, logical, shard.log_size), cell(columns[1].values, previous, shard.log_size), Q.fromBase(M.fromCanonical(rows)));
            try std.testing.expect(!anyNonzero(&checks));
        }
        const wrong_count = Activity.evaluate(Q, Q.one(), Q.one(), cell(columns[0].values, size - 1, shard.log_size), Q.one(), cell(columns[1].values, size - 1, shard.log_size), Q.fromBase(M.fromCanonical(rows + 1)));
        try std.testing.expect(!wrong_count[3].isZero());
    }
    const hole = Activity.evaluate(Q, Q.zero(), Q.one(), Q.zero(), Q.fromBase(M.fromCanonical(2)), Q.one(), Q.fromBase(M.fromCanonical(2)));
    try std.testing.expect(!hole[1].isZero());
    const nonboolean = Activity.evaluate(Q, Q.zero(), Q.fromBase(M.fromCanonical(2)), Q.one(), Q.fromBase(M.fromCanonical(3)), Q.one(), Q.fromBase(M.fromCanonical(3)));
    try std.testing.expect(!nonboolean[0].isZero());
    const bad_prefix = Activity.evaluate(Q, Q.zero(), Q.one(), Q.one(), Q.fromBase(M.fromCanonical(4)), Q.one(), Q.fromBase(M.fromCanonical(2)));
    try std.testing.expect(!bad_prefix[2].isZero());
    // The AIR itself permits public zero count only with all-zero activity;
    // native shape admission forbids relabeling a nonempty shard as zero.
    const zero = Activity.evaluate(Q, Q.one(), Q.zero(), Q.zero(), Q.zero(), Q.zero(), Q.zero());
    try std.testing.expect(!anyNonzero(&zero));
    var illegal = shape(1);
    illegal.component_descs[0].n_rows = 0;
    try std.testing.expectError(error.InvalidStatement, Protocol.Plan.fromShape(&illegal, 0));
}
test "native capacity template reuses same bucket binds exact instance and rejects legacy protocol and shape mutations" {
    var first = shape(5);
    var second = shape(7);
    const one = try Protocol.Template.fromShape(&first, 0, config, .rv32im_zkvm_v1, @splat(8));
    const two = try Protocol.Template.fromShape(&second, 0, config, .rv32im_zkvm_v1, @splat(8));
    try std.testing.expectEqualDeep(one, two);
    const template_id = try one.identity();
    try one.admit(&second, 0, template_id);
    const first_pin = try Public.Admission.init(context(5), &first.public_data);
    const second_pin = try Public.Admission.init(context(7), &second.public_data);
    const roots: Seal.Roots = .{ @splat(8), @splat(9) };
    const first_id = try Protocol.instanceId(template_id, &first, 0, first_pin, roots, 0);
    const second_id = try Protocol.instanceId(template_id, &second, 0, second_pin, roots, 0);
    try std.testing.expect(!std.meta.eql(first_id, second_id));
    const old = try @import("block_v5_native_template_protocol_v3.zig").Template.fromShape(&first, config, .rv32im_zkvm_v1, 0, @splat(8));
    try std.testing.expect(!std.meta.eql(template_id, try old.identity()));
    try std.testing.expectError(error.UntrustedNativeCapacityTemplate, one.admit(&first, 0, try old.identity()));
    var changed = shape(9);
    try std.testing.expectError(error.UntrustedNativeCapacityTemplate, one.admit(&changed, 0, template_id));
    changed = first;
    changed.component_descs[0].n_rows = 6;
    try std.testing.expectError(error.InvalidStatement, Protocol.Plan.fromShape(&changed, 0));
    changed = first;
    changed.component_descs[0].n_columns += 1;
    try std.testing.expectError(error.InvalidStatement, Protocol.Plan.fromShape(&changed, 0));
    var fixed = one;
    fixed.fixed_root[0] ^= 1;
    try std.testing.expectError(error.UntrustedNativeCapacityTemplate, fixed.admit(&first, 0, template_id));
    var cfg = one;
    cfg.config.pow_bits = if (config.pow_bits == 0) 1 else 0;
    try std.testing.expectError(error.UntrustedNativeCapacityTemplate, cfg.admit(&first, 0, template_id));
    try std.testing.expectError(error.UntrustedNativeCapacityInstance, Protocol.instanceId(template_id, &first, 0, first_pin, roots, 1));
    try std.testing.expectError(error.NativeCapacityResourceLimit, (Proof.Limits{ .max_main_cells = 1 }).require(&(try Protocol.Plan.fromShape(&first, 0)), &first));
}
test "native capacity fixed rows are count invariant and column generation cleans every allocation failure" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, checkColumns, .{});
}
fn checkColumns(a: std.mem.Allocator) !void {
    var first = shape(5);
    var second = shape(7);
    const one = try Protocol.fixedColumns(a, &first, 0);
    defer Protocol.freeColumns(a, one);
    const two = try Protocol.fixedColumns(a, &second, 0);
    defer Protocol.freeColumns(a, two);
    for (one, two) |left, right| {
        try std.testing.expectEqual(left.log_size, right.log_size);
        try std.testing.expectEqualSlices(M, left.values, right.values);
    }
    const plan = try Protocol.Plan.fromShape(&first, 0);
    const dynamic = try Activity.columns(a, &plan);
    defer Protocol.freeColumns(a, dynamic);
    const main = try Protocol.columnLogs(a, &first, 0, .main);
    defer a.free(main);
    try std.testing.expectEqual(plan.mainCount(), main.len);
    try std.testing.expectEqual(plan.native_main_count + 2, main.len);
}
fn componentFor(a: std.mem.Allocator, statement: *const Statement.Blake3ExecutionStatement) !Component {
    var claims = std.mem.zeroes(Statement.RiscVInteractionClaim);
    claims.n_components = statement.n_components;
    claims.n_infra = statement.n_infra;
    var c = core.proof_suites.Blake3.Channel{};
    const relations = try @import("../recursion/air/universal_challenges.zig").UniversalRelations.draw(a, &c);
    const pin = try Public.Admission.init(context(statement.total_steps), &statement.public_data);
    const owner = try Joined.Owner.init(a, statement, &claims, relations, pin);
    errdefer owner.deinit();
    const plan = try Protocol.Plan.fromShape(statement, 0);
    const fixed = try Protocol.columnLogs(a, statement, 0, .fixed);
    errdefer a.free(fixed);
    const main = try Protocol.columnLogs(a, statement, 0, .main);
    errdefer a.free(main);
    const interaction = try Protocol.columnLogs(a, statement, 0, .interaction);
    errdefer a.free(interaction);
    return .{ .inner = owner, .plan = plan, .fixed_logs = fixed, .main_logs = main, .interaction_logs = interaction };
}
fn freeComponent(a: std.mem.Allocator, component: *Component) void {
    component.inner.deinit();
    a.free(component.fixed_logs);
    a.free(component.main_logs);
    a.free(component.interaction_logs);
}
test "native capacity combined masks clean every allocation failure without double owning aliases" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, checkMasks, .{});
}
fn checkMasks(a: std.mem.Allocator) !void {
    var statement = shape(3);
    var component = try componentFor(a, &statement);
    defer freeComponent(a, &component);
    var mask = try component.maskPoints(a, core.circle.secureFieldPoint(127), component.maxConstraintLogDegreeBound());
    defer mask.deinitDeep(a);
    var logs = try component.traceLogDegreeBounds(a);
    defer logs.deinitDeep(a);
    const indices = try component.preprocessedColumnIndices(a);
    defer a.free(indices);
    try std.testing.expectEqual(component.fixed_logs.len, indices.len);
}
fn scalar(seed: usize) Q {
    return Q.fromU32Unchecked(@intCast(seed + 1), @intCast(seed + 2), @intCast(seed + 3), @intCast(seed + 4));
}
test "native capacity preserves original point equations masks and binds the appended selector" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var statement = shape(3);
    statement.n_infra = 1;
    statement.infra_descs[0] = .{ .kind = .clock_update, .log_size = 1, .n_rows = 1, .n_columns = @import("../infra_trace.zig").CLOCK_UPDATE_COLS };
    var component = try componentFor(a, &statement);
    defer component.inner.deinit();
    const point = core.circle.secureFieldPoint(127);
    const max_log = component.maxConstraintLogDegreeBound();
    var points = try component.maskPoints(a, point, max_log);
    defer points.deinitDeep(a);
    try std.testing.expectEqual(component.plan.mainCount(), points.items[1].len);
    for (points.items[1][component.plan.native_main_count..]) |column| {
        try std.testing.expectEqual(@as(usize, 2), column.len);
        try std.testing.expect(column[1].eql(@import("../air/logup.zig").prevRowPoint(max_log, point)));
    }
    var masks = try a.alloc([][]Q, points.items.len);
    for (points.items, masks, 0..) |tree, *out, t| {
        out.* = try a.alloc([]Q, tree.len);
        for (tree, out.*, 0..) |column, *values, i| {
            values.* = try a.alloc(Q, column.len);
            for (values.*, 0..) |*value, j| value.* = scalar(10 + t * 113 + i * 7 + j);
        }
    }
    var actual = core.air.accumulation.PointEvaluationAccumulator.init(scalar(3));
    var expected = core.air.accumulation.PointEvaluationAccumulator.init(scalar(3));
    const mask = core.air.components.MaskValues{ .items = masks };
    try component.evaluateConstraintQuotientsAtPoint(point, &mask, &actual, max_log);
    const aliased = try a.dupe([]Q, masks[0]);
    for (component.plan.active()) |shard| aliased[shard.active_index] = masks[1][shard.main_index][0..1];
    var native_trees = [_][][]Q{ aliased, masks[1][0..component.plan.native_main_count], masks[2] };
    const native_mask = core.air.components.MaskValues{ .items = &native_trees };
    for (component.inner.verifying.components.active()) |item| try item.evaluateConstraintQuotientsAtPoint(point, &native_mask, &expected, max_log);
    for (component.plan.active()) |shard| {
        const active = masks[1][shard.main_index];
        const count = masks[1][shard.main_index + 1];
        const checks = Activity.evaluate(Q, masks[0][shard.first_index][0], active[0], active[1], count[0], count[1], Q.fromBase(M.fromCanonical(shard.rows)));
        const inverse = try core.constraints.cosetVanishing(Q, core.poly.circle.canonic.CanonicCoset.new(shard.log_size).coset(), point.repeatedDouble(max_log - shard.log_size)).inv();
        for (checks) |check| expected.accumulate(check.mul(inverse));
    }
    try std.testing.expect(actual.finalize().eql(expected.finalize()));
    masks[1][component.plan.shards[0].main_index][0] = masks[1][component.plan.shards[0].main_index][0].add(Q.one());
    var changed = core.air.accumulation.PointEvaluationAccumulator.init(scalar(3));
    try component.evaluateConstraintQuotientsAtPoint(point, &mask, &changed, max_log);
    try std.testing.expect(!changed.finalize().eql(actual.finalize()));
}
const Degree = struct {
    value: u8,
    pub fn one() Degree {
        return .{ .value = 0 };
    }
    pub fn sub(self: Degree, other: Degree) Degree {
        return .{ .value = @max(self.value, other.value) };
    }
    pub fn mul(self: Degree, other: Degree) Degree {
        return .{ .value = self.value + other.value };
    }
};
test "native capacity each activity equation degree bound is explicit at three" {
    const linear = Degree{ .value = 1 };
    const constant = Degree{ .value = 0 };
    const checks = Activity.evaluate(Degree, linear, linear, linear, linear, linear, constant);
    for (checks, Activity.DEGREES) |check, bound| try std.testing.expectEqual(bound, check.value);
}
test "native capacity legal empty ordinary path retains genuine typed frame and exact instance count" {
    var empty = shape(3);
    empty.n_components = 0;
    const plan = try Protocol.Plan.fromShape(&empty, 3);
    try std.testing.expectEqual(@as(usize, 0), plan.len);
    try std.testing.expectEqual(@as(usize, @import("block_v5_native_frame_v1.zig").MAIN_COLUMNS), plan.mainCount());
    const a = std.testing.allocator;
    const fixed = try Protocol.fixedColumns(a, &empty, 3);
    defer Protocol.freeColumns(a, fixed);
    try std.testing.expectEqual(@as(usize, @import("block_v5_native_frame_v1.zig").FIXED_COLUMNS), fixed.len);
    const dynamic = try Activity.columns(a, &plan);
    defer Protocol.freeColumns(a, dynamic);
    try std.testing.expectEqual(@as(usize, 0), dynamic.len);
    var other = empty;
    other.total_steps = 7;
    other.public_data.clock = 7;
    const template = try Protocol.Template.fromShape(&empty, 3, config, .rv32im_zkvm_v1, @splat(8));
    try template.admit(&other, 7, try template.identity());
    const one = try @import("block_v5_native_frame_v1.zig").expected(&empty, 3);
    const two = try @import("block_v5_native_frame_v1.zig").expected(&other, 7);
    try std.testing.expect(!std.meta.eql(one, two));
    try std.testing.expectError(error.InvalidStatement, Protocol.Plan.fromShape(&empty, 2));
}
test "native capacity transcript binds seal roots ordinal instance and rejects protocol downgrade" {
    const a = std.testing.allocator;
    var sealed = std.mem.zeroes(Seal.Sealed);
    sealed.digest = @splat(1);
    const roots: Seal.Roots = .{ @splat(2), @splat(3) };
    const original = try Protocol.pcsChannel(a, sealed, @splat(4), @splat(5), roots, 0);
    var changed = sealed;
    changed.digest[0] ^= 1;
    try std.testing.expect(!std.meta.eql(original.digestBytes(), (try Protocol.pcsChannel(a, changed, @splat(4), @splat(5), roots, 0)).digestBytes()));
    var different_roots = roots;
    different_roots[1][0] ^= 1;
    try std.testing.expect(!std.meta.eql(original.digestBytes(), (try Protocol.pcsChannel(a, sealed, @splat(4), @splat(5), different_roots, 0)).digestBytes()));
    try std.testing.expect(!std.meta.eql(original.digestBytes(), (try Protocol.pcsChannel(a, sealed, @splat(4), @splat(5), roots, 1)).digestBytes()));
    try std.testing.expect(!std.meta.eql(original.digestBytes(), (try Protocol.pcsChannel(a, sealed, @splat(4), @splat(6), roots, 0)).digestBytes()));
    const legacy = try @import("block_v5_native_template_protocol_v3.zig").pcsChannel(a, sealed, @splat(4), @splat(5), roots, 0);
    try std.testing.expect(!std.meta.eql(original.digestBytes(), legacy.digestBytes()));
    try Proof.requireProtocol(Protocol.VERSION);
    try std.testing.expectError(error.UntrustedNativeCapacityProtocol, Proof.requireProtocol(0));
    try std.testing.expectError(error.UntrustedNativeCapacityProtocol, Proof.requireProtocol(3));
}
fn poly(a: std.mem.Allocator, log: u32, seed: usize) !engine.air.component_prover.Poly {
    const coeff = try a.alloc(M, @as(usize, 1) << @intCast(log));
    @memset(coeff, M.zero());
    coeff[0] = M.fromCanonical(@intCast(seed + 7));
    coeff[1] = M.fromCanonical(@intCast(seed * 3 + 11));
    return .{ .log_size = log, .values = &.{}, .coefficients = try engine.poly.circle.poly.CircleCoefficients.initBorrowed(coeff) };
}
test "native capacity mixed bucket domain preserves native quotients and shifted count equations" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var statement = shape(5);
    statement.n_infra = 1;
    statement.infra_descs[0] = .{ .kind = .clock_update, .log_size = 1, .n_rows = 2, .n_columns = @import("../infra_trace.zig").CLOCK_UPDATE_COLS };
    var component = try componentFor(a, &statement);
    defer component.inner.deinit();
    var trees: [3][]const engine.air.component_prover.Poly = undefined;
    const logs_by_tree = [_][]const u32{ component.fixed_logs, component.main_logs, component.interaction_logs };
    for (&trees, logs_by_tree, 0..) |*tree, logs, t| {
        const columns = try a.alloc(engine.air.component_prover.Poly, logs.len);
        for (columns, logs, 0..) |*column, log, i| column.* = try poly(a, log, 1 + t * 151 + i * 7);
        tree.* = columns;
    }
    const trace = engine.air.component_prover.Trace{ .polys = .{ .items = &trees } };
    const max_log = component.maxConstraintLogDegreeBound();
    const alpha = scalar(17);
    var actual = try engine.air.accumulation.DomainEvaluationAccumulator.init(a, alpha, max_log, component.nConstraints());
    defer actual.deinit();
    var expected = try engine.air.accumulation.DomainEvaluationAccumulator.init(a, alpha, max_log, component.nConstraints());
    defer expected.deinit();
    try component.evaluateConstraintQuotientsOnDomain(&trace, &actual);
    const aliased = try a.dupe(engine.air.component_prover.Poly, trees[0]);
    for (component.plan.active()) |shard| aliased[shard.active_index] = trees[1][shard.main_index];
    var original_trees = [_][]const engine.air.component_prover.Poly{ aliased, trees[1][0..component.plan.native_main_count], trees[2] };
    const original = engine.air.component_prover.Trace{ .polys = .{ .items = &original_trees } };
    for (component.inner.proving.components.active()) |item| try item.evaluateConstraintQuotientsOnDomain(&original, &expected);
    // Independent oracle evaluates source coefficients at actual domain
    // points; it does not reuse the new component's row-value recovery loop.
    for (component.plan.active()) |shard| {
        const log = shard.log_size + 2;
        const domain = core.poly.circle.canonic.CanonicCoset.new(log).circleDomain();
        const output = try expected.columns(a, &.{.{ .log_size = log, .n_cols = Activity.N_CONSTRAINTS }});
        var bucket = output[0];
        for (0..domain.size()) |physical| {
            const base = domain.at(core.utils.bitReverseIndex(physical, log));
            const point = core.circle.CirclePointQM31{ .x = Q.fromBase(base.x), .y = Q.fromBase(base.y) };
            const prior = @import("../air/logup.zig").prevRowPoint(shard.log_size, point);
            const active = trees[1][shard.main_index].coefficients.?;
            const count = trees[1][shard.main_index + 1].coefficients.?;
            const checks = Activity.evaluate(Q, trees[0][shard.first_index].coefficients.?.evalAtPoint(point), active.evalAtPoint(point), active.evalAtPoint(prior), count.evalAtPoint(point), count.evalAtPoint(prior), Q.fromBase(M.fromCanonical(shard.rows)));
            const inverse = try core.constraints.cosetVanishing(Q, core.poly.circle.canonic.CanonicCoset.new(shard.log_size).coset(), point).inv();
            var folded = Q.zero();
            for (checks, 0..) |check, i| folded = folded.add(bucket.random_coeff_powers[bucket.random_coeff_powers.len - 1 - i].mul(check));
            bucket.accumulate(physical, folded.mul(inverse));
        }
    }
    try std.testing.expectEqual(@as(usize, 0), actual.next_power_index);
    try std.testing.expectEqual(@as(usize, 0), expected.next_power_index);
    for (actual.sub_accumulations, expected.sub_accumulations) |one, two| {
        try std.testing.expectEqual(one == null, two == null);
        if (one) |left| for (0..left.len()) |row| try std.testing.expectEqualDeep(left.at(row), two.?.at(row));
    }
}
fn commitBody(a: std.mem.Allocator, native: *@import("blake3_execution_trace.zig").Owner, pin: Public.Admission) anyerror!Proof.ForBackend(Cpu).FirstRound {
    return Proof.ForBackend(Cpu).commitFirstRound(a, native, pin, config, .rv32im_zkvm_v1, 0, .{});
}
fn proveBody(a: std.mem.Allocator, first: *Proof.ForBackend(Cpu).FirstRound, sealed: Seal.Sealed, pins: Seal.Pins, entries: []const Seal.Entry) anyerror!Proof.Proof {
    return Proof.ForBackend(Cpu).prove(a, first, sealed, pins, entries);
}
fn verifyBody(a: std.mem.Allocator, proof: Proof.Proof, statement: *const Statement.Blake3ExecutionStatement, external: u32, pin: Public.Admission, template: Protocol.Template, id: Protocol.Digest, sealed: Seal.Sealed, pins: Seal.Pins, entries: []const Seal.Entry) anyerror!Proof.OpenReceipt {
    return Proof.ForBackend(Cpu).verifyOwned(a, proof, statement, external, pin, template, id, 0, sealed, pins, entries, .{});
}
test "native capacity real CPU first round prove and fresh receive bodies compile without executing" {
    inline for (.{ &commitBody, &proveBody, &verifyBody }) |function| std.mem.doNotOptimizeAway(function);
    const Api = Proof.ForBackend(Cpu);
    std.mem.doNotOptimizeAway(&Api.collect);
    std.mem.doNotOptimizeAway(&Api.commitPhysical);
    std.mem.doNotOptimizeAway(&Api.PhysicalFirstRound.bind);
}
