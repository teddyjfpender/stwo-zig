//! CPU-only B5CT recursive equation/public-supply qualification. No proof runs.
const std = @import("std");
const core = @import("stwo_core");
const Capacity = @import("../block_v5_native_capacity_protocol_v1.zig");
const Proof = @import("../block_v5_native_capacity_proof_v1.zig");
const Public = @import("../block_v5_native_public_admission_v1.zig");
const Statement = @import("../../air/statement.zig");
const Joined = @import("../block_v5_native_components_v3.zig");
const Bus = @import("../../recursion/block_v5_capacity_recursive_public_bus_v1.zig");
const Parent = @import("../../recursion/block_v5_reusable_capacity_parent_protocol_v1.zig");
const Base = @import("../../recursion/blake3_execution_parent_protocol.zig");
const Composition = @import("../../recursion/air/block_v5_native_capacity_composition_v1.zig");
const Recorder = @import("../../recursion/air/composition_graph_recorder.zig");
const Universal = @import("../../recursion/air/universal_challenges.zig");
const Q = core.fields.qm31.QM31;
const M = core.fields.m31.M31;
const S = Recorder.Scalar;
fn shape(rows: u32, empty: bool) Statement.Blake3ExecutionStatement {
    var result = std.mem.zeroes(Statement.Blake3ExecutionStatement);
    result.initializeDescriptorStorage();
    if (!empty) {
        result.n_components = 1;
        result.component_descs[0] = .{ .family = .base_alu_imm, .log_size = 3, .n_rows = rows, .n_columns = @intCast(@import("../../runner/trace.zig").nColumnsForFamily(.base_alu_imm)) };
        result.n_infra = 1;
        result.infra_descs[0] = .{ .kind = .clock_update, .log_size = 1, .n_rows = 2, .n_columns = @import("../../infra_trace.zig").CLOCK_UPDATE_COLS };
    }
    result.total_steps = rows;
    result.public_data = .{ .initial_pc = 0, .final_pc = 0, .clock = rows, .initial_regs = @splat(0), .final_regs = @splat(0), .reg_last_clock = @splat(0), .program_root = .{ .bytes = @splat(3) }, .initial_rw_root = null, .final_rw_root = null, .completion = @import("../../air/public_data.zig").Completion.canonicalSelfLoop(0), .io_entries = .{ .input_start = 0x2000, .input_len = 0, .input_words = &.{}, .output_len = 0, .output_len_addr = 0x3004, .output_data_addr = 0x3008, .output_words = &.{} } };
    return result;
}
fn context(rows: u32) Public.Context {
    return .{ .job_id = @splat(1), .source_image_digest = @splat(2), .program_root = @splat(3), .program_plan_digest = @splat(4), .memory_plan_digest = @splat(5), .initial_source_plan_digest = @splat(6), .rw_endpoint_plan_digest = @splat(7), .execution_index = 0, .first_cycle = 1, .last_cycle = rows };
}
fn scalar(seed: usize) Q {
    return Q.fromU32Unchecked(@intCast(seed + 1), @intCast(seed + 2), @intCast(seed + 3), @intCast(seed + 4));
}
const Samples = struct {
    trees: [][][]S,
    pub fn at(self: Samples, tree: usize, column: usize, sample: usize) !S {
        if (tree >= self.trees.len or column >= self.trees[tree].len or sample >= self.trees[tree][column].len) return error.InvalidTestMask;
        return self.trees[tree][column][sample];
    }
    pub fn secure(self: Samples, column: usize, sample: usize) !S {
        var partials: [4]S = undefined;
        for (&partials, 0..) |*value, i| value.* = try self.at(2, column + i, sample);
        return Recorder.fromPartialEvals(partials);
    }
};
const Oracle = struct {
    arena: std.heap.ArenaAllocator,
    circuit: Recorder.Circuit,
    inputs: []Q,
    values: []Q,
    expected: Q,
    count_input: usize,
    expected_input: usize,
    quotient_node: u32,
    active_input: ?usize,
    prior_count_input: ?usize,
    constraint_count: usize,
    pub fn deinit(self: *Oracle) void {
        self.circuit.deinit();
        self.arena.deinit();
        self.* = undefined;
    }
    fn evaluate(self: *Oracle) !Q {
        try self.circuit.evaluateInto(self.inputs, self.values);
        return self.values[self.quotient_node];
    }
};
fn input(builder: *Recorder.Builder, a: std.mem.Allocator, values: *std.ArrayList(Q), value: Q) !S {
    const symbol = try builder.input();
    try values.append(a, value);
    return symbol.value;
}
/// Compare symbolic recursion against the independent original capacity
/// component point evaluator, including clock infra and its mixed log domain.
fn oracle(a: std.mem.Allocator, rows: u32, empty: bool) !Oracle {
    var arena = std.heap.ArenaAllocator.init(a);
    errdefer arena.deinit();
    const temp = arena.allocator();
    var statement = shape(rows, empty);
    const external: u32 = if (empty) rows else 0;
    const plan = try Capacity.Plan.fromShape(&statement, external);
    var claims = std.mem.zeroes(Statement.RiscVInteractionClaim);
    claims.n_components = statement.n_components;
    claims.n_infra = statement.n_infra;
    var channel = core.proof_suites.Blake3.Channel{};
    const relations = try Universal.UniversalRelations.draw(temp, &channel);
    const pin = try Public.Admission.init(context(rows), &statement.public_data);
    const owner = try Joined.Owner.initWithExternalForProfile(temp, &statement, &claims, relations, pin, external, .rv32im_zkvm_v1);
    defer owner.deinit();
    const component = try Proof.makeComponent(temp, owner, &statement, external);
    const max_log = core.verifier_types.compositionMaskLogSize(component.maxConstraintLogDegreeBound(), component.compositionLogSplit()) orelse return error.InvalidTestMask;
    const seed = scalar(71);
    const point = try core.circle.secureFieldPointFromRandomSeedChecked(seed);
    var points = try component.maskPoints(temp, point, max_log);
    defer points.deinitDeep(temp);
    const concrete = try temp.alloc([][]Q, points.items.len);
    const symbolic = try temp.alloc([][]S, points.items.len);
    var builder = Recorder.Builder.init(a);
    defer builder.deinit();
    var inputs: std.ArrayList(Q) = .empty;
    var active_input: ?usize = null;
    var prior_count_input: ?usize = null;
    for (points.items, concrete, symbolic, 0..) |tree, *out, *symbols, t| {
        out.* = try temp.alloc([]Q, tree.len);
        symbols.* = try temp.alloc([]S, tree.len);
        for (tree, out.*, symbols.*, 0..) |column, *values, *syms, i| {
            values.* = try temp.alloc(Q, column.len);
            syms.* = try temp.alloc(S, column.len);
            for (values.*, syms.*, 0..) |*value, *sym, j| {
                if (plan.len != 0 and t == 1 and i == plan.shards[0].main_index and j == 0) active_input = inputs.items.len;
                if (plan.len != 0 and t == 1 and i == plan.shards[0].main_index + 1 and j == 1) prior_count_input = inputs.items.len;
                value.* = scalar(10 + t * 113 + i * 7 + j);
                sym.* = try input(&builder, temp, &inputs, value.*);
            }
        }
    }
    var flat_claims: std.ArrayList(S) = .empty;
    for (statement.component_descs[0..statement.n_components], 0..) |desc, i| {
        for (try claims.opcodeClaims(desc.family, i)) |claim| try flat_claims.append(temp, try input(&builder, temp, &inputs, claim));
    }
    for (statement.infra_descs[0..statement.n_infra], 0..) |desc, i| {
        for (try claims.infraClaims(desc.kind, i)) |claim| try flat_claims.append(temp, try input(&builder, temp, &inputs, claim));
    }
    var draws: [Universal.RELATION_COUNT][2]S = undefined;
    for (&draws, relations.elements) |*pair, element| {
        pair[0] = try input(&builder, temp, &inputs, element.z);
        pair[1] = try input(&builder, temp, &inputs, element.alpha);
    }
    const randomness = scalar(17);
    const random_symbol = try input(&builder, temp, &inputs, randomness);
    const seed_symbol = try input(&builder, temp, &inputs, seed);
    const count_input = inputs.items.len;
    const count_symbols = try temp.alloc(S, if (plan.len == 0) 1 else plan.len);
    if (plan.len == 0) {
        count_symbols[0] = try input(&builder, temp, &inputs, Q.fromBase(M.fromCanonical(external)));
    } else {
        for (plan.active(), count_symbols) |shard, *sym| sym.* = try input(&builder, temp, &inputs, Q.fromBase(M.fromCanonical(shard.rows)));
    }
    var expected = core.air.accumulation.PointEvaluationAccumulator.init(randomness);
    const mask = core.air.components.MaskValues{ .items = concrete };
    try component.evaluateConstraintQuotientsAtPoint(point, &mask, &expected, max_log);
    const expected_input = inputs.items.len;
    const expected_symbol = try input(&builder, temp, &inputs, expected.finalize());
    try builder.activate();
    const challenges = try Recorder.ChallengeSet.init(draws);
    var cache: Recorder.DenominatorCache = @splat(null);
    var accumulated = S.zero();
    const count = try Composition.recordConstraints(&statement, &plan, Samples{ .trees = symbolic }, flat_claims.items, &challenges, random_symbol, Recorder.pointFromSeed(seed_symbol), max_log, &cache, &accumulated, count_symbols);
    // Scalar operators record allocation errors in the builder and return a
    // poisoned constant. Preserve the original OOM for the failure allocator
    // harness before examining the recorded quotient handle.
    if (builder.failure) |failure| return failure;
    if (count != component.nConstraints()) return error.InvalidTestConstraintCount;
    const quotient_node = switch (accumulated.handle) {
        .node => |node| node,
        .constant => return error.InvalidTestConstraintCount,
    };
    builder.constrainZero(accumulated.sub(expected_symbol)) catch |err| return builder.failure orelse err;
    builder.deactivate();
    var circuit = try builder.finish();
    errdefer circuit.deinit();
    const values = try temp.alloc(Q, circuit.nodes.len);
    var result = Oracle{ .arena = arena, .circuit = circuit, .inputs = inputs.items, .values = values, .expected = expected.finalize(), .count_input = count_input, .expected_input = expected_input, .quotient_node = quotient_node, .active_input = active_input, .prior_count_input = prior_count_input, .constraint_count = count };
    try std.testing.expect((try result.evaluate()).eql(result.expected));
    return result;
}
test "capacity recursion: original equations match symbolic mixed-domain activity graph and public count mutations" {
    var first = try oracle(std.testing.allocator, 5, false);
    defer first.deinit();
    var second = try oracle(std.testing.allocator, 7, false);
    defer second.deinit();
    try std.testing.expectEqualDeep(first.circuit.identity_digest, second.circuit.identity_digest);
    const original = try first.evaluate();
    first.inputs[first.count_input] = Q.fromBase(M.fromCanonical(7));
    try std.testing.expectError(error.UnsatisfiedCircuit, first.evaluate());
    first.inputs[first.expected_input] = second.expected;
    try std.testing.expect((try first.evaluate()).eql(try second.evaluate()));
    try std.testing.expect(!(try first.evaluate()).eql(original));
    first.inputs[first.count_input] = Q.fromBase(M.fromCanonical(5));
    first.inputs[first.expected_input] = first.expected;
    first.inputs[first.active_input.?] = first.inputs[first.active_input.?].add(Q.one());
    try std.testing.expectError(error.UnsatisfiedCircuit, first.evaluate());
    first.inputs[first.active_input.?] = first.inputs[first.active_input.?].sub(Q.one());
    first.inputs[first.prior_count_input.?] = first.inputs[first.prior_count_input.?].add(Q.one());
    try std.testing.expectError(error.UnsatisfiedCircuit, first.evaluate());
}
test "capacity recursion: genuine empty frame counts are public and reuse one graph" {
    var first = try oracle(std.testing.allocator, 3, true);
    defer first.deinit();
    var second = try oracle(std.testing.allocator, 7, true);
    defer second.deinit();
    try std.testing.expectEqualDeep(first.circuit.identity_digest, second.circuit.identity_digest);
    first.inputs[first.count_input] = Q.fromBase(M.fromCanonical(7));
    try std.testing.expectError(error.UnsatisfiedCircuit, first.evaluate());
    first.inputs[first.expected_input] = second.expected;
    try std.testing.expect((try first.evaluate()).eql(try second.evaluate()));
    try std.testing.expect(!first.expected.eql(second.expected));
}
fn allocationOracle(a: std.mem.Allocator) !void {
    var value = try oracle(a, 3, true);
    defer value.deinit();
}
test "capacity recursion: graph construction releases every failed allocation" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, allocationOracle, .{});
}
fn publicValues(count: u32) Bus.Values {
    var result = Bus.Values{ .sealed = @splat(1), .template = @splat(2), .instance = @splat(3), .roots = .{ @splat(4), @splat(5) }, .index = 0, .compensation = scalar(19), .open_sum = scalar(21), .statement_digest = @splat(6), .exact_geometry_digest = @splat(7), .row_count = count };
    for (result.rows[0..count], 0..) |*rows, i| rows.* = @intCast(i + 1);
    if (count == 0) result.frame_retirements = 3;
    return result;
}
fn geometry() Base.Key {
    return .{ .context = .{ .child_key_id = @splat(2), .child_config = Base.PCS_CONFIG, .graph_ids = .{ @splat(10), @splat(11), @splat(12) }, .transcript_plan_id = @splat(13) }, .log_sizes = @splat(1), .preprocessed_root = @splat(14) };
}
test "capacity recursion: 257 count wires retain wide indices and changed public values reuse setup" {
    var wires: [Capacity.MAX_SHARDS]Bus.Wire = undefined;
    for (&wires, 0..) |*wire, i| wire.* = .{ .circuit = 1500, .wire = @intCast(i), .uses = 1, .source = .row_count, .coordinate = @intCast(i) };
    const values = publicValues(Capacity.MAX_SHARDS);
    try values.validate();
    const binding = try values.publicInput(258);
    try std.testing.expectEqual(@as(u32, 256), binding.coordinate);
    try std.testing.expectEqualDeep(M.fromCanonical(257), (try values.at(binding.source, binding.coordinate))[0]);
    const key = try Parent.Key.fromGeometry(geometry(), &wires);
    const key_id = try key.identity();
    const first = try Parent.Admission.init(key, key_id, &wires, values);
    var changed = values;
    changed.rows[256] = 258;
    const second = try Parent.Admission.init(key, key_id, &wires, changed);
    try std.testing.expectEqualDeep(try first.key.identity(), try second.key.identity());
    try std.testing.expect(!std.meta.eql(try first.publicInputIdentity(), try second.publicInputIdentity()));
    var channel = core.proof_suites.Blake3.Channel{};
    const relations = try Universal.UniversalRelations.draw(std.testing.allocator, &channel);
    const supply = try Bus.supply(&wires, values, relations);
    try std.testing.expect(!supply.eql(try Bus.supply(&wires, changed, relations)));
    var claims: @import("../../recursion/blake3_native_parent_artifact.zig").Claims = @splat(Q.zero());
    claims[0] = supply.neg();
    try first.validateClaimsForRelations(claims, relations);
    try std.testing.expectError(error.InvalidReusableCapacityParentPublicClosure, second.validateClaimsForRelations(claims, relations));
    var duplicate = wires;
    duplicate[256].wire = 0;
    try std.testing.expectError(error.InvalidRecursivePublicSchedule, Bus.scheduleDigest(&duplicate));
    var outside = wires;
    outside[256].coordinate = 257;
    try std.testing.expectError(error.InvalidRecursivePublicSchedule, Bus.scheduleDigest(&outside));
    changed = values;
    changed.row_count -= 1;
    try std.testing.expectError(error.InvalidCapacityPublicInputs, changed.validate());
    var wrong_template = values;
    wrong_template.template[0] ^= 1;
    try std.testing.expectError(error.UntrustedCapacityRecursiveTemplate, Parent.Admission.init(key, key_id, &wires, wrong_template));
    var security = key;
    security.context.child_config.pow_bits = 1;
    try std.testing.expectError(error.CapacityRecursiveSecurityMismatch, Parent.Admission.init(security, key_id, &wires, values));
}

const Seal = @import("../block_v5_source_seal_v1.zig");
const Catalog = @import("../block_v5_native_capacity_catalog_v1.zig");
const Recursive = @import("../block_v5_native_capacity_recursive_admission_v1.zig").Prepared;
/// These are independently planned metadata, not a manufactured proof/capture.
const PolicyFixture = struct {
    template: Capacity.Template,
    records: [1]Catalog.Record,
    pin: Public.Admission,
    entries: [5]Seal.Entry,
    pins: Seal.Pins,
    sealed: Seal.Sealed,
    fn init(statement: *const Statement.Blake3ExecutionStatement, external: u32) !PolicyFixture {
        const template = try Capacity.Template.fromShape(statement, external, Base.PCS_CONFIG, .rv32im_zkvm_v1, @splat(4));
        const records = [_]Catalog.Record{try Catalog.Record.fromTemplate(0, template)};
        const pin = try Public.Admission.init(context(statement.total_steps), &statement.public_data);
        const roots: Seal.Roots = .{ template.fixed_root, @splat(20) };
        const entries = [_]Seal.Entry{
            .{ .family = .program, .index = 0, .instance_id = @splat(10), .roots = .{ @splat(11), @splat(12) } },
            .{ .family = .execution, .index = 0, .instance_id = try Capacity.instanceId(records[0].template_id, statement, external, pin, roots, 0), .roots = roots },
            .{ .family = .execution_sidecar, .index = 0, .instance_id = @splat(30), .roots = .{ @splat(31), @splat(32) } },
            .{ .family = .program_request, .index = 0, .instance_id = @splat(40), .roots = .{ @splat(41), @splat(42) } },
            .{ .family = .memory, .index = 0, .instance_id = @splat(50), .roots = .{ @splat(51), @splat(52) } },
        };
        var counts: [Seal.family_count]u32 = @splat(0);
        for (entries) |entry| counts[@intFromEnum(entry.family) - 1] += 1;
        const pins = Seal.Pins{ .job_id = @splat(1), .source_image_digest = @splat(2), .program_root = @splat(3), .program_plan_digest = @splat(4), .memory_plan_digest = @splat(5), .initial_source_plan_digest = @splat(6), .rw_endpoint_plan_digest = @splat(7), .native_template_catalog_digest = try (Catalog.Admission{ .records = &records }).digest(), .config = Base.PCS_CONFIG, .counts = counts };
        return .{ .template = template, .records = records, .pin = pin, .entries = entries, .pins = pins, .sealed = try Seal.seal(pins, &entries) };
    }
    fn prepared(self: *const PolicyFixture, a: std.mem.Allocator, statement: *const Statement.Blake3ExecutionStatement, external: u32) !Recursive {
        return Recursive.init(a, statement, external, self.pin, self.template, self.records[0].template_id, 0, self.sealed, self.pins, &self.entries, .{ .records = &self.records }, .{});
    }
    fn expectedMetadata(self: *const PolicyFixture, statement: *const Statement.Blake3ExecutionStatement, external: u32) !Proof.OpenReceipt {
        return .{ .template_id = self.records[0].template_id, .instance_id = self.entries[1].instance_id, .first_roots = self.entries[1].roots, .sealed_digest = self.sealed.digest, .exact_geometry_digest = try @import("../block_v5_native_template_protocol_v3.zig").geometryDigest(statement, external), .open_sum = scalar(32) };
    }
};
fn admissionAllocation(a: std.mem.Allocator, fixture: *const PolicyFixture, statement: *const Statement.Blake3ExecutionStatement) !void {
    var policy = try fixture.prepared(a, statement, 0);
    defer policy.deinit();
    const plan = try Capacity.Plan.fromShape(statement, 0);
    try std.testing.expectEqual(plan.mainCount(), policy.logs[1].len);
    try std.testing.expectEqual(plan.native_main_count + 2 * plan.len, policy.logs[1].len);
}
test "capacity recursion: independent catalog admission owns geometry and fails closed on source public and root mutations" {
    var statement = shape(5, false);
    var fixture = try PolicyFixture.init(&statement, 0);
    var policy = try fixture.prepared(std.testing.allocator, &statement, 0);
    defer policy.deinit();
    const metadata = try fixture.expectedMetadata(&statement, 0);
    const values = try Bus.Values.fromCapacity(std.testing.allocator, &policy, metadata);
    try std.testing.expectEqual(@as(u32, 2), values.row_count);
    try std.testing.expectEqual(@as(u32, 5), values.rows[0]);
    try std.testing.expectEqual(@as(u32, 2), values.rows[1]);
    try std.testing.expectEqual(@as(u32, 0), values.frame_retirements);
    var forged = metadata;
    forged.instance_id[0] ^= 1;
    try std.testing.expectError(error.UntrustedCapacityPublicInputs, Bus.Values.fromCapacity(std.testing.allocator, &policy, forged));
    forged = metadata;
    forged.exact_geometry_digest[0] ^= 1;
    try std.testing.expectError(error.UntrustedCapacityPublicInputs, Bus.Values.fromCapacity(std.testing.allocator, &policy, forged));
    forged = metadata;
    forged.first_roots[1][0] ^= 1;
    try std.testing.expectError(error.UntrustedCapacityPublicInputs, Bus.Values.fromCapacity(std.testing.allocator, &policy, forged));
    const saved_log = policy.logs[1][0];
    policy.logs[1][0] += 1;
    try std.testing.expectError(error.UntrustedNativeCapacityRecursiveGeometry, policy.validate(policy.template_id));
    policy.logs[1][0] = saved_log;
    var altered = policy;
    altered.config.pow_bits = 1;
    try std.testing.expectError(error.UntrustedNativeCapacityRecursiveAdmission, altered.validate(policy.template_id));
    var other = shape(7, false);
    altered = policy;
    altered.shape = &other;
    try std.testing.expectError(error.UntrustedNativeV5PublicAdmission, altered.validate(policy.template_id));
    fixture.records[0].fixed_root[0] ^= 1;
    try std.testing.expectError(error.UntrustedNativeCapacityCatalog, policy.validate(policy.template_id));
}
test "capacity recursion: independent prepared geometry releases every failed allocation" {
    var statement = shape(5, false);
    const fixture = try PolicyFixture.init(&statement, 0);
    try std.testing.checkAllAllocationFailures(std.testing.allocator, admissionAllocation, .{ &fixture, &statement });
}
test "native column geometry: actual prepared validation needs no scratch allocation and retains mutation rejection" {
    var statement = shape(5, false);
    const fixture = try PolicyFixture.init(&statement, 0);
    var policy = try fixture.prepared(std.testing.allocator, &statement, 0);
    defer policy.deinit();
    var denied = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 0 });
    policy.allocator = denied.allocator();
    defer policy.allocator = std.testing.allocator;
    try policy.validate(policy.template_id);
    for (policy.logs) |logs| {
        const original = logs[logs.len - 1];
        logs[logs.len - 1] += 1;
        try std.testing.expectError(error.UntrustedNativeCapacityRecursiveGeometry, policy.validate(policy.template_id));
        logs[logs.len - 1] = original;
    }
    try std.testing.expectEqual(@as(usize, 0), denied.alloc_index);
}
test "native column geometry: legacy prepared masks reject mutation and truncation without allocation" {
    const Legacy = @import("../block_v5_native_template_protocol_v3.zig");
    const Prepared = @import("../block_v5_native_recursive_admission_v3.zig").Prepared;
    for ([_]bool{ false, true }) |empty| {
        const external: u32 = if (empty) 3 else 0;
        var statement = shape(if (empty) 3 else 5, empty);
        var fixture = try PolicyFixture.init(&statement, external);
        const template = try Legacy.Template.fromShape(&statement, Base.PCS_CONFIG, .rv32im_zkvm_v1, external, @splat(4));
        const expected = try template.identity();
        fixture.pins.native_template_catalog_digest = @splat(0);
        fixture.pins.native_template_id = expected;
        fixture.entries[1].instance_id = try Legacy.instanceId(expected, &statement, fixture.pin, fixture.entries[1].roots, 0);
        fixture.sealed = try Seal.seal(fixture.pins, &fixture.entries);
        var prepared = try Prepared.init(std.testing.allocator, &statement, fixture.pin, template, expected, 0, fixture.sealed, fixture.pins, &fixture.entries, null);
        defer prepared.deinit();
        var denied = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 0 });
        prepared.allocator = denied.allocator();
        defer prepared.allocator = std.testing.allocator;
        try prepared.validate(expected);
        for (prepared.logs) |logs| {
            const original = logs[logs.len - 1];
            logs[logs.len - 1] += 1;
            try std.testing.expectError(error.UntrustedNativeV5RecursiveGeometry, prepared.validate(expected));
            logs[logs.len - 1] = original;
        }
        const main = prepared.logs[1];
        prepared.logs[1] = main[0 .. main.len - 1];
        try std.testing.expectError(error.UntrustedNativeV5RecursiveGeometry, prepared.validate(expected));
        prepared.logs[1] = main;
        try std.testing.expectEqual(@as(usize, 0), denied.alloc_index);
    }
}
test "capacity recursion: independent empty policy binds retirement count through frame public supply" {
    var statement = shape(3, true);
    const fixture = try PolicyFixture.init(&statement, 3);
    var policy = try fixture.prepared(std.testing.allocator, &statement, 3);
    defer policy.deinit();
    const values = try Bus.Values.fromCapacity(std.testing.allocator, &policy, try fixture.expectedMetadata(&statement, 3));
    try std.testing.expectEqual(@as(u32, 0), values.row_count);
    try std.testing.expectEqual(@as(u32, 3), values.frame_retirements);
    const binding = try values.publicInput(2);
    try std.testing.expectEqual(Bus.Source.frame_retirements, binding.source);
    try std.testing.expectEqualDeep(M.fromCanonical(3), (try values.at(binding.source, 0))[0]);
    try std.testing.expectError(error.InvalidCapacityPublicSchedule, values.publicInput(3));
    const wire = [_]Bus.Wire{.{ .circuit = 1500, .wire = 0, .uses = 2, .source = .frame_retirements, .coordinate = 0 }};
    var base_geometry = geometry();
    base_geometry.context.child_key_id = values.template;
    const key = try Parent.Key.fromGeometry(base_geometry, &wire);
    const original = try Parent.Admission.init(key, try key.identity(), &wire, values);
    var changed = values;
    changed.frame_retirements = 7;
    const other = try Parent.Admission.init(key, try key.identity(), &wire, changed);
    try std.testing.expect(!std.meta.eql(try original.publicInputIdentity(), try other.publicInputIdentity()));
}
