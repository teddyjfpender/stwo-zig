//! Rung R3: every in-circuit evaluator (83 Cairo slots, 11 circuit
//! components) built in a fresh context, against `vectors/circuit/r3/components.json`
//! and the upstream `sample_evaluations.json` assignments, and per harness
//! stage against `vectors/circuit/r3/statement_trace.json`.
//!
//! The harness mirrors the oracle's (`tools/stwo-circuit-oracle-rs/src/components/harness.rs`),
//! which is upstream `gen_tests_module`'s `test_evaluation_result`:
//! `TestComponentData::from_values`; `new_var` of random_coeff, z, alpha;
//! `constant` per preprocessed column then per public parameter, in the
//! recorded orders; the accumulator; `evaluate`; `new_var(claimed_sum)`;
//! `finalize_logup_in_pairs`. There is no `Context::finalize`.
//!
//! Each evaluator runs in value mode (with `assert_eq_on_eval`) and in
//! topology mode; both must build the recorded gate lists and the recorded
//! statement trace (the oracle traces topology mode).

const std = @import("std");
const stwo_core = @import("stwo_core");
const circuit = @import("stwo_circuit_frontend");
const stand_in = @import("../testing/builder_stand_in.zig");
const fixture = @import("../../testing/fixture_json.zig");
const statement_trace = @import("statement_trace.zig");

const QM31 = stwo_core.fields.qm31.QM31;
const M31 = stwo_core.fields.m31.M31;
const air_eval = circuit.air_eval;
const constraint_eval = circuit.stark_verifier.constraint_eval;
const TestComponentData = circuit.stark_verifier.test_utils.TestComponentData;
const Table = air_eval.component_table.Table;
const Value = std.json.Value;

const projection_path = "vectors/circuit/official/compiled_air_constraints_v1.bin";
const components_path = "vectors/circuit/r3/components.json";
const statement_trace_path = "vectors/circuit/r3/statement_trace.json";
const casm_samples_path = "vectors/circuit/official/compiled_casm_air.sample_evaluations.json";
const circuit_samples_path = "vectors/circuit/official/compiled_circuit_air.sample_evaluations.json";

const Named = struct { name: []const u8, value: QM31 };

/// The values fed to one evaluator, in harness order.
const Inputs = struct {
    base_trace: []const QM31,
    interaction_trace: []const QM31,
    preprocessed_columns: []const Named,
    public_params: []const Named,
    random_coeff: QM31,
    last_row_sum: QM31,
    z: QM31,
    alpha: QM31,
    claimed_sum: QM31,
    log_height: u32,
};

fn Outcome(comptime V: type) type {
    return struct {
        summary: stand_in.Summary,
        result: V,
        values_sha256: ?[32]u8,
        trace: statement_trace.Trace,
    };
}

/// Steps 1-5 of the harness in a fresh context. The statement trace is
/// allocated from `arena`.
fn runHarness(
    comptime V: type,
    allocator: std.mem.Allocator,
    arena: std.mem.Allocator,
    table: *const Table,
    slot: usize,
    inputs: Inputs,
) !Outcome(V) {
    const Ctx = stand_in.Context(V);
    var ctx = try Ctx.init(allocator);
    defer ctx.deinit();
    ctx.assert_eq_on_eval = V == QM31;

    var data = try TestComponentData(Ctx).fromValues(
        allocator,
        &ctx,
        inputs.base_trace,
        inputs.interaction_trace,
        inputs.last_row_sum,
        @as(u32, 1) << @intCast(inputs.log_height),
    );
    defer data.deinit(allocator);
    const random_coeff = try ctx.newVar(Ctx.lift(inputs.random_coeff));
    const interaction_elements = [2]Ctx.Var{ try ctx.newVar(Ctx.lift(inputs.z)), try ctx.newVar(Ctx.lift(inputs.alpha)) };

    var preprocessed: constraint_eval.ColumnMap(Ctx.Var) = .empty;
    defer preprocessed.deinit(allocator);
    for (inputs.preprocessed_columns) |column| try preprocessed.put(allocator, column.name, try ctx.constant(column.value));
    var public_params: constraint_eval.ColumnMap(Ctx.Var) = .empty;
    defer public_params.deinit(allocator);
    for (inputs.public_params) |param| try public_params.put(allocator, param.name, try ctx.constant(param.value));

    var acc = constraint_eval.CompositionConstraintAccumulator(Ctx).init(
        allocator,
        &ctx,
        &preprocessed,
        &public_params,
        random_coeff,
        interaction_elements,
    );
    defer acc.deinit();
    var marks: [statement_trace.stage_names.len]statement_trace.Mark(stand_in.kind_names.len) = undefined;
    marks[0] = statement_trace.mark(&ctx);
    var scratch = std.heap.ArenaAllocator.init(allocator);
    defer scratch.deinit();
    try table.evaluate(slot, Ctx, &ctx, &data, &acc, scratch.allocator());
    marks[1] = statement_trace.mark(&ctx);
    const claimed_sum = try ctx.newVar(Ctx.lift(inputs.claimed_sum));
    try acc.finalizeLogupInPairs(&ctx, data.interactionColumns(), &data, claimed_sum);
    marks[2] = statement_trace.mark(&ctx);
    const result = acc.finalize();
    return .{
        .summary = ctx.summary(),
        .result = ctx.get(result),
        .values_sha256 = if (V == QM31) ctx.valuesSha256() else null,
        .trace = try statement_trace.trace(arena, &ctx, &stand_in.kind_names, &marks),
    };
}

const Samples = struct {
    casm: fixture.Document,
    circuit: fixture.Document,

    fn forAir(self: *const Samples, air: []const u8) Value {
        return if (std.mem.eql(u8, air, "cairo")) self.casm.root() else self.circuit.root();
    }
};

/// Inputs of a `sample_evaluations` assignment: values from the upstream
/// sample, orders from the checkpoint record (`Seq` is keyed `seq_{log_height}`).
fn sampleInputs(arena: std.mem.Allocator, sample: Value, record: Value) !Inputs {
    const assignment = try fixture.field(sample, "assignment");
    const environment = try fixture.field(assignment, "environment");
    const log_height = try fixture.unsigned(u32, try fixture.field(assignment, "log_height"));
    if (log_height != try fixture.unsigned(u32, try fixture.field(record, "log_height"))) return error.FixtureShape;
    const seq_id = try std.fmt.allocPrint(arena, "seq_{d}", .{log_height});

    const external_states = try fixture.array(try fixture.field(environment, "external_states"));
    const column_ids = try fixture.array(try fixture.field(record, "preprocessed_columns"));
    const columns = try arena.alloc(Named, column_ids.len);
    for (column_ids, columns) |id_value, *column| {
        const id = try fixture.string(id_value);
        const key = if (hasState(external_states, id)) id else if (std.mem.eql(u8, id, seq_id)) "Seq" else return error.FixtureShape;
        column.* = .{ .name = id, .value = try stateValue(external_states, key) };
    }
    const params_object = try fixture.field(environment, "public_params");
    const param_names = try fixture.array(try fixture.field(record, "public_params"));
    const params = try arena.alloc(Named, param_names.len);
    for (param_names, params) |name_value, *param| {
        const name = try fixture.string(name_value);
        param.* = .{ .name = name, .value = QM31.fromBase(try fixture.m31(try fixture.field(params_object, name))) };
    }
    const lookup_elements = try fixture.field(assignment, "common_lookup_elements");
    return .{
        .base_trace = try fixture.qm31List(arena, try fixture.field(assignment, "base_trace")),
        .interaction_trace = try fixture.qm31List(arena, try fixture.field(assignment, "interaction_trace")),
        .preprocessed_columns = columns,
        .public_params = params,
        .random_coeff = try fixture.qm31(try fixture.field(assignment, "random_coeff")),
        .last_row_sum = try fixture.qm31(try fixture.field(assignment, "last_row_sum")),
        .z = try fixture.qm31(try fixture.field(lookup_elements, "z")),
        .alpha = try fixture.qm31(try fixture.field(lookup_elements, "alpha")),
        .claimed_sum = try fixture.qm31(try fixture.field(assignment, "claimed_sum")),
        .log_height = log_height,
    };
}

fn hasState(states: []const Value, name: []const u8) bool {
    for (states) |entry| {
        const pair = fixture.array(entry) catch return false;
        if (pair.len == 2 and pair[0] == .string and std.mem.eql(u8, pair[0].string, name)) return true;
    }
    return false;
}

fn stateValue(states: []const Value, name: []const u8) !QM31 {
    for (states) |entry| {
        const pair = try fixture.array(entry);
        if (pair.len != 2) return error.FixtureShape;
        if (std.mem.eql(u8, try fixture.string(pair[0]), name)) return fixture.qm31(pair[1]);
    }
    return error.FixtureShape;
}

/// Inputs synthesized by the oracle for hand-written evaluators, emitted inline.
fn synthesizedInputs(arena: std.mem.Allocator, inputs: Value) !Inputs {
    const columns = try namedList(arena, try fixture.field(inputs, "preprocessed_columns"), .qm31);
    const params = try namedList(arena, try fixture.field(inputs, "public_params"), .m31);
    return .{
        .base_trace = try fixture.qm31List(arena, try fixture.field(inputs, "base_trace")),
        .interaction_trace = try fixture.qm31List(arena, try fixture.field(inputs, "interaction_trace")),
        .preprocessed_columns = columns,
        .public_params = params,
        .random_coeff = try fixture.qm31(try fixture.field(inputs, "random_coeff")),
        .last_row_sum = try fixture.qm31(try fixture.field(inputs, "last_row_sum")),
        .z = try fixture.qm31(try fixture.field(inputs, "z")),
        .alpha = try fixture.qm31(try fixture.field(inputs, "alpha")),
        .claimed_sum = try fixture.qm31(try fixture.field(inputs, "claimed_sum")),
        .log_height = try fixture.unsigned(u32, try fixture.field(inputs, "log_height")),
    };
}

fn namedList(arena: std.mem.Allocator, value: Value, comptime kind: enum { qm31, m31 }) ![]const Named {
    const items = try fixture.array(value);
    const out = try arena.alloc(Named, items.len);
    for (items, out) |item, *entry| {
        const pair = try fixture.array(item);
        if (pair.len != 2) return error.FixtureShape;
        entry.* = .{
            .name = try fixture.string(pair[0]),
            .value = switch (kind) {
                .qm31 => try fixture.qm31(pair[1]),
                .m31 => QM31.fromBase(try fixture.m31(pair[1])),
            },
        };
    }
    return out;
}

fn expectQm31(expected: Value, actual: QM31) !void {
    try std.testing.expect((try fixture.qm31(expected)).eql(actual));
}

fn expectSummary(expected: Value, actual: stand_in.Summary) !void {
    try std.testing.expectEqual(try fixture.unsigned(u32, try fixture.field(expected, "n_vars")), actual.n_vars);
    const kinds = try fixture.array(try fixture.field(expected, "kinds"));
    try std.testing.expectEqual(stand_in.kind_names.len, kinds.len);
    for (kinds, actual.kinds, stand_in.kind_names) |kind, summary, name| {
        try std.testing.expectEqualStrings(name, try fixture.string(try fixture.field(kind, "kind")));
        try std.testing.expectEqual(try fixture.unsigned(u64, try fixture.field(kind, "count")), summary.count);
        try std.testing.expectEqual(try fixture.digest(try fixture.field(kind, "sha256")), summary.sha256);
    }
    try std.testing.expectEqual(try fixture.digest(try fixture.field(expected, "gate_list_sha256")), actual.gate_list_sha256);
    try std.testing.expectEqual(try fixture.digest(try fixture.field(expected, "debug_text_sha256")), actual.debug_text_sha256);
}

fn expectEntryShape(record: Value, table: *const Table, slot: usize) !void {
    const entry = table.entries[slot];
    try std.testing.expectEqualStrings(try fixture.string(try fixture.field(record, "name")), entry.name);
    try std.testing.expectEqualStrings(try fixture.string(try fixture.field(record, "evaluator_name")), entry.name);
    try std.testing.expectEqual(try fixture.unsigned(usize, try fixture.field(record, "trace_columns")), entry.shape.trace_columns);
    try std.testing.expectEqual(try fixture.unsigned(usize, try fixture.field(record, "interaction_columns")), entry.shape.interaction_columns);
    try std.testing.expectEqual(try fixture.boolean(try fixture.field(record, "hand_written")), entry.evaluator == .manual);
    const uses = try fixture.array(try fixture.field(record, "relation_uses_per_row"));
    try std.testing.expectEqual(uses.len, entry.shape.relation_uses_per_row.len);
    for (uses, entry.shape.relation_uses_per_row) |use, actual| {
        try std.testing.expectEqualStrings(try fixture.string(try fixture.field(use, "relation_id")), actual.relation_id);
        try std.testing.expectEqual(try fixture.unsigned(u64, try fixture.field(use, "uses")), actual.uses);
    }
}

/// For a generated evaluator the recorded preprocessed and public-parameter
/// orders must be the projected function's `external_states` and
/// `public_params` (the harness order), with `Seq` keyed `seq_{log_height}`.
fn expectHarnessOrders(table: *const Table, slot: usize, record: Value, log_height: u32) !void {
    const function_index = switch (table.entries[slot].evaluator) {
        .generated => |index| index,
        .manual => return,
    };
    const projection = table.projection;
    const function = table.source.functions[function_index];
    const ids = try fixture.array(try fixture.field(record, "preprocessed_columns"));
    const states = projection.nameList(function.external_states);
    try std.testing.expectEqual(states.len, ids.len);
    var seq_buffer: [16]u8 = undefined;
    for (states, ids) |state, id| {
        const name = projection.str(state);
        const expected = if (std.mem.eql(u8, name, "Seq")) try std.fmt.bufPrint(&seq_buffer, "seq_{d}", .{log_height}) else name;
        try std.testing.expectEqualStrings(expected, try fixture.string(id));
    }
    const params = try fixture.array(try fixture.field(record, "public_params"));
    const projected = projection.nameList(function.public_params);
    try std.testing.expectEqual(projected.len, params.len);
    for (projected, params) |param, name| try std.testing.expectEqualStrings(projection.str(param), try fixture.string(name));
}

test "R3: all 94 in-circuit evaluators match the oracle gate lists, values and results" {
    const gpa = std.testing.allocator;
    const bytes = try std.fs.cwd().readFileAlloc(gpa, projection_path, 4 << 20);
    defer gpa.free(bytes);
    var projection = try air_eval.projection.parse(gpa, bytes);
    defer projection.deinit();
    var cairo_table = try air_eval.cairo_components.build(gpa, &projection);
    defer cairo_table.deinit();
    var circuit_table = try air_eval.circuit_components.build(gpa, &projection);
    defer circuit_table.deinit();

    var components = try fixture.load(gpa, components_path, 4 << 20);
    defer components.deinit();
    var traces = try fixture.load(gpa, statement_trace_path, 4 << 20);
    defer traces.deinit();
    const traces_body = try fixture.checkpointBody(traces.root(), "r3", "statement-trace");
    try std.testing.expectEqual(@as(u64, statement_trace.window), try fixture.unsigned(u64, try fixture.field(traces_body, "window")));
    const trace_records = try fixture.array(try fixture.field(traces_body, "evaluators"));
    var samples: Samples = .{
        .casm = try fixture.load(gpa, casm_samples_path, 4 << 20),
        .circuit = try fixture.load(gpa, circuit_samples_path, 1 << 20),
    };
    defer samples.casm.deinit();
    defer samples.circuit.deinit();

    const body = try fixture.checkpointBody(components.root(), "r3", "components");
    try expectSlotNames(try fixture.field(body, "cairo_slots"), &cairo_table);
    try expectSlotNames(try fixture.field(body, "circuit_components"), &circuit_table);

    var used_samples: std.StringHashMapUnmanaged(void) = .empty;
    defer used_samples.deinit(gpa);
    const evaluators = try fixture.array(try fixture.field(body, "evaluators"));
    try std.testing.expectEqual(@as(usize, 94), evaluators.len);
    try std.testing.expectEqual(evaluators.len, trace_records.len);
    var sample_results_checked: usize = 0;
    for (evaluators, trace_records) |record, trace_record| {
        var arena_state = std.heap.ArenaAllocator.init(gpa);
        defer arena_state.deinit();
        const arena = arena_state.allocator();

        const air = try fixture.string(try fixture.field(record, "air"));
        const table = if (std.mem.eql(u8, air, "cairo")) &cairo_table else &circuit_table;
        const slot = try fixture.unsigned(usize, try fixture.field(record, "slot"));
        errdefer std.debug.print("R3 mismatch at {s} slot {d} ({s})\n", .{ air, slot, table.entries[slot].name });
        try expectEntryShape(record, table, slot);

        const assignment = try fixture.field(record, "assignment");
        const source = try fixture.string(try fixture.field(assignment, "source"));
        const inputs = if (std.mem.eql(u8, source, "synthesized"))
            try synthesizedInputs(arena, try fixture.field(assignment, "inputs"))
        else blk: {
            const key = try fixture.string(try fixture.field(assignment, "key"));
            const sample = try fixture.field(samples.forAir(air), key);
            try used_samples.put(gpa, key, {});
            try expectHarnessOrders(table, slot, assignment, try fixture.unsigned(u32, try fixture.field(assignment, "log_height")));
            break :blk try sampleInputs(arena, sample, assignment);
        };

        const value_mode = try runHarness(QM31, gpa, arena, table, slot, inputs);
        const topology_mode = try runHarness(stand_in.NoValue, gpa, arena, table, slot, inputs);
        try std.testing.expectEqualDeep(value_mode.summary, topology_mode.summary);
        try std.testing.expectEqualDeep(value_mode.trace, topology_mode.trace);

        // The statement trace record names the same evaluator and assignment.
        try std.testing.expectEqualStrings(air, try fixture.string(try fixture.field(trace_record, "air")));
        try std.testing.expectEqual(slot, try fixture.unsigned(usize, try fixture.field(trace_record, "slot")));
        try std.testing.expectEqualStrings(table.entries[slot].name, try fixture.string(try fixture.field(trace_record, "name")));
        try std.testing.expectEqualStrings(
            if (std.mem.eql(u8, source, "synthesized")) "synthesized" else try fixture.string(try fixture.field(assignment, "key")),
            try fixture.string(try fixture.field(trace_record, "assignment")),
        );
        try statement_trace.expectTrace(trace_record, topology_mode.trace);
        try expectSummary(try fixture.field(record, "circuit"), value_mode.summary);
        try std.testing.expectEqual(try fixture.digest(try fixture.field(record, "values_sha256")), value_mode.values_sha256.?);
        try expectQm31(try fixture.field(record, "result"), value_mode.result);
        if (try fixture.optionalField(record, "expected_result")) |expected| {
            try std.testing.expect(table.entries[slot].evaluator == .generated);
            try expectQm31(expected, value_mode.result);
            // The generated evaluator reproduces upstream's `*_SAMPLE_EVAL_RESULT`.
            const key = try fixture.string(try fixture.field(assignment, "key"));
            try expectQm31(try fixture.field(try fixture.field(samples.forAir(air), key), "result"), value_mode.result);
            sample_results_checked += 1;
        }
    }
    // Every generated evaluator asserts its sample result (65 Cairo + 8 circuit).
    try std.testing.expectEqual(@as(usize, 73), sample_results_checked);
    // Every upstream sample drives an evaluator, except those of the hand-written
    // evaluators the oracle synthesizes inputs for.
    const synthesized = [_][]const u8{ "memory_address_to_id", "verify_bitwise_xor_12" };
    for ([_]Value{ samples.casm.root(), samples.circuit.root() }) |document| {
        var keys = document.object.iterator();
        while (keys.next()) |entry| {
            const used = used_samples.contains(entry.key_ptr.*);
            const skipped = for (synthesized) |name| {
                if (std.mem.eql(u8, name, entry.key_ptr.*)) break true;
            } else false;
            try std.testing.expect(used or skipped);
        }
    }
}

fn expectSlotNames(expected: Value, table: *const Table) !void {
    const names = try fixture.array(expected);
    try std.testing.expectEqual(names.len, table.entries.len);
    for (names, table.entries) |name, entry| try std.testing.expectEqualStrings(try fixture.string(name), entry.name);
}
