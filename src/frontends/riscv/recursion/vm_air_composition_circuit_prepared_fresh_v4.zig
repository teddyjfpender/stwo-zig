//! Fresh prepared-circuit constructor with explicit graph/schedule ownership.
//! Cold callers continue to use the owned/deep-validation path.

const dependency = @import("vm_air_composition_circuit_error.zig");
const validation =
    @import("vm_air_composition_circuit_validate_sample_geometry.zig");
const parallel_v4 = @import("vm_air_composition_circuit_parallel_v4.zig");

const std = dependency.std;
const M31 = dependency.M31;
const QM31 = dependency.QM31;
const graph_mod = dependency.graph_mod;
const row18_witness = dependency.row18_witness;
const Sha256 = dependency.Sha256;
const CIRCUIT_ID = dependency.CIRCUIT_ID;
const Error = dependency.Error;

pub const MAX_WORKER_COUNT = parallel_v4.MAX_WORKER_COUNT;

pub const CircuitStorageV3 = enum(u8) {
    owned = 1,
    borrowed_fresh_program = 2,
};

pub fn init(
    comptime Prepared: type,
    comptime Circuit: type,
    comptime Evaluation: type,
    allocator: std.mem.Allocator,
    lane: graph_mod.VmLane,
    air_profile_digest: [Sha256.digest_length]u8,
    input_values: []const M31,
    storage: CircuitStorageV3,
    retained_schedule: ?*graph_mod.CompiledSchedule,
    worker_count: usize,
) Error!Prepared {
    var retained: ?graph_mod.CompiledSchedule = if (retained_schedule) |source| blk: {
        const moved = source.*;
        source.* = undefined;
        break :blk moved;
    } else null;
    defer if (retained) |*value| value.deinit();
    if (lane.circuit_id != CIRCUIT_ID or
        input_values.len != lane.bindings.len or
        lane.bindings.len != validation.countInputNodes(lane.graph.nodes))
    {
        return error.BindingCountMismatch;
    }
    try lane.graph.validate();

    const owns_storage = storage == .owned;
    const nodes: []graph_mod.Node = if (owns_storage)
        try allocator.dupe(graph_mod.Node, lane.graph.nodes)
    else
        @constCast(lane.graph.nodes);
    errdefer if (owns_storage) allocator.free(nodes);
    const outputs: []u32 = if (owns_storage)
        try allocator.dupe(u32, lane.graph.outputs)
    else
        @constCast(lane.graph.outputs);
    errdefer if (owns_storage) allocator.free(outputs);
    const bindings: []graph_mod.VmInputBinding = if (owns_storage)
        try allocator.dupe(graph_mod.VmInputBinding, lane.bindings)
    else
        @constCast(lane.bindings);
    errdefer if (owns_storage) allocator.free(bindings);
    const owned_lane = graph_mod.VmLane{
        .circuit_id = CIRCUIT_ID,
        .graph = .{
            .nodes = nodes,
            .outputs = outputs,
            .identity_digest = lane.graph.identity_digest,
        },
        .profile = lane.profile,
        .bindings = bindings,
    };
    const reference_digest = graph_mod.computeReferenceDigest(
        owned_lane,
        &.{},
        &.{},
    );
    const reference = try graph_mod.Reference.authenticate(
        owned_lane,
        &.{},
        &.{},
        reference_digest,
    );
    var schedule = if (retained) |value| blk: {
        retained = null;
        break :blk value;
    } else try graph_mod.compile(allocator, &reference);
    var schedule_owned = true;
    defer if (schedule_owned) schedule.deinit();
    if (!std.mem.eql(
        u8,
        &schedule.reference_digest,
        &reference_digest,
    ) or !std.mem.eql(
        u8,
        &schedule.authority_digest,
        &graph_mod.computeScheduleDigest(reference_digest, schedule.rows),
    )) return error.CircuitIdentityMismatch;
    try graph_mod.validateCompiledRows(schedule.rows);
    var circuit = Circuit{
        .allocator = allocator,
        .nodes = nodes,
        .outputs = outputs,
        .bindings = bindings,
        .input_profile = lane.profile,
        .air_profile_digest = air_profile_digest,
        .graph_digest = lane.graph.identity_digest,
        .reference_digest = reference_digest,
        .schedule_digest = schedule.authority_digest,
        .identity_digest = undefined,
        .storage = storage,
    };
    circuit.identity_digest = validation.circuitDigest(
        circuit.air_profile_digest,
        circuit.graph_digest,
        circuit.reference_digest,
        circuit.schedule_digest,
        circuit.input_profile,
        circuit.bindings,
    );
    // Individual graph allocations above own error cleanup until return.
    if (owns_storage) try circuit.validate();

    const values = try allocator.alloc(QM31, circuit.nodes.len);
    errdefer allocator.free(values);
    @memset(values, QM31.zero());
    for (circuit.bindings, input_values) |binding, value| {
        if (binding.node_id >= values.len or
            std.meta.activeTag(circuit.nodes[binding.node_id].op) != .input)
        {
            return error.BindingCountMismatch;
        }
        values[binding.node_id] = QM31.fromBase(value);
    }
    for (circuit.nodes, 0..) |node, node_id| {
        values[node_id] = switch (node.op) {
            .input => values[node_id],
            .constant => |words| QM31.fromU32Unchecked(
                words[0],
                words[1],
                words[2],
                words[3],
            ),
            .add => |operands| values[operands.lhs].add(values[operands.rhs]),
            .sub => |operands| values[operands.lhs].sub(values[operands.rhs]),
            .mul => |operands| values[operands.lhs].mul(values[operands.rhs]),
            .neg => |operand| values[operand].neg(),
            .inverse => |operand| try values[operand].inv(),
        };
    }
    const evaluation = Evaluation{
        .allocator = allocator,
        .values = values,
        .circuit_identity = circuit.identity_digest,
    };
    // `values` already has one error-cleanup owner.
    circuit.validateEvaluation(&evaluation) catch |err| {
        if (err == error.UnsatisfiedCircuit) {
            for (circuit.outputs, 0..) |node, output_index| {
                if (values[node].isZero()) continue;
                std.debug.print(
                    "VM_COMPOSITION_UNSAT output={d}/{d} node={d} value={any}\n",
                    .{ output_index, circuit.outputs.len, node, values[node] },
                );
                if (@import("ethereum_vm_composition_graph_support_v2.zig").compositionDiagnosticsEnabled())
                    printCompositionHorner(circuit.nodes, node, values);
                break;
            }
        }
        return err;
    };

    schedule_owned = false;
    var preprocessing = try row18_witness.Preprocessed.initTakingCompiled(
        &schedule,
    );
    errdefer preprocessing.deinit();
    const schedule_values = try allocator.alloc(M31, preprocessing.rows.len);
    errdefer allocator.free(schedule_values);
    try parallel_v4.fillScheduleValues(
        allocator,
        preprocessing.rows,
        evaluation.values,
        schedule_values,
        CIRCUIT_ID,
        worker_count,
    );
    var result = Prepared{
        .allocator = allocator,
        .circuit = circuit,
        .evaluation = evaluation,
        .preprocessing = preprocessing,
        .schedule_values = schedule_values,
    };
    if (owns_storage) try result.validate();
    return result;
}

// Reads only the rejected graph's already evaluated values. The last V4 output
// is selector * (composition - accumulated constraints). Stop on any other
// shape; this diagnostic cannot affect acceptance or graph construction.
fn printCompositionHorner(nodes: []const graph_mod.Node, output: u32, values: []const QM31) void {
    const product = switch (nodes[output].op) {
        .mul => |v| v,
        else => return,
    };
    const difference = switch (nodes[product.rhs].op) {
        .sub => |v| v,
        else => return,
    };
    std.debug.print("VM_COMPOSITION_EXPECTED node={d} value={any}\n", .{ difference.lhs, values[difference.lhs] });
    var node = difference.rhs;
    while (true) {
        std.debug.print("VM_COMPOSITION_HORNER node={d} value={any}\n", .{ node, values[node] });
        const weighted = switch (nodes[node].op) {
            .add => |v| v.lhs,
            .mul => node,
            else => return,
        };
        const operands = switch (nodes[weighted].op) {
            .mul => |v| v,
            else => return,
        };
        if (operands.lhs >= node) return;
        node = operands.lhs;
    }
}

test "fresh prepared circuit releases allocations once on rejection and allocation failure" {
    const Prepared = @import("vm_air_composition_circuit.zig").Prepared;
    const profile = graph_mod.InputProfile{
        .sampled_value_count = 0,
        .claimed_sum_count = 0,
        .relation_challenge_count = 0,
    };
    var nodes: [10]graph_mod.Node = undefined;
    var bindings: [9]graph_mod.VmInputBinding = undefined;
    for (&bindings, 0..) |*binding, index| {
        nodes[index] = .{ .op = .input };
        binding.* = .{ .node_id = @intCast(index), .source = graph_mod.expectedVmSource(profile, index).? };
    }
    nodes[9] = .{ .op = .{ .sub = .{ .lhs = 0, .rhs = 1 } } };
    const outputs = [_]u32{9};
    const lane = graph_mod.VmLane{
        .circuit_id = CIRCUIT_ID,
        .graph = .{
            .nodes = &nodes,
            .outputs = &outputs,
            .identity_digest = graph_mod.computeGraphDigest(&nodes, &outputs),
        },
        .profile = profile,
        .bindings = &bindings,
    };
    const Check = struct {
        fn run(allocator: std.mem.Allocator, value: graph_mod.VmLane) !void {
            var prepared = try Prepared.initFromAuthenticatedLaneV2(allocator, value, .{1} ** 32, &([_]M31{M31.zero()} ** 9));
            defer prepared.deinit();
            try prepared.validate();
        }
    };
    try std.testing.checkAllAllocationFailures(std.testing.allocator, Check.run, .{lane});
    var prepared = try Prepared.initFromAuthenticatedLaneV2(std.testing.allocator, lane, .{1} ** 32, &([_]M31{M31.zero()} ** 9));
    defer prepared.deinit();
    // A complete prepared-boundary check must still reject independently
    // corrupted graph, binding, identity, derived value and input schedule.
    const original_node = prepared.circuit.nodes[9];
    prepared.circuit.nodes[9] = .{ .op = .{ .sub = .{ .lhs = 1, .rhs = 0 } } };
    try std.testing.expectError(error.GraphSealMismatch, prepared.validate());
    prepared.circuit.nodes[9] = original_node;
    prepared.circuit.bindings[0].node_id = 1;
    try std.testing.expectError(error.InputBindingNodeMismatch, prepared.validate());
    prepared.circuit.bindings[0].node_id = 0;
    prepared.circuit.reference_digest[0] ^= 1;
    try std.testing.expectError(error.CircuitIdentityMismatch, prepared.validate());
    prepared.circuit.reference_digest[0] ^= 1;
    prepared.circuit.identity_digest[0] ^= 1;
    try std.testing.expectError(error.CircuitIdentityMismatch, prepared.validate());
    prepared.circuit.identity_digest[0] ^= 1;
    prepared.evaluation.values[9] = QM31.one();
    try std.testing.expectError(error.CircuitIdentityMismatch, prepared.validate());
    prepared.evaluation.values[9] = QM31.zero();
    const original_schedule_value = prepared.schedule_values[0];
    prepared.schedule_values[0] = original_schedule_value.add(M31.one());
    try std.testing.expectError(error.CircuitIdentityMismatch, prepared.validate());
    prepared.schedule_values[0] = original_schedule_value;
    try prepared.validate();
    var bad_inputs = [_]M31{M31.zero()} ** 9;
    bad_inputs[0] = M31.one();
    try std.testing.expectError(error.UnsatisfiedCircuit, Prepared.initFromAuthenticatedLaneV2(std.testing.allocator, lane, .{1} ** 32, &bad_inputs));
}
