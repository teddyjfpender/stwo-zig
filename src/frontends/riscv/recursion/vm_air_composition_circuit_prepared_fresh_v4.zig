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
    errdefer circuit.deinit();
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
    var evaluation = Evaluation{
        .allocator = allocator,
        .values = values,
        .circuit_identity = circuit.identity_digest,
    };
    errdefer evaluation.deinit();
    try circuit.validateEvaluation(&evaluation);

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
