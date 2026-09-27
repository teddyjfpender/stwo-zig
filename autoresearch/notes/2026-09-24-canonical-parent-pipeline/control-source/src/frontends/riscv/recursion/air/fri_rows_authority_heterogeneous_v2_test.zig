const std = @import("std");
const stwo_core = @import("stwo_core");
const M31 = stwo_core.fields.m31.M31;
const channel = @import("../poseidon2_channel.zig");
const fixed_profile = @import("../fixed_profile.zig");
const protocol = @import("../protocol.zig");
const fri_circuit = @import("fri_verifier_circuit.zig");
const fri_profile = @import("fri_merkle_leaf_witness.zig");
const pcs_fixture = @import("pcs_input_arena_heterogeneous_v2_test.zig");
const query_mapping = @import("query_mapping_witness.zig");
const schedule = @import("verifier_schedule.zig");
const descriptor = @import("fri_rows_program_descriptor_v2.zig");
const subject = @import("fri_rows_authority_heterogeneous_v2.zig");
const trace = @import("trace_merkle_witness.zig");

const VM_LOGS = [_]u32{5};
const LEFT_LOGS = [_]u32{ 6, 5 };
const RIGHT_LOGS = [_]u32{ 7, 6, 5 };
const VM_HEIGHTS = [_]u32{8};
const LEFT_HEIGHTS = [_]u32{8};
const RIGHT_HEIGHTS = [_]u32{8};
const VM_TREES = [_]trace.TreeProfile{.{
    .height = 8,
    .column_log_sizes = &VM_LOGS,
}};
const LEFT_TREES = [_]trace.TreeProfile{.{
    .height = 8,
    .column_log_sizes = &LEFT_LOGS,
}};
const RIGHT_TREES = [_]trace.TreeProfile{.{
    .height = 8,
    .column_log_sizes = &RIGHT_LOGS,
}};

test "R-012 FRI rows V2 compiles independent programs and variable PCS arenas" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    const program = try fixture.program();
    const witness = subject.WitnessInputV2{ .pcs_values = fixture.values.lanes() };
    var authority = try subject.FriRowsAuthorityV2.init(
        std.testing.allocator,
        program,
        witness,
    );
    defer authority.deinit();
    try authority.validateAgainst(program, witness);

    try std.testing.expectEqual(schedule.Schema.vm, program.lanes[1].plan.schema);
    try std.testing.expectEqual(schedule.Schema.recursion, program.lanes[2].plan.schema);
    try std.testing.expect(authority.pcs_inputs.offsets[1] - authority.pcs_inputs.offsets[0] !=
        authority.pcs_inputs.offsets[2] - authority.pcs_inputs.offsets[1]);
    try std.testing.expect(!std.mem.eql(
        u8,
        &authority.program_sha256,
        &authority.instance_sha256,
    ));

    const published = try descriptor.FriRowsProgramDescriptorV2.mint(
        &authority,
        program,
    );
    const encoded = try published.encodeCanonical();
    const decoded = try descriptor.FriRowsProgramDescriptorV2.decodeCanonical(&encoded);
    try decoded.validateAgainst(&authority, program);
    try std.testing.expectEqual(descriptor.ENCODED_BYTE_COUNT, encoded.len);

    var hostile_bytes = encoded;
    hostile_bytes[hostile_bytes.len - 1] ^= 1;
    try std.testing.expectError(
        error.InvalidFriRowsProgramDescriptor,
        descriptor.FriRowsProgramDescriptorV2.decodeCanonical(&hostile_bytes),
    );

    const original_row = authority.control_preprocessing.rows[0];
    const original_rows_identity = authority.control_preprocessing.authority_sha256;
    authority.control_preprocessing.rows[0].query += 1;
    authority.control_preprocessing.authority_sha256 =
        authority.control_preprocessing.computedAuthoritySha256();
    try std.testing.expectError(
        error.AuthorityMismatch,
        authority.validateProgramAgainst(program),
    );
    authority.control_preprocessing.rows[0] = original_row;
    authority.control_preprocessing.authority_sha256 = original_rows_identity;
    try authority.validateProgramAgainst(program);

    var swapped = program;
    swapped.lanes[2].mapping = swapped.lanes[1].mapping;
    try std.testing.expectError(
        error.AuthorityMismatch,
        authority.validateProgramAgainst(swapped),
    );

    var rerouted = program;
    rerouted.lanes[2].fri_circuit_id += 10;
    try std.testing.expectError(
        error.InvalidHeterogeneousFriRowsAuthority,
        decoded.validateAgainst(&authority, rerouted),
    );
}

pub const Fixture = struct {
    pcs: pcs_fixture.Fixture,
    values: pcs_fixture.Values,
    plans: [3]schedule.Plan,
    circuits: [3]fri_circuit.Circuit,
    layers: [3][fixed_profile.MAX_FRI_ROUNDS]fri_profile.LayerProfile,
    layer_counts: [3]usize,

    pub fn init() !Fixture {
        var pcs_value = try pcs_fixture.Fixture.init(std.testing.allocator);
        errdefer pcs_value.deinit();
        const pcs_reference = try pcs_value.reference();
        var values = try pcs_fixture.Values.init(
            std.testing.allocator,
            pcs_reference,
            .binary_node,
        );
        errdefer values.deinit();

        var plans: [3]schedule.Plan = undefined;
        var circuits: [3]fri_circuit.Circuit = undefined;
        var layers: [3][fixed_profile.MAX_FRI_ROUNDS]fri_profile.LayerProfile = undefined;
        var layer_counts = [_]usize{0} ** 3;
        var initialized: usize = 0;
        errdefer {
            for (circuits[0..initialized]) |*item| item.deinit();
            for (plans[0..initialized]) |*item| item.deinit();
        }
        const schemas = [_]schedule.Schema{ .vm, .vm, .recursion };
        const names = [_][]const u8{ "rows-v2-vm", "rows-v2-left", "rows-v2-right" };
        const queries = [_]u32{ 1, 2, 3 };
        const fold_steps = [_]u32{ 2, 3, 4 };
        for (0..3) |lane_index| {
            const fri = try makeFriSchedule(fold_steps[lane_index]);
            plans[lane_index] = try makePlan(
                schemas[lane_index],
                names[lane_index],
                queries[lane_index],
                fri,
            );
            const widths = try widthsFromSchedule(fri);
            circuits[lane_index] = try fri_circuit.build(std.testing.allocator, .{
                .lifting_log_size = 8,
                .log_blowup_factor = 1,
                .log_last_layer_degree_bound = 1,
                .fold_widths = widths.values[0..widths.count],
                .query_count = queries[lane_index],
            });
            layer_counts[lane_index] = fri.active().len;
            for (fri.active(), 0..) |round, index| layers[lane_index][index] = .{
                .width = round.fold_width,
                .tree_height = round.merkle_tree_height,
            };
            initialized += 1;
        }
        return .{
            .pcs = pcs_value,
            .values = values,
            .plans = plans,
            .circuits = circuits,
            .layers = layers,
            .layer_counts = layer_counts,
        };
    }

    pub fn deinit(self: *Fixture) void {
        for (&self.circuits) |*item| item.deinit();
        for (&self.plans) |*item| item.deinit();
        self.values.deinit();
        self.pcs.deinit();
        self.* = undefined;
    }

    pub fn program(self: *const Fixture) !subject.ProgramInputV2 {
        const pcs_reference = try self.pcs.reference();
        return .{ .lanes = .{
            self.lane(0, pcs_reference.lanes[0], &VM_HEIGHTS, &VM_TREES),
            self.lane(1, pcs_reference.lanes[1], &LEFT_HEIGHTS, &LEFT_TREES),
            self.lane(2, pcs_reference.lanes[2], &RIGHT_HEIGHTS, &RIGHT_TREES),
        } };
    }

    pub fn witness(self: *const Fixture) subject.WitnessInputV2 {
        return .{ .pcs_values = self.values.lanes() };
    }

    fn lane(
        self: *const Fixture,
        lane_index: usize,
        pcs_lane: @import("pcs_deep_input_witness.zig").Lane,
        heights: []const u32,
        trees: []const trace.TreeProfile,
    ) subject.LaneProgramV2 {
        const circuit = &self.circuits[lane_index];
        return .{
            .plan = &self.plans[lane_index],
            .mapping = query_mapping.LaneProfile{
                .query_count = circuit.query_count,
                .lifting_log_size = circuit.lifting_log_size,
                .tree_heights = heights,
                .fri_fold_widths = circuit.fold_widths,
            },
            .trace = .{
                .query_count = circuit.query_count,
                .lifting_log_size = circuit.lifting_log_size,
                .trees = trees,
                .fri_fold_widths = circuit.fold_widths,
            },
            .fri = .{
                .query_count = circuit.query_count,
                .lifting_log_size = circuit.lifting_log_size,
                .layers = self.layers[lane_index][0..self.layer_counts[lane_index]],
            },
            .pcs = pcs_lane,
            .fri_circuit_id = @intCast(801 + lane_index),
            .fri_circuit = circuit,
        };
    }
};

const Widths = struct {
    values: [fixed_profile.MAX_FRI_ROUNDS]u32,
    count: usize,
};

fn widthsFromSchedule(fri: fixed_profile.FriSchedule) !Widths {
    var result = Widths{
        .values = [_]u32{0} ** fixed_profile.MAX_FRI_ROUNDS,
        .count = fri.active().len,
    };
    for (fri.active(), 0..) |round, index| result.values[index] = round.fold_width;
    return result;
}

fn makeFriSchedule(fold_step: u32) !fixed_profile.FriSchedule {
    var config = protocol.PCS_CONFIG.fri_config;
    config.log_blowup_factor = 1;
    config.log_last_layer_degree_bound = 1;
    config.fold_step = fold_step;
    return fixed_profile.FriSchedule.init(7, config);
}

fn makePlan(
    schema: schedule.Schema,
    name: []const u8,
    query_count: u32,
    fri: fixed_profile.FriSchedule,
) !schedule.Plan {
    return schedule.Plan.initShape(
        std.testing.allocator,
        try schedule.ProgramSpec.init(schema, 3, 2, 3, 2),
        .{
            .protocol_id = protocol.protocolId(),
            .shape_id = channel.hashBytes(name, 0x4652_4132),
            .interaction_pow_bits = 10,
            .pcs_pow_bits = 16,
            .query_count = query_count,
            .table_count = 3,
            .claimed_sum_count = 2,
            .sampled_value_count = 7,
            .tree_heights = [_]u32{8} ** fixed_profile.TREE_COUNT,
            .fri = fri,
        },
    );
}
