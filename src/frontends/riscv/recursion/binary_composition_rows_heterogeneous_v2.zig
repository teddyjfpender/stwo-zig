//! Heterogeneous compiler authority for universal rows 18--19.
//!
//! The two child lanes are independently admitted verifier programs. Their
//! authenticated composition DAGs may have different native AIR rosters,
//! sampled-value geometry, schemas, and circuit identities. Row 18 consumes
//! the full graph input values; transport SHA values are never substituted for
//! in-circuit statement, claim, challenge, or sampled-value coordinates.
//!
//! `program_sha256` seals only deterministic compiler products. Evaluated
//! proof values are retained separately in `instance_sha256`, so this module
//! is a required subauthority rather than complete verifier-program authority.

const std = @import("std");
const stwo_core = @import("stwo_core");
const M31 = stwo_core.fields.m31.M31;
const QM31 = stwo_core.fields.qm31.QM31;
const digest = @import("../air/lang/digest.zig");
const composition = @import("air/composition_circuit.zig");
const input_air = @import("air/vm_air_composition_input.zig");
const input_relation = @import("air/vm_air_composition_input_relation.zig");
const input_witness = @import("air/vm_air_composition_input_witness.zig");
const control_air = @import("air/vm_air_composition_control.zig").Air;
const control = @import("air/control_slice_heterogeneous_v2.zig");
const universal_binding = @import("air/universal_relation_binding.zig");
const lowering = @import("air/verifier_arithmetic_lowering.zig");
const schedule = @import("air/verifier_schedule.zig");
const legacy_rows = @import("binary_fri_outer_source_composition_rows_authority.zig");
const source_values = @import("binary_fri_outer_source_composition_source_value.zig");
const trusted = @import("binary_fri_outer_source_trusted_composition_profile_v1.zig");

pub const FORMAT_VERSION: u16 = 2;
pub const SCHEMA_VERSION: u16 = 1;
pub const LANE_COUNT: usize = 2;
pub const ROW_COUNT: usize = 2;
pub const VM_CAPACITY_CIRCUIT_ID: u32 = 431;
pub const LEFT_VERIFIER_ID: u32 = 1;
pub const RIGHT_VERIFIER_ID: u32 = 2;
const PROGRAM_DOMAIN =
    "stwo-zig/typed-air/binary-composition-rows-program/v2\x00";
const INSTANCE_DOMAIN =
    "stwo-zig/typed-air/binary-composition-rows-instance/v2\x00";
const ControlRelation = universal_binding.Binding(control_air);

pub const Error = error{
    InvalidHeterogeneousCompositionAuthority,
};

pub const ChildProgramV2 = struct {
    plan: *const schedule.Plan,
    composition: composition.RecursionLane,
};

/// Trusted, proof-independent compiler input. The VM capacity count remains
/// explicit because row 19 carries all proof-kind schedules even though that
/// lane is inactive in a binary parent.
pub const ProgramInputV2 = struct {
    vm_plan: *const schedule.Plan,
    vm_sampled_value_count: u32,
    children: [LANE_COUNT]ChildProgramV2,
};

pub const WitnessInputV2 = struct {
    evaluations: [LANE_COUNT]lowering.Evaluation,
};

pub const CompositionRowsAuthorityV2 = struct {
    const ReferenceStorage = struct {
        child_lanes: [LANE_COUNT]composition.RecursionLane,
        anchors: [LANE_COUNT]composition.AnchorLane,
    };

    allocator: std.mem.Allocator,
    reference_storage: *ReferenceStorage,
    reference: composition.Reference,
    input_preprocessing: input_witness.Preprocessed,
    control_preprocessing: control.CompositionPreprocessedV2,
    input_definition: input_air.Definition,
    control_definition: control_air.Definition,
    input_relation_plan: input_relation.Plan,
    control_relation_plan: ControlRelation.Plan,
    input_executor: input_witness.Executor,
    schedule_values: []M31,
    log_sizes: [ROW_COUNT]u32,
    program_sha256: digest.Digest,
    instance_sha256: digest.Digest,

    pub fn init(
        allocator: std.mem.Allocator,
        program: ProgramInputV2,
        witness: WitnessInputV2,
    ) !CompositionRowsAuthorityV2 {
        try validateProgramInput(program);
        try validateEvaluations(program, witness);
        const reference_storage = try allocator.create(ReferenceStorage);
        errdefer allocator.destroy(reference_storage);
        const reference = try makeReference(reference_storage, program);

        var input_preprocessing = try input_witness.Preprocessed
            .initFromReference(allocator, &reference);
        errdefer input_preprocessing.deinit();
        var control_preprocessing = try control.CompositionPreprocessedV2.init(
            allocator,
            program.vm_plan,
            program.vm_plan.spec.air_instruction_count,
            program.vm_sampled_value_count,
            program.children[0].plan,
            program.children[0].plan.spec.air_instruction_count,
            program.children[0].composition.profile.sampled_value_count,
            program.children[1].plan,
            program.children[1].plan.spec.air_instruction_count,
            program.children[1].composition.profile.sampled_value_count,
        );
        errdefer control_preprocessing.deinit();
        var input_definition = try input_air.build(allocator);
        errdefer input_definition.deinit();
        var control_definition = try control_air.build(allocator);
        errdefer control_definition.deinit();
        const input_binding = try input_witness.Binding.canonical(
            &input_definition,
        );
        const schedule_values = try allocator.alloc(
            M31,
            input_preprocessing.rows.len,
        );
        errdefer allocator.free(schedule_values);
        try source_values.materializeRecorderScheduleValues(
            witness.evaluations,
            input_preprocessing.rows,
            schedule_values,
        );

        var result = CompositionRowsAuthorityV2{
            .allocator = allocator,
            .reference_storage = reference_storage,
            .reference = reference,
            .input_preprocessing = input_preprocessing,
            .control_preprocessing = control_preprocessing,
            .input_definition = input_definition,
            .control_definition = control_definition,
            .input_relation_plan = try input_relation.authenticate(
                &input_definition,
            ),
            .control_relation_plan = try ControlRelation.authenticate(
                &control_definition,
            ),
            .input_executor = try input_witness.Executor.init(
                &input_definition,
                &input_binding,
            ),
            .schedule_values = schedule_values,
            .log_sizes = .{
                input_preprocessing.log_size,
                control_preprocessing.log_size,
            },
            .program_sha256 = undefined,
            .instance_sha256 = undefined,
        };
        result.program_sha256 = programIdentity(&result);
        result.instance_sha256 = instanceIdentity(&result, witness);
        try result.validateAgainst(program, witness);
        return result;
    }

    pub fn deinit(self: *CompositionRowsAuthorityV2) void {
        self.allocator.free(self.schedule_values);
        self.control_definition.deinit();
        self.input_definition.deinit();
        self.control_preprocessing.deinit();
        self.input_preprocessing.deinit();
        self.allocator.destroy(self.reference_storage);
        self.* = undefined;
    }

    pub fn validateProgramAgainst(
        self: *const CompositionRowsAuthorityV2,
        program: ProgramInputV2,
    ) !void {
        try validateProgramInput(program);
        try self.reference.validate();
        const expected_reference = try expectedReferenceIdentity(program);
        if (!std.mem.eql(u8, &self.reference.identity_digest, &expected_reference))
            return error.InvalidHeterogeneousCompositionAuthority;
        try validateCompiledInputRows(self, program);
        try self.control_preprocessing.validateAgainst(
            program.vm_plan,
            program.children[0].plan,
            program.children[1].plan,
        );
        try validateCompilerBindings(self);
        if (!std.meta.eql(self.log_sizes, [ROW_COUNT]u32{
            self.input_preprocessing.log_size,
            self.control_preprocessing.log_size,
        }) or !std.mem.eql(
            u8,
            &self.program_sha256,
            &programIdentity(self),
        )) return error.InvalidHeterogeneousCompositionAuthority;
    }

    pub fn validateAgainst(
        self: *const CompositionRowsAuthorityV2,
        program: ProgramInputV2,
        witness: WitnessInputV2,
    ) !void {
        try self.validateProgramAgainst(program);
        try validateEvaluations(program, witness);
        try source_values.validateRecorderScheduleValues(
            witness.evaluations,
            self.input_preprocessing.rows,
            self.schedule_values,
        );
        if (!std.mem.eql(
            u8,
            &self.instance_sha256,
            &instanceIdentity(self, witness),
        )) return error.InvalidHeterogeneousCompositionAuthority;
    }
};

fn validateProgramInput(program: ProgramInputV2) !void {
    try program.vm_plan.validate();
    if (program.vm_plan.schema != .vm)
        return error.InvalidHeterogeneousCompositionAuthority;
    for (program.children, 0..) |child, child_index| {
        try child.plan.validate();
        try child.composition.graph.validate();
        try composition.validateRecursionBindings(child.composition);
        const expected_id: u32 = if (child_index == 0)
            LEFT_VERIFIER_ID
        else
            RIGHT_VERIFIER_ID;
        if (child.composition.verifier_id != expected_id or
            child.composition.statement_scope !=
                trusted.compositionStatementScope(child_index))
        {
            return error.InvalidHeterogeneousCompositionAuthority;
        }
    }
    if (program.children[0].composition.circuit_id ==
        program.children[1].composition.circuit_id)
    {
        return error.InvalidHeterogeneousCompositionAuthority;
    }
}

fn makeReference(
    storage: *CompositionRowsAuthorityV2.ReferenceStorage,
    program: ProgramInputV2,
) !composition.Reference {
    for (program.children, 0..) |child, child_index| {
        storage.child_lanes[child_index] = child.composition;
        storage.anchors[child_index] = .{
            .circuit_id = child.composition.circuit_id,
            .graph = child.composition.graph,
            .active_in = .BINARY,
        };
    }
    const vm_graph_digest = composition.computeGraphDigest(
        &trusted.VM_CAPACITY_NODES,
        &trusted.VM_CAPACITY_OUTPUTS,
    );
    const vm_graph = try composition.CircuitGraph.authenticate(
        &trusted.VM_CAPACITY_NODES,
        &trusted.VM_CAPACITY_OUTPUTS,
        vm_graph_digest,
    );
    const vm_lane = composition.VmLane{
        .circuit_id = VM_CAPACITY_CIRCUIT_ID,
        .graph = vm_graph,
        .profile = .{
            .sampled_value_count = 0,
            .claimed_sum_count = 0,
            .relation_challenge_count = 0,
        },
        .bindings = &legacy_rows.VM_CAPACITY_BINDINGS,
    };
    const reference_digest = composition.computeReferenceDigest(
        vm_lane,
        &storage.child_lanes,
        &storage.anchors,
    );
    return composition.Reference.authenticate(
        vm_lane,
        &storage.child_lanes,
        &storage.anchors,
        reference_digest,
    );
}

fn expectedReferenceIdentity(program: ProgramInputV2) !digest.Digest {
    var storage: CompositionRowsAuthorityV2.ReferenceStorage = undefined;
    const reference = try makeReference(&storage, program);
    return reference.identity_digest;
}

fn validateCompiledInputRows(
    self: *const CompositionRowsAuthorityV2,
    program: ProgramInputV2,
) !void {
    var storage: CompositionRowsAuthorityV2.ReferenceStorage = undefined;
    const reference = try makeReference(&storage, program);
    var expected = try input_witness.Preprocessed.initFromReference(
        self.allocator,
        &reference,
    );
    defer expected.deinit();
    if (self.input_preprocessing.log_size != expected.log_size or
        self.input_preprocessing.source != expected.source or
        !std.meta.eql(
            self.input_preprocessing.reference_digest,
            expected.reference_digest,
        ) or !std.mem.eql(
        u8,
        &self.input_preprocessing.authority_digest,
        &expected.authority_digest,
    ) or self.input_preprocessing.rows.len != expected.rows.len) {
        return error.InvalidHeterogeneousCompositionAuthority;
    }
    for (self.input_preprocessing.rows, expected.rows) |actual, wanted|
        if (!std.meta.eql(actual, wanted))
            return error.InvalidHeterogeneousCompositionAuthority;
}

fn validateCompilerBindings(self: *const CompositionRowsAuthorityV2) !void {
    try self.input_definition.validate();
    try self.control_definition.validate();
    try self.input_relation_plan.validateAgainst(
        &self.input_definition.arena,
        input_air.SEMANTIC_DIGEST,
        self.input_definition.events,
    );
    try self.control_relation_plan.validateAgainst(
        &self.control_definition.arena,
        control_air.SEMANTIC_DIGEST,
        .{self.control_definition.event},
    );
    const expected_binding = try input_witness.Binding.canonical(
        &self.input_definition,
    );
    if (!std.meta.eql(self.input_executor.binding, expected_binding))
        return error.InvalidHeterogeneousCompositionAuthority;
}

fn validateEvaluations(
    program: ProgramInputV2,
    witness: WitnessInputV2,
) !void {
    for (program.children, witness.evaluations) |child, evaluation| {
        if (!std.mem.eql(
            u8,
            &child.composition.graph.identity_digest,
            &evaluation.circuit_identity,
        )) return error.InvalidHeterogeneousCompositionAuthority;
        try source_values.validateGraphEvaluation(
            child.composition.graph,
            evaluation,
        );
    }
}

fn programIdentity(value: *const CompositionRowsAuthorityV2) digest.Digest {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(PROGRAM_DOMAIN);
    hashInt(&hash, u16, FORMAT_VERSION);
    hashInt(&hash, u16, SCHEMA_VERSION);
    hash.update(&value.reference.identity_digest);
    hash.update(&value.input_preprocessing.authority_digest);
    hash.update(&value.control_preprocessing.authority_sha256);
    hash.update(&input_air.SEMANTIC_DIGEST);
    hash.update(&control_air.SEMANTIC_DIGEST);
    hash.update(&value.input_executor.binding_digest);
    hash.update(&value.input_relation_plan.semantic_digest);
    hash.update(&value.input_relation_plan.registry_order_digest);
    hash.update(&value.control_relation_plan.semantic_digest);
    hash.update(&value.control_relation_plan.registry_order_digest);
    for (value.log_sizes) |log_size| hashInt(&hash, u32, log_size);
    return hash.finalResult();
}

fn instanceIdentity(
    value: *const CompositionRowsAuthorityV2,
    witness: WitnessInputV2,
) digest.Digest {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(INSTANCE_DOMAIN);
    hash.update(&value.program_sha256);
    for (witness.evaluations) |evaluation| {
        hash.update(&evaluation.circuit_identity);
        hashInt(&hash, u64, evaluation.values.len);
        for (evaluation.values) |item| hashQm31(&hash, item);
    }
    hashInt(&hash, u64, value.schedule_values.len);
    for (value.schedule_values) |item| hashInt(&hash, u32, item.v);
    return hash.finalResult();
}

fn hashQm31(hash: anytype, value: QM31) void {
    for (value.toM31Array()) |word| hashInt(hash, u32, word.v);
}

fn hashInt(hash: anytype, comptime T: type, value: anytype) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, @intCast(value), .little);
    hash.update(&bytes);
}

comptime {
    if (FORMAT_VERSION != 2 or SCHEMA_VERSION != 1 or
        LANE_COUNT != 2 or ROW_COUNT != 2)
    {
        @compileError("heterogeneous composition rows contract drifted");
    }
}
