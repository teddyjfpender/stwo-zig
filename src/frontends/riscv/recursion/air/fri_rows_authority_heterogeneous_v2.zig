//! Cold compiler authority for heterogeneous verifier rows 20--29.
//!
//! A parent may verify child proofs with different AIR programs, column
//! inventories, domains, FRI schedules, and PCS circuit widths.  This module
//! compiles all three verifier lanes from trusted typed inputs, reconstructs
//! every retained preprocessing row, and separates deterministic program
//! identity from proof-instance PCS values.

const std = @import("std");
const stwo_core = @import("stwo_core");
const M31 = stwo_core.fields.m31.M31;
const digest = @import("../../air/lang/digest.zig");
const query_bits_air = @import("query_bits_heterogeneous_v2.zig");
const query_bits = @import("query_bits_witness_heterogeneous_v2.zig");
const query_mapping_air = @import("query_mapping.zig");
const query_mapping_base = @import("query_mapping_witness.zig");
const query_mapping = @import("query_mapping_witness_heterogeneous_v2.zig");
const merkle_root_air = @import("merkle_root.zig");
const merkle_root_base = @import("merkle_root_witness.zig");
const merkle_root = @import("merkle_root_witness_heterogeneous_v2.zig");
const trace_air = @import("trace_merkle.zig");
const trace_base = @import("trace_merkle_witness.zig");
const trace = @import("trace_merkle_witness_heterogeneous_v2.zig");
const pcs_air = @import("pcs_deep_input.zig");
const pcs = @import("pcs_deep_input_witness.zig");
const pcs_arena = @import("pcs_input_arena_heterogeneous_v2.zig");
const fri_leaf_air = @import("fri_merkle_leaf.zig");
const fri_leaf_base = @import("fri_merkle_leaf_witness.zig");
const fri_node_air = @import("fri_merkle_node.zig");
const fri_anchor_air = @import("fri_merkle_anchor.zig");
const fri_reference = @import("fri_merkle_reference_heterogeneous_v2.zig");
const fri_rows = @import("fri_merkle_rows_heterogeneous_v2.zig");
const control_air = @import("fri_verifier_control.zig");
const control_base = @import("fri_verifier_control_witness.zig");
const control = @import("fri_verifier_control_heterogeneous_v2.zig");
const fri_input_air = @import("fri_verifier_input.zig");
const fri_input = @import("fri_verifier_input_witness.zig");
const schedule = @import("verifier_schedule.zig");

pub const FORMAT_VERSION: u16 = 2;
pub const SCHEMA_VERSION: u16 = 1;
pub const LANE_COUNT: usize = 3;
pub const ROW_COUNT: usize = 10;
pub const PROOF_KIND: pcs.ProofKind = .binary_node;
const PROGRAM_DOMAIN = "stwo-zig/typed-air/recursion-fri-rows-program/v2\x00";
const INSTANCE_DOMAIN = "stwo-zig/typed-air/recursion-fri-rows-instance/v2\x00";

pub const Error = error{
    InvalidHeterogeneousFriRowsAuthority,
};

/// Trusted compiler inputs for one verifier namespace. Borrowed slices are
/// hashed by value; pointer identity is never part of a program seal.
pub const LaneProgramV2 = struct {
    plan: *const schedule.Plan,
    mapping: query_mapping_base.LaneProfile,
    trace: trace_base.LaneProfile,
    fri: fri_leaf_base.LaneProfile,
    pcs: pcs.Lane,
    fri_circuit_id: u32,
    fri_circuit: *const fri_input.Circuit,
};

pub const ProgramInputV2 = struct {
    lanes: [LANE_COUNT]LaneProgramV2,
};

/// Proof-instance values are deliberately separate from the pre-proof
/// compiler program. They affect `instance_sha256`, never `program_sha256`.
pub const WitnessInputV2 = struct {
    pcs_values: [LANE_COUNT][]const M31,
};

pub const FriRowsAuthorityV2 = struct {
    allocator: std.mem.Allocator,

    query_mapping_reference: query_mapping.Reference,
    query_bits_reference: query_bits.Reference,
    merkle_root_reference: merkle_root.Reference,
    trace_reference: trace.Reference,
    fri_reference: fri_reference.Reference,
    control_reference: control.Reference,
    pcs_reference: pcs.Reference,
    input_reference: fri_input.Reference,

    query_bits_preprocessing: query_bits.Preprocessed,
    query_mapping_preprocessing: query_mapping.Preprocessed,
    merkle_root_preprocessing: merkle_root.Preprocessed,
    trace_preprocessing: trace.Preprocessed,
    pcs_preprocessing: pcs.Preprocessed,
    fri_leaf_preprocessing: fri_rows.Preprocessed(.leaf),
    fri_node_preprocessing: fri_rows.Preprocessed(.node),
    fri_anchor_preprocessing: fri_rows.Preprocessed(.anchor),
    control_preprocessing: control.Preprocessed,
    input_preprocessing: fri_input.Preprocessed,
    pcs_inputs: pcs_arena.Arena,

    log_sizes: [ROW_COUNT]u32,
    program_sha256: digest.Digest,
    instance_sha256: digest.Digest,

    pub fn init(
        allocator: std.mem.Allocator,
        program: ProgramInputV2,
        witness: WitnessInputV2,
    ) !FriRowsAuthorityV2 {
        const references = try compileReferences(program);

        var query_bits_preprocessing = try query_bits.Preprocessed.init(
            allocator,
            references.query_bits,
        );
        errdefer query_bits_preprocessing.deinit();
        var query_mapping_preprocessing = try query_mapping.Preprocessed.init(
            allocator,
            &references.query_mapping,
        );
        errdefer query_mapping_preprocessing.deinit();
        var merkle_root_preprocessing = try merkle_root.Preprocessed.init(
            allocator,
            &references.merkle_root,
        );
        errdefer merkle_root_preprocessing.deinit();
        var trace_preprocessing = try trace.Preprocessed.init(
            allocator,
            &references.trace,
            program.lanes[0].plan,
            program.lanes[1].plan,
            program.lanes[2].plan,
        );
        errdefer trace_preprocessing.deinit();
        var pcs_preprocessing = try pcs.Preprocessed.init(allocator, references.pcs);
        errdefer pcs_preprocessing.deinit();
        var fri_leaf_preprocessing = try fri_rows.Preprocessed(.leaf).init(
            allocator,
            &references.fri,
            .none,
        );
        errdefer fri_leaf_preprocessing.deinit();
        var fri_node_preprocessing = try fri_rows.Preprocessed(.node).init(
            allocator,
            &references.fri,
            .none,
        );
        errdefer fri_node_preprocessing.deinit();
        const plans = friPlans(program);
        var fri_anchor_preprocessing = try fri_rows.Preprocessed(.anchor).init(
            allocator,
            &references.fri,
            plans,
        );
        errdefer fri_anchor_preprocessing.deinit();
        var control_preprocessing = try control.Preprocessed.init(
            allocator,
            &references.control,
        );
        errdefer control_preprocessing.deinit();
        var input_preprocessing = try fri_input.Preprocessed.init(
            allocator,
            references.input,
        );
        errdefer input_preprocessing.deinit();
        var pcs_inputs = try pcs_arena.Arena.init(
            allocator,
            references.pcs,
            PROOF_KIND,
            witness.pcs_values,
        );
        errdefer pcs_inputs.deinit();

        var result = FriRowsAuthorityV2{
            .allocator = allocator,
            .query_mapping_reference = references.query_mapping,
            .query_bits_reference = references.query_bits,
            .merkle_root_reference = references.merkle_root,
            .trace_reference = references.trace,
            .fri_reference = references.fri,
            .control_reference = references.control,
            .pcs_reference = references.pcs,
            .input_reference = references.input,
            .query_bits_preprocessing = query_bits_preprocessing,
            .query_mapping_preprocessing = query_mapping_preprocessing,
            .merkle_root_preprocessing = merkle_root_preprocessing,
            .trace_preprocessing = trace_preprocessing,
            .pcs_preprocessing = pcs_preprocessing,
            .fri_leaf_preprocessing = fri_leaf_preprocessing,
            .fri_node_preprocessing = fri_node_preprocessing,
            .fri_anchor_preprocessing = fri_anchor_preprocessing,
            .control_preprocessing = control_preprocessing,
            .input_preprocessing = input_preprocessing,
            .pcs_inputs = pcs_inputs,
            .log_sizes = undefined,
            .program_sha256 = undefined,
            .instance_sha256 = undefined,
        };
        result.log_sizes = result.expectedLogSizes();
        result.program_sha256 = programIdentity(&result);
        result.instance_sha256 = instanceIdentity(&result);
        try result.validateAgainst(program, witness);
        return result;
    }

    pub fn deinit(self: *FriRowsAuthorityV2) void {
        self.pcs_inputs.deinit();
        self.input_preprocessing.deinit();
        self.control_preprocessing.deinit();
        self.fri_anchor_preprocessing.deinit();
        self.fri_node_preprocessing.deinit();
        self.fri_leaf_preprocessing.deinit();
        self.pcs_preprocessing.deinit();
        self.trace_preprocessing.deinit();
        self.merkle_root_preprocessing.deinit();
        self.query_mapping_preprocessing.deinit();
        self.query_bits_preprocessing.deinit();
        self.* = undefined;
    }

    pub fn validateProgramAgainst(
        self: *const FriRowsAuthorityV2,
        program: ProgramInputV2,
    ) !void {
        const expected = try compileReferences(program);
        try expectReferences(self, expected);
        try self.query_bits_preprocessing.validateAgainst(self.query_bits_reference);
        try self.query_mapping_preprocessing.validateAgainstAuthority(
            &self.query_mapping_reference,
        );
        try self.merkle_root_preprocessing.validateAgainstAuthority(
            &self.merkle_root_reference,
        );
        try self.trace_preprocessing.validateAgainstAuthority(
            &self.trace_reference,
            program.lanes[0].plan,
            program.lanes[1].plan,
            program.lanes[2].plan,
        );
        try self.pcs_preprocessing.validateAgainstAuthority(self.pcs_reference);
        try self.fri_leaf_preprocessing.validateAgainstAuthority(
            &self.fri_reference,
            .none,
        );
        try self.fri_node_preprocessing.validateAgainstAuthority(
            &self.fri_reference,
            .none,
        );
        try self.fri_anchor_preprocessing.validateAgainstAuthority(
            &self.fri_reference,
            friPlans(program),
        );
        try self.control_preprocessing.validateAgainstAuthority(
            &self.control_reference,
        );
        try self.input_preprocessing.validateAgainstAuthority(
            self.allocator,
            self.input_reference,
        );
        if (!std.meta.eql(self.log_sizes, self.expectedLogSizes()) or
            !std.mem.eql(u8, &self.program_sha256, &programIdentity(self)))
        {
            return error.InvalidHeterogeneousFriRowsAuthority;
        }
    }

    pub fn validateAgainst(
        self: *const FriRowsAuthorityV2,
        program: ProgramInputV2,
        witness: WitnessInputV2,
    ) !void {
        try self.validateProgramAgainst(program);
        try self.pcs_inputs.validateAgainst(self.pcs_reference);
        for (witness.pcs_values, 0..) |values, lane|
            if (!m31Eql(values, self.pcs_inputs.laneValues(lane)))
                return error.InvalidHeterogeneousFriRowsAuthority;
        if (!std.mem.eql(u8, &self.instance_sha256, &instanceIdentity(self)))
            return error.InvalidHeterogeneousFriRowsAuthority;
    }

    fn expectedLogSizes(self: *const FriRowsAuthorityV2) [ROW_COUNT]u32 {
        return .{
            self.query_bits_preprocessing.log_size,
            self.query_mapping_preprocessing.log_size,
            self.merkle_root_preprocessing.log_size,
            self.trace_preprocessing.log_size,
            self.pcs_preprocessing.log_size,
            self.fri_leaf_preprocessing.log_size,
            self.fri_node_preprocessing.log_size,
            self.fri_anchor_preprocessing.log_size,
            self.control_preprocessing.log_size,
            self.input_preprocessing.log_size,
        };
    }
};

const References = struct {
    query_mapping: query_mapping.Reference,
    query_bits: query_bits.Reference,
    merkle_root: merkle_root.Reference,
    trace: trace.Reference,
    fri: fri_reference.Reference,
    control: control.Reference,
    pcs: pcs.Reference,
    input: fri_input.Reference,
};

fn compileReferences(program: ProgramInputV2) !References {
    try validateLaneOrder(program);
    const mapping = try query_mapping.Reference.seal(
        program.lanes[0].mapping,
        program.lanes[1].mapping,
        program.lanes[2].mapping,
    );
    const bits = try mapping.queryBitsReference();
    const roots = try merkle_root.Reference.seal(
        rootProfile(program.lanes[0]),
        rootProfile(program.lanes[1]),
        rootProfile(program.lanes[2]),
    );
    const trace_reference_value = try trace.Reference.seal(
        program.lanes[0].trace,
        program.lanes[0].plan,
        program.lanes[1].trace,
        program.lanes[1].plan,
        program.lanes[2].trace,
        program.lanes[2].plan,
    );
    try trace_reference_value.validateQueryMapping(&mapping);
    const fri = try fri_reference.Reference.seal(
        program.lanes[0].fri,
        program.lanes[1].fri,
        program.lanes[2].fri,
    );
    try fri.validateQueryMapping(&mapping);
    try fri.validateMerkleRoots(&roots);
    const control_reference_value = try control.Reference.seal(
        controlLane(program.lanes[0]),
        controlLane(program.lanes[1]),
        controlLane(program.lanes[2]),
    );
    try control_reference_value.validateMapping(&mapping);
    const pcs_lanes = [LANE_COUNT]pcs.Lane{
        program.lanes[0].pcs,
        program.lanes[1].pcs,
        program.lanes[2].pcs,
    };
    const pcs_reference_value = try pcs.Reference.authenticate(
        pcs_lanes,
        pcs.computeReferenceDigest(pcs_lanes),
    );
    const input_reference_value = try fri_input.Reference.seal(.{
        friInputLane(program.lanes[0]),
        friInputLane(program.lanes[1]),
        friInputLane(program.lanes[2]),
    });
    for (program.lanes) |lane| try validateLaneCrossBindings(lane);
    return .{
        .query_mapping = mapping,
        .query_bits = bits,
        .merkle_root = roots,
        .trace = trace_reference_value,
        .fri = fri,
        .control = control_reference_value,
        .pcs = pcs_reference_value,
        .input = input_reference_value,
    };
}

fn validateLaneOrder(program: ProgramInputV2) !void {
    if (program.lanes[0].plan.schema != .vm)
        return error.InvalidHeterogeneousFriRowsAuthority;
    for (program.lanes, 0..) |lane, lane_index| {
        const expected: u32 = @intCast(lane_index);
        if (lane.pcs.verifier_id != expected or lane.fri_circuit_id >= 0x7fff_ffff)
            return error.InvalidHeterogeneousFriRowsAuthority;
        for (program.lanes[0..lane_index]) |previous| {
            if (previous.pcs.circuit_id == lane.pcs.circuit_id or
                previous.fri_circuit_id == lane.fri_circuit_id)
            {
                return error.InvalidHeterogeneousFriRowsAuthority;
            }
        }
    }
}

fn validateLaneCrossBindings(lane: LaneProgramV2) !void {
    try pcs.profileMatchesTrace(lane.pcs.profile, lane.trace);
    const circuit_profile = lane.fri_circuit.profile();
    try circuit_profile.validate();
    if (circuit_profile.query_count != lane.mapping.query_count or
        circuit_profile.lifting_log_size != lane.mapping.lifting_log_size or
        !std.mem.eql(u32, circuit_profile.fold_widths, lane.mapping.fri_fold_widths) or
        lane.fri.query_count != lane.mapping.query_count or
        lane.fri.lifting_log_size != lane.mapping.lifting_log_size or
        lane.fri.layers.len != circuit_profile.fold_widths.len)
    {
        return error.InvalidHeterogeneousFriRowsAuthority;
    }
    for (lane.fri.layers, circuit_profile.fold_widths) |layer, width|
        if (layer.width != width)
            return error.InvalidHeterogeneousFriRowsAuthority;
}

fn rootProfile(lane: LaneProgramV2) merkle_root_base.LaneProfile {
    return .{
        .query_count = lane.mapping.query_count,
        .trace_tree_count = @intCast(lane.trace.trees.len),
        .fri_layer_count = @intCast(lane.fri.layers.len),
    };
}

fn controlLane(lane: LaneProgramV2) control_base.Lane {
    return .{ .plan = lane.plan, .mapping = lane.mapping };
}

fn friInputLane(lane: LaneProgramV2) fri_input.Lane {
    return .{
        .verifier_id = lane.pcs.verifier_id,
        .circuit_id = lane.fri_circuit_id,
        .circuit = lane.fri_circuit,
    };
}

fn friPlans(program: ProgramInputV2) fri_rows.Plans {
    return .{ .anchor = .{
        program.lanes[0].plan,
        program.lanes[1].plan,
        program.lanes[2].plan,
    } };
}

fn expectReferences(self: *const FriRowsAuthorityV2, expected: References) !void {
    const retained = [_]digest.Digest{
        self.query_mapping_reference.authority_sha256,
        self.query_bits_reference.authority_digest,
        self.merkle_root_reference.authority_sha256,
        self.trace_reference.authority_sha256,
        self.fri_reference.authority_sha256,
        self.control_reference.authority_sha256,
        self.pcs_reference.authority_digest,
        self.input_reference.authority_digest,
    };
    const compiled = [_]digest.Digest{
        expected.query_mapping.authority_sha256,
        expected.query_bits.authority_digest,
        expected.merkle_root.authority_sha256,
        expected.trace.authority_sha256,
        expected.fri.authority_sha256,
        expected.control.authority_sha256,
        expected.pcs.authority_digest,
        expected.input.authority_digest,
    };
    for (retained, compiled) |actual, wanted| if (!std.mem.eql(u8, &actual, &wanted))
        return error.InvalidHeterogeneousFriRowsAuthority;
}

fn programIdentity(value: *const FriRowsAuthorityV2) digest.Digest {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(PROGRAM_DOMAIN);
    hashInt(&hash, u16, FORMAT_VERSION);
    hashInt(&hash, u16, SCHEMA_VERSION);
    for ([_]digest.Digest{
        value.query_mapping_reference.authority_sha256,
        value.query_bits_reference.authority_digest,
        value.merkle_root_reference.authority_sha256,
        value.trace_reference.authority_sha256,
        value.fri_reference.authority_sha256,
        value.control_reference.authority_sha256,
        value.pcs_reference.authority_digest,
        value.input_reference.authority_digest,
        value.query_bits_preprocessing.authority_digest,
        value.query_mapping_preprocessing.authority_sha256,
        value.merkle_root_preprocessing.authority_sha256,
        value.trace_preprocessing.authority_sha256,
        value.pcs_preprocessing.authority_digest,
        value.fri_leaf_preprocessing.authority_sha256,
        value.fri_node_preprocessing.authority_sha256,
        value.fri_anchor_preprocessing.authority_sha256,
        value.control_preprocessing.authority_sha256,
        value.input_preprocessing.authority_digest,
    }) |identity| hash.update(&identity);
    hashSemanticSuite(&hash);
    for (value.log_sizes) |log_size| hashInt(&hash, u32, log_size);
    return hash.finalResult();
}

fn instanceIdentity(value: *const FriRowsAuthorityV2) digest.Digest {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(INSTANCE_DOMAIN);
    hash.update(&value.program_sha256);
    hash.update(&value.pcs_inputs.authority_sha256);
    return hash.finalResult();
}

fn hashSemanticSuite(hash: anytype) void {
    const semantic = [_]digest.Digest{
        query_bits_air.SEMANTIC_DIGEST,
        query_mapping_air.SEMANTIC_DIGEST,
        merkle_root_air.SEMANTIC_DIGEST,
        trace_air.SEMANTIC_DIGEST,
        pcs_air.SEMANTIC_DIGEST,
        fri_leaf_air.SEMANTIC_DIGEST,
        fri_node_air.SEMANTIC_DIGEST,
        fri_anchor_air.SEMANTIC_DIGEST,
        control_air.SEMANTIC_DIGEST,
        fri_input_air.SEMANTIC_DIGEST,
    };
    const bindings = [_]digest.Digest{
        query_bits.BINDING_DIGEST,
        query_mapping_base.BINDING_DIGEST,
        merkle_root_base.BINDING_DIGEST,
        trace_base.BINDING_DIGEST,
        pcs.BINDING_DIGEST,
        fri_leaf_base.BINDING_DIGEST,
        @import("fri_merkle_node_witness.zig").BINDING_DIGEST,
        @import("fri_merkle_anchor_witness.zig").BINDING_DIGEST,
        control_base.BINDING_DIGEST,
        fri_input.BINDING_DIGEST,
    };
    for (semantic) |identity| hash.update(&identity);
    for (bindings) |identity| hash.update(&identity);
}

/// Pointer-free identity of the ten AIR semantics and witness bindings used
/// by this compiler. Descriptor transport records this separately from the
/// profile-dependent program identity so a fresh verifier can diagnose a
/// semantic binary mismatch without interpreting any dynamic geometry.
pub fn semanticSuiteSha256() digest.Digest {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo-zig/typed-air/recursion-fri-rows-semantic-suite/v2\x00");
    hashSemanticSuite(&hash);
    return hash.finalResult();
}

fn m31Eql(left: []const M31, right: []const M31) bool {
    if (left.len != right.len) return false;
    for (left, right) |lhs, rhs| if (!lhs.eql(rhs)) return false;
    return true;
}

fn hashInt(hash: anytype, comptime T: type, value: anytype) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, @intCast(value), .little);
    hash.update(&bytes);
}

comptime {
    if (FORMAT_VERSION != 2 or SCHEMA_VERSION != 1 or
        LANE_COUNT != 3 or ROW_COUNT != 10 or PROOF_KIND != .binary_node)
    {
        @compileError("heterogeneous FRI rows compiler contract drifted");
    }
}
