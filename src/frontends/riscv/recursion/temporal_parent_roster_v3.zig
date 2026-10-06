//! Versioned V3 temporal-parent roster and key preimage, prior to proof activation.
//!
//! Only row 11 currently has qualified typed AIR geometry. The remaining
//! rows are explicit obligations, not zero-cost components or claimed proofs.
//! A parent key cannot be published until each obligation has a pinned AIR,
//! shared lookup closure, preprocessed root, and fresh verifier transaction.
const std = @import("std");
const core = @import("stwo_core");
const channel = @import("poseidon2_channel.zig");
const graph = @import("statement_semantics_circuit_temporal_v3.zig");
const row11_session = @import("temporal_parent_row11_session_v3.zig");
const row11_air = @import("air/statement_semantics_input.zig");
const row11_witness = @import("air/statement_semantics_input_witness.zig");
const inputs = @import("temporal_parent_inputs_v3.zig");

pub const FORMAT_VERSION: u32 = 3;
pub const SCHEMA_VERSION: u32 = 1;
pub const STAGE_DOMAIN: u32 = 0x5450_5333; // TPS3, never a verifier-key domain.
pub const COMPONENT_COUNT: usize = 6;
pub const PRODUCTION_PROOF_ACTIVATION = false;

pub const Component = enum(u8) {
    left_child_verifier = 0,
    right_child_verifier = 1,
    statement_row11 = 2,
    boundary_and_completion = 3,
    endpoint_identity = 4,
    lookup_provider = 5,
};

pub const Qualification = enum(u8) {
    missing_typed_air = 0,
    qualified_row11 = 1,
};

/// Actual committed geometry is recorded only where an AIR exists.
pub const Geometry = struct {
    log_size: u32,
    preprocessed_columns: u16,
    main_columns: u16,
    interaction_columns: u16,
    direct_constraints: u16,
    interaction_batches: u16,
    semantic_digest: [32]u8,
};

pub const Descriptor = struct {
    component: Component,
    input_words: u32,
    qualification: Qualification,
    geometry: ?Geometry,
};

pub const PlanV3 = struct {
    format_version: u32 = FORMAT_VERSION,
    schema_version: u32 = SCHEMA_VERSION,
    pins: inputs.KeyPinsV3,
    input_words: u32 = inputs.INPUT_WORDS,
    row11_circuit_id: u32 = row11_session.CIRCUIT_ID,
    row11_trace_rows: u32 = row11_session.TRACE_SIZE,
    row11_graph_inputs: u32 = graph.INPUT_COUNT,
    row11_graph_nodes: u32 = graph.NODE_COUNT,
    row11_graph_outputs: u32 = graph.OUTPUT_COUNT,
    graph_identity: [32]u8 = graph.IDENTITY_DIGEST,
    row11_preprocessed_identity: [32]u8 = row11_session.PREPROCESSED_DIGEST,
    row11_binding_identity: [32]u8 = row11_witness.BINDING_DIGEST,
    descriptors: [COMPONENT_COUNT]Descriptor,
    /// Namespaces the candidate design. It is not a verification key.
    stage_identity: channel.Digest,

    pub fn init(pins: inputs.KeyPinsV3) !PlanV3 {
        try pins.validate();
        var result = PlanV3{
            .pins = pins,
            .descriptors = expectedDescriptors(),
            .stage_identity = undefined,
        };
        result.stage_identity = stageIdentity(&result);
        return result;
    }

    pub fn validate(self: *const PlanV3) !void {
        const expected = try init(self.pins);
        if (!std.meta.eql(self.*, expected)) return error.TemporalParentRosterMismatch;
    }

    pub fn checkCandidate(self: *const PlanV3, candidate: *const inputs.CandidateInputsV3) !void {
        try self.validate();
        try candidate.validate();
        if (!std.meta.eql(self.pins, candidate.pins)) return error.TemporalParentKeyPinsMismatch;
    }

    pub fn requireVerificationKey(_: *const PlanV3) error{ParentProofUnavailable}!void {
        return error.ParentProofUnavailable;
    }
};

fn expectedDescriptors() [COMPONENT_COUNT]Descriptor {
    return .{
        .{ .component = .left_child_verifier, .input_words = inputs.CHILD_WORDS, .qualification = .missing_typed_air, .geometry = null },
        .{ .component = .right_child_verifier, .input_words = inputs.CHILD_WORDS, .qualification = .missing_typed_air, .geometry = null },
        .{ .component = .statement_row11, .input_words = 3 * @import("span_statement.zig").SPAN_STATEMENT_CANONICAL_WORDS, .qualification = .qualified_row11, .geometry = .{
            .log_size = row11_session.LOG_SIZE,
            .preprocessed_columns = row11_air.PREPROCESSED_COLUMN_COUNT,
            .main_columns = row11_air.PHYSICAL_MAIN_COLUMN_COUNT,
            .interaction_columns = row11_air.INTERACTION_COLUMN_COUNT,
            .direct_constraints = row11_air.DIRECT_CONSTRAINT_COUNT,
            .interaction_batches = row11_air.INTERACTION_BATCH_COUNT,
            .semantic_digest = row11_air.SEMANTIC_DIGEST,
        } },
        .{ .component = .boundary_and_completion, .input_words = 6 * inputs.BOUNDARY_WORDS + 3 * inputs.COMPLETION_WORDS, .qualification = .missing_typed_air, .geometry = null },
        .{ .component = .endpoint_identity, .input_words = 6 * 8, .qualification = .missing_typed_air, .geometry = null },
        .{ .component = .lookup_provider, .input_words = 0, .qualification = .missing_typed_air, .geometry = null },
    };
}

fn stageIdentity(plan: *const PlanV3) channel.Digest {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo-zig/riscv-temporal-parent-stage/v3\x00");
    hashWord(&hash, plan.format_version);
    hashWord(&hash, plan.schema_version);
    hashWord(&hash, plan.input_words);
    hashWord(&hash, plan.row11_circuit_id);
    hashWord(&hash, plan.row11_trace_rows);
    hashWord(&hash, plan.row11_graph_inputs);
    hashWord(&hash, plan.row11_graph_nodes);
    hashWord(&hash, plan.row11_graph_outputs);
    hash.update(&plan.graph_identity);
    hash.update(&plan.row11_preprocessed_identity);
    hash.update(&plan.row11_binding_identity);
    for (plan.pins.leaf_wrapper) |word| hashWord(&hash, word);
    for (plan.pins.temporal_child) |word| hashWord(&hash, word);
    for (plan.descriptors) |descriptor| {
        hashWord(&hash, @intFromEnum(descriptor.component));
        hashWord(&hash, descriptor.input_words);
        hashWord(&hash, @intFromEnum(descriptor.qualification));
        if (descriptor.geometry) |geometry| {
            hashWord(&hash, 1);
            hashWord(&hash, geometry.log_size);
            hashWord(&hash, geometry.preprocessed_columns);
            hashWord(&hash, geometry.main_columns);
            hashWord(&hash, geometry.interaction_columns);
            hashWord(&hash, geometry.direct_constraints);
            hashWord(&hash, geometry.interaction_batches);
            hash.update(&geometry.semantic_digest);
        } else hashWord(&hash, 0);
    }
    const sha = hash.finalResult();
    return channel.hashBytes(&sha, STAGE_DOMAIN);
}

fn hashWord(hash: *std.crypto.hash.sha2.Sha256, value: u32) void {
    var bytes: [4]u8 = undefined;
    std.mem.writeInt(u32, &bytes, value, .little);
    hash.update(&bytes);
}

comptime {
    if (STAGE_DOMAIN >= core.fields.m31.Modulus or
        COMPONENT_COUNT != 6 or PRODUCTION_PROOF_ACTIVATION)
        @compileError("V3 temporal parent roster identity drifted");
}
