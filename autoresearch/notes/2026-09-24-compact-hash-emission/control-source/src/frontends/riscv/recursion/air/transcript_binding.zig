//! Exact typed logical AIR for Stark-V universal transcript-binding row 2.
//!
//! Trusted preprocessing fixes the verifier lane, control operation, sponge
//! session, call coordinate, and frame boundaries.  The proof commits only
//! eight rate deltas and the final eight-word rate output.  This single typed
//! definition owns every direct root and relation tuple used by both prover
//! and verifier lowering.

const std = @import("std");
const digest = @import("../../air/lang/digest.zig");
const ir = @import("../../air/lang/ir.zig");
const relation = @import("../../air/lang/relation.zig");
const source = @import("../../air/lang/source.zig");
const types = @import("../../air/lang/types.zig");
const validate_mod = @import("../../air/lang/validate.zig");
const relation_effect = @import("relation_effect.zig");

pub const STABLE_NAME = "recursion.transcript_binding.v1";
pub const RATE: usize = 8;
pub const PHYSICAL_MAIN_COLUMN_COUNT: usize = 1 + 2 * RATE;
pub const PREPROCESSED_COLUMN_COUNT: usize = 18;
pub const PARAMETER_COUNT: usize = 2;
pub const LOGICAL_INPUT_COUNT: usize =
    PHYSICAL_MAIN_COLUMN_COUNT + PREPROCESSED_COLUMN_COUNT + PARAMETER_COUNT;
pub const DIRECT_CONSTRAINT_COUNT: usize = 1 + 3 * RATE;
pub const RELATION_EVENT_COUNT: usize = 6 + RATE;
pub const LOOKUP_BATCH_SIZE: u8 = 2;
pub const INTERACTION_BATCH_COUNT: usize = 7;
pub const INTERACTION_COLUMN_COUNT: usize = 28;
pub const FRAMEWORK_CONSTRAINT_COUNT: usize =
    DIRECT_CONSTRAINT_COUNT + INTERACTION_BATCH_COUNT;
pub const SOURCE_DECLARED_MAXIMUM_DEGREE: u32 = 3;
pub const REFERENCE_MAXIMUM_CONSTRAINT_DEGREE: u32 = 3;
pub const MAXIMUM_CONSTRAINT_DEGREE: u32 = 3;

pub const STARK_V_REVISION: [40]u8 =
    "59172a201bd01f2f4b699bc2f7d4442d8ee81597".*;
pub const STARK_V_BINDING_PATH =
    "crates/recursion/src/transcript_binding_air.rs";
pub const STARK_V_BINDING_SHA256 = hexDigest(
    "78fdd64602e44b593915a7d4bf60059682e12812eb1575cf4941c083526e714e",
    "invalid pinned Stark-V transcript_binding_air.rs digest",
);
pub const STARK_V_LAYOUT_PATH = "crates/recursion/src/transcript_layout.rs";
pub const STARK_V_LAYOUT_SHA256 = hexDigest(
    "b5362d81ea1b487d964b59660bfac2d35ad290e5ce51b2cb9d8bc064b45e911d",
    "invalid pinned Stark-V transcript_layout.rs digest",
);
pub const STARK_V_PROGRAM_PATH = "crates/recursion/src/transcript_program.rs";
pub const STARK_V_PROGRAM_SHA256 = hexDigest(
    "a1a3795f13b1530c5b8e4f7e7e6c214da8546a22234a15086d663113f6edbabc",
    "invalid pinned Stark-V transcript_program.rs digest",
);
pub const STARK_V_TRANSCRIPT_PATH = "crates/recursion/src/transcript.rs";
pub const STARK_V_TRANSCRIPT_SHA256 = hexDigest(
    "86978ce7a7679d3050e0e72e51733a68036e0f1d229b3dc0927be8fb1f54b74e",
    "invalid pinned Stark-V transcript.rs digest",
);
pub const STARK_V_KERNEL_PATH = "crates/recursion/src/kernel.rs";
pub const STARK_V_KERNEL_SHA256 = hexDigest(
    "5ecc2ec4597b21dd14a2be81dcd8da0324f6b57eed27823cf9986de5d5212e77",
    "invalid pinned Stark-V kernel.rs digest",
);
pub const STARK_V_AIR_FNS_PATH = "crates/stwo-macros/src/air_fns.rs";
pub const STARK_V_AIR_FNS_SHA256 = hexDigest(
    "cd3922d517bb96dcb660ed25e1bd58811109ab21721936f8e56b0a74fe582e79",
    "invalid pinned Stark-V air_fns.rs digest",
);

pub const SOURCE_AUTHORITY_FORMAT_VERSION: u16 = 1;
pub const SOURCE_AUTHORITY_DOMAIN =
    "stwo-zig/typed-air/recursion-transcript-binding-source/v1\x00";
pub const SOURCE_AUTHORITY_DIGEST_HEX =
    "b036392b0e125c12e0c966d7db3ac4129df35e0ab3aded5d256d62435fc5c31a";
pub const SOURCE_AUTHORITY_DIGEST = hexDigest(
    SOURCE_AUTHORITY_DIGEST_HEX,
    "invalid recursion transcript-binding source-authority digest",
);

pub const SourceAuthority = struct {
    format_version: u16,
    revision: [40]u8,
    binding_sha256: digest.Digest,
    layout_sha256: digest.Digest,
    program_sha256: digest.Digest,
    transcript_sha256: digest.Digest,
    kernel_sha256: digest.Digest,
    air_fns_sha256: digest.Digest,
    main_columns: u8,
    preprocessed_columns: u8,
    parameters: u8,
    direct_constraints: u8,
    framework_constraints: u8,
    relation_events: u8,
    interaction_columns: u8,
    maximum_degree: u8,

    pub fn pinned() SourceAuthority {
        return .{
            .format_version = SOURCE_AUTHORITY_FORMAT_VERSION,
            .revision = STARK_V_REVISION,
            .binding_sha256 = STARK_V_BINDING_SHA256,
            .layout_sha256 = STARK_V_LAYOUT_SHA256,
            .program_sha256 = STARK_V_PROGRAM_SHA256,
            .transcript_sha256 = STARK_V_TRANSCRIPT_SHA256,
            .kernel_sha256 = STARK_V_KERNEL_SHA256,
            .air_fns_sha256 = STARK_V_AIR_FNS_SHA256,
            .main_columns = PHYSICAL_MAIN_COLUMN_COUNT,
            .preprocessed_columns = PREPROCESSED_COLUMN_COUNT,
            .parameters = PARAMETER_COUNT,
            .direct_constraints = DIRECT_CONSTRAINT_COUNT,
            .framework_constraints = FRAMEWORK_CONSTRAINT_COUNT,
            .relation_events = RELATION_EVENT_COUNT,
            .interaction_columns = INTERACTION_COLUMN_COUNT,
            .maximum_degree = SOURCE_DECLARED_MAXIMUM_DEGREE,
        };
    }

    pub fn validate(self: SourceAuthority) error{AuthorityMismatch}!void {
        if (!std.meta.eql(self, pinned())) return error.AuthorityMismatch;
        const domains = [_]relation.Domain{
            .recursion_hash_call_control,
            .recursion_hash_data,
            .recursion_hash_output,
            .recursion_transcript_frame_output,
            .recursion_transcript_pow_frame,
            .recursion_step,
            .recursion_transcript_frame_word,
        };
        const arities = [_]usize{ 7, 11, 12, 10, 14, 7, 4 };
        const roles = [_]relation.Role{
            .emit,
            .emit,
            .consume,
            .emit,
            .emit,
            .consume,
            .consume,
        };
        for (domains, arities, roles) |domain, arity, role| {
            const schema = relation.requireExactUniversalSchema(domain) catch
                return error.AuthorityMismatch;
            if (schema.fields.len != arity or !schema.allowed_roles.allows(role))
                return error.AuthorityMismatch;
        }
        const actual = self.identityDigest();
        if (!std.mem.eql(u8, &actual, &SOURCE_AUTHORITY_DIGEST))
            return error.AuthorityMismatch;
    }

    pub fn identityDigest(self: SourceAuthority) digest.Digest {
        var hash = std.crypto.hash.sha2.Sha256.init(.{});
        hash.update(SOURCE_AUTHORITY_DOMAIN);
        hashInt(&hash, u16, self.format_version);
        hash.update(&self.revision);
        hashSource(&hash, STARK_V_BINDING_PATH, self.binding_sha256);
        hashSource(&hash, STARK_V_LAYOUT_PATH, self.layout_sha256);
        hashSource(&hash, STARK_V_PROGRAM_PATH, self.program_sha256);
        hashSource(&hash, STARK_V_TRANSCRIPT_PATH, self.transcript_sha256);
        hashSource(&hash, STARK_V_KERNEL_PATH, self.kernel_sha256);
        hashSource(&hash, STARK_V_AIR_FNS_PATH, self.air_fns_sha256);
        hashInt(&hash, u8, self.main_columns);
        hashInt(&hash, u8, self.preprocessed_columns);
        hashInt(&hash, u8, self.parameters);
        hashInt(&hash, u8, self.direct_constraints);
        hashInt(&hash, u8, self.framework_constraints);
        hashInt(&hash, u8, self.relation_events);
        hashInt(&hash, u8, self.interaction_columns);
        hashInt(&hash, u8, self.maximum_degree);
        return hash.finalResult();
    }
};

pub const SEMANTIC_DIGEST_HEX =
    "a4ef0721f94578f893cb39dadc1dfe3b2575dbcdf22dfa4c786e2606f800caa3";
pub const SEMANTIC_DIGEST: digest.Digest = hexDigest(
    SEMANTIC_DIGEST_HEX,
    "invalid recursion transcript-binding semantic digest",
);
pub const STATIC_PROFILE_DIGEST_HEX =
    "29ef60f836d5b0b8544e388de7e4b728ee63490ba1e7a3d0646f8383e6c15443";

pub const MAIN_COLUMN_NAMES = [PHYSICAL_MAIN_COLUMN_COUNT][]const u8{
    "recursion.transcript_binding.enabler",
    "recursion.transcript_binding.chunk_0",
    "recursion.transcript_binding.chunk_1",
    "recursion.transcript_binding.chunk_2",
    "recursion.transcript_binding.chunk_3",
    "recursion.transcript_binding.chunk_4",
    "recursion.transcript_binding.chunk_5",
    "recursion.transcript_binding.chunk_6",
    "recursion.transcript_binding.chunk_7",
    "recursion.transcript_binding.output_0",
    "recursion.transcript_binding.output_1",
    "recursion.transcript_binding.output_2",
    "recursion.transcript_binding.output_3",
    "recursion.transcript_binding.output_4",
    "recursion.transcript_binding.output_5",
    "recursion.transcript_binding.output_6",
    "recursion.transcript_binding.output_7",
};

pub const PREPROCESSED_COLUMN_NAMES = [PREPROCESSED_COLUMN_COUNT][]const u8{
    "recursion_transcript_call_row_mask",
    "recursion_transcript_call_segment_mask",
    "recursion_transcript_call_binary_mask",
    "recursion_transcript_call_verifier_id",
    "recursion_transcript_call_sequence",
    "recursion_transcript_call_tag",
    "recursion_transcript_call_arg_0",
    "recursion_transcript_call_arg_1",
    "recursion_transcript_call_arg_2",
    "recursion_transcript_call_arg_3",
    "recursion_transcript_call_call_id",
    "recursion_transcript_call_hash_id",
    "recursion_transcript_call_hash_step",
    "recursion_transcript_call_is_first",
    "recursion_transcript_call_is_last",
    "recursion_transcript_call_is_draw",
    "recursion_transcript_call_is_operation_first",
    "recursion_transcript_call_pow_final_mask",
};

pub const PARAMETER_NAMES = [PARAMETER_COUNT][]const u8{
    "recursion.transcript_binding.param.segment_active",
    "recursion.transcript_binding.param.binary_active",
};

pub const MainColumns = struct {
    enabler: types.ValueId,
    chunks: [RATE]types.ValueId,
    outputs: [RATE]types.ValueId,

    pub fn physical(self: MainColumns) [PHYSICAL_MAIN_COLUMN_COUNT]types.ValueId {
        return .{self.enabler} ++ self.chunks ++ self.outputs;
    }
};

pub const PreprocessedColumns = struct {
    row_mask: types.ValueId,
    segment_mask: types.ValueId,
    binary_mask: types.ValueId,
    verifier_id: types.ValueId,
    sequence: types.ValueId,
    tag: types.ValueId,
    args: [4]types.ValueId,
    call_id: types.ValueId,
    hash_id: types.ValueId,
    hash_step: types.ValueId,
    is_first: types.ValueId,
    is_last: types.ValueId,
    is_draw: types.ValueId,
    is_operation_first: types.ValueId,
    pow_final_mask: types.ValueId,

    pub fn physical(self: PreprocessedColumns) [PREPROCESSED_COLUMN_COUNT]types.ValueId {
        return .{
            self.row_mask,
            self.segment_mask,
            self.binary_mask,
            self.verifier_id,
            self.sequence,
            self.tag,
        } ++ self.args ++ .{
            self.call_id,
            self.hash_id,
            self.hash_step,
            self.is_first,
            self.is_last,
            self.is_draw,
            self.is_operation_first,
            self.pow_final_mask,
        };
    }
};

pub const Parameters = struct {
    segment_active: types.ValueId,
    binary_active: types.ValueId,

    pub fn physical(self: Parameters) [PARAMETER_COUNT]types.ValueId {
        return .{ self.segment_active, self.binary_active };
    }
};

pub const ValidationError = validate_mod.Error || relation_effect.Error || error{
    AuthorityMismatch,
    InvalidTranscriptBindingDefinition,
};

pub const Definition = struct {
    arena: ir.Arena,
    main: MainColumns,
    preprocessed: PreprocessedColumns,
    parameters: Parameters,
    active: types.ValueId,
    roots: [DIRECT_CONSTRAINT_COUNT]types.ValueId,
    constraints: [DIRECT_CONSTRAINT_COUNT]types.ConstraintId,
    weights: [RELATION_EVENT_COUNT]types.ValueId,
    word_indices: [RATE]types.ValueId,
    events: [RELATION_EVENT_COUNT]types.EffectId,

    pub fn deinit(self: *Definition) void {
        self.arena.deinit();
        self.* = undefined;
    }

    pub fn validate(self: *const Definition) ValidationError!void {
        try SourceAuthority.pinned().validate();
        try validate_mod.validate(&self.arena);
        const actual = try digest.computeIdentity(&self.arena);
        if (actual.format_version != digest.typed_effect_format_version or
            !std.mem.eql(u8, &actual.bytes, &SEMANTIC_DIGEST) or
            self.arena.constraintsView().len != DIRECT_CONSTRAINT_COUNT or
            self.arena.effectsView().len != RELATION_EVENT_COUNT or
            self.arena.hints.items.len != 0 or self.arena.functions.items.len != 0 or
            self.arena.calls.items.len != 0 or self.arena.range_refinements.items.len != 0 or
            self.arena.fixed_table_requests.items.len != 0)
        {
            return error.InvalidTranscriptBindingDefinition;
        }
        try validateInputs(&self.arena, &self.main.physical(), &MAIN_COLUMN_NAMES, 0, &.{0});
        try validateInputs(
            &self.arena,
            &self.preprocessed.physical(),
            &PREPROCESSED_COLUMN_NAMES,
            PHYSICAL_MAIN_COLUMN_COUNT,
            &.{ 0, 1, 2, 13, 14, 15, 16, 17 },
        );
        try validateInputs(
            &self.arena,
            &self.parameters.physical(),
            &PARAMETER_NAMES,
            PHYSICAL_MAIN_COLUMN_COUNT + PREPROCESSED_COLUMN_COUNT,
            &.{ 0, 1 },
        );
        var name_buffer: [96]u8 = undefined;
        for (self.constraints, self.roots, 0..) |constraint_id, root, index| {
            const item = self.arena.constraint(constraint_id) orelse
                return error.InvalidTranscriptBindingDefinition;
            const actual_name = self.arena.name(item.name) orelse
                return error.InvalidTranscriptBindingDefinition;
            const expected_name = constraintName(index, &name_buffer) catch
                return error.InvalidTranscriptBindingDefinition;
            if (types.idIndex(constraint_id) != index or item.root != root or
                item.gate != null or item.category != .semantic or
                !std.mem.eql(u8, actual_name, expected_name))
            {
                return error.InvalidTranscriptBindingDefinition;
            }
        }
        try validateEvents(self);
    }
};

pub fn build(allocator: std.mem.Allocator) !Definition {
    var result = try buildDefinition(allocator);
    errdefer result.deinit();
    try result.validate();
    return result;
}

pub fn identity(allocator: std.mem.Allocator) !digest.Identity {
    var result = try buildDefinition(allocator);
    defer result.deinit();
    return digest.computeIdentity(&result.arena);
}

fn buildDefinition(allocator: std.mem.Allocator) !Definition {
    var arena = ir.Arena.init(allocator);
    errdefer arena.deinit();
    const span = source.SourceSpan.generated();

    var main_values: [PHYSICAL_MAIN_COLUMN_COUNT]types.ValueId = undefined;
    for (&main_values, MAIN_COLUMN_NAMES, 0..) |*value, name, index|
        value.* = try arena.input(name, if (index == 0) .selector else .felt, span);
    const main = MainColumns{
        .enabler = main_values[0],
        .chunks = main_values[1 .. 1 + RATE].*,
        .outputs = main_values[1 + RATE ..][0..RATE].*,
    };

    var pp_values: [PREPROCESSED_COLUMN_COUNT]types.ValueId = undefined;
    for (&pp_values, PREPROCESSED_COLUMN_NAMES, 0..) |*value, name, index| {
        const is_selector = index <= 2 or index >= 13;
        value.* = try arena.input(name, if (is_selector) .selector else .felt, span);
    }
    const preprocessed = PreprocessedColumns{
        .row_mask = pp_values[0],
        .segment_mask = pp_values[1],
        .binary_mask = pp_values[2],
        .verifier_id = pp_values[3],
        .sequence = pp_values[4],
        .tag = pp_values[5],
        .args = pp_values[6..10].*,
        .call_id = pp_values[10],
        .hash_id = pp_values[11],
        .hash_step = pp_values[12],
        .is_first = pp_values[13],
        .is_last = pp_values[14],
        .is_draw = pp_values[15],
        .is_operation_first = pp_values[16],
        .pow_final_mask = pp_values[17],
    };
    const parameters = Parameters{
        .segment_active = try arena.input(PARAMETER_NAMES[0], .selector, span),
        .binary_active = try arena.input(PARAMETER_NAMES[1], .selector, span),
    };
    const active = try arena.add(
        try arena.mul(preprocessed.segment_mask, parameters.segment_active, span),
        try arena.mul(preprocessed.binary_mask, parameters.binary_active, span),
        span,
    );
    const inactive_lane = try arena.sub(preprocessed.row_mask, active, span);
    const non_final = try arena.sub(preprocessed.row_mask, preprocessed.is_last, span);

    var roots: [DIRECT_CONSTRAINT_COUNT]types.ValueId = undefined;
    roots[0] = try arena.sub(main.enabler, preprocessed.row_mask, span);
    for (main.chunks, 0..) |chunk, index|
        roots[1 + index] = try arena.mul(inactive_lane, chunk, span);
    for (main.outputs, 0..) |output, index|
        roots[1 + RATE + index] = try arena.mul(non_final, output, span);
    for (main.outputs, 0..) |output, index|
        roots[1 + 2 * RATE + index] = try arena.mul(inactive_lane, output, span);

    var constraints: [DIRECT_CONSTRAINT_COUNT]types.ConstraintId = undefined;
    var name_buffer: [96]u8 = undefined;
    for (&constraints, roots, 0..) |*constraint, root, index| {
        constraint.* = try arena.assertZero(
            try constraintName(index, &name_buffer),
            root,
            null,
            .semantic,
            span,
        );
    }

    var weights: [RELATION_EVENT_COUNT]types.ValueId = undefined;
    weights[0] = active;
    weights[1] = active;
    weights[2] = try arena.mul(active, preprocessed.is_last, span);
    weights[3] = weights[2];
    weights[4] = try arena.mul(active, preprocessed.pow_final_mask, span);
    weights[5] = try arena.mul(active, preprocessed.is_operation_first, span);
    for (weights[6..]) |*weight| weight.* = active;

    const hash_control_tuple = [_]types.ValueId{
        preprocessed.verifier_id,
        preprocessed.call_id,
        preprocessed.hash_id,
        preprocessed.hash_step,
        preprocessed.is_first,
        preprocessed.is_last,
        preprocessed.is_draw,
    };
    const hash_data_tuple = .{
        preprocessed.verifier_id,
        preprocessed.hash_id,
        preprocessed.hash_step,
    } ++ main.chunks;
    const hash_output_tuple = .{
        preprocessed.verifier_id,
        preprocessed.hash_id,
        preprocessed.call_id,
        preprocessed.is_draw,
    } ++ main.outputs;
    const frame_output_tuple = .{
        preprocessed.verifier_id,
        preprocessed.hash_id,
    } ++ main.outputs;
    const pow_frame_tuple = .{
        preprocessed.verifier_id,
        preprocessed.sequence,
        preprocessed.tag,
        preprocessed.hash_id,
        preprocessed.call_id,
        preprocessed.args[0],
    } ++ main.outputs;
    const step_tuple = .{
        preprocessed.verifier_id,
        preprocessed.sequence,
        preprocessed.tag,
    } ++ preprocessed.args;
    var word_indices: [RATE]types.ValueId = undefined;
    var word_tuples: [RATE][4]types.ValueId = undefined;
    var event_specs: [RELATION_EVENT_COUNT]relation_effect.EventSpec = undefined;
    event_specs[0] = .{
        .domain = .recursion_hash_call_control,
        .role = .emit,
        .values = &hash_control_tuple,
        .weight = weights[0],
    };
    event_specs[1] = .{
        .domain = .recursion_hash_data,
        .role = .emit,
        .values = &hash_data_tuple,
        .weight = weights[1],
    };
    event_specs[2] = .{
        .domain = .recursion_hash_output,
        .role = .consume,
        .values = &hash_output_tuple,
        .weight = weights[2],
    };
    event_specs[3] = .{
        .domain = .recursion_transcript_frame_output,
        .role = .emit,
        .values = &frame_output_tuple,
        .weight = weights[3],
    };
    event_specs[4] = .{
        .domain = .recursion_transcript_pow_frame,
        .role = .emit,
        .values = &pow_frame_tuple,
        .weight = weights[4],
    };
    event_specs[5] = .{
        .domain = .recursion_step,
        .role = .consume,
        .values = &step_tuple,
        .weight = weights[5],
    };
    const rate = try arena.constantField(RATE, span);
    const word_base = try arena.mul(preprocessed.hash_step, rate, span);
    for (main.chunks, 0..) |chunk, word| {
        word_indices[word] = if (word == 0)
            word_base
        else
            try arena.add(
                word_base,
                try arena.constantField(@intCast(word), span),
                span,
            );
        word_tuples[word] = .{
            preprocessed.verifier_id,
            preprocessed.hash_id,
            word_indices[word],
            chunk,
        };
        event_specs[6 + word] = .{
            .domain = .recursion_transcript_frame_word,
            .role = .consume,
            .values = &word_tuples[word],
            .weight = weights[6 + word],
        };
    }
    const events = try relation_effect.appendGroup(
        RELATION_EVENT_COUNT,
        &arena,
        event_specs,
        span,
    );
    return .{
        .arena = arena,
        .main = main,
        .preprocessed = preprocessed,
        .parameters = parameters,
        .active = active,
        .roots = roots,
        .constraints = constraints,
        .weights = weights,
        .word_indices = word_indices,
        .events = events,
    };
}

fn validateInputs(
    arena: *const ir.Arena,
    values: []const types.ValueId,
    names: []const []const u8,
    offset: usize,
    selector_indices: []const usize,
) error{InvalidTranscriptBindingDefinition}!void {
    if (values.len != names.len) return error.InvalidTranscriptBindingDefinition;
    for (values, names, 0..) |value, expected_name, local_index| {
        if (types.idIndex(value) != offset + local_index)
            return error.InvalidTranscriptBindingDefinition;
        var selector = false;
        for (selector_indices) |index| selector = selector or index == local_index;
        const node = arena.node(value) orelse return error.InvalidTranscriptBindingDefinition;
        if (!std.meta.eql(node.key.ty, if (selector) types.Type.selector else .felt))
            return error.InvalidTranscriptBindingDefinition;
        const name_id = switch (node.key.op) {
            .input => |input_name| input_name,
            else => return error.InvalidTranscriptBindingDefinition,
        };
        const actual_name = arena.name(name_id) orelse
            return error.InvalidTranscriptBindingDefinition;
        if (!std.mem.eql(u8, actual_name, expected_name))
            return error.InvalidTranscriptBindingDefinition;
    }
}

fn validateEvents(self: *const Definition) error{InvalidTranscriptBindingDefinition}!void {
    const hash_control_tuple = [_]types.ValueId{
        self.preprocessed.verifier_id,
        self.preprocessed.call_id,
        self.preprocessed.hash_id,
        self.preprocessed.hash_step,
        self.preprocessed.is_first,
        self.preprocessed.is_last,
        self.preprocessed.is_draw,
    };
    const hash_data_tuple = .{
        self.preprocessed.verifier_id,
        self.preprocessed.hash_id,
        self.preprocessed.hash_step,
    } ++ self.main.chunks;
    const hash_output_tuple = .{
        self.preprocessed.verifier_id,
        self.preprocessed.hash_id,
        self.preprocessed.call_id,
        self.preprocessed.is_draw,
    } ++ self.main.outputs;
    const frame_output_tuple = .{
        self.preprocessed.verifier_id,
        self.preprocessed.hash_id,
    } ++ self.main.outputs;
    const pow_frame_tuple = .{
        self.preprocessed.verifier_id,
        self.preprocessed.sequence,
        self.preprocessed.tag,
        self.preprocessed.hash_id,
        self.preprocessed.call_id,
        self.preprocessed.args[0],
    } ++ self.main.outputs;
    const step_tuple = .{
        self.preprocessed.verifier_id,
        self.preprocessed.sequence,
        self.preprocessed.tag,
    } ++ self.preprocessed.args;
    const domains = [_]relation.Domain{
        .recursion_hash_call_control,
        .recursion_hash_data,
        .recursion_hash_output,
        .recursion_transcript_frame_output,
        .recursion_transcript_pow_frame,
        .recursion_step,
    };
    const roles = [_]relation.Role{
        .emit,
        .emit,
        .consume,
        .emit,
        .emit,
        .consume,
    };
    const tuples = .{
        hash_control_tuple[0..],
        hash_data_tuple[0..],
        hash_output_tuple[0..],
        frame_output_tuple[0..],
        pow_frame_tuple[0..],
        step_tuple[0..],
    };
    inline for (0..6) |index| try validateEvent(
        self,
        index,
        domains[index],
        roles[index],
        tuples[index],
    );
    for (self.main.chunks, self.word_indices, 0..) |chunk, word_index, word| {
        const tuple = [_]types.ValueId{
            self.preprocessed.verifier_id,
            self.preprocessed.hash_id,
            word_index,
            chunk,
        };
        try validateEvent(
            self,
            6 + word,
            .recursion_transcript_frame_word,
            .consume,
            &tuple,
        );
    }
}

fn validateEvent(
    self: *const Definition,
    index: usize,
    domain: relation.Domain,
    role: relation.Role,
    expected_values: []const types.ValueId,
) error{InvalidTranscriptBindingDefinition}!void {
    const effect_id = self.events[index];
    if (types.idIndex(effect_id) != index)
        return error.InvalidTranscriptBindingDefinition;
    const item = self.arena.effect(effect_id) orelse
        return error.InvalidTranscriptBindingDefinition;
    const binding = item.binding orelse
        return error.InvalidTranscriptBindingDefinition;
    const schema = relation.get(domain);
    const values = self.arena.effectValues(effect_id) orelse
        return error.InvalidTranscriptBindingDefinition;
    if (item.kind != .component_call or item.liveness != self.weights[index] or
        item.access_ordinal != null or binding.schema != schema.id or
        binding.schema_version != schema.version or binding.role != role or
        !std.mem.eql(types.ValueId, values, expected_values))
    {
        return error.InvalidTranscriptBindingDefinition;
    }
}

fn constraintName(index: usize, buffer: *[96]u8) ![]const u8 {
    if (index == 0) return "recursion.transcript_binding.enabler_matches_row_mask";
    if (index <= RATE) return std.fmt.bufPrint(
        buffer,
        "recursion.transcript_binding.inactive_chunk_{d}_zero",
        .{index - 1},
    );
    if (index <= 2 * RATE) return std.fmt.bufPrint(
        buffer,
        "recursion.transcript_binding.non_final_output_{d}_zero",
        .{index - 1 - RATE},
    );
    if (index <= 3 * RATE) return std.fmt.bufPrint(
        buffer,
        "recursion.transcript_binding.inactive_output_{d}_zero",
        .{index - 1 - 2 * RATE},
    );
    return error.InvalidConstraintIndex;
}

fn hashSource(hash: anytype, path: []const u8, bytes: digest.Digest) void {
    hashInt(hash, u32, path.len);
    hash.update(path);
    hash.update(&bytes);
}

fn hashInt(hash: anytype, comptime T: type, value: anytype) void {
    var encoded: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &encoded, @intCast(value), .little);
    hash.update(&encoded);
}

fn hexDigest(comptime value: []const u8, comptime message: []const u8) digest.Digest {
    var result: digest.Digest = undefined;
    _ = std.fmt.hexToBytes(&result, value) catch @compileError(message);
    return result;
}

comptime {
    if (PHYSICAL_MAIN_COLUMN_COUNT != 17 or
        PREPROCESSED_COLUMN_COUNT != 18 or PARAMETER_COUNT != 2 or
        LOGICAL_INPUT_COUNT != 37 or DIRECT_CONSTRAINT_COUNT != 25 or
        RELATION_EVENT_COUNT != 14 or INTERACTION_BATCH_COUNT != 7 or
        INTERACTION_COLUMN_COUNT != 28 or FRAMEWORK_CONSTRAINT_COUNT != 32)
    {
        @compileError("universal transcript-binding geometry drifted");
    }
}
