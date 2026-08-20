//! Exact typed logical AIR for Stark-V universal transcript-word row 4.
//!
//! One row owns each padded non-digest word in every verifier transcript
//! frame. Verifier-owned preprocessing fixes the operation, frame, slot,
//! payload index, and constant. The committed value is nonzero only for a
//! payload slot in an active lane. The row emits the complete frame word and
//! consumes payload words from their semantic producer.

const std = @import("std");
const digest = @import("../../air/lang/digest.zig");
const ir = @import("../../air/lang/ir.zig");
const relation = @import("../../air/lang/relation.zig");
const source = @import("../../air/lang/source.zig");
const types = @import("../../air/lang/types.zig");
const validate_mod = @import("../../air/lang/validate.zig");
const relation_effect = @import("relation_effect.zig");

pub const STABLE_NAME = "recursion.transcript_word.v1";
pub const DIGEST_WORD_COUNT: usize = 8;
pub const RATE: usize = 8;
pub const TRANSCRIPT_HEADER_WORD_COUNT: usize = 8;
pub const PCS_PARAMETER_WORD_COUNT: usize = 16;
pub const STATEMENT_WORD_COUNT: usize = 412;
pub const POW_NONCE_WORD_COUNT: usize = 4;
pub const TRANSCRIPT_OPERATION_TAG: u32 = 0x5452;
pub const DRAW_COUNTER: u32 = 0;
pub const DRAW_TAG: u32 = 0x4452_4157;
pub const MIN_LOG_SIZE: u32 = 4;
pub const MAX_LOG_SIZE: u32 = 30;

pub const PHYSICAL_MAIN_COLUMN_COUNT: usize = 2;
pub const PREPROCESSED_COLUMN_COUNT: usize = 15;
pub const PARAMETER_COUNT: usize = 2;
pub const LOGICAL_INPUT_COUNT: usize =
    PHYSICAL_MAIN_COLUMN_COUNT + PREPROCESSED_COLUMN_COUNT + PARAMETER_COUNT;
pub const DIRECT_CONSTRAINT_COUNT: usize = 3;
pub const FRAMEWORK_CONSTRAINT_COUNT: usize = DIRECT_CONSTRAINT_COUNT + 1;
pub const RELATION_EVENT_COUNT: usize = 2;
pub const LOOKUP_BATCH_SIZE: u8 = 2;
pub const INTERACTION_BATCH_COUNT: usize = 1;
pub const INTERACTION_COLUMN_COUNT: usize = 4;
pub const FRAME_WORD_RELATION_ARITY: usize = 4;
pub const PAYLOAD_WORD_RELATION_ARITY: usize = 9;
pub const REFERENCE_MAXIMUM_CONSTRAINT_DEGREE: u32 = 3;
// The reference treats preprocessing and proof-kind parameters as constants.
// Our conservative logical analyzer assigns each input degree one.
pub const MAXIMUM_CONSTRAINT_DEGREE: u32 = 4;

pub const STARK_V_REVISION: [40]u8 =
    "59172a201bd01f2f4b699bc2f7d4442d8ee81597".*;
pub const SOURCE_FILES = [_]SourceFile{
    sourceFile(
        "crates/recursion/src/transcript_word_air.rs",
        "ef946aa7269b4cc2c5b45d022b8854a8ddf6bd612a4643056e3a1c2d8199337b",
    ),
    sourceFile(
        "crates/recursion/src/transcript_layout.rs",
        "b5362d81ea1b487d964b59660bfac2d35ad290e5ce51b2cb9d8bc064b45e911d",
    ),
    sourceFile(
        "crates/recursion/src/transcript_binding_air.rs",
        "78fdd64602e44b593915a7d4bf60059682e12812eb1575cf4941c083526e714e",
    ),
    sourceFile(
        "crates/recursion/src/transcript_program.rs",
        "a1a3795f13b1530c5b8e4f7e7e6c214da8546a22234a15086d663113f6edbabc",
    ),
    sourceFile(
        "crates/recursion/src/transcript.rs",
        "86978ce7a7679d3050e0e72e51733a68036e0f1d229b3dc0927be8fb1f54b74e",
    ),
    sourceFile(
        "crates/recursion/src/kernel.rs",
        "5ecc2ec4597b21dd14a2be81dcd8da0324f6b57eed27823cf9986de5d5212e77",
    ),
    sourceFile(
        "crates/recursion/src/protocol.rs",
        "fa602d61d42763c58aa9b9769302307c32adadc6282d4fc06a95a5b809273a70",
    ),
    sourceFile(
        "crates/recursion/src/statement.rs",
        "a0bff241e54dc394f05c24a170a460b7921dfe0e45703aa3f7e093cff89cab11",
    ),
    sourceFile(
        "crates/stwo-macros/src/air_fns.rs",
        "cd3922d517bb96dcb660ed25e1bd58811109ab21721936f8e56b0a74fe582e79",
    ),
};

pub const SOURCE_AUTHORITY_FORMAT_VERSION: u16 = 1;
pub const SOURCE_AUTHORITY_DOMAIN =
    "stwo-zig/typed-air/recursion-transcript-word-source/v1\x00";
pub const SOURCE_AUTHORITY_DIGEST_HEX =
    "3d7f952a9a67a6941b7db78c02123869c2db5fefd38bf61540c568b13f990ace";
pub const SOURCE_AUTHORITY_DIGEST = hexDigest(
    SOURCE_AUTHORITY_DIGEST_HEX,
    "invalid transcript-word source-authority digest",
);

pub const SourceFile = struct {
    path: []const u8,
    sha256: digest.Digest,
};

pub const SourceAuthority = struct {
    format_version: u16,
    revision: [40]u8,
    files: [SOURCE_FILES.len]SourceFile,
    main_columns: u8,
    preprocessed_columns: u8,
    parameters: u8,
    direct_constraints: u8,
    framework_constraints: u8,
    relation_events: u8,
    lookup_batch: u8,
    interaction_columns: u8,
    frame_word_arity: u8,
    payload_word_arity: u8,
    digest_words: u8,
    rate: u8,
    header_words: u8,
    pcs_parameter_words: u8,
    statement_words: u16,
    nonce_words: u8,

    pub fn pinned() SourceAuthority {
        return .{
            .format_version = SOURCE_AUTHORITY_FORMAT_VERSION,
            .revision = STARK_V_REVISION,
            .files = SOURCE_FILES,
            .main_columns = PHYSICAL_MAIN_COLUMN_COUNT,
            .preprocessed_columns = PREPROCESSED_COLUMN_COUNT,
            .parameters = PARAMETER_COUNT,
            .direct_constraints = DIRECT_CONSTRAINT_COUNT,
            .framework_constraints = FRAMEWORK_CONSTRAINT_COUNT,
            .relation_events = RELATION_EVENT_COUNT,
            .lookup_batch = LOOKUP_BATCH_SIZE,
            .interaction_columns = INTERACTION_COLUMN_COUNT,
            .frame_word_arity = FRAME_WORD_RELATION_ARITY,
            .payload_word_arity = PAYLOAD_WORD_RELATION_ARITY,
            .digest_words = DIGEST_WORD_COUNT,
            .rate = RATE,
            .header_words = TRANSCRIPT_HEADER_WORD_COUNT,
            .pcs_parameter_words = PCS_PARAMETER_WORD_COUNT,
            .statement_words = STATEMENT_WORD_COUNT,
            .nonce_words = POW_NONCE_WORD_COUNT,
        };
    }

    pub fn validate(self: SourceAuthority) error{AuthorityMismatch}!void {
        if (!std.meta.eql(self, pinned())) return error.AuthorityMismatch;
        const frame = relation.requireExactUniversalSchema(
            .recursion_transcript_frame_word,
        ) catch return error.AuthorityMismatch;
        const payload = relation.requireExactUniversalSchema(
            .recursion_transcript_payload_word,
        ) catch return error.AuthorityMismatch;
        if (frame.fields.len != self.frame_word_arity or
            !frame.allowed_roles.allows(.emit) or
            payload.fields.len != self.payload_word_arity or
            !payload.allowed_roles.allows(.consume))
        {
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
        hashInt(&hash, u8, self.files.len);
        for (self.files) |file| {
            hashBytes(&hash, file.path);
            hash.update(&file.sha256);
        }
        inline for (.{
            self.main_columns,
            self.preprocessed_columns,
            self.parameters,
            self.direct_constraints,
            self.framework_constraints,
            self.relation_events,
            self.lookup_batch,
            self.interaction_columns,
            self.frame_word_arity,
            self.payload_word_arity,
            self.digest_words,
            self.rate,
            self.header_words,
            self.pcs_parameter_words,
        }) |value| hashInt(&hash, u8, value);
        hashInt(&hash, u16, self.statement_words);
        hashInt(&hash, u8, self.nonce_words);
        hashInt(&hash, u32, TRANSCRIPT_OPERATION_TAG);
        hashInt(&hash, u32, DRAW_COUNTER);
        hashInt(&hash, u32, DRAW_TAG);
        return hash.finalResult();
    }
};

pub const SEMANTIC_DIGEST_HEX =
    "5d762c5d65a4f0a0c357b6fe2c43df8034cd316e816bf1794f3dc36a11e329f3";
pub const SEMANTIC_DIGEST = hexDigest(
    SEMANTIC_DIGEST_HEX,
    "invalid recursion transcript-word semantic digest",
);
pub const STATIC_PROFILE_DIGEST_HEX =
    "bfac09abed0921a9f973784dd0fc8c1f452898fb076ab527cc7030b2283d4984";

pub const MAIN_COLUMN_NAMES = [PHYSICAL_MAIN_COLUMN_COUNT][]const u8{
    "recursion.transcript_word.enabler",
    "recursion.transcript_word.value",
};

pub const PREPROCESSED_COLUMN_NAMES = [PREPROCESSED_COLUMN_COUNT][]const u8{
    "recursion_transcript_word_row_mask",
    "recursion_transcript_word_segment_mask",
    "recursion_transcript_word_binary_mask",
    "recursion_transcript_word_verifier_id",
    "recursion_transcript_word_sequence",
    "recursion_transcript_word_tag",
    "recursion_transcript_word_arg_0",
    "recursion_transcript_word_arg_1",
    "recursion_transcript_word_arg_2",
    "recursion_transcript_word_arg_3",
    "recursion_transcript_word_hash_id",
    "recursion_transcript_word_index",
    "recursion_transcript_word_is_payload",
    "recursion_transcript_word_payload_index",
    "recursion_transcript_word_constant",
};

pub const PARAMETER_NAMES = [PARAMETER_COUNT][]const u8{
    "recursion.transcript_word.param.segment_active",
    "recursion.transcript_word.param.binary_active",
};

pub const CONSTRAINT_NAMES = [DIRECT_CONSTRAINT_COUNT][]const u8{
    "recursion.transcript_word.enabler_row_mask",
    "recursion.transcript_word.inactive_value_zero",
    "recursion.transcript_word.constant_value_zero",
};

pub const MainColumns = struct {
    enabler: types.ValueId,
    value: types.ValueId,

    pub fn physical(self: MainColumns) [PHYSICAL_MAIN_COLUMN_COUNT]types.ValueId {
        return .{ self.enabler, self.value };
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
    hash_id: types.ValueId,
    word_index: types.ValueId,
    is_payload: types.ValueId,
    payload_index: types.ValueId,
    constant_value: types.ValueId,

    pub fn physical(
        self: PreprocessedColumns,
    ) [PREPROCESSED_COLUMN_COUNT]types.ValueId {
        return .{
            self.row_mask,
            self.segment_mask,
            self.binary_mask,
            self.verifier_id,
            self.sequence,
            self.tag,
        } ++ self.args ++ .{
            self.hash_id,
            self.word_index,
            self.is_payload,
            self.payload_index,
            self.constant_value,
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

pub const Events = struct {
    frame_word_emit: types.EffectId,
    payload_word_consume: types.EffectId,

    pub fn ordered(self: Events) [RELATION_EVENT_COUNT]types.EffectId {
        return .{ self.frame_word_emit, self.payload_word_consume };
    }
};

pub const ValidationError = validate_mod.Error || relation_effect.Error || error{
    InvalidTranscriptWordDefinition,
};

pub const Definition = struct {
    arena: ir.Arena,
    main: MainColumns,
    preprocessed: PreprocessedColumns,
    parameters: Parameters,
    active: types.ValueId,
    constant_mask: types.ValueId,
    frame_value: types.ValueId,
    payload_weight: types.ValueId,
    roots: [DIRECT_CONSTRAINT_COUNT]types.ValueId,
    constraints: [DIRECT_CONSTRAINT_COUNT]types.ConstraintId,
    events: Events,

    pub fn deinit(self: *Definition) void {
        self.arena.deinit();
        self.* = undefined;
    }

    pub fn validate(self: *const Definition) ValidationError!void {
        try validate_mod.validate(&self.arena);
        const actual_identity = try digest.computeIdentity(&self.arena);
        if (actual_identity.format_version != digest.typed_effect_format_version or
            !std.mem.eql(u8, &actual_identity.bytes, &SEMANTIC_DIGEST) or
            self.arena.constraintsView().len != DIRECT_CONSTRAINT_COUNT or
            self.arena.effectsView().len != RELATION_EVENT_COUNT or
            self.arena.hints.items.len != 0 or self.arena.functions.items.len != 0 or
            self.arena.calls.items.len != 0 or self.arena.range_refinements.items.len != 0 or
            self.arena.fixed_table_requests.items.len != 0)
        {
            return error.InvalidTranscriptWordDefinition;
        }
        try validateInputs(
            &self.arena,
            &self.main.physical(),
            &MAIN_COLUMN_NAMES,
            0,
            &.{0},
        );
        try validateInputs(
            &self.arena,
            &self.preprocessed.physical(),
            &PREPROCESSED_COLUMN_NAMES,
            PHYSICAL_MAIN_COLUMN_COUNT,
            &.{ 0, 1, 2, 12 },
        );
        try validateInputs(
            &self.arena,
            &self.parameters.physical(),
            &PARAMETER_NAMES,
            PHYSICAL_MAIN_COLUMN_COUNT + PREPROCESSED_COLUMN_COUNT,
            &.{ 0, 1 },
        );
        for (self.constraints, self.roots, CONSTRAINT_NAMES, 0..) |
            constraint_id,
            root,
            expected_name,
            index,
        | {
            const item = self.arena.constraint(constraint_id) orelse
                return error.InvalidTranscriptWordDefinition;
            const actual_name = self.arena.name(item.name) orelse
                return error.InvalidTranscriptWordDefinition;
            if (types.idIndex(constraint_id) != index or item.root != root or
                item.gate != null or item.category != .semantic or
                !std.mem.eql(u8, actual_name, expected_name))
            {
                return error.InvalidTranscriptWordDefinition;
            }
        }
        const frame_tuple = [FRAME_WORD_RELATION_ARITY]types.ValueId{
            self.preprocessed.verifier_id,
            self.preprocessed.hash_id,
            self.preprocessed.word_index,
            self.frame_value,
        };
        const payload_tuple = .{
            self.preprocessed.verifier_id,
            self.preprocessed.sequence,
            self.preprocessed.tag,
        } ++ self.preprocessed.args ++ .{
            self.preprocessed.payload_index,
            self.main.value,
        };
        try validateEvent(
            self,
            self.events.frame_word_emit,
            0,
            .recursion_transcript_frame_word,
            .emit,
            self.active,
            &frame_tuple,
        );
        try validateEvent(
            self,
            self.events.payload_word_consume,
            1,
            .recursion_transcript_payload_word,
            .consume,
            self.payload_weight,
            &payload_tuple,
        );
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
    const main = MainColumns{
        .enabler = try arena.input(MAIN_COLUMN_NAMES[0], .selector, span),
        .value = try arena.input(MAIN_COLUMN_NAMES[1], .felt, span),
    };
    var preprocessed_values: [PREPROCESSED_COLUMN_COUNT]types.ValueId = undefined;
    for (&preprocessed_values, PREPROCESSED_COLUMN_NAMES, 0..) |
        *value,
        name,
        index,
    | value.* = try arena.input(
        name,
        switch (index) {
            0, 1, 2, 12 => .selector,
            else => .felt,
        },
        span,
    );
    const preprocessed = PreprocessedColumns{
        .row_mask = preprocessed_values[0],
        .segment_mask = preprocessed_values[1],
        .binary_mask = preprocessed_values[2],
        .verifier_id = preprocessed_values[3],
        .sequence = preprocessed_values[4],
        .tag = preprocessed_values[5],
        .args = preprocessed_values[6..10].*,
        .hash_id = preprocessed_values[10],
        .word_index = preprocessed_values[11],
        .is_payload = preprocessed_values[12],
        .payload_index = preprocessed_values[13],
        .constant_value = preprocessed_values[14],
    };
    const parameters = Parameters{
        .segment_active = try arena.input(PARAMETER_NAMES[0], .selector, span),
        .binary_active = try arena.input(PARAMETER_NAMES[1], .selector, span),
    };
    const one = try arena.constantField(1, span);
    const active = try arena.add(
        try arena.mul(preprocessed.segment_mask, parameters.segment_active, span),
        try arena.mul(preprocessed.binary_mask, parameters.binary_active, span),
        span,
    );
    const constant_mask = try arena.sub(one, preprocessed.is_payload, span);
    const frame_value = try arena.add(main.value, preprocessed.constant_value, span);
    const payload_weight = try arena.mul(active, preprocessed.is_payload, span);
    const roots = [DIRECT_CONSTRAINT_COUNT]types.ValueId{
        try arena.sub(main.enabler, preprocessed.row_mask, span),
        try arena.mul(
            try arena.sub(preprocessed.row_mask, active, span),
            main.value,
            span,
        ),
        try arena.mul(
            try arena.mul(active, constant_mask, span),
            main.value,
            span,
        ),
    };
    var constraints: [DIRECT_CONSTRAINT_COUNT]types.ConstraintId = undefined;
    for (&constraints, roots, CONSTRAINT_NAMES) |*constraint, root, name|
        constraint.* = try arena.assertZero(name, root, null, .semantic, span);
    const frame_tuple = [FRAME_WORD_RELATION_ARITY]types.ValueId{
        preprocessed.verifier_id,
        preprocessed.hash_id,
        preprocessed.word_index,
        frame_value,
    };
    const payload_tuple = .{
        preprocessed.verifier_id,
        preprocessed.sequence,
        preprocessed.tag,
    } ++ preprocessed.args ++ .{ preprocessed.payload_index, main.value };
    const ordered = try relation_effect.appendGroup(RELATION_EVENT_COUNT, &arena, .{
        .{
            .domain = .recursion_transcript_frame_word,
            .role = .emit,
            .values = &frame_tuple,
            .weight = active,
        },
        .{
            .domain = .recursion_transcript_payload_word,
            .role = .consume,
            .values = &payload_tuple,
            .weight = payload_weight,
        },
    }, span);
    return .{
        .arena = arena,
        .main = main,
        .preprocessed = preprocessed,
        .parameters = parameters,
        .active = active,
        .constant_mask = constant_mask,
        .frame_value = frame_value,
        .payload_weight = payload_weight,
        .roots = roots,
        .constraints = constraints,
        .events = .{
            .frame_word_emit = ordered[0],
            .payload_word_consume = ordered[1],
        },
    };
}

fn validateInputs(
    arena: *const ir.Arena,
    values: []const types.ValueId,
    names: []const []const u8,
    offset: usize,
    selector_indices: []const usize,
) error{InvalidTranscriptWordDefinition}!void {
    if (values.len != names.len) return error.InvalidTranscriptWordDefinition;
    for (values, names, 0..) |value, name, local_index| {
        if (types.idIndex(value) != offset + local_index)
            return error.InvalidTranscriptWordDefinition;
        const node = arena.node(value) orelse
            return error.InvalidTranscriptWordDefinition;
        const expected_type: types.Type = if (contains(selector_indices, local_index))
            .selector
        else
            .felt;
        if (!std.meta.eql(node.key.ty, expected_type))
            return error.InvalidTranscriptWordDefinition;
        const name_id = switch (node.key.op) {
            .input => |input_name| input_name,
            else => return error.InvalidTranscriptWordDefinition,
        };
        const actual_name = arena.name(name_id) orelse
            return error.InvalidTranscriptWordDefinition;
        if (!std.mem.eql(u8, actual_name, name))
            return error.InvalidTranscriptWordDefinition;
    }
}

fn validateEvent(
    definition: *const Definition,
    effect_id: types.EffectId,
    index: usize,
    domain: relation.Domain,
    role: relation.Role,
    weight: types.ValueId,
    tuple: []const types.ValueId,
) error{InvalidTranscriptWordDefinition}!void {
    if (types.idIndex(effect_id) != index)
        return error.InvalidTranscriptWordDefinition;
    const item = definition.arena.effect(effect_id) orelse
        return error.InvalidTranscriptWordDefinition;
    const binding = item.binding orelse
        return error.InvalidTranscriptWordDefinition;
    const schema = relation.get(domain);
    const values = definition.arena.effectValues(effect_id) orelse
        return error.InvalidTranscriptWordDefinition;
    if (item.kind != .component_call or item.liveness != weight or
        item.access_ordinal != null or binding.schema != schema.id or
        binding.schema_version != schema.version or binding.role != role or
        !std.mem.eql(types.ValueId, values, tuple))
    {
        return error.InvalidTranscriptWordDefinition;
    }
}

fn contains(values: []const usize, target: usize) bool {
    for (values) |value| if (value == target) return true;
    return false;
}

fn sourceFile(comptime path: []const u8, comptime sha256: []const u8) SourceFile {
    return .{
        .path = path,
        .sha256 = hexDigest(sha256, "invalid pinned transcript-word source digest"),
    };
}

fn hashBytes(hash: anytype, value: []const u8) void {
    hashInt(hash, u32, value.len);
    hash.update(value);
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
    if (PHYSICAL_MAIN_COLUMN_COUNT != 2 or PREPROCESSED_COLUMN_COUNT != 15 or
        PARAMETER_COUNT != 2 or LOGICAL_INPUT_COUNT != 19 or
        DIRECT_CONSTRAINT_COUNT != 3 or FRAMEWORK_CONSTRAINT_COUNT != 4 or
        RELATION_EVENT_COUNT != 2 or LOOKUP_BATCH_SIZE != 2 or
        INTERACTION_BATCH_COUNT != 1 or INTERACTION_COLUMN_COUNT != 4 or
        FRAME_WORD_RELATION_ARITY != 4 or PAYLOAD_WORD_RELATION_ARITY != 9 or
        STATEMENT_WORD_COUNT != 412)
    {
        @compileError("universal transcript-word geometry drifted");
    }
}
