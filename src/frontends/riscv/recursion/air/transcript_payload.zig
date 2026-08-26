//! Exact typed logical AIR for Stark-V universal transcript-payload row 5.
//!
//! Verifier-owned preprocessing assigns every payload word a semantic source
//! class and coordinate. Protocol and PCS words are fixed directly; dynamic
//! statement/proof words are exported with exact multiplicity so every later
//! verifier gadget consumes the same value that entered Fiat-Shamir.

const std = @import("std");
const digest = @import("../../air/lang/digest.zig");
const ir = @import("../../air/lang/ir.zig");
const relation = @import("../../air/lang/relation.zig");
const source = @import("../../air/lang/source.zig");
const types = @import("../../air/lang/types.zig");
const validate_mod = @import("../../air/lang/validate.zig");
const relation_effect = @import("relation_effect.zig");

pub const STABLE_NAME = "recursion.transcript_payload.v1";
pub const DIGEST_WORD_COUNT: usize = 8;
pub const PROTOCOL_BINDING_WORD_COUNT: usize = 2 * DIGEST_WORD_COUNT;
pub const QM31_WORD_COUNT: usize = 4;
pub const PCS_PARAMETER_WORD_COUNT: usize = 16;
pub const STATEMENT_WORD_COUNT: usize = 412;
pub const MIN_LOG_SIZE: u32 = 4;
pub const MAX_LOG_SIZE: u32 = 30;

pub const PHYSICAL_MAIN_COLUMN_COUNT: usize = 2;
pub const PREPROCESSED_COLUMN_COUNT: usize = 17;
pub const PARAMETER_COUNT: usize = 2;
pub const LOGICAL_INPUT_COUNT: usize =
    PHYSICAL_MAIN_COLUMN_COUNT + PREPROCESSED_COLUMN_COUNT + PARAMETER_COUNT;
pub const DIRECT_CONSTRAINT_COUNT: usize = 3;
pub const RELATION_EVENT_COUNT: usize = 2;
pub const LOOKUP_BATCH_SIZE: u8 = 2;
pub const INTERACTION_BATCH_COUNT: usize = 1;
pub const INTERACTION_COLUMN_COUNT: usize = 4;
pub const FRAMEWORK_CONSTRAINT_COUNT: usize =
    DIRECT_CONSTRAINT_COUNT + INTERACTION_BATCH_COUNT;
pub const PAYLOAD_WORD_RELATION_ARITY: usize = 9;
pub const INPUT_WORD_RELATION_ARITY: usize = 5;
pub const REFERENCE_MAXIMUM_CONSTRAINT_DEGREE: u32 = 3;
// Stark-V treats preprocessing and proof-kind parameters as constants. The
// conservative logical analyzer assigns every typed input degree one.
pub const MAXIMUM_CONSTRAINT_DEGREE: u32 = 4;

pub const STARK_V_REVISION: [40]u8 =
    "59172a201bd01f2f4b699bc2f7d4442d8ee81597".*;
pub const SOURCE_FILES = [_]SourceFile{
    sourceFile(
        "crates/recursion/src/transcript_payload_air.rs",
        "d2e05e13e8985f1ad781854c1a96a7321f8447951429a6720dc7852841a1bb5d",
    ),
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
    "stwo-zig/typed-air/recursion-transcript-payload-source/v1\x00";
pub const SOURCE_AUTHORITY_DIGEST_HEX =
    "46330a155adfd762c8be0f7a08fc357239f2ef12a69fe0dae4b0d1f4b795789e";
pub const SOURCE_AUTHORITY_DIGEST = hexDigest(
    SOURCE_AUTHORITY_DIGEST_HEX,
    "invalid transcript-payload source-authority digest",
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
    payload_word_arity: u8,
    input_word_arity: u8,
    input_kind_count: u8,
    digest_words: u8,
    qm31_words: u8,
    pcs_parameter_words: u8,
    statement_words: u16,

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
            .payload_word_arity = PAYLOAD_WORD_RELATION_ARITY,
            .input_word_arity = INPUT_WORD_RELATION_ARITY,
            .input_kind_count = INPUT_KIND_COUNT,
            .digest_words = DIGEST_WORD_COUNT,
            .qm31_words = QM31_WORD_COUNT,
            .pcs_parameter_words = PCS_PARAMETER_WORD_COUNT,
            .statement_words = STATEMENT_WORD_COUNT,
        };
    }

    pub fn validate(self: SourceAuthority) error{AuthorityMismatch}!void {
        if (!std.meta.eql(self, pinned())) return error.AuthorityMismatch;
        const payload = relation.requireExactUniversalSchema(
            .recursion_transcript_payload_word,
        ) catch return error.AuthorityMismatch;
        const input = relation.requireExactUniversalSchema(
            .recursion_verifier_input_word,
        ) catch return error.AuthorityMismatch;
        if (payload.fields.len != self.payload_word_arity or
            !payload.allowed_roles.allows(.emit) or
            input.fields.len != self.input_word_arity or
            !input.allowed_roles.allows(.emit))
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
            self.payload_word_arity,
            self.input_word_arity,
            self.input_kind_count,
            self.digest_words,
            self.qm31_words,
            self.pcs_parameter_words,
        }) |value| hashInt(&hash, u8, value);
        hashInt(&hash, u16, self.statement_words);
        hashInt(&hash, u32, @intFromEnum(VerifierInputKind.vm_air_claimed_sum));
        return hash.finalResult();
    }
};

pub const SEMANTIC_DIGEST_HEX =
    "9f44f023f3112c2a194d5c476909df57d5aabf61210b119186f1cf04324375f0";
pub const SEMANTIC_DIGEST = hexDigest(
    SEMANTIC_DIGEST_HEX,
    "invalid recursion transcript-payload semantic digest",
);
pub const STATIC_PROFILE_DIGEST_HEX =
    "bdb80afc971fe5c1d8483330df0d58453d9f1b22139ed7eed0fd07f488be762a";

pub const VerifierInputKind = enum(u32) {
    protocol = 1,
    statement = 2,
    pcs_parameters = 3,
    commitment = 4,
    claimed_sum = 5,
    sampled_value = 6,
    fri_commitment = 7,
    last_layer_coefficient = 8,
    interaction_pow_nonce = 9,
    pcs_pow_nonce = 10,
    vm_public_claim_digest = 11,
    vm_air_claimed_sum = 12,
};
pub const INPUT_KIND_COUNT: u8 = std.enums.values(VerifierInputKind).len;

pub const MAIN_COLUMN_NAMES = [PHYSICAL_MAIN_COLUMN_COUNT][]const u8{
    "recursion.transcript_payload.enabler",
    "recursion.transcript_payload.value",
};

pub const PREPROCESSED_COLUMN_NAMES = [PREPROCESSED_COLUMN_COUNT][]const u8{
    "recursion_transcript_payload_row_mask",
    "recursion_transcript_payload_segment_mask",
    "recursion_transcript_payload_binary_mask",
    "recursion_transcript_payload_verifier_id",
    "recursion_transcript_payload_sequence",
    "recursion_transcript_payload_tag",
    "recursion_transcript_payload_arg_0",
    "recursion_transcript_payload_arg_1",
    "recursion_transcript_payload_arg_2",
    "recursion_transcript_payload_arg_3",
    "recursion_transcript_payload_index",
    "recursion_transcript_payload_source_kind",
    "recursion_transcript_payload_item_index",
    "recursion_transcript_payload_limb_index",
    "recursion_transcript_payload_constant_mask",
    "recursion_transcript_payload_input_use_count",
    "recursion_transcript_payload_constant",
};

pub const PARAMETER_NAMES = [PARAMETER_COUNT][]const u8{
    "recursion.transcript_payload.param.segment_active",
    "recursion.transcript_payload.param.binary_active",
};

pub const CONSTRAINT_NAMES = [DIRECT_CONSTRAINT_COUNT][]const u8{
    "recursion.transcript_payload.enabler_row_mask",
    "recursion.transcript_payload.inactive_value_zero",
    "recursion.transcript_payload.constant_value",
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
    payload_index: types.ValueId,
    source_kind: types.ValueId,
    item_index: types.ValueId,
    limb_index: types.ValueId,
    constant_mask: types.ValueId,
    input_use_count: types.ValueId,
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
            self.payload_index,
            self.source_kind,
            self.item_index,
            self.limb_index,
            self.constant_mask,
            self.input_use_count,
            self.constant_value,
        };
    }
};

pub const Parameters = struct {
    segment_active: types.ValueId,
    binary_active: types.ValueId,

    pub fn physical(self: Parameters) [PARAMETER_COUNT]types.ValueId {
        return .{
            self.segment_active,
            self.binary_active,
        };
    }
};

pub const Events = struct {
    payload_word_emit: types.EffectId,
    shared_input_emit: types.EffectId,

    pub fn ordered(self: Events) [RELATION_EVENT_COUNT]types.EffectId {
        return .{
            self.payload_word_emit,
            self.shared_input_emit,
        };
    }
};

pub const ValidationError = validate_mod.Error || relation_effect.Error || error{
    InvalidTranscriptPayloadDefinition,
};

pub const Definition = struct {
    arena: ir.Arena,
    main: MainColumns,
    preprocessed: PreprocessedColumns,
    parameters: Parameters,
    active: types.ValueId,
    shared_input: types.ValueId,
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
            return error.InvalidTranscriptPayloadDefinition;
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
            &.{ 0, 1, 2, 14 },
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
                return error.InvalidTranscriptPayloadDefinition;
            const actual_name = self.arena.name(item.name) orelse
                return error.InvalidTranscriptPayloadDefinition;
            if (types.idIndex(constraint_id) != index or item.root != root or
                item.gate != null or item.category != .semantic or
                !std.mem.eql(u8, actual_name, expected_name))
            {
                return error.InvalidTranscriptPayloadDefinition;
            }
        }
        const payload_tuple = .{
            self.preprocessed.verifier_id,
            self.preprocessed.sequence,
            self.preprocessed.tag,
        } ++ self.preprocessed.args ++ .{
            self.preprocessed.payload_index,
            self.main.value,
        };
        const input_tuple = [INPUT_WORD_RELATION_ARITY]types.ValueId{
            self.preprocessed.verifier_id,
            self.preprocessed.source_kind,
            self.preprocessed.item_index,
            self.preprocessed.limb_index,
            self.main.value,
        };
        try validateEvent(
            self,
            self.events.payload_word_emit,
            0,
            .recursion_transcript_payload_word,
            self.active,
            &payload_tuple,
        );
        try validateEvent(
            self,
            self.events.shared_input_emit,
            1,
            .recursion_verifier_input_word,
            self.shared_input,
            &input_tuple,
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
    var fixed: [PREPROCESSED_COLUMN_COUNT]types.ValueId = undefined;
    for (&fixed, PREPROCESSED_COLUMN_NAMES, 0..) |*value, name, index| {
        value.* = try arena.input(
            name,
            switch (index) {
                0, 1, 2, 14 => .selector,
                else => .felt,
            },
            span,
        );
    }
    const preprocessed = PreprocessedColumns{
        .row_mask = fixed[0],
        .segment_mask = fixed[1],
        .binary_mask = fixed[2],
        .verifier_id = fixed[3],
        .sequence = fixed[4],
        .tag = fixed[5],
        .args = fixed[6..10].*,
        .payload_index = fixed[10],
        .source_kind = fixed[11],
        .item_index = fixed[12],
        .limb_index = fixed[13],
        .constant_mask = fixed[14],
        .input_use_count = fixed[15],
        .constant_value = fixed[16],
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
    const shared_input = try arena.mul(active, preprocessed.input_use_count, span);
    const roots = [DIRECT_CONSTRAINT_COUNT]types.ValueId{
        try arena.sub(main.enabler, preprocessed.row_mask, span),
        try arena.mul(
            try arena.sub(preprocessed.row_mask, active, span),
            main.value,
            span,
        ),
        try arena.mul(
            try arena.mul(active, preprocessed.constant_mask, span),
            try arena.sub(main.value, preprocessed.constant_value, span),
            span,
        ),
    };
    var constraints: [DIRECT_CONSTRAINT_COUNT]types.ConstraintId = undefined;
    for (&constraints, roots, CONSTRAINT_NAMES) |*constraint, root, name| {
        constraint.* = try arena.assertZero(name, root, null, .semantic, span);
    }
    const payload_tuple = .{
        preprocessed.verifier_id,
        preprocessed.sequence,
        preprocessed.tag,
    } ++ preprocessed.args ++ .{ preprocessed.payload_index, main.value };
    const input_tuple = [INPUT_WORD_RELATION_ARITY]types.ValueId{
        preprocessed.verifier_id,
        preprocessed.source_kind,
        preprocessed.item_index,
        preprocessed.limb_index,
        main.value,
    };
    const ordered = try relation_effect.appendGroup(RELATION_EVENT_COUNT, &arena, .{
        .{
            .domain = .recursion_transcript_payload_word,
            .role = .emit,
            .values = &payload_tuple,
            .weight = active,
        },
        .{
            .domain = .recursion_verifier_input_word,
            .role = .emit,
            .values = &input_tuple,
            .weight = shared_input,
        },
    }, span);
    return .{
        .arena = arena,
        .main = main,
        .preprocessed = preprocessed,
        .parameters = parameters,
        .active = active,
        .shared_input = shared_input,
        .roots = roots,
        .constraints = constraints,
        .events = .{
            .payload_word_emit = ordered[0],
            .shared_input_emit = ordered[1],
        },
    };
}

fn validateInputs(
    arena: *const ir.Arena,
    values: []const types.ValueId,
    names: []const []const u8,
    offset: usize,
    selector_indices: []const usize,
) error{InvalidTranscriptPayloadDefinition}!void {
    if (values.len != names.len)
        return error.InvalidTranscriptPayloadDefinition;
    for (values, names, 0..) |value, name, local_index| {
        if (types.idIndex(value) != offset + local_index)
            return error.InvalidTranscriptPayloadDefinition;
        const node = arena.node(value) orelse
            return error.InvalidTranscriptPayloadDefinition;
        const expected_type: types.Type = if (contains(selector_indices, local_index))
            .selector
        else
            .felt;
        if (!std.meta.eql(node.key.ty, expected_type))
            return error.InvalidTranscriptPayloadDefinition;
        const name_id = switch (node.key.op) {
            .input => |input_name| input_name,
            else => return error.InvalidTranscriptPayloadDefinition,
        };
        const actual_name = arena.name(name_id) orelse
            return error.InvalidTranscriptPayloadDefinition;
        if (!std.mem.eql(u8, actual_name, name))
            return error.InvalidTranscriptPayloadDefinition;
    }
}

fn validateEvent(
    definition: *const Definition,
    effect_id: types.EffectId,
    index: usize,
    domain: relation.Domain,
    weight: types.ValueId,
    tuple: []const types.ValueId,
) error{InvalidTranscriptPayloadDefinition}!void {
    if (types.idIndex(effect_id) != index)
        return error.InvalidTranscriptPayloadDefinition;
    const item = definition.arena.effect(effect_id) orelse
        return error.InvalidTranscriptPayloadDefinition;
    const binding = item.binding orelse
        return error.InvalidTranscriptPayloadDefinition;
    const schema = relation.get(domain);
    const values = definition.arena.effectValues(effect_id) orelse
        return error.InvalidTranscriptPayloadDefinition;
    if (item.kind != .component_call or item.liveness != weight or
        item.access_ordinal != null or binding.schema != schema.id or
        binding.schema_version != schema.version or binding.role != .emit or
        !std.mem.eql(types.ValueId, values, tuple))
    {
        return error.InvalidTranscriptPayloadDefinition;
    }
}

fn contains(values: []const usize, target: usize) bool {
    for (values) |value| if (value == target) return true;
    return false;
}

fn sourceFile(comptime path: []const u8, comptime sha256: []const u8) SourceFile {
    return .{
        .path = path,
        .sha256 = hexDigest(sha256, "invalid pinned transcript-payload source digest"),
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
    if (PHYSICAL_MAIN_COLUMN_COUNT != 2 or PREPROCESSED_COLUMN_COUNT != 17 or
        PARAMETER_COUNT != 2 or LOGICAL_INPUT_COUNT != 21 or
        DIRECT_CONSTRAINT_COUNT != 3 or FRAMEWORK_CONSTRAINT_COUNT != 4 or
        RELATION_EVENT_COUNT != 2 or LOOKUP_BATCH_SIZE != 2 or
        INTERACTION_BATCH_COUNT != 1 or INTERACTION_COLUMN_COUNT != 4 or
        PAYLOAD_WORD_RELATION_ARITY != 9 or INPUT_WORD_RELATION_ARITY != 5 or
        INPUT_KIND_COUNT != 12 or STATEMENT_WORD_COUNT != 412)
    {
        @compileError("universal transcript-payload geometry drifted");
    }
}
