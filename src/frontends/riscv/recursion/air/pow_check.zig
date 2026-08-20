//! Exact typed logical AIR for Stark-V universal PoW predicate row 6.
//!
//! The source component commits an enabler, five relation coordinates, the
//! canonical 31-bit decomposition of one M31 word, and a 31-bit prefix mask.
//! Its 125 authored `constrain` roots are ungated and vanish on an all-zero
//! padding row; the macro contributes the enabler boolean as root zero.  The
//! singleton LogUp recurrence is framework-owned and is therefore counted
//! separately rather than duplicated in this logical program.

const std = @import("std");
const digest = @import("../../air/lang/digest.zig");
const ir = @import("../../air/lang/ir.zig");
const relation = @import("../../air/lang/relation.zig");
const source = @import("../../air/lang/source.zig");
const types = @import("../../air/lang/types.zig");
const validate_mod = @import("../../air/lang/validate.zig");
const relation_effect = @import("relation_effect.zig");

pub const STABLE_NAME = "recursion.pow_check.v1";
pub const M31_BIT_COUNT: usize = 31;
pub const RELATION_COORDINATE_COUNT: usize = 5;
pub const AUXILIARY_COLUMN_COUNT: usize = 2 * M31_BIT_COUNT;
pub const DECLARED_COMMITTED_COLUMN_COUNT: usize =
    RELATION_COORDINATE_COUNT + AUXILIARY_COLUMN_COUNT;
pub const PHYSICAL_MAIN_COLUMN_COUNT: usize =
    1 + DECLARED_COMMITTED_COLUMN_COUNT;
pub const PREPROCESSED_COLUMN_COUNT: usize = 0;
pub const PARAMETER_COUNT: usize = 0;
pub const LOGICAL_INPUT_COUNT: usize = PHYSICAL_MAIN_COLUMN_COUNT;
pub const AUTHORED_CONSTRAINT_COUNT: usize =
    3 * M31_BIT_COUNT + (M31_BIT_COUNT - 1) + 2;
pub const DIRECT_CONSTRAINT_COUNT: usize = 1 + AUTHORED_CONSTRAINT_COUNT;
pub const FRAMEWORK_CONSTRAINT_COUNT: usize = DIRECT_CONSTRAINT_COUNT + 1;
pub const RELATION_EVENT_COUNT: usize = 1;
pub const LOOKUP_BATCH_SIZE: u8 = 1;
pub const INTERACTION_BATCH_COUNT: usize = 1;
pub const INTERACTION_COLUMN_COUNT: usize = 4;
pub const SOURCE_DECLARED_MAXIMUM_DEGREE: u32 = 3;
pub const REFERENCE_MAXIMUM_CONSTRAINT_DEGREE: u32 = 2;
pub const MAXIMUM_CONSTRAINT_DEGREE: u32 = 2;

pub const STARK_V_REVISION: [40]u8 =
    "59172a201bd01f2f4b699bc2f7d4442d8ee81597".*;
pub const STARK_V_POW_PATH = "crates/recursion/src/pow.rs";
pub const STARK_V_POW_SHA256 = hexDigest(
    "cbb0c12614eaae6f03686393fe168a9f3433c2fdb9783ac89858efc3dda942e4",
    "invalid pinned Stark-V pow.rs digest",
);
pub const STARK_V_AIR_FNS_PATH = "crates/stwo-macros/src/air_fns.rs";
pub const STARK_V_AIR_FNS_SHA256 = hexDigest(
    "cd3922d517bb96dcb660ed25e1bd58811109ab21721936f8e56b0a74fe582e79",
    "invalid pinned Stark-V air_fns.rs digest",
);
pub const STARK_V_TRANSCRIPT_PATH = "crates/recursion/src/transcript.rs";
pub const STARK_V_TRANSCRIPT_SHA256 = hexDigest(
    "86978ce7a7679d3050e0e72e51733a68036e0f1d229b3dc0927be8fb1f54b74e",
    "invalid pinned Stark-V transcript.rs digest",
);
pub const STARK_V_TRANSCRIPT_LAYOUT_PATH =
    "crates/recursion/src/transcript_layout.rs";
pub const STARK_V_TRANSCRIPT_LAYOUT_SHA256 = hexDigest(
    "b5362d81ea1b487d964b59660bfac2d35ad290e5ce51b2cb9d8bc064b45e911d",
    "invalid pinned Stark-V transcript_layout.rs digest",
);
pub const STARK_V_TRANSCRIPT_BINDING_PATH =
    "crates/recursion/src/transcript_binding_air.rs";
pub const STARK_V_TRANSCRIPT_BINDING_SHA256 = hexDigest(
    "78fdd64602e44b593915a7d4bf60059682e12812eb1575cf4941c083526e714e",
    "invalid pinned Stark-V transcript_binding_air.rs digest",
);
pub const STARK_V_KERNEL_PATH = "crates/recursion/src/kernel.rs";
pub const STARK_V_KERNEL_SHA256 = hexDigest(
    "5ecc2ec4597b21dd14a2be81dcd8da0324f6b57eed27823cf9986de5d5212e77",
    "invalid pinned Stark-V kernel.rs digest",
);

pub const SOURCE_AUTHORITY_FORMAT_VERSION: u16 = 1;
pub const SOURCE_AUTHORITY_DOMAIN =
    "stwo-zig/typed-air/recursion-pow-source/v1\x00";
pub const SOURCE_AUTHORITY_DIGEST_HEX =
    "c3397fa310a7fbcc8f6f54e09278c9611e49419e4056e95b6f52ffa480ca7c85";
pub const SOURCE_AUTHORITY_DIGEST = hexDigest(
    SOURCE_AUTHORITY_DIGEST_HEX,
    "invalid recursion PoW source-authority digest",
);

/// One seal covers both rows 6 and 7 because they are two halves of the same
/// pinned `pow.rs` relation contract.
pub const SourceAuthority = struct {
    format_version: u16,
    revision: [40]u8,
    pow_sha256: digest.Digest,
    air_fns_sha256: digest.Digest,
    transcript_sha256: digest.Digest,
    transcript_layout_sha256: digest.Digest,
    transcript_binding_sha256: digest.Digest,
    kernel_sha256: digest.Digest,
    check_main_columns: u8,
    check_direct_constraints: u8,
    check_framework_constraints: u8,
    check_relation_arity: u8,
    check_interaction_columns: u8,
    frame_main_columns: u8,
    frame_direct_constraints: u8,
    frame_framework_constraints: u8,
    frame_relation_arity: u8,
    frame_check_arity: u8,
    frame_interaction_columns: u8,

    pub fn pinned() SourceAuthority {
        return .{
            .format_version = SOURCE_AUTHORITY_FORMAT_VERSION,
            .revision = STARK_V_REVISION,
            .pow_sha256 = STARK_V_POW_SHA256,
            .air_fns_sha256 = STARK_V_AIR_FNS_SHA256,
            .transcript_sha256 = STARK_V_TRANSCRIPT_SHA256,
            .transcript_layout_sha256 = STARK_V_TRANSCRIPT_LAYOUT_SHA256,
            .transcript_binding_sha256 = STARK_V_TRANSCRIPT_BINDING_SHA256,
            .kernel_sha256 = STARK_V_KERNEL_SHA256,
            .check_main_columns = PHYSICAL_MAIN_COLUMN_COUNT,
            .check_direct_constraints = DIRECT_CONSTRAINT_COUNT,
            .check_framework_constraints = FRAMEWORK_CONSTRAINT_COUNT,
            .check_relation_arity = RELATION_COORDINATE_COUNT,
            .check_interaction_columns = INTERACTION_COLUMN_COUNT,
            .frame_main_columns = 15,
            .frame_direct_constraints = 2,
            .frame_framework_constraints = 3,
            .frame_relation_arity = 14,
            .frame_check_arity = RELATION_COORDINATE_COUNT,
            .frame_interaction_columns = 4,
        };
    }

    pub fn validate(self: SourceAuthority) error{AuthorityMismatch}!void {
        if (!std.meta.eql(self, pinned())) return error.AuthorityMismatch;
        const check_schema = relation.requireExactUniversalSchema(
            .recursion_pow_check,
        ) catch return error.AuthorityMismatch;
        const frame_schema = relation.requireExactUniversalSchema(
            .recursion_transcript_pow_frame,
        ) catch return error.AuthorityMismatch;
        if (check_schema.fields.len != self.check_relation_arity or
            !check_schema.allowed_roles.allows(.consume) or
            !check_schema.allowed_roles.allows(.emit) or
            frame_schema.fields.len != self.frame_relation_arity or
            !frame_schema.allowed_roles.allows(.consume))
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
        hashSource(&hash, STARK_V_POW_PATH, self.pow_sha256);
        hashSource(&hash, STARK_V_AIR_FNS_PATH, self.air_fns_sha256);
        hashSource(&hash, STARK_V_TRANSCRIPT_PATH, self.transcript_sha256);
        hashSource(
            &hash,
            STARK_V_TRANSCRIPT_LAYOUT_PATH,
            self.transcript_layout_sha256,
        );
        hashSource(
            &hash,
            STARK_V_TRANSCRIPT_BINDING_PATH,
            self.transcript_binding_sha256,
        );
        hashSource(&hash, STARK_V_KERNEL_PATH, self.kernel_sha256);
        hashInt(&hash, u8, self.check_main_columns);
        hashInt(&hash, u8, self.check_direct_constraints);
        hashInt(&hash, u8, self.check_framework_constraints);
        hashInt(&hash, u8, self.check_relation_arity);
        hashInt(&hash, u8, self.check_interaction_columns);
        hashInt(&hash, u8, self.frame_main_columns);
        hashInt(&hash, u8, self.frame_direct_constraints);
        hashInt(&hash, u8, self.frame_framework_constraints);
        hashInt(&hash, u8, self.frame_relation_arity);
        hashInt(&hash, u8, self.frame_check_arity);
        hashInt(&hash, u8, self.frame_interaction_columns);
        return hash.finalResult();
    }
};

pub const PowKind = enum(u32) {
    interaction = 1,
    pcs = 2,

    pub fn felt(self: PowKind) u32 {
        return @intFromEnum(self);
    }
};

pub const SEMANTIC_DIGEST_HEX =
    "82daca02fda06de461c5cb5538b15771cd93347bf0379213ed53a60515111385";
pub const SEMANTIC_DIGEST = hexDigest(
    SEMANTIC_DIGEST_HEX,
    "invalid recursion PoW-check semantic digest",
);

pub const MAIN_COLUMN_NAMES = makeMainNames();

pub const MainColumns = struct {
    enabler: types.ValueId,
    verifier_id: types.ValueId,
    pow_kind: types.ValueId,
    call_id: types.ValueId,
    bits: types.ValueId,
    word: types.ValueId,
    word_bits: [M31_BIT_COUNT]types.ValueId,
    active: [M31_BIT_COUNT]types.ValueId,

    pub fn relationTuple(self: MainColumns) [RELATION_COORDINATE_COUNT]types.ValueId {
        return .{
            self.verifier_id,
            self.pow_kind,
            self.call_id,
            self.bits,
            self.word,
        };
    }

    pub fn physical(self: MainColumns) [PHYSICAL_MAIN_COLUMN_COUNT]types.ValueId {
        return .{self.enabler} ++ self.relationTuple() ++
            self.word_bits ++ self.active;
    }
};

pub const ValidationError = validate_mod.Error || relation_effect.Error || error{
    InvalidPowCheckDefinition,
};

pub const Definition = struct {
    arena: ir.Arena,
    main: MainColumns,
    roots: [DIRECT_CONSTRAINT_COUNT]types.ValueId,
    constraints: [DIRECT_CONSTRAINT_COUNT]types.ConstraintId,
    events: [RELATION_EVENT_COUNT]types.EffectId,

    pub fn deinit(self: *Definition) void {
        self.arena.deinit();
        self.* = undefined;
    }

    pub fn validate(self: *const Definition) ValidationError!void {
        try validate_mod.validate(&self.arena);
        const actual = try digest.computeIdentity(&self.arena);
        if (actual.format_version != digest.typed_effect_format_version or
            !std.mem.eql(u8, &actual.bytes, &SEMANTIC_DIGEST) or
            self.arena.constraintsView().len != DIRECT_CONSTRAINT_COUNT or
            self.arena.effectsView().len != RELATION_EVENT_COUNT or
            self.arena.hints.items.len != 0 or
            self.arena.functions.items.len != 0 or
            self.arena.calls.items.len != 0 or
            self.arena.range_refinements.items.len != 0 or
            self.arena.fixed_table_requests.items.len != 0)
        {
            return error.InvalidPowCheckDefinition;
        }
        try validateInputs(&self.arena, &self.main.physical());
        var name_buffer: [96]u8 = undefined;
        for (self.constraints, self.roots, 0..) |constraint_id, root, index| {
            const item = self.arena.constraint(constraint_id) orelse
                return error.InvalidPowCheckDefinition;
            const actual_name = self.arena.name(item.name) orelse
                return error.InvalidPowCheckDefinition;
            const expected_name = constraintName(index, &name_buffer) catch
                return error.InvalidPowCheckDefinition;
            if (types.idIndex(constraint_id) != index or item.root != root or
                item.gate != null or item.category != .semantic or
                !std.mem.eql(u8, actual_name, expected_name))
            {
                return error.InvalidPowCheckDefinition;
            }
        }
        const event_id = self.events[0];
        const item = self.arena.effect(event_id) orelse
            return error.InvalidPowCheckDefinition;
        const binding = item.binding orelse
            return error.InvalidPowCheckDefinition;
        const schema = relation.get(.recursion_pow_check);
        const values = self.arena.effectValues(event_id) orelse
            return error.InvalidPowCheckDefinition;
        const tuple = self.main.relationTuple();
        if (types.idIndex(event_id) != 0 or item.kind != .component_call or
            item.liveness != self.main.enabler or item.access_ordinal != null or
            binding.schema != schema.id or binding.schema_version != schema.version or
            binding.role != .consume or
            !std.mem.eql(types.ValueId, values, &tuple))
        {
            return error.InvalidPowCheckDefinition;
        }
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
    var input_values: [PHYSICAL_MAIN_COLUMN_COUNT]types.ValueId = undefined;
    for (&input_values, MAIN_COLUMN_NAMES, 0..) |*value, name, index| {
        const ty: types.Type = if (index == 0)
            .selector
        else if (index >= 1 + RELATION_COORDINATE_COUNT)
            .bit
        else
            .felt;
        value.* = try arena.input(name, ty, span);
    }
    const main = MainColumns{
        .enabler = input_values[0],
        .verifier_id = input_values[1],
        .pow_kind = input_values[2],
        .call_id = input_values[3],
        .bits = input_values[4],
        .word = input_values[5],
        .word_bits = input_values[6..][0..M31_BIT_COUNT].*,
        .active = input_values[6 + M31_BIT_COUNT ..][0..M31_BIT_COUNT].*,
    };
    const zero = try arena.constantField(0, span);
    const one = try arena.constantField(1, span);
    var roots: [DIRECT_CONSTRAINT_COUNT]types.ValueId = undefined;
    var at: usize = 0;
    roots[at] = try booleanRoot(&arena, main.enabler, one, span);
    at += 1;
    for (main.word_bits, main.active) |word_bit, active| {
        roots[at] = try booleanRoot(&arena, word_bit, one, span);
        roots[at + 1] = try booleanRoot(&arena, active, one, span);
        roots[at + 2] = try arena.mul(active, word_bit, span);
        at += 3;
    }
    for (0..M31_BIT_COUNT - 1) |bit| {
        roots[at] = try arena.mul(
            try arena.sub(one, main.active[bit], span),
            main.active[bit + 1],
            span,
        );
        at += 1;
    }
    var reconstructed = zero;
    var active_sum = zero;
    for (main.word_bits, main.active, 0..) |word_bit, active, bit| {
        reconstructed = try arena.add(
            reconstructed,
            try arena.mul(
                try arena.constantField(@as(u32, 1) << @intCast(bit), span),
                word_bit,
                span,
            ),
            span,
        );
        active_sum = try arena.add(active_sum, active, span);
    }
    roots[at] = try arena.sub(main.word, reconstructed, span);
    at += 1;
    roots[at] = try arena.sub(main.bits, active_sum, span);
    at += 1;
    std.debug.assert(at == roots.len);

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
    const tuple = main.relationTuple();
    const events = try relation_effect.appendGroup(RELATION_EVENT_COUNT, &arena, .{
        .{
            .domain = .recursion_pow_check,
            .role = .consume,
            .values = &tuple,
            .weight = main.enabler,
        },
    }, span);
    return .{
        .arena = arena,
        .main = main,
        .roots = roots,
        .constraints = constraints,
        .events = events,
    };
}

fn validateInputs(
    arena: *const ir.Arena,
    values: []const types.ValueId,
) error{InvalidPowCheckDefinition}!void {
    if (values.len != MAIN_COLUMN_NAMES.len)
        return error.InvalidPowCheckDefinition;
    for (values, MAIN_COLUMN_NAMES, 0..) |value, expected_name, index| {
        if (types.idIndex(value) != index) return error.InvalidPowCheckDefinition;
        const node = arena.node(value) orelse return error.InvalidPowCheckDefinition;
        const expected_type: types.Type = if (index == 0)
            .selector
        else if (index >= 1 + RELATION_COORDINATE_COUNT)
            .bit
        else
            .felt;
        if (!std.meta.eql(node.key.ty, expected_type))
            return error.InvalidPowCheckDefinition;
        const name_id = switch (node.key.op) {
            .input => |name| name,
            else => return error.InvalidPowCheckDefinition,
        };
        const actual_name = arena.name(name_id) orelse
            return error.InvalidPowCheckDefinition;
        if (!std.mem.eql(u8, actual_name, expected_name))
            return error.InvalidPowCheckDefinition;
    }
}

fn constraintName(
    index: usize,
    buffer: []u8,
) std.fmt.BufPrintError![]const u8 {
    if (index == 0) return "recursion.pow_check.enabler_boolean";
    const authored = index - 1;
    if (authored < 3 * M31_BIT_COUNT) {
        const bit = authored / 3;
        return switch (authored % 3) {
            0 => std.fmt.bufPrint(buffer, "recursion.pow_check.word_bit_{d}_boolean", .{bit}),
            1 => std.fmt.bufPrint(buffer, "recursion.pow_check.active_{d}_boolean", .{bit}),
            2 => std.fmt.bufPrint(buffer, "recursion.pow_check.active_{d}_zero_bit", .{bit}),
            else => unreachable,
        };
    }
    const after_bits = authored - 3 * M31_BIT_COUNT;
    if (after_bits < M31_BIT_COUNT - 1)
        return std.fmt.bufPrint(buffer, "recursion.pow_check.active_prefix_{d}", .{after_bits});
    return if (after_bits == M31_BIT_COUNT - 1)
        "recursion.pow_check.word_reconstruction"
    else
        "recursion.pow_check.difficulty_sum";
}

fn booleanRoot(
    arena: *ir.Arena,
    value: types.ValueId,
    one: types.ValueId,
    span: source.SourceSpan,
) !types.ValueId {
    return arena.mul(value, try arena.sub(one, value, span), span);
}

fn makeMainNames() [PHYSICAL_MAIN_COLUMN_COUNT][]const u8 {
    var names: [PHYSICAL_MAIN_COLUMN_COUNT][]const u8 = undefined;
    names[0] = "recursion.pow_check.enabler";
    names[1] = "recursion.pow_check.verifier_id";
    names[2] = "recursion.pow_check.pow_kind";
    names[3] = "recursion.pow_check.call_id";
    names[4] = "recursion.pow_check.bits";
    names[5] = "recursion.pow_check.word";
    for (0..M31_BIT_COUNT) |bit| {
        names[6 + bit] = switch (bit) {
            0 => "recursion.pow_check.word_bit_0",
            1 => "recursion.pow_check.word_bit_1",
            2 => "recursion.pow_check.word_bit_2",
            3 => "recursion.pow_check.word_bit_3",
            4 => "recursion.pow_check.word_bit_4",
            5 => "recursion.pow_check.word_bit_5",
            6 => "recursion.pow_check.word_bit_6",
            7 => "recursion.pow_check.word_bit_7",
            8 => "recursion.pow_check.word_bit_8",
            9 => "recursion.pow_check.word_bit_9",
            10 => "recursion.pow_check.word_bit_10",
            11 => "recursion.pow_check.word_bit_11",
            12 => "recursion.pow_check.word_bit_12",
            13 => "recursion.pow_check.word_bit_13",
            14 => "recursion.pow_check.word_bit_14",
            15 => "recursion.pow_check.word_bit_15",
            16 => "recursion.pow_check.word_bit_16",
            17 => "recursion.pow_check.word_bit_17",
            18 => "recursion.pow_check.word_bit_18",
            19 => "recursion.pow_check.word_bit_19",
            20 => "recursion.pow_check.word_bit_20",
            21 => "recursion.pow_check.word_bit_21",
            22 => "recursion.pow_check.word_bit_22",
            23 => "recursion.pow_check.word_bit_23",
            24 => "recursion.pow_check.word_bit_24",
            25 => "recursion.pow_check.word_bit_25",
            26 => "recursion.pow_check.word_bit_26",
            27 => "recursion.pow_check.word_bit_27",
            28 => "recursion.pow_check.word_bit_28",
            29 => "recursion.pow_check.word_bit_29",
            30 => "recursion.pow_check.word_bit_30",
            else => unreachable,
        };
        names[6 + M31_BIT_COUNT + bit] = switch (bit) {
            0 => "recursion.pow_check.active_0",
            1 => "recursion.pow_check.active_1",
            2 => "recursion.pow_check.active_2",
            3 => "recursion.pow_check.active_3",
            4 => "recursion.pow_check.active_4",
            5 => "recursion.pow_check.active_5",
            6 => "recursion.pow_check.active_6",
            7 => "recursion.pow_check.active_7",
            8 => "recursion.pow_check.active_8",
            9 => "recursion.pow_check.active_9",
            10 => "recursion.pow_check.active_10",
            11 => "recursion.pow_check.active_11",
            12 => "recursion.pow_check.active_12",
            13 => "recursion.pow_check.active_13",
            14 => "recursion.pow_check.active_14",
            15 => "recursion.pow_check.active_15",
            16 => "recursion.pow_check.active_16",
            17 => "recursion.pow_check.active_17",
            18 => "recursion.pow_check.active_18",
            19 => "recursion.pow_check.active_19",
            20 => "recursion.pow_check.active_20",
            21 => "recursion.pow_check.active_21",
            22 => "recursion.pow_check.active_22",
            23 => "recursion.pow_check.active_23",
            24 => "recursion.pow_check.active_24",
            25 => "recursion.pow_check.active_25",
            26 => "recursion.pow_check.active_26",
            27 => "recursion.pow_check.active_27",
            28 => "recursion.pow_check.active_28",
            29 => "recursion.pow_check.active_29",
            30 => "recursion.pow_check.active_30",
            else => unreachable,
        };
    }
    return names;
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
    if (PHYSICAL_MAIN_COLUMN_COUNT != 68 or
        AUTHORED_CONSTRAINT_COUNT != 125 or
        DIRECT_CONSTRAINT_COUNT != 126 or
        FRAMEWORK_CONSTRAINT_COUNT != 127 or
        RELATION_EVENT_COUNT != 1 or
        INTERACTION_BATCH_COUNT != 1 or
        INTERACTION_COLUMN_COUNT != 4 or
        MAXIMUM_CONSTRAINT_DEGREE != 2)
    {
        @compileError("universal PoW-check geometry drifted");
    }
}
