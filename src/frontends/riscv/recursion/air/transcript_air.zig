//! Exact typed logical AIR for Stark-V universal transcript row 1.
//!
//! This component authenticates one atomic transcript sponge call. It does
//! not duplicate Poseidon2: the complete input/output tuple is a request to
//! the existing shared provider. Row 2 owns fixed call coordinates and rate
//! chunks, while this row alone owns within-frame state chaining.

const std = @import("std");
const digest = @import("../../air/lang/digest.zig");
const ir = @import("../../air/lang/ir.zig");
const relation = @import("../../air/lang/relation.zig");
const source = @import("../../air/lang/source.zig");
const types = @import("../../air/lang/types.zig");
const validate_mod = @import("../../air/lang/validate.zig");
const relation_effect = @import("relation_effect.zig");

pub const STABLE_NAME = "recursion.transcript_air.v1";
pub const RATE: usize = 8;
pub const WIDTH: usize = 16;
pub const CONTROL_ARITY: usize = 7;
pub const DATA_ARITY: usize = 11;
pub const STATE_ARITY: usize = 19;
pub const OUTPUT_ARITY: usize = 12;
pub const POSEIDON_IO_ARITY: usize = 32;

pub const PHYSICAL_MAIN_COLUMN_COUNT: usize = 1 + CONTROL_ARITY + WIDTH + RATE + WIDTH;
pub const PREPROCESSED_COLUMN_COUNT: usize = 0;
pub const PARAMETER_COUNT: usize = 0;
pub const LOGICAL_INPUT_COUNT: usize = PHYSICAL_MAIN_COLUMN_COUNT;
pub const DIRECT_CONSTRAINT_COUNT: usize = 8 + WIDTH;
pub const RELATION_EVENT_COUNT: usize = 6;
pub const LOOKUP_BATCH_SIZE: u8 = 2;
pub const INTERACTION_BATCH_COUNT: usize = 3;
pub const INTERACTION_COLUMN_COUNT: usize = 12;
pub const FRAMEWORK_CONSTRAINT_COUNT: usize =
    DIRECT_CONSTRAINT_COUNT + INTERACTION_BATCH_COUNT;
pub const SOURCE_DECLARED_MAXIMUM_DEGREE: u32 = 3;
pub const REFERENCE_MAXIMUM_CONSTRAINT_DEGREE: u32 = 3;
/// Highest degree among the typed direct roots. The reference protocol remains
/// cubic because the compiler-owned LogUp recurrence is degree three.
pub const MAXIMUM_CONSTRAINT_DEGREE: u32 = 2;

pub const STARK_V_REVISION: [40]u8 =
    "59172a201bd01f2f4b699bc2f7d4442d8ee81597".*;
pub const SOURCE_FILES = [_]SourceFile{
    sourceFile(
        "crates/recursion/src/transcript_air.rs",
        "986010c06871f9c25b09d38024649a61a397cdeead05c629de904d18fb5ce6d8",
    ),
    sourceFile(
        "crates/recursion/src/transcript.rs",
        "86978ce7a7679d3050e0e72e51733a68036e0f1d229b3dc0927be8fb1f54b74e",
    ),
    sourceFile(
        "crates/recursion/src/transcript_binding_air.rs",
        "78fdd64602e44b593915a7d4bf60059682e12812eb1575cf4941c083526e714e",
    ),
    sourceFile(
        "crates/recursion/src/kernel.rs",
        "5ecc2ec4597b21dd14a2be81dcd8da0324f6b57eed27823cf9986de5d5212e77",
    ),
    sourceFile(
        "crates/air/src/poseidon2.rs",
        "d029f2ee6b3b63b6d7c992a208038b1d451d16e9bc8f0770f49aecc8b4b17b8a",
    ),
    sourceFile(
        "crates/air/src/trace.rs",
        "c8ac2b71e3cc5d94682533dbc4228030e5696e40d0ad42b3c042ce82940bc761",
    ),
    sourceFile(
        "crates/prover/src/relations.rs",
        "779d65db96f8b4371ef42c70b77b99bc7a02e4d195443a6ac9b7f4ed48fd9a26",
    ),
    sourceFile(
        "crates/stwo-macros/src/air_fns.rs",
        "cd3922d517bb96dcb660ed25e1bd58811109ab21721936f8e56b0a74fe582e79",
    ),
};

pub const SOURCE_AUTHORITY_FORMAT_VERSION: u16 = 1;
pub const SOURCE_AUTHORITY_DOMAIN =
    "stwo-zig/typed-air/recursion-transcript-air-source/v1\x00";
pub const SOURCE_AUTHORITY_DIGEST_HEX =
    "9e00b5cc075be96d834a880ea0cbb417295cd307c0b20e982153a1f9ce8cb4e4";
pub const SOURCE_AUTHORITY_DIGEST = hexDigest(
    SOURCE_AUTHORITY_DIGEST_HEX,
    "invalid transcript-air source-authority digest",
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
    direct_constraints: u8,
    framework_constraints: u8,
    relation_events: u8,
    lookup_batch: u8,
    interaction_batches: u8,
    interaction_columns: u8,
    poseidon_io_arity: u8,
    control_arity: u8,
    data_arity: u8,
    state_arity: u8,
    output_arity: u8,
    maximum_degree: u8,

    pub fn pinned() SourceAuthority {
        return .{
            .format_version = SOURCE_AUTHORITY_FORMAT_VERSION,
            .revision = STARK_V_REVISION,
            .files = SOURCE_FILES,
            .main_columns = PHYSICAL_MAIN_COLUMN_COUNT,
            .direct_constraints = DIRECT_CONSTRAINT_COUNT,
            .framework_constraints = FRAMEWORK_CONSTRAINT_COUNT,
            .relation_events = RELATION_EVENT_COUNT,
            .lookup_batch = LOOKUP_BATCH_SIZE,
            .interaction_batches = INTERACTION_BATCH_COUNT,
            .interaction_columns = INTERACTION_COLUMN_COUNT,
            .poseidon_io_arity = POSEIDON_IO_ARITY,
            .control_arity = CONTROL_ARITY,
            .data_arity = DATA_ARITY,
            .state_arity = STATE_ARITY,
            .output_arity = OUTPUT_ARITY,
            .maximum_degree = SOURCE_DECLARED_MAXIMUM_DEGREE,
        };
    }

    pub fn validate(self: SourceAuthority) error{AuthorityMismatch}!void {
        if (!std.meta.eql(self, pinned())) return error.AuthorityMismatch;
        const domains = [_]relation.Domain{
            .poseidon2_io,
            .recursion_hash_call_control,
            .recursion_hash_data,
            .recursion_hash_state,
            .recursion_hash_state,
            .recursion_hash_output,
        };
        const arities = [_]usize{
            POSEIDON_IO_ARITY,
            CONTROL_ARITY,
            DATA_ARITY,
            STATE_ARITY,
            STATE_ARITY,
            OUTPUT_ARITY,
        };
        const roles = [_]relation.Role{
            .request,
            .consume,
            .consume,
            .consume,
            .emit,
            .emit,
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
        hashInt(&hash, u8, self.files.len);
        for (self.files) |file| {
            hashBytes(&hash, file.path);
            hash.update(&file.sha256);
        }
        inline for (.{
            self.main_columns,
            self.direct_constraints,
            self.framework_constraints,
            self.relation_events,
            self.lookup_batch,
            self.interaction_batches,
            self.interaction_columns,
            self.poseidon_io_arity,
            self.control_arity,
            self.data_arity,
            self.state_arity,
            self.output_arity,
            self.maximum_degree,
        }) |value| hashInt(&hash, u8, value);
        for ([_]relation.Domain{
            .poseidon2_io,
            .recursion_hash_call_control,
            .recursion_hash_data,
            .recursion_hash_state,
            .recursion_hash_state,
            .recursion_hash_output,
        }) |domain| hashInt(&hash, u8, @intFromEnum(domain));
        return hash.finalResult();
    }
};

pub const SEMANTIC_DIGEST_HEX =
    "421c08cae7f6f1d5ebe2787999612ddd83830e050175cd9f98b2d87a19e57480";
pub const SEMANTIC_DIGEST = hexDigest(
    SEMANTIC_DIGEST_HEX,
    "invalid recursion transcript-air semantic digest",
);
pub const STATIC_PROFILE_DIGEST_HEX =
    "6f4e281d89cc018b5a9043d12fe3ddf4f9a1d7c02c30ec731f4a5bacd03f7223";

pub const MAIN_COLUMN_NAMES: [PHYSICAL_MAIN_COLUMN_COUNT][]const u8 = blk: {
    var names: [PHYSICAL_MAIN_COLUMN_COUNT][]const u8 = undefined;
    names[0] = "recursion.transcript_air.enabler";
    names[1] = "recursion.transcript_air.verifier_id";
    names[2] = "recursion.transcript_air.call_id";
    names[3] = "recursion.transcript_air.hash_id";
    names[4] = "recursion.transcript_air.step";
    names[5] = "recursion.transcript_air.is_first";
    names[6] = "recursion.transcript_air.is_last";
    names[7] = "recursion.transcript_air.is_draw";
    for (0..WIDTH) |index| names[8 + index] = std.fmt.comptimePrint(
        "recursion.transcript_air.previous_{d}",
        .{index},
    );
    for (0..RATE) |index| names[8 + WIDTH + index] = std.fmt.comptimePrint(
        "recursion.transcript_air.chunk_{d}",
        .{index},
    );
    for (0..WIDTH) |index| names[8 + WIDTH + RATE + index] = std.fmt.comptimePrint(
        "recursion.transcript_air.output_{d}",
        .{index},
    );
    break :blk names;
};

pub const MainColumns = struct {
    enabler: types.ValueId,
    verifier_id: types.ValueId,
    call_id: types.ValueId,
    hash_id: types.ValueId,
    step: types.ValueId,
    is_first: types.ValueId,
    is_last: types.ValueId,
    is_draw: types.ValueId,
    previous: [WIDTH]types.ValueId,
    chunks: [RATE]types.ValueId,
    outputs: [WIDTH]types.ValueId,

    pub fn physical(self: MainColumns) [PHYSICAL_MAIN_COLUMN_COUNT]types.ValueId {
        return .{
            self.enabler,
            self.verifier_id,
            self.call_id,
            self.hash_id,
            self.step,
            self.is_first,
            self.is_last,
            self.is_draw,
        } ++ self.previous ++ self.chunks ++ self.outputs;
    }
};

pub const Events = struct {
    poseidon2_io_request: types.EffectId,
    control_consume: types.EffectId,
    data_consume: types.EffectId,
    state_consume: types.EffectId,
    state_emit: types.EffectId,
    output_emit: types.EffectId,

    pub fn ordered(self: Events) [RELATION_EVENT_COUNT]types.EffectId {
        return .{
            self.poseidon2_io_request,
            self.control_consume,
            self.data_consume,
            self.state_consume,
            self.state_emit,
            self.output_emit,
        };
    }
};

pub const ValidationError = validate_mod.Error || relation_effect.Error || error{
    AuthorityMismatch,
    InvalidTranscriptAirDefinition,
};

pub const Definition = struct {
    arena: ir.Arena,
    main: MainColumns,
    roots: [DIRECT_CONSTRAINT_COUNT]types.ValueId,
    constraints: [DIRECT_CONSTRAINT_COUNT]types.ConstraintId,
    poseidon_inputs: [WIDTH]types.ValueId,
    next_step: types.ValueId,
    weights: [RELATION_EVENT_COUNT]types.ValueId,
    events: Events,

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
            return error.InvalidTranscriptAirDefinition;
        }
        try validateInputs(&self.arena, &self.main.physical());
        var name_buffer: [96]u8 = undefined;
        for (self.constraints, self.roots, 0..) |constraint_id, root, index| {
            const item = self.arena.constraint(constraint_id) orelse
                return error.InvalidTranscriptAirDefinition;
            const name = self.arena.name(item.name) orelse
                return error.InvalidTranscriptAirDefinition;
            const expected = constraintName(index, &name_buffer) catch
                return error.InvalidTranscriptAirDefinition;
            if (types.idIndex(constraint_id) != index or item.root != root or
                item.gate != null or item.category != .semantic or
                !std.mem.eql(u8, name, expected))
            {
                return error.InvalidTranscriptAirDefinition;
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
    var physical: [PHYSICAL_MAIN_COLUMN_COUNT]types.ValueId = undefined;
    for (&physical, MAIN_COLUMN_NAMES, 0..) |*value, name, index| {
        value.* = try arena.input(
            name,
            switch (index) {
                0, 5, 6, 7 => .selector,
                else => .felt,
            },
            span,
        );
    }
    const main = MainColumns{
        .enabler = physical[0],
        .verifier_id = physical[1],
        .call_id = physical[2],
        .hash_id = physical[3],
        .step = physical[4],
        .is_first = physical[5],
        .is_last = physical[6],
        .is_draw = physical[7],
        .previous = physical[8 .. 8 + WIDTH].*,
        .chunks = physical[8 + WIDTH .. 8 + WIDTH + RATE].*,
        .outputs = physical[8 + WIDTH + RATE ..][0..WIDTH].*,
    };

    const one = try arena.constantField(1, span);
    var roots: [DIRECT_CONSTRAINT_COUNT]types.ValueId = undefined;
    roots[0] = try arena.mul(
        main.enabler,
        try arena.sub(one, main.enabler, span),
        span,
    );
    for ([_]types.ValueId{ main.is_first, main.is_last, main.is_draw }, 0..) |
        selector,
        index,
    | roots[1 + index] = try arena.mul(
        selector,
        try arena.sub(one, selector, span),
        span,
    );
    roots[4] = try arena.mul(main.is_first, try arena.sub(one, main.enabler, span), span);
    roots[5] = try arena.mul(main.is_last, try arena.sub(one, main.enabler, span), span);
    roots[6] = try arena.mul(main.is_draw, try arena.sub(one, main.enabler, span), span);
    roots[7] = try arena.mul(main.is_first, main.step, span);
    for (main.previous, 0..) |previous, index|
        roots[8 + index] = try arena.mul(main.is_first, previous, span);

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

    var poseidon_inputs: [WIDTH]types.ValueId = main.previous;
    for (main.previous[0..RATE], main.chunks, 0..) |previous, chunk, index|
        poseidon_inputs[index] = try arena.add(previous, chunk, span);
    const next_step = try arena.add(main.step, one, span);
    const weights = [RELATION_EVENT_COUNT]types.ValueId{
        main.enabler,
        main.enabler,
        main.enabler,
        try arena.sub(main.enabler, main.is_first, span),
        try arena.sub(main.enabler, main.is_last, span),
        main.is_last,
    };
    const poseidon_tuple = poseidon_inputs ++ main.outputs;
    const control_tuple = [_]types.ValueId{
        main.verifier_id,
        main.call_id,
        main.hash_id,
        main.step,
        main.is_first,
        main.is_last,
        main.is_draw,
    };
    const data_tuple = .{
        main.verifier_id,
        main.hash_id,
        main.step,
    } ++ main.chunks;
    const state_input_tuple = .{
        main.verifier_id,
        main.hash_id,
        main.step,
    } ++ main.previous;
    const state_output_tuple = .{
        main.verifier_id,
        main.hash_id,
        next_step,
    } ++ main.outputs;
    const output_tuple = .{
        main.verifier_id,
        main.hash_id,
        main.call_id,
        main.is_draw,
    } ++ main.outputs[0..RATE].*;
    const ordered = try relation_effect.appendGroup(RELATION_EVENT_COUNT, &arena, .{
        .{ .domain = .poseidon2_io, .role = .request, .values = &poseidon_tuple, .weight = weights[0] },
        .{ .domain = .recursion_hash_call_control, .role = .consume, .values = &control_tuple, .weight = weights[1] },
        .{ .domain = .recursion_hash_data, .role = .consume, .values = &data_tuple, .weight = weights[2] },
        .{ .domain = .recursion_hash_state, .role = .consume, .values = &state_input_tuple, .weight = weights[3] },
        .{ .domain = .recursion_hash_state, .role = .emit, .values = &state_output_tuple, .weight = weights[4] },
        .{ .domain = .recursion_hash_output, .role = .emit, .values = &output_tuple, .weight = weights[5] },
    }, span);
    return .{
        .arena = arena,
        .main = main,
        .roots = roots,
        .constraints = constraints,
        .poseidon_inputs = poseidon_inputs,
        .next_step = next_step,
        .weights = weights,
        .events = .{
            .poseidon2_io_request = ordered[0],
            .control_consume = ordered[1],
            .data_consume = ordered[2],
            .state_consume = ordered[3],
            .state_emit = ordered[4],
            .output_emit = ordered[5],
        },
    };
}

fn validateInputs(
    arena: *const ir.Arena,
    values: *const [PHYSICAL_MAIN_COLUMN_COUNT]types.ValueId,
) error{InvalidTranscriptAirDefinition}!void {
    for (values, MAIN_COLUMN_NAMES, 0..) |value, expected_name, index| {
        if (types.idIndex(value) != index)
            return error.InvalidTranscriptAirDefinition;
        const node = arena.node(value) orelse
            return error.InvalidTranscriptAirDefinition;
        const expected_type: types.Type = switch (index) {
            0, 5, 6, 7 => .selector,
            else => .felt,
        };
        if (!std.meta.eql(node.key.ty, expected_type))
            return error.InvalidTranscriptAirDefinition;
        const name_id = switch (node.key.op) {
            .input => |input_name| input_name,
            else => return error.InvalidTranscriptAirDefinition,
        };
        const actual_name = arena.name(name_id) orelse
            return error.InvalidTranscriptAirDefinition;
        if (!std.mem.eql(u8, actual_name, expected_name))
            return error.InvalidTranscriptAirDefinition;
    }
}

fn validateEvents(self: *const Definition) error{InvalidTranscriptAirDefinition}!void {
    const poseidon_tuple = self.poseidon_inputs ++ self.main.outputs;
    const control_tuple = [_]types.ValueId{
        self.main.verifier_id,
        self.main.call_id,
        self.main.hash_id,
        self.main.step,
        self.main.is_first,
        self.main.is_last,
        self.main.is_draw,
    };
    const data_tuple = .{
        self.main.verifier_id,
        self.main.hash_id,
        self.main.step,
    } ++ self.main.chunks;
    const state_input_tuple = .{
        self.main.verifier_id,
        self.main.hash_id,
        self.main.step,
    } ++ self.main.previous;
    const state_output_tuple = .{
        self.main.verifier_id,
        self.main.hash_id,
        self.next_step,
    } ++ self.main.outputs;
    const output_tuple = .{
        self.main.verifier_id,
        self.main.hash_id,
        self.main.call_id,
        self.main.is_draw,
    } ++ self.main.outputs[0..RATE].*;
    const domains = [_]relation.Domain{
        .poseidon2_io,
        .recursion_hash_call_control,
        .recursion_hash_data,
        .recursion_hash_state,
        .recursion_hash_state,
        .recursion_hash_output,
    };
    const roles = [_]relation.Role{
        .request,
        .consume,
        .consume,
        .consume,
        .emit,
        .emit,
    };
    const tuples = .{
        poseidon_tuple[0..],
        control_tuple[0..],
        data_tuple[0..],
        state_input_tuple[0..],
        state_output_tuple[0..],
        output_tuple[0..],
    };
    const events = self.events.ordered();
    inline for (0..RELATION_EVENT_COUNT) |index| {
        const effect_id = events[index];
        if (types.idIndex(effect_id) != index)
            return error.InvalidTranscriptAirDefinition;
        const item = self.arena.effect(effect_id) orelse
            return error.InvalidTranscriptAirDefinition;
        const binding = item.binding orelse
            return error.InvalidTranscriptAirDefinition;
        const schema = relation.get(domains[index]);
        const values = self.arena.effectValues(effect_id) orelse
            return error.InvalidTranscriptAirDefinition;
        if (item.kind != .component_call or
            item.liveness != self.weights[index] or
            item.access_ordinal != null or binding.schema != schema.id or
            binding.schema_version != schema.version or
            binding.role != roles[index] or
            !std.mem.eql(types.ValueId, values, tuples[index]))
        {
            return error.InvalidTranscriptAirDefinition;
        }
    }
}

fn constraintName(index: usize, buffer: *[96]u8) ![]const u8 {
    return switch (index) {
        0 => "recursion.transcript_air.enabler_boolean",
        1 => "recursion.transcript_air.is_first_boolean",
        2 => "recursion.transcript_air.is_last_boolean",
        3 => "recursion.transcript_air.is_draw_boolean",
        4 => "recursion.transcript_air.is_first_implies_enabled",
        5 => "recursion.transcript_air.is_last_implies_enabled",
        6 => "recursion.transcript_air.is_draw_implies_enabled",
        7 => "recursion.transcript_air.first_step_zero",
        8...8 + WIDTH => std.fmt.bufPrint(
            buffer,
            "recursion.transcript_air.first_previous_{d}_zero",
            .{index - 8},
        ),
        else => error.InvalidConstraintIndex,
    };
}

fn sourceFile(comptime path: []const u8, comptime sha256: []const u8) SourceFile {
    return .{
        .path = path,
        .sha256 = hexDigest(sha256, "invalid pinned transcript-air source digest"),
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
    if (RATE != 8 or WIDTH != 16 or PHYSICAL_MAIN_COLUMN_COUNT != 48 or
        PREPROCESSED_COLUMN_COUNT != 0 or PARAMETER_COUNT != 0 or
        LOGICAL_INPUT_COUNT != 48 or DIRECT_CONSTRAINT_COUNT != 24 or
        RELATION_EVENT_COUNT != 6 or LOOKUP_BATCH_SIZE != 2 or
        INTERACTION_BATCH_COUNT != 3 or INTERACTION_COLUMN_COUNT != 12 or
        FRAMEWORK_CONSTRAINT_COUNT != 27)
    {
        @compileError("universal transcript-air geometry drifted");
    }
}
