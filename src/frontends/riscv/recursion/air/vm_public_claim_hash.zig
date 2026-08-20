//! Exact typed logical AIR for Stark-V universal VM-claim hash row 13.
//!
//! Verifier-owned preprocessing fixes the eight-word sponge schedule derived
//! from row 12's public-claim shape. The committed row carries only the
//! chained state, absorbed chunk, and permutation output. Permutation
//! correctness remains owned by the shared Poseidon2 provider through the
//! standard 32-word I/O relation.

const std = @import("std");
const digest = @import("../../air/lang/digest.zig");
const ir = @import("../../air/lang/ir.zig");
const relation = @import("../../air/lang/relation.zig");
const source = @import("../../air/lang/source.zig");
const types = @import("../../air/lang/types.zig");
const validate_mod = @import("../../air/lang/validate.zig");
const relation_effect = @import("relation_effect.zig");

pub const STABLE_NAME = "recursion.vm_public_claim_hash.v1";
pub const STATE_WIDTH: usize = 16;
pub const RATE: usize = STATE_WIDTH / 2;
pub const DIGEST_WORD_COUNT: usize = RATE;
pub const PHYSICAL_MAIN_COLUMN_COUNT: usize = 1 + STATE_WIDTH + RATE + STATE_WIDTH;
pub const PREPROCESSED_COLUMN_COUNT: usize = 4 + RATE * 3;
pub const PARAMETER_COUNT: usize = 5;
pub const LOGICAL_INPUT_COUNT: usize =
    PHYSICAL_MAIN_COLUMN_COUNT + PREPROCESSED_COLUMN_COUNT + PARAMETER_COUNT;
pub const DIRECT_CONSTRAINT_COUNT: usize =
    1 + STATE_WIDTH + RATE + STATE_WIDTH + STATE_WIDTH + RATE;
pub const RELATION_EVENT_COUNT: usize = 1 + RATE + 2 + DIGEST_WORD_COUNT;
pub const LOOKUP_BATCH_SIZE: u8 = 2;
pub const INTERACTION_BATCH_COUNT: usize = 10;
pub const INTERACTION_COLUMN_COUNT: usize = 40;
pub const FRAMEWORK_CONSTRAINT_COUNT: usize =
    DIRECT_CONSTRAINT_COUNT + INTERACTION_BATCH_COUNT;
pub const SOURCE_DECLARED_MAXIMUM_DEGREE: u32 = 3;
pub const REFERENCE_MAXIMUM_CONSTRAINT_DEGREE: u32 = 3;
pub const MAXIMUM_CONSTRAINT_DEGREE: u32 = 3;

pub const VM_PUBLIC_CLAIM_HASH_DOMAIN: u32 = 0x5643;
pub const VM_CLAIM_HASH_SCOPE: u32 = 1;
pub const SEGMENT_VERIFIER_ID: u32 = 0;
pub const VM_PUBLIC_CLAIM_DIGEST_INPUT_KIND: u32 = 11;

pub const STARK_V_REVISION: [40]u8 =
    "59172a201bd01f2f4b699bc2f7d4442d8ee81597".*;
pub const STARK_V_HASH_AIR_PATH =
    "crates/recursion/src/vm_public_claim_hash_air.rs";
pub const STARK_V_HASH_AIR_SHA256 = hexDigest(
    "24b21c4929b59d6ec8709bf2e86cb6ca76642c18d0e2b5f2dd39f840b242e972",
    "invalid pinned Stark-V vm_public_claim_hash_air.rs digest",
);
pub const STARK_V_CLAIM_PATH = "crates/recursion/src/vm_public_claim.rs";
pub const STARK_V_CLAIM_SHA256 = hexDigest(
    "4a090e32f36637ecdd26dd553427538467289b3f1d4dae1df256e685f5ed094c",
    "invalid pinned Stark-V vm_public_claim.rs digest",
);
pub const STARK_V_CLAIM_INPUT_PATH =
    "crates/recursion/src/vm_public_claim_input_air.rs";
pub const STARK_V_CLAIM_INPUT_SHA256 = hexDigest(
    "fdb24652823105b5ce9076e49ef49c761eca55e90543f5ad38274fa4ec7e0968",
    "invalid pinned Stark-V vm_public_claim_input_air.rs digest",
);
pub const STARK_V_PAYLOAD_PATH =
    "crates/recursion/src/transcript_payload_air.rs";
pub const STARK_V_PAYLOAD_SHA256 = hexDigest(
    "d2e05e13e8985f1ad781854c1a96a7321f8447951429a6720dc7852841a1bb5d",
    "invalid pinned Stark-V transcript_payload_air.rs digest",
);
pub const STARK_V_CONTROL_PATH = "crates/recursion/src/control_air.rs";
pub const STARK_V_CONTROL_SHA256 = hexDigest(
    "1c514c2f1066456f4819c1b4304fa7c6d60b1fe35125f42e3cc7f2a06f1489dc",
    "invalid pinned Stark-V control_air.rs digest",
);
pub const STARK_V_KERNEL_PATH = "crates/recursion/src/kernel.rs";
pub const STARK_V_KERNEL_SHA256 = hexDigest(
    "5ecc2ec4597b21dd14a2be81dcd8da0324f6b57eed27823cf9986de5d5212e77",
    "invalid pinned Stark-V kernel.rs digest",
);
pub const STARK_V_POSEIDON_PATH = "crates/air/src/poseidon2.rs";
pub const STARK_V_POSEIDON_SHA256 = hexDigest(
    "d029f2ee6b3b63b6d7c992a208038b1d451d16e9bc8f0770f49aecc8b4b17b8a",
    "invalid pinned Stark-V poseidon2.rs digest",
);
pub const STARK_V_AIR_FNS_PATH = "crates/stwo-macros/src/air_fns.rs";
pub const STARK_V_AIR_FNS_SHA256 = hexDigest(
    "cd3922d517bb96dcb660ed25e1bd58811109ab21721936f8e56b0a74fe582e79",
    "invalid pinned Stark-V air_fns.rs digest",
);
pub const STARK_V_PUBLIC_DATA_PATH = "crates/prover/src/public_data.rs";
pub const STARK_V_PUBLIC_DATA_SHA256 = hexDigest(
    "499337383ff7b4c5d98e721e4188bf0fd03ac85e3870241f926cf44286b26324",
    "invalid pinned Stark-V public_data.rs digest",
);

pub const SOURCE_AUTHORITY_FORMAT_VERSION: u16 = 1;
pub const SOURCE_AUTHORITY_DOMAIN =
    "stwo-zig/typed-air/recursion-vm-public-claim-hash-source/v1\x00";
pub const SOURCE_AUTHORITY_DIGEST_HEX =
    "e4cbfe9db35e8faf718a7a72a3eab11aec18bd7e263d582cef5017499fbbb1cd";
pub const SOURCE_AUTHORITY_DIGEST = hexDigest(
    SOURCE_AUTHORITY_DIGEST_HEX,
    "invalid recursion VM public-claim hash source-authority digest",
);

pub const SourceAuthority = struct {
    format_version: u16,
    revision: [40]u8,
    hash_air_sha256: digest.Digest,
    claim_sha256: digest.Digest,
    claim_input_sha256: digest.Digest,
    payload_sha256: digest.Digest,
    control_sha256: digest.Digest,
    kernel_sha256: digest.Digest,
    poseidon_sha256: digest.Digest,
    air_fns_sha256: digest.Digest,
    public_data_sha256: digest.Digest,
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
            .hash_air_sha256 = STARK_V_HASH_AIR_SHA256,
            .claim_sha256 = STARK_V_CLAIM_SHA256,
            .claim_input_sha256 = STARK_V_CLAIM_INPUT_SHA256,
            .payload_sha256 = STARK_V_PAYLOAD_SHA256,
            .control_sha256 = STARK_V_CONTROL_SHA256,
            .kernel_sha256 = STARK_V_KERNEL_SHA256,
            .poseidon_sha256 = STARK_V_POSEIDON_SHA256,
            .air_fns_sha256 = STARK_V_AIR_FNS_SHA256,
            .public_data_sha256 = STARK_V_PUBLIC_DATA_SHA256,
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
            .poseidon2_io,
            .recursion_vm_public_claim_word,
            .recursion_vm_public_claim_hash_state,
            .recursion_verifier_input_word,
        };
        const arities = [_]usize{ 32, 3, 17, 5 };
        for (domains, arities, 0..) |domain, arity, index| {
            const schema = relation.requireExactUniversalSchema(domain) catch
                return error.AuthorityMismatch;
            if (schema.fields.len != arity) return error.AuthorityMismatch;
            if (index == 0) {
                if (!schema.allowed_roles.allows(.request))
                    return error.AuthorityMismatch;
            } else if (!schema.allowed_roles.allows(.consume) or
                !schema.allowed_roles.allows(.emit))
            {
                return error.AuthorityMismatch;
            }
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
        hashSource(&hash, STARK_V_HASH_AIR_PATH, self.hash_air_sha256);
        hashSource(&hash, STARK_V_CLAIM_PATH, self.claim_sha256);
        hashSource(&hash, STARK_V_CLAIM_INPUT_PATH, self.claim_input_sha256);
        hashSource(&hash, STARK_V_PAYLOAD_PATH, self.payload_sha256);
        hashSource(&hash, STARK_V_CONTROL_PATH, self.control_sha256);
        hashSource(&hash, STARK_V_KERNEL_PATH, self.kernel_sha256);
        hashSource(&hash, STARK_V_POSEIDON_PATH, self.poseidon_sha256);
        hashSource(&hash, STARK_V_AIR_FNS_PATH, self.air_fns_sha256);
        hashSource(&hash, STARK_V_PUBLIC_DATA_PATH, self.public_data_sha256);
        inline for (.{
            self.main_columns,
            self.preprocessed_columns,
            self.parameters,
            self.direct_constraints,
            self.framework_constraints,
            self.relation_events,
            self.interaction_columns,
            self.maximum_degree,
        }) |value| hashInt(&hash, u8, value);
        return hash.finalResult();
    }
};

pub const SEMANTIC_DIGEST_HEX =
    "123f3ee614fa87189e4fc4d4222c4a49c2e446947b3babdbd2b62bbd2844a5c8";
pub const SEMANTIC_DIGEST: digest.Digest = hexDigest(
    SEMANTIC_DIGEST_HEX,
    "invalid recursion VM public-claim hash semantic digest",
);
pub const STATIC_PROFILE_DIGEST_HEX =
    "332dadc469be253c44f4923a5a2a86246547ebd542d3ee724572e0e2cd0bbc29";

pub const MAIN_COLUMN_NAMES = blk: {
    var names: [PHYSICAL_MAIN_COLUMN_COUNT][]const u8 = undefined;
    names[0] = "recursion.vm_public_claim_hash.enabler";
    for (0..STATE_WIDTH) |index| names[1 + index] = std.fmt.comptimePrint(
        "recursion.vm_public_claim_hash.previous_{d}",
        .{index},
    );
    for (0..RATE) |index| names[1 + STATE_WIDTH + index] = std.fmt.comptimePrint(
        "recursion.vm_public_claim_hash.chunk_{d}",
        .{index},
    );
    for (0..STATE_WIDTH) |index| names[1 + STATE_WIDTH + RATE + index] =
        std.fmt.comptimePrint(
            "recursion.vm_public_claim_hash.output_{d}",
            .{index},
        );
    break :blk names;
};

pub const PREPROCESSED_COLUMN_NAMES = blk: {
    var names: [PREPROCESSED_COLUMN_COUNT][]const u8 = undefined;
    names[0] = "recursion_vm_claim_hash_row_mask";
    names[1] = "recursion_vm_claim_hash_step";
    names[2] = "recursion_vm_claim_hash_first_mask";
    names[3] = "recursion_vm_claim_hash_last_mask";
    for (0..RATE) |index| {
        names[4 + 3 * index] = std.fmt.comptimePrint(
            "recursion_vm_claim_hash_chunk_{d}_source_mask",
            .{index},
        );
        names[5 + 3 * index] = std.fmt.comptimePrint(
            "recursion_vm_claim_hash_chunk_{d}_word_index",
            .{index},
        );
        names[6 + 3 * index] = std.fmt.comptimePrint(
            "recursion_vm_claim_hash_chunk_{d}_constant",
            .{index},
        );
    }
    break :blk names;
};

pub const PARAMETER_NAMES = [PARAMETER_COUNT][]const u8{
    "recursion.vm_public_claim_hash.param.segment_active",
    "recursion.vm_public_claim_hash.param.hash_domain",
    "recursion.vm_public_claim_hash.param.hash_scope",
    "recursion.vm_public_claim_hash.param.verifier_id",
    "recursion.vm_public_claim_hash.param.verifier_input_kind",
};

pub const MainColumns = struct {
    enabler: types.ValueId,
    previous: [STATE_WIDTH]types.ValueId,
    chunks: [RATE]types.ValueId,
    output: [STATE_WIDTH]types.ValueId,

    pub fn physical(self: MainColumns) [PHYSICAL_MAIN_COLUMN_COUNT]types.ValueId {
        return .{self.enabler} ++ self.previous ++ self.chunks ++ self.output;
    }
};

pub const ChunkPreprocessed = struct {
    source_mask: types.ValueId,
    word_index: types.ValueId,
    constant: types.ValueId,
};

pub const PreprocessedColumns = struct {
    row_mask: types.ValueId,
    step: types.ValueId,
    first: types.ValueId,
    last: types.ValueId,
    chunks: [RATE]ChunkPreprocessed,

    pub fn physical(self: PreprocessedColumns) [PREPROCESSED_COLUMN_COUNT]types.ValueId {
        var result: [PREPROCESSED_COLUMN_COUNT]types.ValueId = undefined;
        result[0..4].* = .{ self.row_mask, self.step, self.first, self.last };
        for (self.chunks, 0..) |chunk, index| result[4 + 3 * index ..][0..3].* = .{
            chunk.source_mask,
            chunk.word_index,
            chunk.constant,
        };
        return result;
    }
};

pub const Parameters = struct {
    segment_active: types.ValueId,
    hash_domain: types.ValueId,
    hash_scope: types.ValueId,
    verifier_id: types.ValueId,
    verifier_input_kind: types.ValueId,

    pub fn physical(self: Parameters) [PARAMETER_COUNT]types.ValueId {
        return .{
            self.segment_active,
            self.hash_domain,
            self.hash_scope,
            self.verifier_id,
            self.verifier_input_kind,
        };
    }
};

pub const ValidationError = validate_mod.Error || relation_effect.Error || error{
    AuthorityMismatch,
    InvalidVmPublicClaimHashDefinition,
};

pub const Definition = struct {
    arena: ir.Arena,
    main: MainColumns,
    preprocessed: PreprocessedColumns,
    parameters: Parameters,
    active: types.ValueId,
    zero: types.ValueId,
    permutation_input: [STATE_WIDTH]types.ValueId,
    state_step_next: types.ValueId,
    roots: [DIRECT_CONSTRAINT_COUNT]types.ValueId,
    constraints: [DIRECT_CONSTRAINT_COUNT]types.ConstraintId,
    weights: [RELATION_EVENT_COUNT]types.ValueId,
    digest_limb_indices: [DIGEST_WORD_COUNT]types.ValueId,
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
            return error.InvalidVmPublicClaimHashDefinition;
        }
        try validateInputs(
            &self.arena,
            &self.main.physical(),
            &MAIN_COLUMN_NAMES,
            0,
            &.{0},
        );
        var pp_selectors: [3 + RATE]usize = undefined;
        pp_selectors[0..3].* = .{ 0, 2, 3 };
        for (0..RATE) |index| pp_selectors[3 + index] = 4 + 3 * index;
        try validateInputs(
            &self.arena,
            &self.preprocessed.physical(),
            &PREPROCESSED_COLUMN_NAMES,
            PHYSICAL_MAIN_COLUMN_COUNT,
            &pp_selectors,
        );
        try validateInputs(
            &self.arena,
            &self.parameters.physical(),
            &PARAMETER_NAMES,
            PHYSICAL_MAIN_COLUMN_COUNT + PREPROCESSED_COLUMN_COUNT,
            &.{0},
        );
        var name_buffer: [112]u8 = undefined;
        for (self.constraints, self.roots, 0..) |constraint_id, root, index| {
            const item = self.arena.constraint(constraint_id) orelse
                return error.InvalidVmPublicClaimHashDefinition;
            const actual_name = self.arena.name(item.name) orelse
                return error.InvalidVmPublicClaimHashDefinition;
            const expected_name = constraintName(index, &name_buffer) catch
                return error.InvalidVmPublicClaimHashDefinition;
            if (types.idIndex(constraint_id) != index or item.root != root or
                item.gate != null or item.category != .semantic or
                !std.mem.eql(u8, actual_name, expected_name))
            {
                return error.InvalidVmPublicClaimHashDefinition;
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
        .previous = main_values[1..][0..STATE_WIDTH].*,
        .chunks = main_values[1 + STATE_WIDTH ..][0..RATE].*,
        .output = main_values[1 + STATE_WIDTH + RATE ..][0..STATE_WIDTH].*,
    };

    var pp_values: [PREPROCESSED_COLUMN_COUNT]types.ValueId = undefined;
    for (&pp_values, PREPROCESSED_COLUMN_NAMES, 0..) |*value, name, index| {
        const selector = index == 0 or index == 2 or index == 3 or
            (index >= 4 and (index - 4) % 3 == 0);
        value.* = try arena.input(name, if (selector) .selector else .felt, span);
    }
    var chunks: [RATE]ChunkPreprocessed = undefined;
    for (&chunks, 0..) |*chunk, index| chunk.* = .{
        .source_mask = pp_values[4 + 3 * index],
        .word_index = pp_values[5 + 3 * index],
        .constant = pp_values[6 + 3 * index],
    };
    const preprocessed = PreprocessedColumns{
        .row_mask = pp_values[0],
        .step = pp_values[1],
        .first = pp_values[2],
        .last = pp_values[3],
        .chunks = chunks,
    };
    const parameters = Parameters{
        .segment_active = try arena.input(PARAMETER_NAMES[0], .selector, span),
        .hash_domain = try arena.input(PARAMETER_NAMES[1], .felt, span),
        .hash_scope = try arena.input(PARAMETER_NAMES[2], .felt, span),
        .verifier_id = try arena.input(PARAMETER_NAMES[3], .felt, span),
        .verifier_input_kind = try arena.input(PARAMETER_NAMES[4], .felt, span),
    };
    const zero = try arena.constantField(0, span);
    const one = try arena.constantField(1, span);
    const active = try arena.mul(preprocessed.row_mask, parameters.segment_active, span);
    const inactive = try arena.sub(one, active, span);

    var roots: [DIRECT_CONSTRAINT_COUNT]types.ValueId = undefined;
    var cursor: usize = 0;
    roots[cursor] = try arena.sub(main.enabler, active, span);
    cursor += 1;
    for (main.previous) |value| {
        roots[cursor] = try arena.mul(inactive, value, span);
        cursor += 1;
    }
    for (main.chunks) |value| {
        roots[cursor] = try arena.mul(inactive, value, span);
        cursor += 1;
    }
    for (main.output) |value| {
        roots[cursor] = try arena.mul(inactive, value, span);
        cursor += 1;
    }
    const initial_active = try arena.mul(parameters.segment_active, preprocessed.first, span);
    for (main.previous, 0..) |value, index| {
        const expected = if (index == STATE_WIDTH - 1)
            try arena.sub(value, parameters.hash_domain, span)
        else
            value;
        roots[cursor] = try arena.mul(initial_active, expected, span);
        cursor += 1;
    }
    for (main.chunks, preprocessed.chunks) |value, metadata| {
        roots[cursor] = try arena.mul(
            try arena.mul(
                parameters.segment_active,
                try arena.sub(preprocessed.row_mask, metadata.source_mask, span),
                span,
            ),
            try arena.sub(value, metadata.constant, span),
            span,
        );
        cursor += 1;
    }
    std.debug.assert(cursor == roots.len);

    var constraints: [DIRECT_CONSTRAINT_COUNT]types.ConstraintId = undefined;
    var name_buffer: [112]u8 = undefined;
    for (&constraints, roots, 0..) |*constraint, root, index| constraint.* =
        try arena.assertZero(
            try constraintName(index, &name_buffer),
            root,
            null,
            .semantic,
            span,
        );

    var weights: [RELATION_EVENT_COUNT]types.ValueId = undefined;
    weights[0] = active;
    for (preprocessed.chunks, 0..) |metadata, index| weights[1 + index] =
        try arena.mul(parameters.segment_active, metadata.source_mask, span);
    weights[9] = try arena.mul(
        parameters.segment_active,
        try arena.sub(preprocessed.row_mask, preprocessed.first, span),
        span,
    );
    weights[10] = try arena.mul(
        parameters.segment_active,
        try arena.sub(preprocessed.row_mask, preprocessed.last, span),
        span,
    );
    const final_active = try arena.mul(parameters.segment_active, preprocessed.last, span);
    for (weights[11..]) |*weight| weight.* = final_active;

    var permutation_input: [STATE_WIDTH]types.ValueId = undefined;
    for (main.previous, 0..) |value, index| permutation_input[index] = if (index < RATE)
        try arena.add(value, main.chunks[index], span)
    else
        value;
    const poseidon_tuple = permutation_input ++ main.output;
    var claim_tuples: [RATE][3]types.ValueId = undefined;
    for (&claim_tuples, preprocessed.chunks, main.chunks) |*tuple, metadata, value|
        tuple.* = .{ parameters.hash_scope, metadata.word_index, value };
    const current_state = .{preprocessed.step} ++ main.previous;
    const next_state = .{
        try arena.add(preprocessed.step, one, span),
    } ++ main.output;
    const state_step_next = next_state[0];
    var digest_limb_indices: [DIGEST_WORD_COUNT]types.ValueId = undefined;
    var digest_tuples: [DIGEST_WORD_COUNT][5]types.ValueId = undefined;
    for (&digest_limb_indices, &digest_tuples, main.output[0..DIGEST_WORD_COUNT], 0..) |
        *limb_value,
        *tuple,
        output,
        limb,
    | {
        limb_value.* = try arena.constantField(@intCast(limb), span);
        tuple.* = .{
            parameters.verifier_id,
            parameters.verifier_input_kind,
            zero,
            limb_value.*,
            output,
        };
    }
    var specs: [RELATION_EVENT_COUNT]relation_effect.EventSpec = undefined;
    specs[0] = .{
        .domain = .poseidon2_io,
        .role = .request,
        .values = &poseidon_tuple,
        .weight = weights[0],
    };
    for (specs[1..9], &claim_tuples, weights[1..9]) |*spec, *tuple, weight| spec.* = .{
        .domain = .recursion_vm_public_claim_word,
        .role = .consume,
        .values = tuple,
        .weight = weight,
    };
    specs[9] = .{
        .domain = .recursion_vm_public_claim_hash_state,
        .role = .consume,
        .values = &current_state,
        .weight = weights[9],
    };
    specs[10] = .{
        .domain = .recursion_vm_public_claim_hash_state,
        .role = .emit,
        .values = &next_state,
        .weight = weights[10],
    };
    for (specs[11..], &digest_tuples, weights[11..]) |*spec, *tuple, weight| spec.* = .{
        .domain = .recursion_verifier_input_word,
        .role = .consume,
        .values = tuple,
        .weight = weight,
    };
    const events = try relation_effect.appendGroup(
        RELATION_EVENT_COUNT,
        &arena,
        specs,
        span,
    );
    return .{
        .arena = arena,
        .main = main,
        .preprocessed = preprocessed,
        .parameters = parameters,
        .active = active,
        .zero = zero,
        .permutation_input = permutation_input,
        .state_step_next = state_step_next,
        .roots = roots,
        .constraints = constraints,
        .weights = weights,
        .digest_limb_indices = digest_limb_indices,
        .events = events,
    };
}

fn validateInputs(
    arena: *const ir.Arena,
    values: []const types.ValueId,
    names: []const []const u8,
    offset: usize,
    selector_indices: []const usize,
) error{InvalidVmPublicClaimHashDefinition}!void {
    if (values.len != names.len) return error.InvalidVmPublicClaimHashDefinition;
    for (values, names, 0..) |value, expected_name, local_index| {
        if (types.idIndex(value) != offset + local_index)
            return error.InvalidVmPublicClaimHashDefinition;
        var selector = false;
        for (selector_indices) |index| selector = selector or index == local_index;
        const node = arena.node(value) orelse
            return error.InvalidVmPublicClaimHashDefinition;
        if (!std.meta.eql(node.key.ty, if (selector) types.Type.selector else .felt))
            return error.InvalidVmPublicClaimHashDefinition;
        const name_id = switch (node.key.op) {
            .input => |input_name| input_name,
            else => return error.InvalidVmPublicClaimHashDefinition,
        };
        const actual_name = arena.name(name_id) orelse
            return error.InvalidVmPublicClaimHashDefinition;
        if (!std.mem.eql(u8, actual_name, expected_name))
            return error.InvalidVmPublicClaimHashDefinition;
    }
}

fn validateEvents(self: *const Definition) error{InvalidVmPublicClaimHashDefinition}!void {
    const poseidon_tuple = self.permutation_input ++ self.main.output;
    try validateEvent(self, 0, .poseidon2_io, .request, &poseidon_tuple);
    for (self.preprocessed.chunks, self.main.chunks, 0..) |metadata, value, index| {
        const tuple = [_]types.ValueId{
            self.parameters.hash_scope,
            metadata.word_index,
            value,
        };
        try validateEvent(
            self,
            1 + index,
            .recursion_vm_public_claim_word,
            .consume,
            &tuple,
        );
    }
    const current_state = .{self.preprocessed.step} ++ self.main.previous;
    try validateEvent(
        self,
        9,
        .recursion_vm_public_claim_hash_state,
        .consume,
        &current_state,
    );
    const next_state = .{self.state_step_next} ++ self.main.output;
    try validateEvent(
        self,
        10,
        .recursion_vm_public_claim_hash_state,
        .emit,
        &next_state,
    );
    for (self.main.output[0..DIGEST_WORD_COUNT], self.digest_limb_indices, 0..) |
        output,
        limb,
        index,
    | {
        const values = self.arena.effectValues(self.events[11 + index]) orelse
            return error.InvalidVmPublicClaimHashDefinition;
        if (values.len != 5 or values[0] != self.parameters.verifier_id or
            values[1] != self.parameters.verifier_input_kind or values[2] != self.zero or
            values[3] != limb or
            values[4] != output)
        {
            return error.InvalidVmPublicClaimHashDefinition;
        }
        try validateEventHeader(
            self,
            11 + index,
            .recursion_verifier_input_word,
            .consume,
        );
    }
}

fn validateEvent(
    self: *const Definition,
    index: usize,
    domain: relation.Domain,
    role: relation.Role,
    expected_values: []const types.ValueId,
) error{InvalidVmPublicClaimHashDefinition}!void {
    try validateEventHeader(self, index, domain, role);
    const values = self.arena.effectValues(self.events[index]) orelse
        return error.InvalidVmPublicClaimHashDefinition;
    if (!std.mem.eql(types.ValueId, values, expected_values))
        return error.InvalidVmPublicClaimHashDefinition;
}

fn validateEventHeader(
    self: *const Definition,
    index: usize,
    domain: relation.Domain,
    role: relation.Role,
) error{InvalidVmPublicClaimHashDefinition}!void {
    const effect_id = self.events[index];
    if (types.idIndex(effect_id) != index)
        return error.InvalidVmPublicClaimHashDefinition;
    const item = self.arena.effect(effect_id) orelse
        return error.InvalidVmPublicClaimHashDefinition;
    const binding = item.binding orelse
        return error.InvalidVmPublicClaimHashDefinition;
    const schema = relation.get(domain);
    const values = self.arena.effectValues(effect_id) orelse
        return error.InvalidVmPublicClaimHashDefinition;
    if (item.kind != .component_call or item.liveness != self.weights[index] or
        item.access_ordinal != null or binding.schema != schema.id or
        binding.schema_version != schema.version or binding.role != role or
        values.len != schema.fields.len)
    {
        return error.InvalidVmPublicClaimHashDefinition;
    }
}

fn constraintName(index: usize, buffer: *[112]u8) ![]const u8 {
    if (index == 0)
        return "recursion.vm_public_claim_hash.enabler_matches_active";
    if (index <= STATE_WIDTH) return std.fmt.bufPrint(
        buffer,
        "recursion.vm_public_claim_hash.inactive_previous_{d}_zero",
        .{index - 1},
    );
    if (index <= STATE_WIDTH + RATE) return std.fmt.bufPrint(
        buffer,
        "recursion.vm_public_claim_hash.inactive_chunk_{d}_zero",
        .{index - 1 - STATE_WIDTH},
    );
    if (index <= 2 * STATE_WIDTH + RATE) return std.fmt.bufPrint(
        buffer,
        "recursion.vm_public_claim_hash.inactive_output_{d}_zero",
        .{index - 1 - STATE_WIDTH - RATE},
    );
    if (index <= 3 * STATE_WIDTH + RATE) return std.fmt.bufPrint(
        buffer,
        "recursion.vm_public_claim_hash.initial_previous_{d}",
        .{index - 1 - 2 * STATE_WIDTH - RATE},
    );
    if (index < DIRECT_CONSTRAINT_COUNT) return std.fmt.bufPrint(
        buffer,
        "recursion.vm_public_claim_hash.fixed_chunk_{d}",
        .{index - 1 - 3 * STATE_WIDTH - RATE},
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
    if (STATE_WIDTH != 16 or RATE != 8 or
        PHYSICAL_MAIN_COLUMN_COUNT != 41 or PREPROCESSED_COLUMN_COUNT != 28 or
        PARAMETER_COUNT != 5 or LOGICAL_INPUT_COUNT != 74 or
        DIRECT_CONSTRAINT_COUNT != 65 or RELATION_EVENT_COUNT != 19 or
        INTERACTION_BATCH_COUNT != 10 or INTERACTION_COLUMN_COUNT != 40 or
        FRAMEWORK_CONSTRAINT_COUNT != 75)
    {
        @compileError("universal VM public-claim hash geometry drifted");
    }
}
