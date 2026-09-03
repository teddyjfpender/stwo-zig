//! Completion-bound public-semantics authority for the stage-102 role-0 leaf.
//!
//! Legacy recursive public semantics hardcode `jal x0, 0`.  A nonfinal V4
//! incremental leaf instead consumes the actual declared-program word at its
//! exit PC.  This module derives the exact Ethereum-profile program tuple
//! exclusively from a live stage-101 cold-verifier capability and evaluates
//! its challenge-dependent public boundary claim.  It is the typed input to
//! the role-0 row-16 circuit; no caller-supplied tuple or digest can mint it.

const std = @import("std");
const stwo_core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");

const field_public =
    @import("recursive_common_ethereum_incremental_leaf_field_public_v4.zig");
const input_mod =
    @import("recursive_common_ethereum_incremental_leaf_input_v4.zig");

const M31 = stwo_core.fields.m31.M31;
const QM31 = stwo_core.fields.qm31.QM31;
const relation_challenges = frontend.air.relation_challenges;
const arithmetic = frontend.recursion.arithmetic_circuit;

pub const FORMAT_VERSION: u16 = 4;
pub const SCHEMA_VERSION: u16 = 2;
pub const PROGRAM_TUPLE_ARITY: usize = 5;
pub const LEGACY_SELF_LOOP_ASSUMED = false;
pub const CALLER_AUTHORED_TUPLE_ADMITTED = false;
pub const AIR_ROW_OWNER_AVAILABLE = false;
pub const PRODUCTION_ACTIVATION = false;

const IDENTITY_DOMAIN =
    "stwo-zig/common-ethereum-incremental-public-semantics/v4-schema2\x00";
const PROGRAM_IDENTITY_DOMAIN =
    "stwo-zig/common-ethereum-incremental-public-semantics-program/v4-schema2\x00";

pub const Error = field_public.Error || error{
    EthereumIncrementalPublicSemanticsMismatchV4,
    ZeroDenominator,
};

pub const CircuitInputV4 = union(enum) {
    program_term_present,
    program_tuple: u3,
    relation_z,
    relation_alpha,
    claimed_sum,
};

pub const PreparedCircuitV4 = struct {
    allocator: std.mem.Allocator,
    inputs: [9]QM31,
    evaluation: arithmetic.Evaluation,

    pub fn deinit(self: *PreparedCircuitV4) void {
        self.evaluation.deinit();
        self.* = undefined;
    }

    pub fn validateAgainst(
        self: *const PreparedCircuitV4,
        circuit: *const CompletionProgramCircuitV4,
        value: *const CompletionProgramClaimV4,
    ) !void {
        const expected_inputs = try circuitInputs(value);
        if (!std.meta.eql(self.inputs, expected_inputs) or
            !try circuit.circuit.outputsAreZero(self.evaluation.values))
        {
            return error.EthereumIncrementalPublicSemanticsMismatchV4;
        }
    }
};

/// Exact arithmetic subgraph replacing the legacy constant-JAL term. Its
/// typed inputs are later lowered into the shared universal arithmetic rows;
/// both the activation boolean and `claimed_sum = -1 / denominator` are
/// constrained by graph outputs, not trusted as a host receipt.
pub const CompletionProgramCircuitV4 = struct {
    allocator: std.mem.Allocator,
    circuit: arithmetic.Circuit,
    sources: [9]CircuitInputV4,

    pub fn init(allocator: std.mem.Allocator) !CompletionProgramCircuitV4 {
        var builder = arithmetic.Builder.initDefault(allocator);
        errdefer builder.deinit();
        const active = try builder.input(0);
        var tuple_values: [PROGRAM_TUPLE_ARITY]arithmetic.Value = undefined;
        for (&tuple_values, 0..) |*value, index|
            value.* = try builder.input(@intCast(index + 1));
        const z = try builder.input(6);
        const alpha = try builder.input(7);
        const published_claim = try builder.input(8);

        var combined = arithmetic.Value.zero();
        var alpha_power = arithmetic.Value.one();
        for (tuple_values) |value| {
            combined = try builder.add(
                combined,
                try builder.mul(value, alpha_power),
            );
            alpha_power = try builder.mul(alpha_power, alpha);
        }
        const denominator = try builder.sub(combined, z);
        const selected = try builder.add(
            try builder.mul(active, denominator),
            try builder.sub(arithmetic.Value.one(), active),
        );
        const contribution = try builder.mul(
            active,
            try builder.inverse(selected),
        );
        _ = try builder.markOutput(try builder.mul(
            active,
            try builder.sub(active, arithmetic.Value.one()),
        ));
        _ = try builder.markOutput(try builder.add(
            published_claim,
            contribution,
        ));
        const circuit = try builder.finish();
        builder.deinit();
        const result = CompletionProgramCircuitV4{
            .allocator = allocator,
            .circuit = circuit,
            .sources = .{
                .program_term_present,
                .{ .program_tuple = 0 },
                .{ .program_tuple = 1 },
                .{ .program_tuple = 2 },
                .{ .program_tuple = 3 },
                .{ .program_tuple = 4 },
                .relation_z,
                .relation_alpha,
                .claimed_sum,
            },
        };
        try result.circuit.validate();
        return result;
    }

    pub fn deinit(self: *CompletionProgramCircuitV4) void {
        self.circuit.deinit();
        self.* = undefined;
    }

    pub fn prepare(
        self: *const CompletionProgramCircuitV4,
        allocator: std.mem.Allocator,
        value: *const CompletionProgramClaimV4,
    ) !PreparedCircuitV4 {
        const inputs = try circuitInputs(value);
        var evaluation = try self.circuit.evaluate(allocator, &inputs);
        errdefer evaluation.deinit();
        if (!try self.circuit.outputsAreZero(evaluation.values))
            return error.EthereumIncrementalPublicSemanticsMismatchV4;
        return .{
            .allocator = allocator,
            .inputs = inputs,
            .evaluation = evaluation,
        };
    }
};

fn circuitInputs(value: *const CompletionProgramClaimV4) ![9]QM31 {
    var inputs: [9]QM31 = undefined;
    inputs[0] = QM31.fromBase(M31.fromCanonical(
        value.completion.program_term_present,
    ));
    for (value.program_tuple, 0..) |word, index| {
        if (word >= stwo_core.fields.m31.Modulus)
            return error.EthereumIncrementalPublicSemanticsMismatchV4;
        inputs[index + 1] = QM31.fromBase(M31.fromCanonical(word));
    }
    inputs[6] = value.relation_z;
    inputs[7] = value.relation_alpha;
    inputs[8] = value.claimed_sum;
    return inputs;
}

pub const CompletionProgramClaimV4 = struct {
    format_version: u16 = FORMAT_VERSION,
    schema_version: u16 = SCHEMA_VERSION,
    completion: field_public.CompletionProjectionV4,
    program_tuple: [PROGRAM_TUPLE_ARITY]u32,
    relation_z: QM31,
    relation_alpha: QM31,
    claimed_sum: QM31,
    identity_sha256: [32]u8,

    pub fn init(
        comptime Engine: type,
        input: *const input_mod.FreshInputV4(Engine),
    ) !CompletionProgramClaimV4 {
        const source = try field_public.SourceAuthorityV4.seal(Engine, input);
        const relations = &input.stage101.relations.base;
        const result = try initProjected(source.completion, relations);
        try result.validateAgainst(Engine, input);
        return result;
    }

    pub fn validateAgainst(
        self: *const CompletionProgramClaimV4,
        comptime Engine: type,
        input: *const input_mod.FreshInputV4(Engine),
    ) !void {
        const source = try field_public.SourceAuthorityV4.seal(Engine, input);
        const relations = &input.stage101.relations.base;
        if (self.format_version != FORMAT_VERSION or
            self.schema_version != SCHEMA_VERSION or
            !std.meta.eql(self.completion, source.completion) or
            !std.meta.eql(self.program_tuple, tuple(source.completion)) or
            !self.relation_z.eql(relations.program_access.z) or
            !self.relation_alpha.eql(relations.program_access.alpha) or
            !self.claimed_sum.eql(try claim(source.completion, relations)) or
            !std.mem.eql(u8, &self.identity_sha256, &identity(self)))
        {
            return error.EthereumIncrementalPublicSemanticsMismatchV4;
        }
    }

    pub fn validateStructure(
        self: *const CompletionProgramClaimV4,
        relations: *const relation_challenges.Relations,
    ) !void {
        const expected = try initProjected(self.completion, relations);
        if (!std.meta.eql(self.*, expected))
            return error.EthereumIncrementalPublicSemanticsMismatchV4;
    }
};

/// Structural projection used by the role-0 row owner. For a halt boundary
/// `program_term_present` is zero and the claim is exactly zero; for both
/// unretired kinds it is the actual decoded word at the verified final PC.
pub fn tuple(
    completion: field_public.CompletionProjectionV4,
) [PROGRAM_TUPLE_ARITY]u32 {
    return .{
        limbsToU32(completion.address_limbs),
        completion.program_values[0],
        completion.program_values[1],
        completion.program_values[2],
        completion.program_values[3],
    };
}

pub fn claim(
    completion: field_public.CompletionProjectionV4,
    relations: *const relation_challenges.Relations,
) Error!QM31 {
    try completion.validate();
    if (completion.program_term_present == 0) return QM31.zero();
    const values = tuple(completion);
    var felt_values: [PROGRAM_TUPLE_ARITY]M31 = undefined;
    for (&felt_values, values) |*destination, value| {
        if (value >= stwo_core.fields.m31.Modulus)
            return error.EthereumIncrementalPublicSemanticsMismatchV4;
        destination.* = M31.fromCanonical(value);
    }
    return (relations.program_access.combineBase(felt_values).inv() catch
        return error.ZeroDenominator).neg();
}

pub fn requireAirRowOwner() Error!void {
    return error.EthereumIncrementalPublicSemanticsMismatchV4;
}

/// Circuit-program identity bound into the role-0 manifest. It names the
/// completion-selector, five-tuple denominator, and negative public-consume
/// equation; it is never accepted in lieu of the actual graph/evaluation.
pub fn programIdentity() [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(PROGRAM_IDENTITY_DOMAIN);
    hashInt(&hash, u16, FORMAT_VERSION);
    hashInt(&hash, u16, SCHEMA_VERSION);
    hashInt(&hash, u32, PROGRAM_TUPLE_ARITY);
    hashInt(&hash, u32, 9); // typed circuit input count
    hashInt(&hash, u32, 2); // boolean + claimed-sum closure outputs
    hashInt(&hash, u32, @intFromBool(LEGACY_SELF_LOOP_ASSUMED));
    return hash.finalResult();
}

/// Mutation-test seam only. Production construction remains `init`, which
/// first remints the projection from the live stage-101 verifier capability.
pub const testing = struct {
    pub fn initProjectedClaim(
        completion: field_public.CompletionProjectionV4,
        relations: *const relation_challenges.Relations,
    ) !CompletionProgramClaimV4 {
        return initProjected(completion, relations);
    }
};

fn initProjected(
    completion: field_public.CompletionProjectionV4,
    relations: *const relation_challenges.Relations,
) !CompletionProgramClaimV4 {
    try completion.validate();
    var result = CompletionProgramClaimV4{
        .completion = completion,
        .program_tuple = tuple(completion),
        .relation_z = relations.program_access.z,
        .relation_alpha = relations.program_access.alpha,
        .claimed_sum = try claim(completion, relations),
        .identity_sha256 = undefined,
    };
    result.identity_sha256 = identity(&result);
    return result;
}

fn identity(value: *const CompletionProgramClaimV4) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(IDENTITY_DOMAIN);
    hashInt(&hash, u16, value.format_version);
    hashInt(&hash, u16, value.schema_version);
    const completion_words = value.completion.words() catch
        return [_]u8{0} ** 32;
    for (completion_words) |word| hashInt(&hash, u32, word);
    for (value.program_tuple) |word| hashInt(&hash, u32, word);
    hashQm31(&hash, value.relation_z);
    hashQm31(&hash, value.relation_alpha);
    hashQm31(&hash, value.claimed_sum);
    return hash.finalResult();
}

fn limbsToU32(value: [2]u32) u32 {
    return value[0] | (value[1] << 16);
}

fn hashQm31(hash: anytype, value: QM31) void {
    for (value.toM31Array()) |limb| hashInt(hash, u32, limb.toU32());
}

fn hashInt(hash: anytype, comptime T: type, value: anytype) void {
    var encoded: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &encoded, @intCast(value), .little);
    hash.update(&encoded);
}

comptime {
    if (FORMAT_VERSION != 4 or SCHEMA_VERSION != 2 or
        PROGRAM_TUPLE_ARITY != 5 or LEGACY_SELF_LOOP_ASSUMED or
        CALLER_AUTHORED_TUPLE_ADMITTED or AIR_ROW_OWNER_AVAILABLE or
        PRODUCTION_ACTIVATION)
    {
        @compileError("Ethereum incremental public semantics V4 drifted");
    }
}
