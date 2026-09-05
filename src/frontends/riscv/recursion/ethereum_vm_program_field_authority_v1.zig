//! Field-native authority for one cold-compiled Ethereum VM verifier program.
//!
//! SHA-256 identities remain useful transport checks, but a recursive proof
//! cannot treat their bytes as algebraic authority.  This module instead
//! Poseidon-hashes the exact canonical graph, bindings, protocol profile, and
//! numeric base/extension geometry.  A wrapper verifier reconstructs these
//! values from trusted typed semantics and commits the resulting two digests
//! in its preprocessed tree.

const std = @import("std");
const core = @import("stwo_core");

const graph = @import("air/composition_circuit.zig");
const extension_geometry_mod =
    @import("ethereum_composition_extension_geometry_v2.zig");
const program_mod = @import("ethereum_vm_composition_program_v2.zig");
const profile_mod = @import("vm_air_profile_v2.zig");
const protocol = @import("protocol.zig");
const channel = @import("poseidon2_channel.zig");

const M31 = core.fields.m31.M31;
const m31 = core.fields.m31;

pub const FORMAT_VERSION: u16 = 1;
pub const SCHEMA_VERSION: u16 = 1;
pub const PROGRAM_DIGEST_DOMAIN: u32 = 0x4550_4631; // "EPF1"
pub const MANIFEST_DIGEST_DOMAIN: u32 = 0x4550_4d31; // "EPM1"

pub const Error = error{
    ArithmeticOverflow,
    InvalidEthereumVmFieldAuthority,
    NonCanonicalFieldAuthorityWord,
};

/// Pointer-free public result.  It deliberately contains no SHA-256 field:
/// the two Poseidon digests are reconstructed from typed compiler inputs.
pub const AuthorityV1 = struct {
    format_version: u16 = FORMAT_VERSION,
    schema_version: u16 = SCHEMA_VERSION,
    program_word_count: u32,
    manifest_word_count: u32,
    verifier_program_authority: channel.Digest,
    component_manifest_authority: channel.Digest,

    pub fn validate(self: AuthorityV1) !void {
        if (self.format_version != FORMAT_VERSION or
            self.schema_version != SCHEMA_VERSION or
            self.program_word_count == 0 or self.manifest_word_count == 0)
        {
            return error.InvalidEthereumVmFieldAuthority;
        }
        try requireDigest(self.verifier_program_authority);
        try requireDigest(self.component_manifest_authority);
    }

    /// Cold re-admission always rebuilds both digests from the trusted
    /// compiler inputs.  A self-consistent retained value cannot select a
    /// graph, component roster, or protocol profile.
    pub fn validateAgainst(
        self: AuthorityV1,
        allocator: std.mem.Allocator,
        program: *const program_mod.EthereumVmCompositionProgramV2,
        input: program_mod.CompilerInputV2,
    ) !void {
        try self.validate();
        try program.validateAgainst(input);
        const expected = try deriveUnchecked(allocator, program, input);
        if (!std.meta.eql(self, expected))
            return error.InvalidEthereumVmFieldAuthority;
    }
};

pub fn compile(
    allocator: std.mem.Allocator,
    program: *const program_mod.EthereumVmCompositionProgramV2,
    input: program_mod.CompilerInputV2,
) !AuthorityV1 {
    try program.validateAgainst(input);
    const result = try deriveUnchecked(allocator, program, input);
    try result.validateAgainst(allocator, program, input);
    return result;
}

fn deriveUnchecked(
    allocator: std.mem.Allocator,
    program: *const program_mod.EthereumVmCompositionProgramV2,
    input: program_mod.CompilerInputV2,
) !AuthorityV1 {
    var extension = try extension_geometry_mod.GeometryV2.init(
        allocator,
        input.base_profile,
        input.core_statement,
        input.extension_statement,
    );
    defer extension.deinit();
    try extension.validateAgainst(
        input.base_profile,
        input.core_statement,
        input.extension_statement,
    );

    var program_encoder = Encoder.init(PROGRAM_DIGEST_DOMAIN);
    try encodeProgram(&program_encoder, program);
    const program_result = program_encoder.finalize();
    var manifest_encoder = Encoder.init(MANIFEST_DIGEST_DOMAIN);
    try manifest_encoder.digest(program_result.digest);
    try encodeBaseProfile(&manifest_encoder, input.base_profile);
    try encodeExtensionGeometry(&manifest_encoder, &extension);
    const manifest_result = manifest_encoder.finalize();
    const result = AuthorityV1{
        .program_word_count = program_result.word_count,
        .manifest_word_count = manifest_result.word_count,
        .verifier_program_authority = program_result.digest,
        .component_manifest_authority = manifest_result.digest,
    };
    try result.validate();
    return result;
}

fn encodeProgram(
    encoder: *Encoder,
    program: *const program_mod.EthereumVmCompositionProgramV2,
) !void {
    try encoder.word(FORMAT_VERSION);
    try encoder.word(SCHEMA_VERSION);
    try encoder.word(program.format_version);
    try encoder.word(program.schema_version);
    try encoder.word(program_mod.CIRCUIT_ID);
    try encodeInputProfile(encoder, program.input_profile);
    const profile = protocol.Profile{};
    try profile.validate();
    for (profile.words()) |word| try encoder.word(word);
    try encoder.digest(protocol.protocolId());

    try encoder.count(program.nodes.len);
    for (program.nodes) |node| try encodeNode(encoder, node);
    try encoder.count(program.outputs.len);
    for (program.outputs) |output| try encoder.word(output);
    try encoder.count(program.bindings.len);
    for (program.bindings) |binding| try encodeBinding(encoder, binding);
}

fn encodeNode(encoder: *Encoder, node: graph.Node) !void {
    var tag: u32 = undefined;
    var payload = [_]u32{0} ** 5;
    switch (node.op) {
        .input => tag = 1,
        .constant => |words| {
            tag = 2;
            @memcpy(payload[0..words.len], &words);
        },
        .add => |operands| {
            tag = 3;
            payload[0] = operands.lhs;
            payload[1] = operands.rhs;
        },
        .sub => |operands| {
            tag = 4;
            payload[0] = operands.lhs;
            payload[1] = operands.rhs;
        },
        .mul => |operands| {
            tag = 5;
            payload[0] = operands.lhs;
            payload[1] = operands.rhs;
        },
        .neg => |operand| {
            tag = 6;
            payload[0] = operand;
        },
        .inverse => |operand| {
            tag = 7;
            payload[0] = operand;
        },
    }
    try encoder.word(tag);
    for (payload) |word| try encoder.word(word);
}

fn encodeBinding(encoder: *Encoder, binding: graph.VmInputBinding) !void {
    try encoder.word(binding.node_id);
    var tag: u32 = undefined;
    var first: u32 = 0;
    var second: u32 = 0;
    switch (binding.source) {
        .segment_selector => tag = 1,
        .sampled_value => |coordinate| {
            tag = 2;
            first = coordinate.item_index;
            second = coordinate.word_index;
        },
        .claimed_sum => |coordinate| {
            tag = 3;
            first = coordinate.item_index;
            second = coordinate.word_index;
        },
        .relation_challenge => |coordinate| {
            tag = 4;
            first = coordinate.challenge;
            second = coordinate.word_index;
        },
        .composition_randomness => |word_index| {
            tag = 5;
            first = word_index;
        },
        .oods_point => |word_index| {
            tag = 6;
            first = word_index;
        },
        .transcript_claimed_sum => |coordinate| {
            tag = 7;
            first = coordinate.item_index;
            second = coordinate.word_index;
        },
    }
    try encoder.word(tag);
    try encoder.word(first);
    try encoder.word(second);
}

fn encodeBaseProfile(
    encoder: *Encoder,
    profile: *const profile_mod.ProfileV2,
) !void {
    try profile.validate();
    try encoder.word(profile.format_version);
    try encoder.word(profile.schema_version);
    try encoder.word(profile.lookup_statement_format_version);
    try encoder.word(profile.physical_component_count);
    try encoder.word(profile.preprocessed_column_count);
    try encoder.word(profile.main_column_count);
    try encoder.word(profile.interaction_column_count);
    try encoder.word(profile.air_instruction_count);
    try encoder.word(profile.input_profile.sampled_value_count);
    try encoder.word(profile.input_profile.claimed_sum_count);
    try encoder.word(profile.input_profile.relation_challenge_count);
    try encoder.word(profile.input_profile.transcript_claimed_sum_count);
    try encoder.word(profile.composition_log_split);
    try encoder.word(profile.composition_log_degree_bound);
    try encoder.word(profile.max_log_degree_bound);
    try encoder.count(profile.entries.len);
    for (profile.entries) |entry| try encodeProfileEntry(encoder, entry);
}

fn encodeProfileEntry(encoder: *Encoder, entry: profile_mod.EntryV2) !void {
    try encoder.word(entry.physical_index);
    try encoder.word(entry.shard_ordinal);
    try encoder.word(@intFromBool(entry.active));
    switch (entry.registry) {
        .opcode_semantic => |key| {
            try encoder.word(1);
            try encoder.word(@intFromEnum(key.descriptor.family));
            try encoder.word(key.descriptor.log_size);
            try encoder.word(key.descriptor.n_rows);
            try encoder.word(key.descriptor.n_columns);
        },
        .opcode_lookup => |key| {
            try encoder.word(2);
            try encoder.word(@intFromEnum(key.family));
            try encoder.word(0);
            try encoder.word(0);
            try encoder.word(0);
        },
        .infrastructure => |key| {
            try encoder.word(3);
            try encoder.word(@intFromEnum(key.kind));
            try encoder.word(@intFromEnum(key.adapter_kind));
            try encoder.word(0);
            try encoder.word(0);
        },
    }
    try encoder.word(entry.log_size);
    try encoder.word(entry.n_rows);
    inline for (.{ entry.preprocessed, entry.main, entry.interaction }) |span| {
        try encoder.word(span.offset);
        try encoder.word(span.sampled_columns);
        try encoder.word(span.declared_columns);
    }
    inline for (.{
        entry.constraint_count,
        entry.relation_event_count,
        entry.interaction_batch_count,
        entry.claimed_sum_offset,
        entry.claimed_sum_count,
        entry.max_constraint_log_degree_bound,
        entry.composition_log_split,
    }) |word| try encoder.word(word);
}

fn encodeExtensionGeometry(
    encoder: *Encoder,
    geometry: *const extension_geometry_mod.GeometryV2,
) !void {
    try geometry.validate();
    try encoder.word(geometry.format_version);
    try encoder.word(geometry.schema_version);
    for (geometry.base_column_counts) |word| try encoder.word(word);
    try encoder.count(geometry.components.len);
    for (geometry.components) |component| {
        try encoder.word(@intFromEnum(component.kind));
        try encoder.word(component.log_size);
        try encoder.word(component.n_rows);
        for (component.spans) |span| {
            try encoder.word(span.offset);
            try encoder.word(span.column_count);
        }
        try encoder.word(component.direct_constraint_count);
        try encoder.word(component.interaction_batch_count);
    }
    for (geometry.columns) |columns| {
        try encoder.count(columns.len);
        for (columns) |column| {
            try encoder.word(column.log_size);
            try encoder.word(column.sample_count);
            for (column.row_offsets) |offset| {
                const normalized = @as(i16, offset) + 128;
                try encoder.word(@as(u32, @intCast(normalized)));
            }
        }
    }
    try encoder.word(geometry.sampled_value_count);
    try encoder.word(geometry.detailed_claim_count);
    try encoder.word(geometry.air_instruction_count);
    try encoder.word(geometry.max_log_degree_bound);
}

fn encodeInputProfile(encoder: *Encoder, profile: graph.InputProfile) !void {
    inline for (.{
        profile.sampled_value_count,
        profile.claimed_sum_count,
        profile.relation_challenge_count,
        profile.transcript_claimed_sum_count,
        profile.public_wire_boundary_count,
    }) |word| try encoder.word(word);
}

const EncodedDigest = struct {
    digest: channel.Digest,
    word_count: u32,
};

const Encoder = struct {
    hasher: channel.CanonicalWordHasher,
    word_count: u32 = 0,

    fn init(domain: u32) Encoder {
        return .{ .hasher = channel.CanonicalWordHasher.init(domain) };
    }

    fn word(self: *Encoder, value: anytype) !void {
        const canonical = std.math.cast(u32, value) orelse
            return error.NonCanonicalFieldAuthorityWord;
        if (canonical >= m31.Modulus)
            return error.NonCanonicalFieldAuthorityWord;
        const words = [1]M31{M31.fromCanonical(canonical)};
        self.hasher.update(&words);
        self.word_count = std.math.add(u32, self.word_count, 1) catch
            return error.ArithmeticOverflow;
    }

    fn count(self: *Encoder, value: usize) !void {
        try self.word(std.math.cast(u32, value) orelse
            return error.ArithmeticOverflow);
    }

    fn digest(self: *Encoder, value: channel.Digest) !void {
        for (value) |element| try self.word(element);
    }

    fn finalize(self: *Encoder) EncodedDigest {
        return .{
            .digest = self.hasher.finalize(),
            .word_count = self.word_count,
        };
    }
};

fn requireDigest(value: channel.Digest) !void {
    var aggregate: u32 = 0;
    for (value) |word| {
        if (word >= m31.Modulus)
            return error.InvalidEthereumVmFieldAuthority;
        aggregate |= word;
    }
    if (aggregate == 0) return error.InvalidEthereumVmFieldAuthority;
}

comptime {
    if (PROGRAM_DIGEST_DOMAIN >= m31.Modulus or
        MANIFEST_DIGEST_DOMAIN >= m31.Modulus or
        program_mod.FORMAT_VERSION != 2 or program_mod.SCHEMA_VERSION != 1)
    {
        @compileError("Ethereum VM field-authority ABI drifted");
    }
}
