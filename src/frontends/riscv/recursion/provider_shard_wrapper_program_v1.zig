//! Proof-independent dynamic-N compiler authority for the provider wrapper.
//!
//! The compiler cold-reopens every shard-local verifier program against one
//! typed provider plan and records their exact ordered field projections. It
//! deliberately does not claim a complete wrapper AIR program: the wrapper
//! rows, their deterministic preprocessed commitment, and a fresh wrapper
//! verifier do not exist yet. `PendingPreprocessedBindingV1` can retain an
//! exact candidate root for that next tranche, but can never mint production
//! authority.

const std = @import("std");
const core = @import("stwo_core");

const poseidon2_air = @import("../air/memory_commitment/poseidon2_air.zig");
const provider_authority =
    @import("../prover/memory_provider_shards/authority.zig");
const channel = @import("poseidon2_channel.zig");
const child_emitter = @import("provider_shard_child_field_emitter_v1.zig");
const child_program = @import("provider_shard_composition_program_v1.zig");

const M31 = core.fields.m31.M31;
const m31 = core.fields.m31;
const Sha256 = std.crypto.hash.sha2.Sha256;

pub const FORMAT_VERSION: u16 = 1;
pub const SCHEMA_VERSION: u16 = 1;
pub const CHILD_MANIFEST_DOMAIN: u32 = 0x5057_5031; // "PWP1"
pub const COMPILER_AUTHORITY_DOMAIN: u32 = 0x5057_5032; // "PWP2"
pub const PENDING_PREPROCESSED_DOMAIN: u32 = 0x5057_5033; // "PWP3"
pub const COMPLETE_WRAPPER_AIR_AVAILABLE = false;
pub const FRESH_WRAPPER_VERIFIER_AVAILABLE = false;
pub const PRODUCTION_ACTIVATION = false;

const TRANSPORT_DOMAIN =
    "stwo-zig/riscv/recursion/provider-wrapper-compiler-transport/v1\x00";

pub const ChildProgramInputV1 = struct {
    program: *const child_program.ProviderShardCompositionProgramV1,
    compiler_input: child_program.CompilerInputV1,
};

pub const CompilerInputV1 = struct {
    plan: *const provider_authority.ProviderShardPlanV1,
    calls: []const poseidon2_air.Call,
    children: []const ChildProgramInputV1,
};

/// Exact proof-independent schedule for one child verifier lane. The native
/// SHA identities are retained separately on `ProgramV1`; this row contains
/// only canonical field-native compiler semantics.
pub const ChildScheduleV1 = struct {
    ordinal: u32,
    first_call: u64,
    call_count: u32,
    log_size: u32,
    max_constraint_log_degree_bound: u32,
    composition_log_size: u32,
    composition_log_split: u32,
    program_word_count: u32,
    child_verifier_program_authority: channel.Digest,

    pub fn validate(self: ChildScheduleV1) !void {
        if (self.call_count == 0 or self.program_word_count == 0 or
            self.composition_log_size <= self.composition_log_split)
        {
            return error.InvalidProviderWrapperCompilerAuthority;
        }
        try requireDigest(self.child_verifier_program_authority);
    }
};

/// Owned, cold-recompilable compiler authority. This is not a complete AIR
/// program and therefore exposes no wrapper `air_program_identity` or wrapper
/// `verifier_program_authority`.
pub const ProgramV1 = struct {
    allocator: std.mem.Allocator,
    format_version: u16 = FORMAT_VERSION,
    schema_version: u16 = SCHEMA_VERSION,
    shard_count: u32,
    total_call_count: u64,
    residency_request_sha256: [32]u8,
    residency_plan_sha256: [32]u8,
    provider_plan_sha256: [32]u8,
    children: []ChildScheduleV1,
    child_manifest_word_count: u32,
    compiler_word_count: u32,
    ordered_child_program_manifest: channel.Digest,
    wrapper_compiler_authority: channel.Digest,
    transport_sha256: [32]u8,

    pub fn deinit(self: *ProgramV1) void {
        self.allocator.free(self.children);
        self.* = undefined;
    }

    /// Self-checks retained transport. Trusted admission must use
    /// `validateAgainst`, which reconstructs every row from typed inputs.
    pub fn validate(self: *const ProgramV1) !void {
        if (self.format_version != FORMAT_VERSION or
            self.schema_version != SCHEMA_VERSION or self.shard_count == 0 or
            self.total_call_count == 0 or self.children.len != self.shard_count or
            self.child_manifest_word_count == 0 or self.compiler_word_count == 0 or
            isZeroSha(self.residency_request_sha256) or
            isZeroSha(self.residency_plan_sha256) or
            isZeroSha(self.provider_plan_sha256) or
            isZeroSha(self.transport_sha256))
        {
            return error.InvalidProviderWrapperCompilerAuthority;
        }
        for (self.children, 0..) |child, index| {
            try child.validate();
            if (child.ordinal != index)
                return error.InvalidProviderWrapperCompilerAuthority;
        }
        const manifest = try encodeChildManifest(
            self.shard_count,
            self.total_call_count,
            self.children,
        );
        if (manifest.word_count != self.child_manifest_word_count or
            !std.meta.eql(manifest.digest, self.ordered_child_program_manifest))
        {
            return error.InvalidProviderWrapperCompilerAuthority;
        }
        const compiler = try encodeCompilerAuthority(
            self.shard_count,
            self.total_call_count,
            manifest.digest,
        );
        if (compiler.word_count != self.compiler_word_count or
            !std.meta.eql(compiler.digest, self.wrapper_compiler_authority))
        {
            return error.InvalidProviderWrapperCompilerAuthority;
        }
        if (!std.meta.eql(self.transport_sha256, transportIdentity(self)))
            return error.InvalidProviderWrapperCompilerAuthority;
    }

    pub fn validateAgainst(
        self: *const ProgramV1,
        input: CompilerInputV1,
    ) !void {
        try self.validate();
        var expected = try compile(self.allocator, input);
        defer expected.deinit();
        if (!programsEqual(self, &expected))
            return error.ProviderWrapperCompilerAuthorityMismatch;
    }

    pub fn requireCompleteWrapperAir(self: *const ProgramV1) !void {
        try self.validate();
        if (!COMPLETE_WRAPPER_AIR_AVAILABLE)
            return error.ProviderWrapperAirUnavailable;
    }
};

/// Exact candidate root paired with the cold compiler authority. It remains
/// pending because only the missing wrapper AIR compiler and fresh verifier
/// can prove that this is the deterministic Tree0 commitment.
pub const PendingPreprocessedBindingV1 = struct {
    format_version: u16 = FORMAT_VERSION,
    schema_version: u16 = SCHEMA_VERSION,
    wrapper_compiler_authority: channel.Digest,
    preprocessed_commitment_root: channel.Digest,
    pending_binding_authority: channel.Digest,

    pub fn validate(self: PendingPreprocessedBindingV1) !void {
        if (self.format_version != FORMAT_VERSION or
            self.schema_version != SCHEMA_VERSION)
        {
            return error.InvalidProviderWrapperPreprocessedBinding;
        }
        try requireDigest(self.wrapper_compiler_authority);
        try requireDigest(self.preprocessed_commitment_root);
        try requireDigest(self.pending_binding_authority);
        const expected = try bindingDigest(
            self.wrapper_compiler_authority,
            self.preprocessed_commitment_root,
        );
        if (!std.meta.eql(expected, self.pending_binding_authority))
            return error.InvalidProviderWrapperPreprocessedBinding;
    }

    pub fn validateAgainst(
        self: PendingPreprocessedBindingV1,
        program: *const ProgramV1,
        compiler_input: CompilerInputV1,
        expected_root: channel.Digest,
    ) !void {
        try self.validate();
        try program.validateAgainst(compiler_input);
        if (!std.meta.eql(
            self.wrapper_compiler_authority,
            program.wrapper_compiler_authority,
        ) or !std.meta.eql(self.preprocessed_commitment_root, expected_root)) {
            return error.ProviderWrapperPreprocessedBindingMismatch;
        }
    }

    pub fn requireFreshVerifierMint(
        self: PendingPreprocessedBindingV1,
    ) !void {
        try self.validate();
        if (!FRESH_WRAPPER_VERIFIER_AVAILABLE)
            return error.ProviderWrapperFreshVerifierUnavailable;
    }
};

pub fn compile(
    allocator: std.mem.Allocator,
    input: CompilerInputV1,
) !ProgramV1 {
    try validateCompilerInput(input);
    const children = try allocator.alloc(ChildScheduleV1, input.children.len);
    errdefer allocator.free(children);
    for (input.children, children, 0..) |child, *destination, index| {
        const geometry = child.program.geometry;
        const field_program = try child_emitter.compileProgramFieldAuthority(
            child.program,
            child.compiler_input,
        );
        destination.* = .{
            .ordinal = @intCast(index),
            .first_call = geometry.first_call,
            .call_count = geometry.call_count,
            .log_size = geometry.log_size,
            .max_constraint_log_degree_bound = geometry.max_constraint_log_degree_bound,
            .composition_log_size = geometry.composition_log_size,
            .composition_log_split = geometry.composition_log_split,
            .program_word_count = field_program.word_count,
            .child_verifier_program_authority = field_program.verifier_program_authority,
        };
    }
    const manifest = try encodeChildManifest(
        input.plan.shard_count,
        input.plan.total_call_count,
        children,
    );
    const compiler = try encodeCompilerAuthority(
        input.plan.shard_count,
        input.plan.total_call_count,
        manifest.digest,
    );
    var result = ProgramV1{
        .allocator = allocator,
        .shard_count = input.plan.shard_count,
        .total_call_count = input.plan.total_call_count,
        .residency_request_sha256 = input.plan.residency.result.request_identity,
        .residency_plan_sha256 = input.plan.residency.result.plan_identity,
        .provider_plan_sha256 = input.plan.identity,
        .children = children,
        .child_manifest_word_count = manifest.word_count,
        .compiler_word_count = compiler.word_count,
        .ordered_child_program_manifest = manifest.digest,
        .wrapper_compiler_authority = compiler.digest,
        .transport_sha256 = undefined,
    };
    result.transport_sha256 = transportIdentity(&result);
    try result.validate();
    return result;
}

pub fn bindPendingPreprocessedCommitment(
    program: *const ProgramV1,
    compiler_input: CompilerInputV1,
    preprocessed_commitment_root: channel.Digest,
) !PendingPreprocessedBindingV1 {
    try program.validateAgainst(compiler_input);
    try requireDigest(preprocessed_commitment_root);
    const result = PendingPreprocessedBindingV1{
        .wrapper_compiler_authority = program.wrapper_compiler_authority,
        .preprocessed_commitment_root = preprocessed_commitment_root,
        .pending_binding_authority = try bindingDigest(
            program.wrapper_compiler_authority,
            preprocessed_commitment_root,
        ),
    };
    try result.validateAgainst(program, compiler_input, preprocessed_commitment_root);
    return result;
}

fn validateCompilerInput(input: CompilerInputV1) !void {
    try input.plan.validate(input.calls);
    if (input.children.len == 0 or input.children.len != input.plan.shards.len)
        return error.InvalidProviderWrapperCompilerInput;
    for (input.children, 0..) |child, index| {
        const expected_index = std.math.cast(u32, index) orelse
            return error.InvalidProviderWrapperCompilerInput;
        if (child.compiler_input.shard_index != expected_index or
            child.compiler_input.plan.shards.len != input.plan.shards.len or
            !std.mem.eql(
                u8,
                &child.compiler_input.plan.identity,
                &input.plan.identity,
            ) or !callsEqual(child.compiler_input.calls, input.calls))
        {
            return error.InvalidProviderWrapperCompilerInput;
        }
        try child.program.validateAgainst(child.compiler_input);
    }
}

fn encodeChildManifest(
    shard_count: u32,
    total_call_count: u64,
    children: []const ChildScheduleV1,
) !EncodedDigest {
    var encoder = Encoder.init(CHILD_MANIFEST_DOMAIN);
    try encoder.word(FORMAT_VERSION);
    try encoder.word(SCHEMA_VERSION);
    try encoder.word(shard_count);
    try encoder.u64Value(total_call_count);
    try encoder.count(children.len);
    for (children) |child| {
        try encoder.word(child.ordinal);
        try encoder.u64Value(child.first_call);
        try encoder.word(child.call_count);
        try encoder.word(child.log_size);
        try encoder.word(child.max_constraint_log_degree_bound);
        try encoder.word(child.composition_log_size);
        try encoder.word(child.composition_log_split);
        try encoder.word(child.program_word_count);
        try encoder.digest(child.child_verifier_program_authority);
    }
    return encoder.finalize();
}

fn encodeCompilerAuthority(
    shard_count: u32,
    total_call_count: u64,
    child_manifest: channel.Digest,
) !EncodedDigest {
    var encoder = Encoder.init(COMPILER_AUTHORITY_DOMAIN);
    try encoder.word(FORMAT_VERSION);
    try encoder.word(SCHEMA_VERSION);
    try encoder.word(shard_count);
    try encoder.u64Value(total_call_count);
    try encoder.digest(child_manifest);
    try encoder.word(child_program.PREPROCESSED_COLUMN_COUNT);
    try encoder.word(child_program.MAIN_COLUMN_COUNT);
    try encoder.word(child_program.INTERACTION_COLUMN_COUNT);
    try encoder.word(child_program.COMPOSITION_COLUMN_COUNT);
    return encoder.finalize();
}

fn bindingDigest(
    compiler_authority: channel.Digest,
    root: channel.Digest,
) !channel.Digest {
    var encoder = Encoder.init(PENDING_PREPROCESSED_DOMAIN);
    try encoder.word(FORMAT_VERSION);
    try encoder.word(SCHEMA_VERSION);
    try encoder.digest(compiler_authority);
    try encoder.digest(root);
    return encoder.finalize().digest;
}

fn programsEqual(left: *const ProgramV1, right: *const ProgramV1) bool {
    if (left.shard_count != right.shard_count or
        left.total_call_count != right.total_call_count or
        !std.meta.eql(left.residency_request_sha256, right.residency_request_sha256) or
        !std.meta.eql(left.residency_plan_sha256, right.residency_plan_sha256) or
        !std.meta.eql(left.provider_plan_sha256, right.provider_plan_sha256) or
        left.child_manifest_word_count != right.child_manifest_word_count or
        left.compiler_word_count != right.compiler_word_count or
        !std.meta.eql(
            left.ordered_child_program_manifest,
            right.ordered_child_program_manifest,
        ) or !std.meta.eql(
        left.wrapper_compiler_authority,
        right.wrapper_compiler_authority,
    ) or !std.meta.eql(left.transport_sha256, right.transport_sha256) or
        left.children.len != right.children.len)
    {
        return false;
    }
    for (left.children, right.children) |a, b| if (!std.meta.eql(a, b))
        return false;
    return true;
}

fn callsEqual(
    left: []const poseidon2_air.Call,
    right: []const poseidon2_air.Call,
) bool {
    if (left.len != right.len) return false;
    for (left, right) |a, b| if (!std.meta.eql(a, b)) return false;
    return true;
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
            return error.NonCanonicalProviderWrapperCompilerWord;
        if (canonical >= m31.Modulus)
            return error.NonCanonicalProviderWrapperCompilerWord;
        self.hasher.update(&.{M31.fromCanonical(canonical)});
        self.word_count = std.math.add(u32, self.word_count, 1) catch
            return error.ProviderWrapperCompilerAuthorityOverflow;
    }

    fn count(self: *Encoder, value: usize) !void {
        try self.word(std.math.cast(u32, value) orelse
            return error.ProviderWrapperCompilerAuthorityOverflow);
    }

    fn u64Value(self: *Encoder, value: u64) !void {
        var remaining = value;
        for (0..5) |_| {
            try self.word(@as(u32, @intCast(remaining & 0x7fff)));
            remaining >>= 15;
        }
        if (remaining != 0)
            return error.NonCanonicalProviderWrapperCompilerWord;
    }

    fn digest(self: *Encoder, value: channel.Digest) !void {
        for (value) |limb| try self.word(limb);
    }

    fn finalize(self: *Encoder) EncodedDigest {
        return .{ .digest = self.hasher.finalize(), .word_count = self.word_count };
    }
};

fn requireDigest(value: channel.Digest) !void {
    var aggregate: u32 = 0;
    for (value) |word| {
        if (word >= m31.Modulus)
            return error.InvalidProviderWrapperCompilerAuthority;
        aggregate |= word;
    }
    if (aggregate == 0)
        return error.InvalidProviderWrapperCompilerAuthority;
}

fn isZeroSha(value: [32]u8) bool {
    return std.mem.allEqual(u8, &value, 0);
}

fn transportIdentity(program: *const ProgramV1) [32]u8 {
    var hash = Sha256.init(.{});
    hash.update(TRANSPORT_DOMAIN);
    hashInt(&hash, u16, program.format_version);
    hashInt(&hash, u16, program.schema_version);
    hashInt(&hash, u32, program.shard_count);
    hashInt(&hash, u64, program.total_call_count);
    hash.update(&program.residency_request_sha256);
    hash.update(&program.residency_plan_sha256);
    hash.update(&program.provider_plan_sha256);
    for (program.ordered_child_program_manifest) |word|
        hashInt(&hash, u32, word);
    for (program.wrapper_compiler_authority) |word|
        hashInt(&hash, u32, word);
    return hash.finalResult();
}

fn hashInt(hash: *Sha256, comptime T: type, value: anytype) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, @intCast(value), .little);
    hash.update(&bytes);
}

pub const testing = struct {
    /// Recomputes public field seals after a retained-row mutation. Cold
    /// validation against typed inputs must still reject the forged program.
    pub fn reseal(program: *ProgramV1) !void {
        const manifest = try encodeChildManifest(
            program.shard_count,
            program.total_call_count,
            program.children,
        );
        const compiler = try encodeCompilerAuthority(
            program.shard_count,
            program.total_call_count,
            manifest.digest,
        );
        program.child_manifest_word_count = manifest.word_count;
        program.compiler_word_count = compiler.word_count;
        program.ordered_child_program_manifest = manifest.digest;
        program.wrapper_compiler_authority = compiler.digest;
        program.transport_sha256 = transportIdentity(program);
    }
};

comptime {
    if (CHILD_MANIFEST_DOMAIN >= m31.Modulus or
        COMPILER_AUTHORITY_DOMAIN >= m31.Modulus or
        PENDING_PREPROCESSED_DOMAIN >= m31.Modulus or
        child_program.PREPROCESSED_COLUMN_COUNT != 2 or
        child_program.MAIN_COLUMN_COUNT != 445 or
        child_program.INTERACTION_COLUMN_COUNT != 12 or
        child_program.COMPOSITION_COLUMN_COUNT != 8 or
        COMPLETE_WRAPPER_AIR_AVAILABLE or FRESH_WRAPPER_VERIFIER_AVAILABLE or
        PRODUCTION_ACTIVATION)
    {
        @compileError("provider wrapper compiler authority ABI drifted");
    }
}
