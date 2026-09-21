//! Canonical postcard custody for one shared-transcript degree-five provider.
//!
//! Decoding is transport admission only.  The caller must feed the decoded
//! statement and proof to `verifyProviderFreshV1` with the exact full-core
//! source, ordered call list, plan, and Stage-A manifest before using a claim.

const std = @import("std");
const core = @import("stwo_core");
const postcard = @import("interop_postcard");
const frontend = @import("stwo_riscv_frontend");

const provider = frontend.testing
    .narrow_memory_provider_degree5_ethereum_omit_proof_v1;
const poseidon2_air = frontend.air.memory_commitment.poseidon2_air;
const guest = frontend.prover_mod.guest_precompile;
const statement_v2 = frontend.air.statement_v2;
const core_artifact = guest.ethereum_segment_poseidon2_proof_artifact;
const statement_wire = guest.ethereum_segment_artifact_statement_wire;

const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
const m31 = core.fields.m31;
const Sha256 = std.crypto.hash.sha2.Sha256;

pub const format_version: u16 = 1;
pub const schema_version: u16 = 1;
pub const magic = [8]u8{ 'S', 'T', 'W', 'D', '5', 'P', 'R', '1' };
pub const header_size: usize = 64;
pub const statement_size: usize = 370;
pub const metadata_size: usize = 32 + statement_size;
pub const composition_columns: u32 = 16;
pub const production_active = false;

pub const bundle_magic = [8]u8{ 'S', 'T', 'W', 'O', 'M', 'L', 'F', '1' };
pub const bundle_header_size: usize = 152;
pub const bundle_section_count: usize = 3;

pub const Limits = struct {
    max_artifact_bytes: usize = 256 * 1024 * 1024,
    max_proof_bytes: usize = 128 * 1024 * 1024,

    pub fn validate(self: Limits) !void {
        if (self.max_proof_bytes == 0 or
            self.max_artifact_bytes < header_size + metadata_size or
            self.max_proof_bytes > self.max_artifact_bytes)
        {
            return error.InvalidDegree5ProviderArtifactLimits;
        }
    }
};

pub fn Decoded(comptime Engine: type) type {
    return struct {
        execution_profile_identity: provider.Digest,
        statement: provider.ProviderStatementV1,
        proof: core.proof.StarkProof(Engine.Hasher),
        artifact_sha256: [32]u8,

        const Self = @This();

        pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
            self.proof.deinit(allocator);
            self.* = undefined;
        }

        pub fn deinitAfterProofMoved(self: *Self) void {
            self.* = undefined;
        }
    };
}

pub fn encodeAlloc(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    config: core.pcs.PcsConfig,
    execution_profile_identity: provider.Digest,
    statement: provider.ProviderStatementV1,
    proof: core.proof.StarkProof(Engine.Hasher),
    limits: Limits,
) ![]u8 {
    try limits.validate();
    try validateStatement(statement);
    try requireDigest(execution_profile_identity);
    if (!pcsConfigsEqual(config, proof.commitment_scheme_proof.config))
        return error.Degree5ProviderArtifactPcsMismatch;
    const shape = try proofShape(Engine, config, statement, limits);

    var proof_bytes: std.ArrayList(u8) = .empty;
    defer proof_bytes.deinit(allocator);
    try postcard.serializeProof(
        Engine.Hasher,
        proof_bytes.writer(allocator),
        proof,
    );
    if (proof_bytes.items.len == 0 or
        proof_bytes.items.len > limits.max_proof_bytes)
    {
        return error.Degree5ProviderProofResourceLimitExceeded;
    }
    try postcard.proof_preflight.validate(proof_bytes.items, shape);

    var statement_bytes: [statement_size]u8 = undefined;
    var statement_writer = Writer{ .bytes = &statement_bytes };
    statement_writer.statement(statement);
    std.debug.assert(statement_writer.at == statement_bytes.len);

    const total = std.math.add(
        usize,
        header_size + metadata_size,
        proof_bytes.items.len,
    ) catch return error.Degree5ProviderArtifactResourceLimitExceeded;
    if (total > limits.max_artifact_bytes)
        return error.Degree5ProviderArtifactResourceLimitExceeded;
    const output = try allocator.alloc(u8, total);
    errdefer allocator.free(output);
    @memcpy(output[header_size..][0..32], &execution_profile_identity);
    @memcpy(output[header_size + 32 ..][0..statement_size], &statement_bytes);
    @memcpy(output[header_size + metadata_size ..], proof_bytes.items);
    const payload_sha256 = sha256(output[header_size..]);
    var header_writer = Writer{ .bytes = output[0..header_size] };
    header_writer.bytesValue(&magic);
    header_writer.int(u16, format_version);
    header_writer.int(u16, schema_version);
    header_writer.int(u64, @intCast(total));
    header_writer.int(u32, metadata_size);
    header_writer.int(u64, @intCast(proof_bytes.items.len));
    header_writer.bytesValue(&payload_sha256);
    std.debug.assert(header_writer.at == header_size);
    return output;
}

pub fn decodeAlloc(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    bytes: []const u8,
    config: core.pcs.PcsConfig,
    limits: Limits,
) !Decoded(Engine) {
    try limits.validate();
    if (bytes.len < header_size + metadata_size or
        bytes.len > limits.max_artifact_bytes)
    {
        return error.InvalidDegree5ProviderArtifactLength;
    }
    var header = Reader{ .bytes = bytes[0..header_size] };
    if (!std.mem.eql(u8, try header.take(magic.len), &magic) or
        try header.int(u16) != format_version or
        try header.int(u16) != schema_version)
    {
        return error.InvalidDegree5ProviderArtifactHeader;
    }
    const encoded_total = try header.int(u64);
    const encoded_metadata = try header.int(u32);
    const encoded_proof = try header.int(u64);
    const payload_sha256 = try header.array(32);
    try header.done();
    if (encoded_total != @as(u64, @intCast(bytes.len)) or
        encoded_metadata != @as(u32, @intCast(metadata_size)) or
        encoded_proof == 0 or
        encoded_proof > @as(u64, @intCast(limits.max_proof_bytes)) or
        encoded_proof != @as(
            u64,
            @intCast(bytes.len - header_size - metadata_size),
        ) or
        !std.mem.eql(u8, &payload_sha256, &sha256(bytes[header_size..])))
    {
        return error.InvalidDegree5ProviderArtifactHeader;
    }

    var metadata = Reader{
        .bytes = bytes[header_size .. header_size + metadata_size],
    };
    const execution_profile_identity = try metadata.array(32);
    try requireDigest(execution_profile_identity);
    const statement = try metadata.statement();
    try metadata.done();
    try validateStatement(statement);
    const shape = try proofShape(Engine, config, statement, limits);
    const proof_bytes = bytes[header_size + metadata_size ..];
    try postcard.proof_preflight.validate(proof_bytes, shape);
    var stream = std.io.fixedBufferStream(proof_bytes);
    var proof = try postcard.deserializeProof(
        Engine.Hasher,
        allocator,
        stream.reader(),
    );
    errdefer proof.deinit(allocator);
    if (stream.pos != proof_bytes.len)
        return error.TrailingDegree5ProviderProofBytes;
    if (!pcsConfigsEqual(config, proof.commitment_scheme_proof.config))
        return error.Degree5ProviderArtifactPcsMismatch;
    return .{
        .execution_profile_identity = execution_profile_identity,
        .statement = statement,
        .proof = proof,
        .artifact_sha256 = sha256(bytes),
    };
}

pub fn proofShape(
    comptime Engine: type,
    config: core.pcs.PcsConfig,
    statement: provider.ProviderStatementV1,
    limits: Limits,
) !postcard.proof_preflight.Shape {
    try limits.validate();
    try validateStatement(statement);
    const hash_size = @sizeOf(Engine.Hasher.Hash);
    if (hash_size == 0 or hash_size % @sizeOf(u32) != 0)
        return error.InvalidDegree5ProviderProofHashWidth;
    return .{
        .config = .{
            .pow_bits = config.pow_bits,
            .log_blowup_factor = config.fri_config.log_blowup_factor,
            .n_queries = config.fri_config.n_queries,
            .log_last_layer_degree_bound = config.fri_config.log_last_layer_degree_bound,
            .fold_step = config.fri_config.fold_step,
            .lifting_log_size = config.lifting_log_size,
        },
        .tree_columns = .{
            2,
            statement.geometry.main_columns,
            statement.geometry.total_interaction_columns,
            composition_columns,
        },
        .max_column_log_size = statement.geometry.composition_log_size -
            statement.geometry.composition_log_split,
        .sample_width_limits = .{ 2, 6, 2, 1 },
        .hash_size = @intCast(hash_size),
        .hash_encoding = .canonical_m31_words,
        .max_wire_bytes = limits.max_proof_bytes,
    };
}

fn validateStatement(value: provider.ProviderStatementV1) !void {
    if (value.format != provider.format_version or value.call_count == 0 or
        value.log_size < 4 or value.log_size >= 30 or
        value.call_count > (@as(u32, 1) << @intCast(value.log_size)) or
        value.ordered_call_claim.first_call != value.first_call or
        value.ordered_call_claim.call_count != value.call_count or
        value.ordered_call_claim.format == 0 or
        !std.meta.eql(
            value.geometry,
            try provider.ProviderTree2GeometryV1.canonical(value.log_size),
        ) or value.geometry.main_columns != 239 or
        value.geometry.total_interaction_columns != provider.tree2_columns or
        value.geometry.composition_log_split != 2 or
        value.geometry.composition_log_size <
            value.geometry.composition_log_split)
    {
        return error.InvalidDegree5ProviderArtifactStatement;
    }
    _ = std.math.add(u64, value.first_call, value.call_count) catch
        return error.InvalidDegree5ProviderArtifactStatement;
    inline for (.{
        value.air_program_identity,
        value.plan_identity,
        value.manifest_identity,
        value.stage_a_identity,
        value.descriptor_identity,
        value.relation_context_identity,
        value.call_list_commitment,
        value.identity,
    }) |digest| try requireDigest(digest);
}

const Writer = struct {
    bytes: []u8,
    at: usize = 0,

    fn int(self: *Writer, comptime T: type, value: T) void {
        const destination: *[@sizeOf(T)]u8 =
            @ptrCast(self.bytes[self.at..].ptr);
        std.mem.writeInt(T, destination, value, .little);
        self.at += @sizeOf(T);
    }

    fn bytesValue(self: *Writer, value: []const u8) void {
        @memcpy(self.bytes[self.at..][0..value.len], value);
        self.at += value.len;
    }

    fn digest(self: *Writer, value: [32]u8) void {
        self.bytesValue(&value);
    }

    fn qm31(self: *Writer, value: QM31) void {
        for (value.toM31Array()) |limb| self.int(u32, limb.toU32());
    }

    fn statement(self: *Writer, value: provider.ProviderStatementV1) void {
        self.int(u32, value.format);
        inline for (.{
            value.air_program_identity,
            value.plan_identity,
            value.manifest_identity,
            value.stage_a_identity,
            value.descriptor_identity,
            value.relation_context_identity,
            value.call_list_commitment,
        }) |digest_value| self.digest(digest_value);
        self.int(u32, value.shard_index);
        self.int(u64, value.first_call);
        self.int(u32, value.call_count);
        self.int(u32, value.log_size);
        self.int(u16, value.geometry.main_columns);
        self.int(u16, value.geometry.poseidon_logup_columns);
        self.int(u16, value.geometry.ordered_call_columns);
        self.int(u16, value.geometry.total_interaction_columns);
        self.int(u16, value.geometry.direct_constraints);
        self.int(u16, value.geometry.logup_constraints);
        self.int(u16, value.geometry.ordered_call_constraints);
        self.int(u32, value.geometry.max_constraint_log_degree_bound);
        self.int(u32, value.geometry.composition_log_size);
        self.int(u32, value.geometry.composition_log_split);
        for (value.claims.sums) |claim| self.qm31(claim);
        self.int(u32, value.ordered_call_claim.format);
        self.int(u64, value.ordered_call_claim.first_call);
        self.int(u32, value.ordered_call_claim.call_count);
        self.qm31(value.ordered_call_claim.terminal);
        self.digest(value.identity);
    }
};

const Reader = struct {
    bytes: []const u8,
    at: usize = 0,

    fn take(self: *Reader, count: usize) ![]const u8 {
        const end = std.math.add(usize, self.at, count) catch
            return error.InvalidDegree5ProviderArtifactLength;
        if (end > self.bytes.len)
            return error.InvalidDegree5ProviderArtifactLength;
        const result = self.bytes[self.at..end];
        self.at = end;
        return result;
    }

    fn int(self: *Reader, comptime T: type) !T {
        const raw = try self.take(@sizeOf(T));
        const source: *const [@sizeOf(T)]u8 = @ptrCast(raw.ptr);
        return std.mem.readInt(T, source, .little);
    }

    fn array(self: *Reader, comptime count: usize) ![count]u8 {
        var result: [count]u8 = undefined;
        @memcpy(&result, try self.take(count));
        return result;
    }

    fn digest(self: *Reader) ![32]u8 {
        return self.array(32);
    }

    fn qm31(self: *Reader) !QM31 {
        var limbs: [4]M31 = undefined;
        for (&limbs) |*limb| {
            const raw = try self.int(u32);
            if (raw >= m31.Modulus) return error.NonCanonicalM31;
            limb.* = M31.fromCanonical(raw);
        }
        return QM31.fromM31Array(limbs);
    }

    fn statement(self: *Reader) !provider.ProviderStatementV1 {
        var result: provider.ProviderStatementV1 = undefined;
        result.format = try self.int(u32);
        result.air_program_identity = try self.digest();
        result.plan_identity = try self.digest();
        result.manifest_identity = try self.digest();
        result.stage_a_identity = try self.digest();
        result.descriptor_identity = try self.digest();
        result.relation_context_identity = try self.digest();
        result.call_list_commitment = try self.digest();
        result.shard_index = try self.int(u32);
        result.first_call = try self.int(u64);
        result.call_count = try self.int(u32);
        result.log_size = try self.int(u32);
        result.geometry = .{
            .main_columns = try self.int(u16),
            .poseidon_logup_columns = try self.int(u16),
            .ordered_call_columns = try self.int(u16),
            .total_interaction_columns = try self.int(u16),
            .direct_constraints = try self.int(u16),
            .logup_constraints = try self.int(u16),
            .ordered_call_constraints = try self.int(u16),
            .max_constraint_log_degree_bound = try self.int(u32),
            .composition_log_size = try self.int(u32),
            .composition_log_split = try self.int(u32),
        };
        for (&result.claims.sums) |*claim| claim.* = try self.qm31();
        result.ordered_call_claim = .{
            .format = try self.int(u32),
            .first_call = try self.int(u64),
            .call_count = try self.int(u32),
            .terminal = try self.qm31(),
        };
        result.identity = try self.digest();
        return result;
    }

    fn done(self: *Reader) !void {
        if (self.at != self.bytes.len)
            return error.TrailingDegree5ProviderArtifactBytes;
    }
};

fn requireDigest(value: [32]u8) !void {
    if (std.mem.allEqual(u8, &value, 0))
        return error.InvalidDegree5ProviderArtifactIdentity;
}

fn sha256(bytes: []const u8) [32]u8 {
    var hash = Sha256.init(.{});
    hash.update(bytes);
    return hash.finalResult();
}

fn pcsConfigsEqual(lhs: core.pcs.PcsConfig, rhs: core.pcs.PcsConfig) bool {
    return lhs.pow_bits == rhs.pow_bits and
        lhs.fri_config.log_blowup_factor == rhs.fri_config.log_blowup_factor and
        lhs.fri_config.n_queries == rhs.fri_config.n_queries and
        lhs.fri_config.log_last_layer_degree_bound ==
            rhs.fri_config.log_last_layer_degree_bound and
        lhs.fri_config.fold_step == rhs.fri_config.fold_step and
        lhs.lifting_log_size == rhs.lifting_log_size;
}

/// Resource limits for the parent omitted-leaf envelope. Child provider and
/// projected-core artifacts retain their own canonical decoders.
pub const BundleLimits = struct {
    max_bundle_bytes: usize = 2 * 1024 * 1024 * 1024,
    max_section_bytes: usize = 512 * 1024 * 1024,
    max_provider_count: usize = 4096,
    core: core_artifact.Limits = .{},
    provider: Limits = .{},

    pub fn validate(self: BundleLimits) !void {
        try self.core.validate();
        try self.provider.validate();
        if (self.max_bundle_bytes < bundle_header_size or
            self.max_section_bytes == 0 or self.max_provider_count == 0 or
            self.max_section_bytes > self.max_bundle_bytes)
        {
            return error.InvalidOmittedLeafBundleLimits;
        }
    }
};

pub const BundleEncodeInput = struct {
    authority_identity: [32]u8,
    full_statement: *const statement_v2.RiscVStatementV2,
    core_artifact_bytes: []const u8,
    provider_artifacts: []const []const u8,
};

pub fn BundleDecoded(comptime Engine: type) type {
    return struct {
        full: statement_wire.Owned,
        core: core_artifact.Decoded,
        providers: []Decoded(Engine),
        authority_identity: [32]u8,
        core_artifact_sha256: [32]u8,
        artifact_sha256: [32]u8,
        core_proof_moved: bool = false,
        provider_proofs_moved: usize = 0,

        pub fn deinit(self: *@This(), allocator: std.mem.Allocator) void {
            for (self.providers, 0..) |*item, index| {
                if (index < self.provider_proofs_moved)
                    item.deinitAfterProofMoved()
                else
                    item.deinit(allocator);
            }
            allocator.free(self.providers);
            if (self.core_proof_moved)
                self.core.deinitAfterProofMoved(allocator)
            else
                self.core.deinit(allocator);
            self.full.deinit(allocator);
            self.* = undefined;
        }
    };
}

pub fn encodeBundleAlloc(
    allocator: std.mem.Allocator,
    input: BundleEncodeInput,
    limits: BundleLimits,
) ![]u8 {
    try limits.validate();
    try input.full_statement.validate();
    if (std.mem.allEqual(u8, &input.authority_identity, 0) or
        input.provider_artifacts.len == 0 or
        input.provider_artifacts.len > limits.max_provider_count or
        input.core_artifact_bytes.len == 0 or
        input.core_artifact_bytes.len > limits.max_section_bytes)
    {
        return error.InvalidOmittedLeafBundleInput;
    }
    var full_section: std.ArrayList(u8) = .empty;
    defer full_section.deinit(allocator);
    try statement_wire.encode(
        full_section.writer(allocator),
        input.full_statement,
        limits.max_section_bytes,
    );
    var provider_section: std.ArrayList(u8) = .empty;
    defer provider_section.deinit(allocator);
    for (input.provider_artifacts) |artifact| {
        if (artifact.len == 0 or artifact.len > limits.provider.max_artifact_bytes)
            return error.InvalidOmittedLeafProviderArtifactLength;
        try appendInt(&provider_section, allocator, u64, @intCast(artifact.len));
        try provider_section.appendSlice(allocator, artifact);
    }
    const sections = [_][]const u8{
        full_section.items,
        input.core_artifact_bytes,
        provider_section.items,
    };
    return encodeBundleSectionsAlloc(
        allocator,
        input.authority_identity,
        @intCast(input.provider_artifacts.len),
        sections,
        limits,
    );
}

const BundleSections = struct {
    authority_identity: [32]u8,
    provider_count: usize,
    sections: [bundle_section_count][]const u8,
    artifact_sha256: [32]u8,
};

fn encodeBundleSectionsAlloc(
    allocator: std.mem.Allocator,
    authority_identity: [32]u8,
    provider_count: u32,
    sections: [bundle_section_count][]const u8,
    limits: BundleLimits,
) ![]u8 {
    var total = bundle_header_size;
    for (sections) |section| {
        if (section.len == 0 or section.len > limits.max_section_bytes)
            return error.OmittedLeafBundleResourceLimitExceeded;
        total = std.math.add(usize, total, section.len) catch
            return error.OmittedLeafBundleResourceLimitExceeded;
    }
    if (total > limits.max_bundle_bytes)
        return error.OmittedLeafBundleResourceLimitExceeded;
    const output = try allocator.alloc(u8, total);
    errdefer allocator.free(output);
    var at = bundle_header_size;
    for (sections) |section| {
        @memcpy(output[at..][0..section.len], section);
        at += section.len;
    }
    @memset(output[0..bundle_header_size], 0);
    var writer = Writer{ .bytes = output[0..bundle_header_size] };
    writer.bytesValue(&bundle_magic);
    writer.int(u16, format_version);
    writer.int(u16, schema_version);
    writer.int(u32, 0);
    writer.int(u64, @intCast(total));
    writer.int(u32, provider_count);
    writer.int(u32, 0);
    for (sections) |section| writer.int(u64, @intCast(section.len));
    writer.bytesValue(&authority_identity);
    writer.bytesValue(&sha256(output[bundle_header_size..]));
    return output;
}

fn parseBundleSections(
    bytes: []const u8,
    expected_authority_identity: [32]u8,
    expected_provider_count: usize,
    limits: BundleLimits,
) !BundleSections {
    try limits.validate();
    if (bytes.len < bundle_header_size or bytes.len > limits.max_bundle_bytes)
        return error.InvalidOmittedLeafBundleLength;
    var reader = Reader{ .bytes = bytes[0..bundle_header_size] };
    if (!std.mem.eql(u8, try reader.take(bundle_magic.len), &bundle_magic) or
        try reader.int(u16) != format_version or
        try reader.int(u16) != schema_version or try reader.int(u32) != 0)
    {
        return error.InvalidOmittedLeafBundleHeader;
    }
    const total = try reader.int(u64);
    const encoded_provider_count = try reader.int(u32);
    if (try reader.int(u32) != 0)
        return error.InvalidOmittedLeafBundleHeader;
    var lengths: [bundle_section_count]usize = undefined;
    for (&lengths) |*length| {
        length.* = std.math.cast(usize, try reader.int(u64)) orelse
            return error.InvalidOmittedLeafBundleLength;
    }
    const authority_identity = try reader.array(32);
    const payload_sha = try reader.array(32);
    if (!std.mem.allEqual(
        u8,
        try reader.take(bundle_header_size - reader.at),
        0,
    )) return error.InvalidOmittedLeafBundleHeader;
    const provider_count: usize = @intCast(encoded_provider_count);
    if (total != @as(u64, @intCast(bytes.len)) or
        provider_count != expected_provider_count or provider_count == 0 or
        provider_count > limits.max_provider_count or
        !std.mem.eql(u8, &authority_identity, &expected_authority_identity) or
        !std.mem.eql(u8, &payload_sha, &sha256(bytes[bundle_header_size..])))
    {
        return error.InvalidOmittedLeafBundleHeader;
    }
    var sections: [bundle_section_count][]const u8 = undefined;
    var at = bundle_header_size;
    for (lengths, &sections) |length, *section| {
        if (length == 0 or length > limits.max_section_bytes)
            return error.InvalidOmittedLeafBundleLength;
        const end = std.math.add(usize, at, length) catch
            return error.InvalidOmittedLeafBundleLength;
        if (end > bytes.len) return error.InvalidOmittedLeafBundleLength;
        section.* = bytes[at..end];
        at = end;
    }
    if (at != bytes.len) return error.InvalidOmittedLeafBundleLength;
    return .{
        .authority_identity = authority_identity,
        .provider_count = provider_count,
        .sections = sections,
        .artifact_sha256 = sha256(bytes),
    };
}

pub fn decodeBundleAlloc(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    bytes: []const u8,
    expected_authority_identity: [32]u8,
    expected_core_security_identity: [32]u8,
    expected_execution_profile_identity: [32]u8,
    expected_provider_count: usize,
    limits: BundleLimits,
) !BundleDecoded(Engine) {
    const frame = try parseBundleSections(
        bytes,
        expected_authority_identity,
        expected_provider_count,
        limits,
    );
    var full = try statement_wire.decode(
        allocator,
        frame.sections[0],
        limits.max_section_bytes,
    );
    errdefer full.deinit(allocator);
    var decoded_core = try core_artifact.decodeAlloc(
        allocator,
        frame.sections[1],
        expected_core_security_identity,
        limits.core,
    );
    errdefer decoded_core.deinit(allocator);
    const providers = try allocator.alloc(
        Decoded(Engine),
        frame.provider_count,
    );
    var providers_initialized: usize = 0;
    errdefer {
        for (providers[0..providers_initialized]) |*item| item.deinit(allocator);
        allocator.free(providers);
    }
    var provider_reader = Reader{ .bytes = frame.sections[2] };
    for (providers, 0..) |*item, index| {
        const length = std.math.cast(usize, try provider_reader.int(u64)) orelse
            return error.InvalidOmittedLeafProviderArtifactLength;
        item.* = try decodeAlloc(
            Engine,
            allocator,
            try provider_reader.take(length),
            core_artifact.pcs_config,
            limits.provider,
        );
        providers_initialized += 1;
        try validateProviderOrdinal(item.statement.shard_index, index);
        if (!std.mem.eql(
            u8,
            &item.execution_profile_identity,
            &expected_execution_profile_identity,
        )) return error.OmittedLeafProviderArtifactOrderMismatch;
    }
    try provider_reader.done();
    return .{
        .full = full,
        .core = decoded_core,
        .providers = providers,
        .authority_identity = frame.authority_identity,
        .core_artifact_sha256 = sha256(frame.sections[1]),
        .artifact_sha256 = frame.artifact_sha256,
    };
}

fn validateProviderOrdinal(actual: u32, expected: usize) !void {
    if (actual != std.math.cast(u32, expected))
        return error.OmittedLeafProviderArtifactOrderMismatch;
}

pub const testing = struct {
    pub const canonical_reserved_offset: usize = 12;

    pub fn encodeRawBundleAlloc(
        allocator: std.mem.Allocator,
        authority_identity: [32]u8,
        sections: [bundle_section_count][]const u8,
        provider_count: u32,
        limits: BundleLimits,
    ) ![]u8 {
        try limits.validate();
        if (std.mem.allEqual(u8, &authority_identity, 0) or
            provider_count == 0 or provider_count > limits.max_provider_count)
        {
            return error.InvalidOmittedLeafBundleInput;
        }
        return encodeBundleSectionsAlloc(
            allocator,
            authority_identity,
            provider_count,
            sections,
            limits,
        );
    }

    pub fn validateRawBundle(
        bytes: []const u8,
        expected_authority_identity: [32]u8,
        expected_provider_count: usize,
        limits: BundleLimits,
    ) !void {
        _ = try parseBundleSections(
            bytes,
            expected_authority_identity,
            expected_provider_count,
            limits,
        );
    }

    pub fn validateProviderOrder(ordinals: []const u32) !void {
        for (ordinals, 0..) |actual, expected|
            try validateProviderOrdinal(actual, expected);
    }
};

fn appendInt(
    list: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    comptime T: type,
    value: T,
) !void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, value, .little);
    try list.appendSlice(allocator, &bytes);
}

comptime {
    if (statement_size != 370 or metadata_size != 402 or
        provider.tree2_columns != 12 or poseidon2_air.N_SUMS != 2 or
        composition_columns != 4 * (@as(u32, 1) << 2))
    {
        @compileError("degree-five provider artifact geometry drifted");
    }
}
