//! Fail-closed validation for the RISC-V proof artifact wire.

const std = @import("std");
const schema = @import("schema.zig");
const protocol = @import("protocol.zig");

const M31_MODULUS: u32 = 0x7fff_ffff;
const MAX_OPCODE_SHARD_ROWS: u32 = 1 << 16;
const MAX_MEMORY_SHARD_ROWS: u32 = 1 << 16;

pub fn validate(artifact: schema.Artifact, release_status: []const u8) !void {
    try requireEqual(artifact.artifact_kind, schema.ARTIFACT_KIND, error.UnsupportedArtifactKind);
    if (artifact.schema_version != schema.SCHEMA_VERSION)
        return error.UnsupportedSchemaVersion;
    try requireEqual(artifact.exchange_mode, schema.EXCHANGE_MODE, error.UnsupportedExchangeMode);
    try requireEqual(artifact.release_status, release_status, error.InvalidReleaseStatus);
    try requireEqual(artifact.generator, schema.GENERATOR, error.UnsupportedGenerator);
    try requireEqual(artifact.air, schema.AIR, error.UnsupportedAir);
    try requireEqual(artifact.backend, "cpu", error.UnsupportedBackend);
    if (!isProtocol(artifact.protocol)) return error.UnsupportedProtocol;
    try requireEqual(
        artifact.provenance.oracle_repository,
        schema.ORACLE_REPOSITORY,
        error.UnsupportedOracleRepository,
    );
    try requireEqual(
        artifact.provenance.oracle_commit,
        schema.ORACLE_COMMIT,
        error.UnsupportedOracleCommit,
    );
    try requireEqual(
        artifact.provenance.implementation_repository,
        schema.IMPLEMENTATION_REPOSITORY,
        error.UnsupportedImplementationRepository,
    );
    try validateCommit(artifact.provenance.implementation_commit);
    try validateSha256(artifact.provenance.witness_layout_sha256);
    try validateSha256(artifact.source.elf_sha256);
    try validateSha256(artifact.source.input_sha256);
    try validatePcsConfig(artifact.protocol, artifact.pcs_config);
    try validateStatement(artifact.statement);
    try validateInputDigest(artifact.source.input_sha256, artifact.statement.public_data);
    try validateClaims(artifact.statement, artifact.interaction_claim);
    try validateProofHex(artifact.proof_bytes_hex);
}

pub fn validateForPolicy(
    artifact: schema.Artifact,
    policy: schema.SecurityPolicy,
    release_status: []const u8,
) !void {
    try validate(artifact, release_status);
    if (!std.mem.eql(u8, artifact.protocol, @tagName(policy)))
        return error.SecurityPolicyMismatch;
}

fn validatePcsConfig(profile: []const u8, actual: schema.PcsConfigWire) !void {
    const expected: schema.PcsConfigWire = if (std.mem.eql(u8, profile, "secure"))
        pcsProfile(26, 70)
    else if (std.mem.eql(u8, profile, "functional"))
        pcsProfile(10, 3)
    else if (std.mem.eql(u8, profile, "smoke"))
        pcsProfile(0, 3)
    else
        return error.UnsupportedProtocol;
    if (!std.meta.eql(expected, actual)) return error.InvalidPcsProfile;
}

fn pcsProfile(pow_bits: u32, n_queries: u64) schema.PcsConfigWire {
    return .{
        .pow_bits = pow_bits,
        .fri_config = .{
            .log_blowup_factor = 1,
            .log_last_layer_degree_bound = 0,
            .n_queries = n_queries,
            .fold_step = 1,
        },
        .lifting_log_size = null,
    };
}

fn validateStatement(statement: schema.StatementWire) !void {
    // The current production adapter emits one complete segment. Encoding the
    // coordinates now prevents an eventual multi-segment prover from changing
    // the expected-statement contract implicitly.
    if (statement.segment_ordinal != 0 or statement.segment_count != 1)
        return error.InvalidSegmentGeometry;
    if (statement.components.len == 0 or statement.components.len > schema.MAX_COMPONENTS)
        return error.InvalidComponentCount;
    if (statement.infrastructure.len < 10 or
        statement.infrastructure.len > schema.MAX_INFRA_COMPONENTS)
        return error.InvalidInfrastructureCount;
    if (statement.total_steps == 0 or statement.total_steps > schema.MAX_TOTAL_STEPS)
        return error.InvalidStepCount;
    if (statement.initial_pc != statement.public_data.initial_pc or
        statement.final_pc != statement.public_data.final_pc or
        statement.total_steps != statement.public_data.clock)
        return error.PublicDataMismatch;
    try validatePublicData(statement.public_data);

    var total_rows: u64 = 0;
    var index: usize = 0;
    var previous_family_rank: ?usize = null;
    while (index < statement.components.len) {
        const first = statement.components[index];
        const family = protocol.familyByOrdinal(first.family) orelse
            return error.InvalidComponentFamily;
        const family_rank = protocol.familyRank(first.family).?;
        if (previous_family_rank) |previous| {
            if (family_rank <= previous) return error.InvalidComponentOrder;
        }
        previous_family_rank = family_rank;

        var end = index + 1;
        while (end < statement.components.len and
            statement.components[end].family == first.family) : (end += 1)
        {}
        const shard_count = end - index;
        var row_offset: u32 = 0;
        for (statement.components[index..end], 0..) |component, shard_index| {
            if (component.index != index + shard_index or
                component.family_shard_index != shard_index or
                component.family_shard_count != shard_count or
                component.row_offset != row_offset)
                return error.InvalidComponentIdentity;
            try validateOpcodeGeometry(component, family);
            if (shard_index + 1 < shard_count and component.n_rows != MAX_OPCODE_SHARD_ROWS)
                return error.InvalidShardGeometry;
            row_offset = std.math.add(u32, row_offset, component.n_rows) catch
                return error.GeometryOverflow;
            total_rows = std.math.add(u64, total_rows, component.n_rows) catch
                return error.GeometryOverflow;
        }
        index = end;
    }
    if (total_rows != statement.total_steps) return error.StepCountMismatch;
    try validateInfrastructure(statement.infrastructure);
    try validateCellBudget(statement);
}

fn validateCommit(value: []const u8) !void {
    if (value.len != 40) return error.InvalidImplementationCommit;
    for (value) |byte| {
        if (!std.ascii.isDigit(byte) and !(byte >= 'a' and byte <= 'f'))
            return error.InvalidImplementationCommit;
    }
}

fn validateOpcodeGeometry(component: schema.ComponentWire, family: protocol.Family) !void {
    if (component.n_rows == 0 or component.n_rows > MAX_OPCODE_SHARD_ROWS or
        component.log_size != opcodeLogSize(component.n_rows) or
        component.n_columns != family.n_main_columns or
        component.interaction_batch_count != family.n_interaction_batches)
        return error.InvalidComponentGeometry;
}

fn validateInfrastructure(components: []const schema.InfraComponentWire) !void {
    for (components, 0..) |component, index| {
        if (component.index != index) return error.InvalidInfrastructureIdentity;
        const kind = std.meta.intToEnum(protocol.InfraKind, component.kind) catch
            return error.InvalidInfrastructureKind;
        if (component.claim_count != protocol.claimCount(kind))
            return error.InvalidInfrastructureClaimWidth;
    }

    const program = components[0];
    if (program.kind != @intFromEnum(protocol.InfraKind.program) or
        program.n_rows == 0 or
        program.log_size != computeLogSize(program.n_rows) or
        program.n_columns != protocol.mainColumns(.program))
        return error.InvalidProgramGeometry;

    var index: usize = 1;
    while (index < components.len and
        components[index].kind == @intFromEnum(protocol.InfraKind.memory)) : (index += 1)
    {
        const component = components[index];
        if (component.n_rows == 0 or component.n_rows > MAX_MEMORY_SHARD_ROWS or
            component.log_size != @max(@as(u32, 4), computeLogSize(component.n_rows)) or
            component.n_columns != protocol.mainColumns(.memory))
            return error.InvalidMemoryGeometry;
    }
    if (index + 3 + protocol.LOOKUP_TABLE_COUNT != components.len)
        return error.InvalidInfrastructureOrder;

    const merkle = components[index];
    const poseidon = components[index + 1];
    const clock_update = components[index + 2];
    try validateFlexibleInfra(
        merkle,
        .merkle,
        protocol.mainColumns(.merkle),
        error.InvalidMerkleGeometry,
    );
    try validateFlexibleInfra(
        poseidon,
        .poseidon2,
        protocol.mainColumns(.poseidon2),
        error.InvalidPoseidonGeometry,
    );
    try validateFlexibleInfra(
        clock_update,
        .clock_update,
        protocol.mainColumns(.clock_update),
        error.InvalidClockGeometry,
    );
    if (poseidon.n_rows != merkle.n_rows) return error.InvalidHashGeometry;
    index += 3;

    for (protocol.TABLES) |table| {
        const component = components[index];
        if (component.kind != @intFromEnum(table.kind) or
            component.log_size != table.log_size or
            component.n_rows != table.n_rows or
            component.n_columns != 1)
            return error.InvalidLookupTableGeometry;
        index += 1;
    }
}

fn validateFlexibleInfra(
    component: schema.InfraComponentWire,
    expected_kind: protocol.InfraKind,
    expected_columns: u32,
    comptime err: anyerror,
) !void {
    if (component.kind != @intFromEnum(expected_kind) or
        component.log_size != @max(@as(u32, 4), computeLogSize(component.n_rows)) or
        component.n_columns != expected_columns)
        return err;
}

fn validatePublicData(public: schema.PublicDataWire) !void {
    if (public.input_len > schema.MAX_IO_BYTES or public.output_len > schema.MAX_IO_BYTES)
        return error.IoLimitExceeded;
    if (public.program_root == null) return error.MissingProgramRoot;
    if ((public.initial_pc & 3) != 0 or (public.final_pc & 3) != 0)
        return error.MisalignedProgramCounter;
    if (public.initial_regs[0] != 0 or public.final_regs[0] != 0)
        return error.NonZeroX0;
    switch (public.completion.kind) {
        .halt_flag => {
            if ((public.completion.address & 3) != 0 or
                public.completion.address >= 0x7fff_fffc)
                return error.InvalidCompletionAddress;
            if (public.completion.value == 0)
                return error.InvalidCompletionValue;
            if (public.completion.clock == 0 or public.completion.clock > public.clock)
                return error.InvalidCompletionClock;
        },
        .unretired_self_loop => {
            if (public.completion.address != public.final_pc or
                public.completion.address > 0x3fff_fffc)
                return error.InvalidCompletionAddress;
            if (public.completion.value != 0x0000_006f)
                return error.InvalidCompletionValue;
            if (public.completion.clock != 0)
                return error.InvalidCompletionClock;
        },
    }
    for (public.reg_last_clock) |clock| {
        if (clock > public.clock) return error.InvalidRegisterClock;
    }

    const expected_input_words_u32 = std.math.divCeil(u32, public.input_len, 4) catch unreachable;
    const expected_input_words = std.math.cast(usize, expected_input_words_u32) orelse
        return error.GeometryOverflow;
    if (public.input_words.len != expected_input_words)
        return error.InvalidInputWords;
    if (public.output_words.len > schema.MAX_IO_BYTES / 4 + 1)
        return error.InvalidOutputWords;
    _ = std.math.add(u32, public.input_start, public.input_len) catch
        return error.AddressOverflow;
    if (public.input_words.len != 0) {
        const last_index = std.math.cast(u32, public.input_words.len - 1) orelse
            return error.AddressOverflow;
        const last_offset = std.math.mul(u32, last_index, 4) catch
            return error.AddressOverflow;
        _ = std.math.add(u32, public.input_start, last_offset) catch
            return error.AddressOverflow;
    }
    const used_input_bytes = public.input_len & 3;
    if (used_input_bytes != 0) {
        const used_bits: u5 = @intCast(used_input_bytes * 8);
        const used_mask = (@as(u32, 1) << used_bits) - 1;
        if ((public.input_words[public.input_words.len - 1] & ~used_mask) != 0)
            return error.NonCanonicalInputPadding;
    }

    if ((public.output_len_addr & 3) != 0) return error.MisalignedOutputLengthAddress;
    if ((public.output_data_addr & 3) != 0) return error.MisalignedOutputDataAddress;
    _ = std.math.add(u32, public.output_data_addr, public.output_len) catch
        return error.AddressOverflow;
    const data_words_u32 = std.math.divCeil(u32, public.output_len, 4) catch unreachable;
    const data_words = std.math.cast(usize, data_words_u32) orelse
        return error.GeometryOverflow;
    const expected_output_words = std.math.add(usize, data_words, 1) catch
        return error.GeometryOverflow;
    if (public.output_words.len != expected_output_words)
        return error.InvalidOutputWords;

    const length_word = public.output_words[0];
    if (length_word.addr != public.output_len_addr)
        return error.InvalidOutputWordAddress;
    if (length_word.value != public.output_len)
        return error.InvalidOutputLengthWord;
    try validateOutputClock(length_word.clock, public.clock);
    for (public.output_words[1..], 0..) |word, index| {
        const word_index = std.math.cast(u32, index) orelse
            return error.AddressOverflow;
        const offset = std.math.mul(u32, word_index, 4) catch
            return error.AddressOverflow;
        const expected_addr = std.math.add(u32, public.output_data_addr, offset) catch
            return error.AddressOverflow;
        if (expected_addr == public.output_len_addr)
            return error.OverlappingOutputRegions;
        if (word.addr != expected_addr)
            return error.InvalidOutputWordAddress;
        try validateOutputClock(word.clock, public.clock);
    }
}

fn validateOutputClock(clock: u32, final_clock: u32) !void {
    if (clock == 0 or clock > final_clock) return error.InvalidOutputClock;
}

fn validateCellBudget(statement: schema.StatementWire) !void {
    var cells: u64 = 0;
    for (statement.components) |component| {
        const domain = try domainSize(component.log_size);
        const columns = std.math.add(
            u64,
            2 + component.n_columns,
            4 * @as(u64, component.interaction_batch_count),
        ) catch return error.GeometryOverflow;
        cells = try checkedCellAdd(cells, domain, columns);
    }
    for (statement.infrastructure) |component| {
        const kind = std.meta.intToEnum(protocol.InfraKind, component.kind) catch
            return error.InvalidInfrastructureKind;
        const domain = try domainSize(component.log_size);
        const columns = std.math.add(
            u64,
            protocol.preprocessedColumns(kind) + component.n_columns,
            4 * @as(u64, component.claim_count),
        ) catch return error.GeometryOverflow;
        cells = try checkedCellAdd(cells, domain, columns);
    }
}

fn checkedCellAdd(current: u64, domain: u64, columns: u64) !u64 {
    const component_cells = std.math.mul(u64, domain, columns) catch
        return error.GeometryOverflow;
    const result = std.math.add(u64, current, component_cells) catch
        return error.GeometryOverflow;
    if (result > schema.MAX_COMMITTED_CELLS) return error.TraceCellLimitExceeded;
    return result;
}

fn domainSize(log_size: u32) !u64 {
    if (log_size == 0 or log_size > schema.MAX_DOMAIN_LOG_SIZE)
        return error.InvalidDomainLogSize;
    return @as(u64, 1) << @intCast(log_size);
}

fn validateClaims(statement: schema.StatementWire, claims: schema.InteractionClaimWire) !void {
    if (claims.opcode_claims.len != statement.components.len or
        claims.infrastructure_claims.len != statement.infrastructure.len)
        return error.InvalidInteractionClaimCount;
    for (claims.opcode_claims, statement.components, 0..) |claim, component, index| {
        if (claim.component_index != index or
            claim.claimed_sums.len != component.interaction_batch_count)
            return error.InvalidOpcodeClaim;
        for (claim.claimed_sums) |sum| try validateQm31(sum);
    }
    for (claims.infrastructure_claims, statement.infrastructure, 0..) |claim, component, index| {
        if (claim.infrastructure_index != index or
            claim.claimed_sums.len != component.claim_count)
            return error.InvalidInfrastructureClaim;
        for (claim.claimed_sums) |sum| try validateQm31(sum);
    }
}

fn validateQm31(value: schema.Qm31Wire) !void {
    for (value) |coefficient| {
        if (coefficient >= M31_MODULUS) return error.NonCanonicalM31;
    }
}

fn validateSha256(value: []const u8) !void {
    if (value.len != 64) return error.InvalidSha256;
    var decoded: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&decoded, value) catch return error.InvalidSha256;
    const canonical = std.fmt.bytesToHex(decoded, .lower);
    if (!std.mem.eql(u8, value, &canonical)) return error.InvalidSha256;
}

fn validateInputDigest(expected: []const u8, public: schema.PublicDataWire) !void {
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    var remaining = public.input_len;
    for (public.input_words) |word_value| {
        var word_bytes: [4]u8 = undefined;
        std.mem.writeInt(u32, &word_bytes, word_value, .little);
        const take: usize = @intCast(@min(remaining, 4));
        hasher.update(word_bytes[0..take]);
        remaining -= @intCast(take);
    }
    if (remaining != 0) return error.InputDigestMismatch;
    const actual = std.fmt.bytesToHex(hasher.finalResult(), .lower);
    if (!std.mem.eql(u8, expected, &actual)) return error.InputDigestMismatch;
}

fn validateProofHex(value: []const u8) !void {
    if (value.len == 0 or (value.len & 1) != 0 or value.len > schema.MAX_PROOF_BYTES * 2)
        return error.InvalidProofPayload;
    for (value) |byte| {
        if (!std.ascii.isDigit(byte) and !(byte >= 'a' and byte <= 'f'))
            return error.InvalidProofPayload;
    }
}

fn opcodeLogSize(count: u32) u32 {
    return @max(@as(u32, 4), computeLogSize(count));
}

fn computeLogSize(count: u32) u32 {
    if (count <= 1) return 1;
    return @intCast(std.math.log2_int_ceil(u32, count));
}

fn isProtocol(value: []const u8) bool {
    return std.mem.eql(u8, value, "secure") or
        std.mem.eql(u8, value, "functional") or
        std.mem.eql(u8, value, "smoke");
}

fn requireEqual(actual: []const u8, expected: []const u8, comptime err: anyerror) !void {
    if (!std.mem.eql(u8, actual, expected)) return err;
}
