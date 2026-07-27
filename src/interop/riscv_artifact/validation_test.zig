const std = @import("std");
const schema = @import("schema.zig");
const validation = @import("validation.zig");
const digest = @import("digest.zig");
const protocol = @import("protocol.zig");
const preflight = @import("preflight.zig");

const AUIPC: u8 = 9;
const BASE_ALU_IMM: u8 = 1;
const RELEASE_STATUS = "not_release_gated";

const zero: schema.Qm31Wire = .{ 0, 0, 0, 0 };
const auipc_sums = [_]schema.Qm31Wire{zero} ** 4;
const immediate_sums = [_]schema.Qm31Wire{zero} ** 8;
const program_sums = [_]schema.Qm31Wire{zero} ** 3;
const merkle_sums = [_]schema.Qm31Wire{zero} ** 3;
const poseidon_sums = [_]schema.Qm31Wire{zero} ** 2;
const clock_sums = [_]schema.Qm31Wire{zero} ** 2;
const lookup_sums = [_]schema.Qm31Wire{zero};
const empty_output_words = [_]schema.OutputWordWire{
    .{ .addr = 0, .value = 0, .clock = 2 },
};

fn fixture() schema.Artifact {
    const components = struct {
        const values = [_]schema.ComponentWire{
            .{
                .index = 0,
                .family = AUIPC,
                .family_shard_index = 0,
                .family_shard_count = 1,
                .row_offset = 0,
                .log_size = 4,
                .n_rows = 1,
                .n_columns = protocol.familyByOrdinal(AUIPC).?.n_main_columns,
                .interaction_batch_count = 4,
            },
            .{
                .index = 1,
                .family = BASE_ALU_IMM,
                .family_shard_index = 0,
                .family_shard_count = 1,
                .row_offset = 0,
                .log_size = 4,
                .n_rows = 1,
                .n_columns = protocol.familyByOrdinal(BASE_ALU_IMM).?.n_main_columns,
                .interaction_batch_count = 8,
            },
        };
    }.values;
    const infrastructure = struct {
        const values = [_]schema.InfraComponentWire{
            infra(0, .program, 1, 1, 8),
            infra(1, .merkle, 4, 0, 10),
            infra(2, .poseidon2, 4, 0, 445),
            infra(3, .clock_update, 4, 0, 10),
            table(4, .bitwise),
            table(5, .range_check_20),
            table(6, .range_check_8_11),
            table(7, .range_check_8_8_4),
            table(8, .range_check_8_8),
            table(9, .range_check_m31),
        };
    }.values;
    const opcode_claims = struct {
        const values = [_]schema.OpcodeClaimWire{
            .{ .component_index = 0, .claimed_sums = &auipc_sums },
            .{ .component_index = 1, .claimed_sums = &immediate_sums },
        };
    }.values;
    const infra_claims = struct {
        const values = [_]schema.InfraClaimWire{
            .{ .infrastructure_index = 0, .claimed_sums = &program_sums },
            .{ .infrastructure_index = 1, .claimed_sums = &merkle_sums },
            .{ .infrastructure_index = 2, .claimed_sums = &poseidon_sums },
            .{ .infrastructure_index = 3, .claimed_sums = &clock_sums },
            .{ .infrastructure_index = 4, .claimed_sums = &lookup_sums },
            .{ .infrastructure_index = 5, .claimed_sums = &lookup_sums },
            .{ .infrastructure_index = 6, .claimed_sums = &lookup_sums },
            .{ .infrastructure_index = 7, .claimed_sums = &lookup_sums },
            .{ .infrastructure_index = 8, .claimed_sums = &lookup_sums },
            .{ .infrastructure_index = 9, .claimed_sums = &lookup_sums },
        };
    }.values;
    return .{
        .artifact_kind = schema.ARTIFACT_KIND,
        .schema_version = schema.SCHEMA_VERSION,
        .exchange_mode = schema.EXCHANGE_MODE,
        .release_status = RELEASE_STATUS,
        .generator = schema.GENERATOR,
        .air = schema.AIR,
        .backend = "cpu",
        .protocol = "functional",
        .source = .{
            .elf_sha256 = "00" ** 32,
            .input_sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        },
        .provenance = .{
            .oracle_repository = schema.ORACLE_REPOSITORY,
            .oracle_commit = schema.ORACLE_COMMIT,
            .implementation_repository = schema.IMPLEMENTATION_REPOSITORY,
            .implementation_commit = "22" ** 20,
            .implementation_dirty = true,
            .witness_layout_sha256 = "33" ** 32,
        },
        .pcs_config = .{
            .pow_bits = 10,
            .fri_config = .{
                .log_blowup_factor = 1,
                .log_last_layer_degree_bound = 0,
                .n_queries = 3,
            },
        },
        .statement = .{
            .segment_ordinal = 0,
            .segment_count = 1,
            .initial_pc = 4,
            .final_pc = 8,
            .total_steps = 2,
            .components = &components,
            .infrastructure = &infrastructure,
            .public_data = .{
                .initial_pc = 4,
                .final_pc = 8,
                .clock = 2,
                .initial_regs = .{0} ** 32,
                .final_regs = .{0} ** 32,
                .reg_last_clock = .{0} ** 32,
                .program_root = 7,
                .initial_rw_root = null,
                .final_rw_root = null,
                .completion = .{
                    .kind = .unretired_self_loop,
                    .address = 8,
                    .value = 0x0000_006f,
                    .clock = 0,
                },
                .input_start = 0,
                .input_len = 0,
                .input_words = &.{},
                .output_len = 0,
                .output_len_addr = 0,
                .output_data_addr = 0,
                .output_words = &empty_output_words,
            },
        },
        .interaction_claim = .{
            .interaction_pow = 0,
            .opcode_claims = &opcode_claims,
            .infrastructure_claims = &infra_claims,
        },
        .proof_bytes_hex = "00",
    };
}

fn infra(
    index: u32,
    kind: protocol.InfraKind,
    log_size: u32,
    n_rows: u32,
    n_columns: u32,
) schema.InfraComponentWire {
    return .{
        .index = index,
        .kind = @intFromEnum(kind),
        .log_size = log_size,
        .n_rows = n_rows,
        .n_columns = n_columns,
        .claim_count = protocol.claimCount(kind),
    };
}

fn table(index: u32, kind: protocol.InfraKind) schema.InfraComponentWire {
    for (protocol.TABLES) |metadata| {
        if (metadata.kind == kind) {
            return infra(index, kind, metadata.log_size, metadata.n_rows, 1);
        }
    }
    unreachable;
}

test "schema v4 accepts completion-bound indexed claims and exact PCS profiles" {
    const artifact = fixture();
    try validation.validate(artifact, RELEASE_STATUS);
    try validation.validateForPolicy(artifact, .functional, RELEASE_STATUS);
    try std.testing.expectError(
        error.SecurityPolicyMismatch,
        validation.validateForPolicy(artifact, .smoke, RELEASE_STATUS),
    );

    var drifted = artifact;
    drifted.pcs_config.pow_bits = 11;
    try std.testing.expectError(error.InvalidPcsProfile, validation.validate(drifted, RELEASE_STATUS));
}

test "schema v4 rejects non-canonical component order" {
    var artifact = fixture();
    var components = [_]schema.ComponentWire{
        artifact.statement.components[0],
        artifact.statement.components[1],
    };
    components[0].family = BASE_ALU_IMM;
    components[0].n_columns = protocol.familyByOrdinal(BASE_ALU_IMM).?.n_main_columns;
    components[0].interaction_batch_count = 8;
    components[1].family = AUIPC;
    components[1].n_columns = protocol.familyByOrdinal(AUIPC).?.n_main_columns;
    components[1].interaction_batch_count = 4;
    artifact.statement.components = &components;
    try std.testing.expectError(
        error.InvalidComponentOrder,
        validation.validate(artifact, RELEASE_STATUS),
    );
}

test "schema v4 rejects padded and misindexed claim arrays" {
    var artifact = fixture();
    var infra_claims = [_]schema.InfraClaimWire{
        artifact.interaction_claim.infrastructure_claims[0],
    } ++ artifact.interaction_claim.infrastructure_claims[1..10].*;
    const padded = [_]schema.Qm31Wire{zero} ** 4;
    infra_claims[0].claimed_sums = &padded;
    artifact.interaction_claim.infrastructure_claims = &infra_claims;
    try std.testing.expectError(
        error.InvalidInfrastructureClaim,
        validation.validate(artifact, RELEASE_STATUS),
    );

    artifact = fixture();
    var opcode_claims = [_]schema.OpcodeClaimWire{
        artifact.interaction_claim.opcode_claims[0],
        artifact.interaction_claim.opcode_claims[1],
    };
    opcode_claims[1].component_index = 0;
    artifact.interaction_claim.opcode_claims = &opcode_claims;
    try std.testing.expectError(error.InvalidOpcodeClaim, validation.validate(artifact, RELEASE_STATUS));
}

test "statement digest binds shard and exact claim geometry" {
    var artifact = fixture();
    const expected = digest.statement(
        artifact.protocol,
        artifact.pcs_config,
        artifact.source,
        artifact.statement,
    );
    var components = [_]schema.ComponentWire{
        artifact.statement.components[0],
        artifact.statement.components[1],
    };
    components[0].family_shard_count = 2;
    artifact.statement.components = &components;
    try std.testing.expect(!std.mem.eql(
        u8,
        &expected,
        &digest.statement(
            artifact.protocol,
            artifact.pcs_config,
            artifact.source,
            artifact.statement,
        ),
    ));

    artifact = fixture();
    artifact.source.elf_sha256 = "44" ** 32;
    try std.testing.expect(!std.mem.eql(
        u8,
        &expected,
        &digest.statement(
            artifact.protocol,
            artifact.pcs_config,
            artifact.source,
            artifact.statement,
        ),
    ));

    artifact = fixture();
    artifact.statement.segment_ordinal = 1;
    try std.testing.expect(!std.mem.eql(
        u8,
        &expected,
        &digest.statement(
            artifact.protocol,
            artifact.pcs_config,
            artifact.source,
            artifact.statement,
        ),
    ));

    artifact = fixture();
    artifact.protocol = "smoke";
    try std.testing.expect(!std.mem.eql(
        u8,
        &expected,
        &digest.statement(
            artifact.protocol,
            artifact.pcs_config,
            artifact.source,
            artifact.statement,
        ),
    ));

    artifact = fixture();
    artifact.pcs_config.pow_bits += 1;
    try std.testing.expect(!std.mem.eql(
        u8,
        &expected,
        &digest.statement(
            artifact.protocol,
            artifact.pcs_config,
            artifact.source,
            artifact.statement,
        ),
    ));

    artifact = fixture();
    artifact.statement.public_data.completion.address += 4;
    try std.testing.expect(!std.mem.eql(
        u8,
        &expected,
        &digest.statement(
            artifact.protocol,
            artifact.pcs_config,
            artifact.source,
            artifact.statement,
        ),
    ));
}

test "schema v4 validates build provenance and current segment geometry" {
    var artifact = fixture();
    artifact.provenance.implementation_commit = "AA" ** 20;
    try std.testing.expectError(
        error.InvalidImplementationCommit,
        validation.validate(artifact, RELEASE_STATUS),
    );

    artifact = fixture();
    artifact.provenance.witness_layout_sha256 = "33" ** 31;
    try std.testing.expectError(
        error.InvalidSha256,
        validation.validate(artifact, RELEASE_STATUS),
    );

    artifact = fixture();
    artifact.statement.segment_count = 2;
    try std.testing.expectError(
        error.InvalidSegmentGeometry,
        validation.validate(artifact, RELEASE_STATUS),
    );
}

test "schema v4 rejects an input digest unrelated to canonical public bytes" {
    var artifact = fixture();
    artifact.source.input_sha256 = "11" ** 32;
    try std.testing.expectError(
        error.InputDigestMismatch,
        validation.validate(artifact, RELEASE_STATUS),
    );
}

test "fixed-memory preflight accepts the canonical typed artifact" {
    const encoded = try std.json.Stringify.valueAlloc(std.testing.allocator, fixture(), .{});
    defer std.testing.allocator.free(encoded);
    try preflight.validate(encoded);
}

test "schema v4 rejects public data that production preflight rejects" {
    var artifact = fixture();
    artifact.statement.public_data.program_root = null;
    try std.testing.expectError(
        error.MissingProgramRoot,
        validation.validate(artifact, RELEASE_STATUS),
    );

    artifact = fixture();
    artifact.statement.public_data.reg_last_clock[4] = 4;
    try std.testing.expectError(
        error.InvalidRegisterClock,
        validation.validate(artifact, RELEASE_STATUS),
    );

    artifact = fixture();
    const input_words = [_]u32{0x0100_0001};
    artifact.statement.public_data.input_len = 1;
    artifact.statement.public_data.input_words = &input_words;
    try std.testing.expectError(
        error.NonCanonicalInputPadding,
        validation.validate(artifact, RELEASE_STATUS),
    );

    artifact = fixture();
    artifact.statement.public_data.output_words = &.{};
    try std.testing.expectError(
        error.InvalidOutputWords,
        validation.validate(artifact, RELEASE_STATUS),
    );

    artifact = fixture();
    artifact.statement.public_data.output_len_addr = 1;
    try std.testing.expectError(
        error.MisalignedOutputLengthAddress,
        validation.validate(artifact, RELEASE_STATUS),
    );
}

test "schema v4 accepts strict access subclocks beyond the instruction clock" {
    var artifact = fixture();
    artifact.statement.public_data.reg_last_clock[4] = 5;
    const output_words = [_]schema.OutputWordWire{
        .{ .addr = 0, .value = 0, .clock = 7 },
    };
    artifact.statement.public_data.output_words = &output_words;
    try validation.validate(artifact, RELEASE_STATUS);

    artifact.statement.public_data.reg_last_clock[4] = 9;
    try std.testing.expectError(
        error.InvalidRegisterClock,
        validation.validate(artifact, RELEASE_STATUS),
    );
}
