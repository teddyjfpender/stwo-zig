const std = @import("std");
const fri = @import("stwo_core").fri;
const m31 = @import("stwo_core").fields.m31;
const qm31 = @import("stwo_core").fields.qm31;
const pcs = @import("stwo_core").pcs;
const blake = @import("../examples/blake.zig");
const poseidon = @import("../examples/poseidon.zig");
const plonk = @import("../examples/plonk.zig");
const plonk_logup = @import("../examples/plonk_logup.zig");
const state_machine = @import("../examples/state_machine.zig");
const wide_fibonacci = @import("../examples/wide_fibonacci.zig");
const xor = @import("../examples/xor.zig");
const proof_wire = @import("stwo_proof_wire");
const atomic_file = @import("atomic_file.zig");

const M31 = m31.M31;
const QM31 = qm31.QM31;

pub const SCHEMA_VERSION: u32 = 1;
pub const UPSTREAM_COMMIT: []const u8 = "a8fcf4bdde3778ae72f1e6cfe61a38e2911648d2";
pub const EXCHANGE_MODE: []const u8 = "proof_exchange_json_wire_v1";
pub const MAX_ARTIFACT_BYTES: usize = 256 * 1024 * 1024;
pub const MAX_PROOF_BYTES: usize = 128 * 1024 * 1024;

pub const PcsConfigWire = proof_wire.PcsConfigWire;
pub const Qm31Wire = proof_wire.Qm31Wire;

pub const StateMachineStatementWire = struct {
    public_input: [2][2]u32,
    stmt0: struct {
        n: u32,
        m: u32,
    },
    stmt1: struct {
        x_axis_claimed_sum: Qm31Wire,
        y_axis_claimed_sum: Qm31Wire,
    },
};

pub const XorStatementWire = struct {
    log_size: u32,
    log_step: u32,
    offset: u64,
    claimed_sum: Qm31Wire = .{0} ** 4,
};

pub const WideFibonacciStatementWire = struct {
    log_n_rows: u32,
    sequence_len: u32,
};

pub const PlonkStatementWire = struct {
    log_n_rows: u32,
};

pub const PlonkLogupStatementWire = struct {
    log_n_rows: u32,
    claimed_sum: Qm31Wire,
};

pub const PoseidonStatementWire = struct {
    log_n_instances: u32,
    claimed_sum: Qm31Wire = .{0} ** 4,
};

pub const BlakeStatement0Wire = struct {
    log_size: u32,
};

pub const BlakeStatement1Wire = struct {
    scheduler_claimed_sum: Qm31Wire,
    round_claimed_sums: [2]Qm31Wire,
    xor_claimed_sums: [5]Qm31Wire,
};

pub const BlakeStatementWire = struct {
    stmt0: BlakeStatement0Wire,
    stmt1: BlakeStatement1Wire,
};

pub const InteropArtifact = struct {
    schema_version: u32,
    upstream_commit: []const u8,
    exchange_mode: []const u8,
    generator: []const u8,
    example: []const u8,
    prove_mode: ?[]const u8 = null,
    pcs_config: PcsConfigWire,
    blake_statement: ?BlakeStatementWire = null,
    plonk_statement: ?PlonkStatementWire = null,
    plonk_logup_statement: ?PlonkLogupStatementWire = null,
    poseidon_statement: ?PoseidonStatementWire = null,
    state_machine_statement: ?StateMachineStatementWire = null,
    wide_fibonacci_statement: ?WideFibonacciStatementWire = null,
    xor_statement: ?XorStatementWire = null,
    proof_bytes_hex: []const u8,
};

pub const NativeStatement = union(enum) {
    blake: blake.Statement,
    plonk: plonk.Statement,
    plonk_logup: plonk_logup.Statement,
    poseidon: poseidon.Statement,
    state_machine: state_machine.PreparedStatement,
    wide_fibonacci: wide_fibonacci.Statement,
    xor: xor.Statement,
};

pub const ArtifactError = error{
    InvalidHexLength,
    InvalidHexDigit,
    NonCanonicalM31,
    ProofTooLarge,
    ValueOutOfRange,
};

pub fn writeArtifact(
    allocator: std.mem.Allocator,
    path: []const u8,
    artifact: InteropArtifact,
) !void {
    const rendered = try std.json.Stringify.valueAlloc(allocator, artifact, .{});
    defer allocator.free(rendered);

    const output = try std.mem.concat(allocator, u8, &.{ rendered, "\n" });
    defer allocator.free(output);
    try atomic_file.writeExclusive(allocator, path, output);
}

/// Writes the canonical proof-exchange artifact used by native suite lanes.
pub fn writeNativeProofArtifact(
    allocator: std.mem.Allocator,
    path: []const u8,
    config: pcs.PcsConfig,
    prove_mode: []const u8,
    statement: NativeStatement,
    proof_bytes: []const u8,
) !void {
    const proof_bytes_hex = try bytesToHexAlloc(allocator, proof_bytes);
    defer allocator.free(proof_bytes_hex);

    var artifact = InteropArtifact{
        .schema_version = SCHEMA_VERSION,
        .upstream_commit = UPSTREAM_COMMIT,
        .exchange_mode = EXCHANGE_MODE,
        .generator = "zig",
        .example = undefined,
        .prove_mode = prove_mode,
        .pcs_config = pcsConfigToWire(config),
        .proof_bytes_hex = proof_bytes_hex,
    };
    switch (statement) {
        .blake => |value| {
            artifact.example = "blake";
            artifact.blake_statement = blakeStatementToWire(value);
        },
        .plonk => |value| {
            artifact.example = "plonk";
            artifact.plonk_statement = plonkStatementToWire(value);
        },
        .plonk_logup => |value| {
            artifact.example = "plonk_logup";
            artifact.plonk_logup_statement = plonkLogupStatementToWire(value);
        },
        .poseidon => |value| {
            artifact.example = "poseidon";
            artifact.poseidon_statement = poseidonStatementToWire(value);
        },
        .state_machine => |value| {
            artifact.example = "state_machine";
            artifact.state_machine_statement = stateMachineStatementToWire(value);
        },
        .wide_fibonacci => |value| {
            artifact.example = "wide_fibonacci";
            artifact.wide_fibonacci_statement = wideFibonacciStatementToWire(value);
        },
        .xor => |value| {
            artifact.example = "xor";
            artifact.xor_statement = xorStatementToWire(value);
        },
    }
    try writeArtifact(allocator, path, artifact);
}

pub fn readArtifact(allocator: std.mem.Allocator, path: []const u8) !std.json.Parsed(InteropArtifact) {
    const raw = try std.fs.cwd().readFileAlloc(allocator, path, MAX_ARTIFACT_BYTES);
    defer allocator.free(raw);

    return parseArtifact(allocator, raw);
}

pub fn parseArtifact(allocator: std.mem.Allocator, raw: []const u8) !std.json.Parsed(InteropArtifact) {
    if (raw.len > MAX_ARTIFACT_BYTES) return error.StreamTooLong;
    return std.json.parseFromSlice(InteropArtifact, allocator, raw, .{
        .ignore_unknown_fields = false,
        .allocate = .alloc_always,
    });
}

pub fn bytesToHexAlloc(allocator: std.mem.Allocator, bytes: []const u8) ![]u8 {
    if (bytes.len > MAX_PROOF_BYTES) return error.ProofTooLarge;
    const encoded_len = try std.math.mul(usize, bytes.len, 2);
    const out = try allocator.alloc(u8, encoded_len);
    const alphabet = "0123456789abcdef";
    for (bytes, 0..) |byte, i| {
        out[2 * i] = alphabet[byte >> 4];
        out[2 * i + 1] = alphabet[byte & 0x0f];
    }
    return out;
}

pub fn hexToBytesAlloc(
    allocator: std.mem.Allocator,
    hex: []const u8,
) (std.mem.Allocator.Error || ArtifactError)![]u8 {
    if ((hex.len & 1) != 0) return ArtifactError.InvalidHexLength;
    if (hex.len > MAX_PROOF_BYTES * 2) return ArtifactError.ProofTooLarge;

    const out = try allocator.alloc(u8, hex.len / 2);
    errdefer allocator.free(out);
    _ = std.fmt.hexToBytes(out, hex) catch return ArtifactError.InvalidHexDigit;
    return out;
}

pub fn pcsConfigToWire(config: pcs.PcsConfig) PcsConfigWire {
    return .{
        .pow_bits = config.pow_bits,
        .fri_config = .{
            .log_blowup_factor = config.fri_config.log_blowup_factor,
            .log_last_layer_degree_bound = config.fri_config.log_last_layer_degree_bound,
            .n_queries = config.fri_config.n_queries,
            .fold_step = config.fri_config.fold_step,
        },
        .lifting_log_size = config.lifting_log_size,
    };
}

pub fn pcsConfigFromWire(wire: PcsConfigWire) !pcs.PcsConfig {
    if (wire.fri_config.n_queries > std.math.maxInt(usize)) return ArtifactError.ValueOutOfRange;
    var fri_config = try fri.FriConfig.init(
        wire.fri_config.log_last_layer_degree_bound,
        wire.fri_config.log_blowup_factor,
        @intCast(wire.fri_config.n_queries),
    );
    fri_config.fold_step = wire.fri_config.fold_step;
    return .{
        .pow_bits = wire.pow_bits,
        .fri_config = fri_config,
        .lifting_log_size = wire.lifting_log_size,
    };
}

pub fn pcsConfigsEqual(expected: pcs.PcsConfig, actual: pcs.PcsConfig) bool {
    return expected.pow_bits == actual.pow_bits and
        expected.fri_config.log_blowup_factor == actual.fri_config.log_blowup_factor and
        expected.fri_config.log_last_layer_degree_bound == actual.fri_config.log_last_layer_degree_bound and
        expected.fri_config.n_queries == actual.fri_config.n_queries and
        expected.fri_config.fold_step == actual.fri_config.fold_step and
        expected.lifting_log_size == actual.lifting_log_size;
}

pub fn stateMachineStatementToWire(statement: state_machine.PreparedStatement) StateMachineStatementWire {
    return .{
        .public_input = .{
            .{
                statement.public_input[0][0].toU32(),
                statement.public_input[0][1].toU32(),
            },
            .{
                statement.public_input[1][0].toU32(),
                statement.public_input[1][1].toU32(),
            },
        },
        .stmt0 = .{
            .n = statement.stmt0.n,
            .m = statement.stmt0.m,
        },
        .stmt1 = .{
            .x_axis_claimed_sum = qm31ToWire(statement.stmt1.x_axis_claimed_sum),
            .y_axis_claimed_sum = qm31ToWire(statement.stmt1.y_axis_claimed_sum),
        },
    };
}

pub fn stateMachineStatementFromWire(wire: StateMachineStatementWire) ArtifactError!state_machine.PreparedStatement {
    return .{
        .public_input = .{
            .{
                try m31FromU32(wire.public_input[0][0]),
                try m31FromU32(wire.public_input[0][1]),
            },
            .{
                try m31FromU32(wire.public_input[1][0]),
                try m31FromU32(wire.public_input[1][1]),
            },
        },
        .stmt0 = .{
            .n = wire.stmt0.n,
            .m = wire.stmt0.m,
        },
        .stmt1 = .{
            .x_axis_claimed_sum = try qm31FromWire(wire.stmt1.x_axis_claimed_sum),
            .y_axis_claimed_sum = try qm31FromWire(wire.stmt1.y_axis_claimed_sum),
        },
    };
}

pub fn xorStatementToWire(statement: xor.Statement) XorStatementWire {
    return .{
        .log_size = statement.log_size,
        .log_step = statement.log_step,
        .offset = statement.offset,
        .claimed_sum = qm31ToWire(statement.claimed_sum),
    };
}

pub fn xorStatementFromWire(wire: XorStatementWire) ArtifactError!xor.Statement {
    if (wire.offset > std.math.maxInt(usize)) return ArtifactError.ValueOutOfRange;
    return .{
        .log_size = wire.log_size,
        .log_step = wire.log_step,
        .offset = @intCast(wire.offset),
        .claimed_sum = try qm31FromWire(wire.claimed_sum),
    };
}

pub fn wideFibonacciStatementToWire(statement: wide_fibonacci.Statement) WideFibonacciStatementWire {
    return .{
        .log_n_rows = statement.log_n_rows,
        .sequence_len = statement.sequence_len,
    };
}

pub fn wideFibonacciStatementFromWire(wire: WideFibonacciStatementWire) ArtifactError!wide_fibonacci.Statement {
    return .{
        .log_n_rows = wire.log_n_rows,
        .sequence_len = wire.sequence_len,
    };
}

pub fn plonkStatementToWire(statement: plonk.Statement) PlonkStatementWire {
    return .{
        .log_n_rows = statement.log_n_rows,
    };
}

pub fn plonkStatementFromWire(wire: PlonkStatementWire) ArtifactError!plonk.Statement {
    return .{
        .log_n_rows = wire.log_n_rows,
    };
}

pub fn plonkLogupStatementToWire(
    statement: plonk_logup.Statement,
) PlonkLogupStatementWire {
    return .{
        .log_n_rows = statement.log_n_rows,
        .claimed_sum = qm31ToWire(statement.claimed_sum),
    };
}

pub fn plonkLogupStatementFromWire(
    wire: PlonkLogupStatementWire,
) ArtifactError!plonk_logup.Statement {
    return .{
        .log_n_rows = wire.log_n_rows,
        .claimed_sum = try qm31FromWire(wire.claimed_sum),
    };
}

pub fn poseidonStatementToWire(statement: poseidon.Statement) PoseidonStatementWire {
    return .{
        .log_n_instances = statement.log_n_instances,
        .claimed_sum = qm31ToWire(statement.claimed_sum),
    };
}

pub fn poseidonStatementFromWire(wire: PoseidonStatementWire) ArtifactError!poseidon.Statement {
    return .{
        .log_n_instances = wire.log_n_instances,
        .claimed_sum = try qm31FromWire(wire.claimed_sum),
    };
}

pub fn blakeStatementToWire(statement: blake.Statement) BlakeStatementWire {
    return .{
        .stmt0 = .{ .log_size = statement.stmt0.log_size },
        .stmt1 = .{
            .scheduler_claimed_sum = qm31ToWire(
                statement.stmt1.scheduler_claimed_sum,
            ),
            .round_claimed_sums = .{
                qm31ToWire(statement.stmt1.round_claimed_sums[0]),
                qm31ToWire(statement.stmt1.round_claimed_sums[1]),
            },
            .xor_claimed_sums = .{
                qm31ToWire(statement.stmt1.xor_claimed_sums[0]),
                qm31ToWire(statement.stmt1.xor_claimed_sums[1]),
                qm31ToWire(statement.stmt1.xor_claimed_sums[2]),
                qm31ToWire(statement.stmt1.xor_claimed_sums[3]),
                qm31ToWire(statement.stmt1.xor_claimed_sums[4]),
            },
        },
    };
}

pub fn blakeStatementFromWire(wire: BlakeStatementWire) ArtifactError!blake.Statement {
    return .{
        .stmt0 = .{ .log_size = wire.stmt0.log_size },
        .stmt1 = .{
            .scheduler_claimed_sum = try qm31FromWire(
                wire.stmt1.scheduler_claimed_sum,
            ),
            .round_claimed_sums = .{
                try qm31FromWire(wire.stmt1.round_claimed_sums[0]),
                try qm31FromWire(wire.stmt1.round_claimed_sums[1]),
            },
            .xor_claimed_sums = .{
                try qm31FromWire(wire.stmt1.xor_claimed_sums[0]),
                try qm31FromWire(wire.stmt1.xor_claimed_sums[1]),
                try qm31FromWire(wire.stmt1.xor_claimed_sums[2]),
                try qm31FromWire(wire.stmt1.xor_claimed_sums[3]),
                try qm31FromWire(wire.stmt1.xor_claimed_sums[4]),
            },
        },
    };
}

fn m31FromU32(value: u32) ArtifactError!M31 {
    if (value >= m31.Modulus) return ArtifactError.NonCanonicalM31;
    return M31.fromCanonical(value);
}

pub fn qm31FromWire(value: Qm31Wire) ArtifactError!QM31 {
    return QM31.fromM31Array(.{
        try m31FromU32(value[0]),
        try m31FromU32(value[1]),
        try m31FromU32(value[2]),
        try m31FromU32(value[3]),
    });
}

fn qm31ToWire(value: QM31) Qm31Wire {
    const coeffs = value.toM31Array();
    return .{
        coeffs[0].toU32(),
        coeffs[1].toU32(),
        coeffs[2].toU32(),
        coeffs[3].toU32(),
    };
}

test "interop artifact: hex roundtrip" {
    const alloc = std.testing.allocator;
    const bytes = &[_]u8{ 0x01, 0xab, 0x7f, 0x00 };

    const hex = try bytesToHexAlloc(alloc, bytes);
    defer alloc.free(hex);

    const decoded = try hexToBytesAlloc(alloc, hex);
    defer alloc.free(decoded);

    try std.testing.expectEqualSlices(u8, bytes, decoded);
}

test "interop artifact: proof and artifact configs require exact equality" {
    const expected = try pcsConfigFromWire(.{
        .pow_bits = 3,
        .fri_config = .{
            .log_blowup_factor = 2,
            .log_last_layer_degree_bound = 1,
            .n_queries = 5,
        },
    });
    try std.testing.expect(pcsConfigsEqual(expected, expected));

    inline for (.{
        "pow_bits",
        "log_blowup_factor",
        "log_last_layer_degree_bound",
        "n_queries",
        "fold_step",
        "lifting_log_size",
    }) |field| {
        var actual = expected;
        if (comptime std.mem.eql(u8, field, "pow_bits")) actual.pow_bits += 1;
        if (comptime std.mem.eql(u8, field, "log_blowup_factor")) actual.fri_config.log_blowup_factor += 1;
        if (comptime std.mem.eql(u8, field, "log_last_layer_degree_bound")) actual.fri_config.log_last_layer_degree_bound += 1;
        if (comptime std.mem.eql(u8, field, "n_queries")) actual.fri_config.n_queries += 1;
        if (comptime std.mem.eql(u8, field, "fold_step")) actual.fri_config.fold_step += 1;
        if (comptime std.mem.eql(u8, field, "lifting_log_size")) actual.lifting_log_size = 4;
        try std.testing.expect(!pcsConfigsEqual(expected, actual));
    }
}

test "interop artifact: PCS wire preserves fold and lifting configuration" {
    const config = try pcsConfigFromWire(.{
        .pow_bits = 3,
        .fri_config = .{
            .log_blowup_factor = 2,
            .log_last_layer_degree_bound = 1,
            .n_queries = 5,
            .fold_step = 2,
        },
        .lifting_log_size = 7,
    });
    const wire = pcsConfigToWire(config);
    const decoded = try pcsConfigFromWire(wire);
    try std.testing.expect(pcsConfigsEqual(config, decoded));
}

test "interop artifact: wide fibonacci statement wire roundtrip" {
    const statement: wide_fibonacci.Statement = .{
        .log_n_rows = 5,
        .sequence_len = 16,
    };

    const wire = wideFibonacciStatementToWire(statement);
    const decoded = try wideFibonacciStatementFromWire(wire);

    try std.testing.expectEqual(statement.log_n_rows, decoded.log_n_rows);
    try std.testing.expectEqual(statement.sequence_len, decoded.sequence_len);
}

test "interop artifact: plonk statement wire roundtrip" {
    const statement: plonk.Statement = .{
        .log_n_rows = 7,
    };
    const wire = plonkStatementToWire(statement);
    const decoded = try plonkStatementFromWire(wire);
    try std.testing.expectEqual(statement.log_n_rows, decoded.log_n_rows);
}

test "interop artifact: state machine derived statement wire roundtrip" {
    const statement = state_machine.PreparedStatement{
        .public_input = .{
            .{ M31.fromCanonical(9), M31.fromCanonical(3) },
            .{ M31.fromCanonical(41), M31.fromCanonical(19) },
        },
        .stmt0 = .{ .n = 5, .m = 4 },
        .stmt1 = .{
            .x_axis_claimed_sum = QM31.fromU32Unchecked(1, 2, 3, 4),
            .y_axis_claimed_sum = QM31.fromU32Unchecked(5, 6, 7, 8),
        },
    };
    const decoded = try stateMachineStatementFromWire(stateMachineStatementToWire(statement));
    try std.testing.expect(std.meta.eql(statement, decoded));
}

test "interop artifact: poseidon statement wire roundtrip" {
    const statement: poseidon.Statement = .{
        .log_n_instances = 8,
    };
    const wire = poseidonStatementToWire(statement);
    const decoded = try poseidonStatementFromWire(wire);
    try std.testing.expectEqual(statement.log_n_instances, decoded.log_n_instances);
}

test "interop artifact: blake statement wire roundtrip" {
    const statement: blake.Statement = .{
        .stmt0 = .{ .log_size = 5 },
        .stmt1 = .{
            .scheduler_claimed_sum = QM31.fromU32Unchecked(1, 2, 3, 4),
            .round_claimed_sums = .{
                QM31.fromU32Unchecked(5, 6, 7, 8),
                QM31.fromU32Unchecked(9, 10, 11, 12),
            },
            .xor_claimed_sums = .{
                QM31.fromU32Unchecked(13, 14, 15, 16),
                QM31.fromU32Unchecked(17, 18, 19, 20),
                QM31.fromU32Unchecked(21, 22, 23, 24),
                QM31.fromU32Unchecked(25, 26, 27, 28),
                QM31.fromU32Unchecked(29, 30, 31, 32),
            },
        },
    };
    const wire = blakeStatementToWire(statement);
    const decoded = try blakeStatementFromWire(wire);
    try std.testing.expect(std.meta.eql(statement, decoded));
}
