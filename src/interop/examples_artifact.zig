const std = @import("std");
const fri = @import("../core/fri.zig");
const m31 = @import("../core/fields/m31.zig");
const qm31 = @import("../core/fields/qm31.zig");
const pcs = @import("../core/pcs/mod.zig");
const state_machine = @import("../examples/state_machine.zig");
const wide_fibonacci = @import("../examples/wide_fibonacci.zig");
const xor = @import("../examples/xor.zig");
const proof_wire = @import("proof_wire.zig");

const M31 = m31.M31;
const QM31 = qm31.QM31;

pub const SCHEMA_VERSION: u32 = 1;
pub const UPSTREAM_COMMIT: []const u8 = "a8fcf4bdde3778ae72f1e6cfe61a38e2911648d2";
pub const EXCHANGE_MODE: []const u8 = "proof_exchange_json_wire_v1";

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
};

pub const WideFibonacciStatementWire = struct {
    log_n_rows: u32,
    sequence_len: u32,
};

pub const InteropArtifact = struct {
    schema_version: u32,
    upstream_commit: []const u8,
    exchange_mode: []const u8,
    generator: []const u8,
    example: []const u8,
    prove_mode: ?[]const u8 = null,
    pcs_config: PcsConfigWire,
    state_machine_statement: ?StateMachineStatementWire = null,
    wide_fibonacci_statement: ?WideFibonacciStatementWire = null,
    xor_statement: ?XorStatementWire = null,
    proof_bytes_hex: []const u8,
};

pub const ArtifactError = error{
    InvalidHexLength,
    InvalidHexDigit,
    NonCanonicalM31,
    ValueOutOfRange,
};

pub fn writeArtifact(
    allocator: std.mem.Allocator,
    path: []const u8,
    artifact: InteropArtifact,
) !void {
    const rendered = try std.json.Stringify.valueAlloc(allocator, artifact, .{
        .whitespace = .indent_2,
    });
    defer allocator.free(rendered);

    const file = try std.fs.cwd().createFile(path, .{ .truncate = true });
    defer file.close();
    try file.writeAll(rendered);
    try file.writeAll("\n");
}

pub fn readArtifact(allocator: std.mem.Allocator, path: []const u8) !std.json.Parsed(InteropArtifact) {
    const raw = try std.fs.cwd().readFileAlloc(allocator, path, std.math.maxInt(usize));
    defer allocator.free(raw);

    return std.json.parseFromSlice(InteropArtifact, allocator, raw, .{
        .ignore_unknown_fields = false,
        .allocate = .alloc_always,
    });
}

pub fn bytesToHexAlloc(allocator: std.mem.Allocator, bytes: []const u8) ![]u8 {
    const out = try allocator.alloc(u8, bytes.len * 2);
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
        },
    };
}

pub fn pcsConfigFromWire(wire: PcsConfigWire) !pcs.PcsConfig {
    if (wire.fri_config.n_queries > std.math.maxInt(usize)) return ArtifactError.ValueOutOfRange;
    return .{
        .pow_bits = wire.pow_bits,
        .fri_config = try fri.FriConfig.init(
            wire.fri_config.log_last_layer_degree_bound,
            wire.fri_config.log_blowup_factor,
            @intCast(wire.fri_config.n_queries),
        ),
    };
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
    };
}

pub fn xorStatementFromWire(wire: XorStatementWire) ArtifactError!xor.Statement {
    if (wire.offset > std.math.maxInt(usize)) return ArtifactError.ValueOutOfRange;
    return .{
        .log_size = wire.log_size,
        .log_step = wire.log_step,
        .offset = @intCast(wire.offset),
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

fn m31FromU32(value: u32) ArtifactError!M31 {
    if (value >= m31.Modulus) return ArtifactError.NonCanonicalM31;
    return M31.fromCanonical(value);
}

fn qm31FromWire(value: Qm31Wire) ArtifactError!QM31 {
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
