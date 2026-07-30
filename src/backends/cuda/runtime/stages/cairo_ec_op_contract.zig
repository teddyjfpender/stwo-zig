//! Authenticated source, ABI, effect, and launch contract for native EC-op.

const std = @import("std");
const runtime_error = @import("../error.zig");

pub const trace_column_count: usize = 273;
pub const lookup_words_per_row: usize = 488;
pub const partial_input_column_count: usize = 127;
pub const partial_real_rounds: u32 = 252;
pub const partial_padded_rounds: u32 = 256;
pub const execution_table_count: usize = 37;
pub const execution_big_limb_count: usize = 28;
pub const execution_small_limb_count: usize = 8;
pub const chain_block: u32 = 16;
pub const normalize_block: u32 = 64;
pub const normalize_round_tile: u32 = 4;
pub const padding_block: u32 = 64;

const source = @embedFile("../../vendor/upstream/ec_op_witness.cu");
const expected_source_sha256 =
    "992f03a616c843f1b180adc397216635c2debb65b3fb4ccbbf9da2ae989a16bc";
const abi_description =
    "ec_op_builtin_witness_on(device-pointer-table-ro,u32,u32,u32," ++
    "device-u32-ro,u32,host-pointer-table-device-u32-rw,device-u32-rw," ++
    "host-pointer-table-device-u32-rw,u32,device-u32-atomic,u32," ++
    "device-u32-atomic,u32,device-u32-atomic,u32,device-u32-atomic,u32," ++
    "ordered-proof-stream)";
const effect_description =
    "trace[273][rows];lookup-word-major[488][rows];" ++
    "partial-input[127][256*rows];atomic-add(address,big,small,rc8);" ++
    "no-allocation;no-copy;no-sync;no-fallback";

pub const Geometry = struct {
    row_count: u32,
    n_addresses: u32,
    n_big: u32,
    n_small: u32,
    address_count_words: u32,
    big_count_words: u32,
    small_count_words: u32,
    range_check_8_count_words: u32,

    pub fn partialRowCount(self: Geometry) runtime_error.Error!u32 {
        return std.math.mul(
            u32,
            self.row_count,
            partial_padded_rounds,
        ) catch return error.SizeOverflow;
    }

    pub fn validate(self: Geometry) runtime_error.Error!void {
        if (self.row_count < 16 or !std.math.isPowerOfTwo(self.row_count) or
            self.n_addresses == 0 or self.n_big == 0 or self.n_small == 0 or
            self.address_count_words < self.n_addresses - 1 or
            self.big_count_words < self.n_big or
            self.small_count_words < self.n_small or
            self.range_check_8_count_words < 256)
        {
            return error.InvalidKernelDescriptor;
        }
        _ = try self.partialRowCount();
    }
};

pub const KernelStage = enum(u8) {
    projective_chain = 1,
    normalize_round_tiles = 2,
    partial_input_padding = 3,
};

pub const Launch = struct {
    stage: KernelStage,
    grid: [3]u32,
    block: [3]u32,
};

pub const Contract = struct {
    geometry: Geometry,
    launches: [3]Launch,
    source_identity: [32]u8,
    abi_identity: [32]u8,
    effect_identity: [32]u8,
    launch_identity: [32]u8,
    identity: [32]u8,

    pub fn compile(geometry: Geometry) runtime_error.Error!Contract {
        try geometry.validate();
        const partial_rows = try geometry.partialRowCount();
        const padding_rows = partial_rows -
            partial_real_rounds * geometry.row_count;
        const launches = [3]Launch{
            .{
                .stage = .projective_chain,
                .grid = .{
                    ceilDiv(geometry.row_count, chain_block),
                    1,
                    1,
                },
                .block = .{ chain_block, 1, 1 },
            },
            .{
                .stage = .normalize_round_tiles,
                .grid = .{
                    ceilDiv(geometry.row_count, normalize_block),
                    partial_real_rounds / normalize_round_tile,
                    1,
                },
                .block = .{ normalize_block, 1, 1 },
            },
            .{
                .stage = .partial_input_padding,
                .grid = .{ ceilDiv(padding_rows, padding_block), 1, 1 },
                .block = .{ padding_block, 1, 1 },
            },
        };

        var source_identity: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(
            source,
            &source_identity,
            .{},
        );
        var expected: [32]u8 = undefined;
        _ = std.fmt.hexToBytes(&expected, expected_source_sha256) catch
            unreachable;
        if (!std.mem.eql(u8, &source_identity, &expected))
            return error.BuildIdentityAbsent;
        const abi_identity = hash(&.{
            "stwo-zig/cuda/ec-op/abi/v1\x00",
            abi_description,
        });
        const geometry_bytes = std.mem.asBytes(&geometry);
        const effect_identity = hash(&.{
            "stwo-zig/cuda/ec-op/effect/v1\x00",
            effect_description,
            geometry_bytes,
        });
        const launch_identity = hashLaunches(&launches);
        const identity = hash(&.{
            "stwo-zig/cuda/ec-op/contract/v1\x00",
            &source_identity,
            &abi_identity,
            &effect_identity,
            &launch_identity,
        });
        return .{
            .geometry = geometry,
            .launches = launches,
            .source_identity = source_identity,
            .abi_identity = abi_identity,
            .effect_identity = effect_identity,
            .launch_identity = launch_identity,
            .identity = identity,
        };
    }
};

fn ceilDiv(value: u32, divisor: u32) u32 {
    return 1 + (value - 1) / divisor;
}

fn hashLaunches(launches: []const Launch) [32]u8 {
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    hasher.update("stwo-zig/cuda/ec-op/launch/v1\x00");
    hashInt(&hasher, u32, @intCast(launches.len));
    for (launches) |launch| {
        hashInt(&hasher, u8, @intFromEnum(launch.stage));
        for (launch.grid) |value| hashInt(&hasher, u32, value);
        for (launch.block) |value| hashInt(&hasher, u32, value);
    }
    return hasher.finalResult();
}

fn hashInt(
    hasher: *std.crypto.hash.sha2.Sha256,
    comptime T: type,
    value: T,
) void {
    var encoded: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &encoded, value, .little);
    hasher.update(&encoded);
}

fn hash(parts: []const []const u8) [32]u8 {
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    for (parts) |part| {
        hasher.update(std.mem.asBytes(&part.len));
        hasher.update(part);
    }
    var digest: [32]u8 = undefined;
    hasher.final(&digest);
    return digest;
}

test "EC-op contract pins exact source, effects, and three-launch geometry" {
    const contract = try Contract.compile(.{
        .row_count = 16,
        .n_addresses = 113,
        .n_big = 80,
        .n_small = 16,
        .address_count_words = 112,
        .big_count_words = 80,
        .small_count_words = 16,
        .range_check_8_count_words = 256,
    });
    try std.testing.expectEqual(
        @as(u32, 4096),
        try contract.geometry.partialRowCount(),
    );
    try std.testing.expectEqual(
        [3]u32{ 1, 63, 1 },
        contract.launches[1].grid,
    );
    try std.testing.expectEqual(
        [3]u32{ 64, 1, 1 },
        contract.launches[1].block,
    );
    try std.testing.expect(!std.mem.allEqual(u8, &contract.identity, 0));
    try std.testing.expect(!std.mem.eql(
        u8,
        &contract.abi_identity,
        &contract.effect_identity,
    ));
}

test "EC-op contract rejects non-power-of-two and undersized tables" {
    const valid = Geometry{
        .row_count = 16,
        .n_addresses = 113,
        .n_big = 80,
        .n_small = 16,
        .address_count_words = 112,
        .big_count_words = 80,
        .small_count_words = 16,
        .range_check_8_count_words = 256,
    };
    var invalid = valid;
    invalid.row_count = 24;
    try std.testing.expectError(
        error.InvalidKernelDescriptor,
        Contract.compile(invalid),
    );
    invalid = valid;
    invalid.address_count_words -= 1;
    try std.testing.expectError(
        error.InvalidKernelDescriptor,
        Contract.compile(invalid),
    );
}

test "EC-op launch identity ignores struct padding" {
    var first: Launch = undefined;
    @memset(std.mem.asBytes(&first), 0xaa);
    first.stage = .projective_chain;
    first.grid = .{ 7, 1, 1 };
    first.block = .{ chain_block, 1, 1 };

    var second: Launch = undefined;
    @memset(std.mem.asBytes(&second), 0x55);
    second.stage = first.stage;
    second.grid = first.grid;
    second.block = first.block;

    try std.testing.expectEqual(
        hashLaunches(&.{first}),
        hashLaunches(&.{second}),
    );
}
