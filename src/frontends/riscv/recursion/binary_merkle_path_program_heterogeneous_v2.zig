//! Heterogeneous program authority for universal row 33.
//!
//! The Merkle-path AIR semantics are shared, but the exact path geometry is
//! derived independently for the ordered left and right verifier programs.
//! No proof-provided sibling or digest enters this cold compiler authority;
//! those values belong to the later instance witness.

const std = @import("std");
const digest = @import("../air/lang/digest.zig");
const fri_rows = @import("air/fri_rows_authority_heterogeneous_v2.zig");
const legacy = @import("binary_fri_outer_source_arithmetic_rows_authority.zig");

pub const FORMAT_VERSION: u16 = 2;
pub const SCHEMA_VERSION: u16 = 1;
pub const CHILD_COUNT: usize = 2;
const PROGRAM_DOMAIN =
    "stwo-zig/typed-air/binary-merkle-path-program/v2\x00";

pub const Error = error{
    ArithmeticOverflow,
    InvalidHeterogeneousMerklePathAuthority,
    LogSizeOutOfRange,
};

pub const ProgramInputV2 = struct {
    fri_authority: *const fri_rows.FriRowsAuthorityV2,
    fri_program: fri_rows.ProgramInputV2,
};

pub const GeometryV2 = struct {
    leaf_count: usize,
    invocation_count: usize,
    log_size: u32,
};

pub const MerklePathProgramAuthorityV2 = struct {
    rows: legacy.MerkleRowsAuthority,
    geometry: GeometryV2,
    fri_program_sha256: digest.Digest,
    program_sha256: digest.Digest,

    pub fn init(
        allocator: std.mem.Allocator,
        input: ProgramInputV2,
    ) !MerklePathProgramAuthorityV2 {
        try validateInput(input);
        var rows = try legacy.MerkleRowsAuthority.init(allocator);
        errdefer rows.deinit();
        var result = MerklePathProgramAuthorityV2{
            .rows = rows,
            .geometry = try geometryFromProgram(input.fri_program),
            .fri_program_sha256 = input.fri_authority.program_sha256,
            .program_sha256 = undefined,
        };
        result.program_sha256 = programIdentity(&result);
        try result.validateProgramAgainst(input);
        return result;
    }

    pub fn deinit(self: *MerklePathProgramAuthorityV2) void {
        self.rows.deinit();
        self.* = undefined;
    }

    pub fn validateProgramAgainst(
        self: *const MerklePathProgramAuthorityV2,
        input: ProgramInputV2,
    ) !void {
        try validateInput(input);
        try self.rows.validate();
        if (!std.meta.eql(
            self.geometry,
            try geometryFromProgram(input.fri_program),
        ) or !std.mem.eql(
            u8,
            &self.fri_program_sha256,
            &input.fri_authority.program_sha256,
        ) or !std.mem.eql(
            u8,
            &self.program_sha256,
            &programIdentity(self),
        )) return error.InvalidHeterogeneousMerklePathAuthority;
    }
};

fn validateInput(input: ProgramInputV2) !void {
    try input.fri_authority.validateProgramAgainst(input.fri_program);
    _ = try geometryFromProgram(input.fri_program);
}

fn geometryFromProgram(program: fri_rows.ProgramInputV2) !GeometryV2 {
    var leaf_count: usize = 0;
    var invocation_count: usize = 0;
    for (program.lanes[1..]) |lane| {
        const query_count: usize = @intCast(lane.trace.query_count);
        const leaf_kinds = try checkedAdd(
            lane.trace.trees.len,
            lane.fri.layers.len,
        );
        leaf_count = try checkedAdd(
            leaf_count,
            try checkedMul(query_count, leaf_kinds),
        );
        var depth: usize = 0;
        for (lane.trace.trees) |tree|
            depth = try checkedAdd(depth, @intCast(tree.height));
        for (lane.fri.layers) |layer|
            depth = try checkedAdd(depth, @intCast(layer.tree_height));
        invocation_count = try checkedAdd(
            invocation_count,
            try checkedMul(query_count, depth),
        );
    }
    return .{
        .leaf_count = leaf_count,
        .invocation_count = invocation_count,
        .log_size = try traceLogSize(invocation_count),
    };
}

fn traceLogSize(row_count: usize) !u32 {
    const result: u32 = @max(
        4,
        @as(u32, @intCast(std.math.log2_int_ceil(
            usize,
            @max(row_count, 1),
        ))),
    );
    if (result > 30) return error.LogSizeOutOfRange;
    return result;
}

fn checkedAdd(left: usize, right: usize) !usize {
    return std.math.add(usize, left, right) catch error.ArithmeticOverflow;
}

fn checkedMul(left: usize, right: usize) !usize {
    return std.math.mul(usize, left, right) catch error.ArithmeticOverflow;
}

fn programIdentity(value: *const MerklePathProgramAuthorityV2) digest.Digest {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(PROGRAM_DOMAIN);
    hashInt(&hash, u16, FORMAT_VERSION);
    hashInt(&hash, u16, SCHEMA_VERSION);
    hash.update(&value.fri_program_sha256);
    hash.update(&value.rows.authority_digest);
    hashInt(&hash, u64, value.geometry.leaf_count);
    hashInt(&hash, u64, value.geometry.invocation_count);
    hashInt(&hash, u32, value.geometry.log_size);
    return hash.finalResult();
}

fn hashInt(hash: anytype, comptime T: type, value: anytype) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, @intCast(value), .little);
    hash.update(&bytes);
}

comptime {
    if (FORMAT_VERSION != 2 or SCHEMA_VERSION != 1 or CHILD_COUNT != 2)
        @compileError("heterogeneous Merkle-path program contract drifted");
}
