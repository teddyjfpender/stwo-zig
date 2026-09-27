//! Heterogeneous compiler authority for universal rows 30--32.
//!
//! Row-18 composition graphs and rows-20--29 PCS/FRI graphs are admitted by
//! separate typed compilers.  This module joins those already-validated
//! programs into the one shared arithmetic-lowering plan without accepting a
//! caller-authored graph inventory.  It contains no proof values and is a
//! required subauthority of a future complete node verifier program.

const std = @import("std");
const digest = @import("../air/lang/digest.zig");
const lowering = @import("air/verifier_arithmetic_lowering.zig");
const schedule = @import("air/verifier_schedule.zig");
const composition_rows = @import("binary_composition_rows_heterogeneous_v2.zig");
const fri_rows = @import("air/fri_rows_authority_heterogeneous_v2.zig");
const legacy = @import("binary_fri_outer_source_arithmetic_rows_authority.zig");

pub const FORMAT_VERSION: u16 = 2;
pub const SCHEMA_VERSION: u16 = 1;
pub const CHILD_COUNT: usize = 2;
pub const LANE_COUNT: usize = 7;
pub const SEGMENT_CAPACITY_CIRCUIT_ID: u32 = 421;
const PROGRAM_DOMAIN =
    "stwo-zig/typed-air/binary-arithmetic-rows-program/v2\x00";
const LANE_DOMAIN =
    "stwo-zig/typed-air/binary-arithmetic-rows-lane/v2\x00";

pub const Error = error{
    InvalidHeterogeneousArithmeticAuthority,
};

pub const ProgramInputV2 = struct {
    composition_authority: *const composition_rows.CompositionRowsAuthorityV2,
    composition_program: composition_rows.ProgramInputV2,
    fri_authority: *const fri_rows.FriRowsAuthorityV2,
    fri_program: fri_rows.ProgramInputV2,
};

pub const ArithmeticRowsAuthorityV2 = struct {
    rows: legacy.ArithmeticRowsAuthority,
    composition_program_sha256: digest.Digest,
    fri_program_sha256: digest.Digest,
    program_sha256: digest.Digest,

    pub fn init(
        allocator: std.mem.Allocator,
        input: ProgramInputV2,
    ) !ArithmeticRowsAuthorityV2 {
        try validateInput(input);
        var lanes: [LANE_COUNT]lowering.Lane = undefined;
        try compileLanes(input, &lanes);
        var rows = try legacy.ArithmeticRowsAuthority.initFromProgramLanes(
            allocator,
            &lanes,
        );
        errdefer rows.deinit();
        var result = ArithmeticRowsAuthorityV2{
            .rows = rows,
            .composition_program_sha256 = input.composition_authority.program_sha256,
            .fri_program_sha256 = input.fri_authority.program_sha256,
            .program_sha256 = undefined,
        };
        result.program_sha256 = programIdentity(&result);
        try result.validateProgramAgainst(input);
        return result;
    }

    pub fn deinit(self: *ArithmeticRowsAuthorityV2) void {
        self.rows.deinit();
        self.* = undefined;
    }

    pub fn validateProgramAgainst(
        self: *const ArithmeticRowsAuthorityV2,
        input: ProgramInputV2,
    ) !void {
        try validateInput(input);
        var expected: [LANE_COUNT]lowering.Lane = undefined;
        try compileLanes(input, &expected);
        try self.rows.validateProgramLanes(&expected);
        if (!std.mem.eql(
            u8,
            &self.composition_program_sha256,
            &input.composition_authority.program_sha256,
        ) or !std.mem.eql(
            u8,
            &self.fri_program_sha256,
            &input.fri_authority.program_sha256,
        ) or !std.mem.eql(
            u8,
            &self.program_sha256,
            &programIdentity(self),
        )) return error.InvalidHeterogeneousArithmeticAuthority;
    }
};

fn validateInput(input: ProgramInputV2) !void {
    try input.composition_authority.validateProgramAgainst(
        input.composition_program,
    );
    try input.fri_authority.validateProgramAgainst(input.fri_program);
    const composition_plans = [_]*const schedule.Plan{
        input.composition_program.vm_plan,
        input.composition_program.children[0].plan,
        input.composition_program.children[1].plan,
    };
    for (composition_plans, input.fri_program.lanes) |left, right| {
        if (left.schema != right.plan.schema or
            !std.meta.eql(left.authority_digest, right.plan.authority_digest))
        {
            return error.InvalidHeterogeneousArithmeticAuthority;
        }
    }
}

fn compileLanes(
    input: ProgramInputV2,
    destination: *[LANE_COUNT]lowering.Lane,
) !void {
    const left_composition = input.composition_program.children[0].composition;
    destination[0] = .{
        .circuit_id = SEGMENT_CAPACITY_CIRCUIT_ID,
        .active_in = .segment,
        .circuit_identity = laneIdentity(
            .composition_capacity,
            0,
            input.composition_authority.program_sha256,
            left_composition.graph.identity_digest,
        ),
        .graph = left_composition.graph,
    };
    inline for (0..CHILD_COUNT) |child_index| {
        const composition_lane =
            input.composition_program.children[child_index].composition;
        const fri_lane_index = child_index + 1;
        const pcs_lane = input.fri_authority.pcs_reference.lanes[fri_lane_index];
        const fri_lane = input.fri_authority.input_reference.lanes[fri_lane_index];
        const lane_base = 1 + child_index * 3;
        destination[lane_base] = .{
            .circuit_id = composition_lane.circuit_id,
            .active_in = .binary,
            .circuit_identity = laneIdentity(
                .composition,
                child_index,
                input.composition_authority.program_sha256,
                composition_lane.graph.identity_digest,
            ),
            .graph = composition_lane.graph,
        };
        destination[lane_base + 1] = .{
            .circuit_id = pcs_lane.circuit_id,
            .active_in = .binary,
            .circuit_identity = laneIdentity(
                .pcs,
                child_index,
                input.fri_authority.program_sha256,
                pcs_lane.graph.identity_digest,
            ),
            .graph = pcs_lane.graph,
        };
        destination[lane_base + 2] = .{
            .circuit_id = fri_lane.circuit_id,
            .active_in = .binary,
            .circuit_identity = input.fri_authority
                .input_reference.circuit_identities[fri_lane_index],
            .graph = fri_lane.circuit.graph(),
        };
    }
    for (destination) |lane| try lane.graph.validate();
}

const LaneKind = enum(u8) {
    composition_capacity = 0,
    composition = 1,
    pcs = 2,
};

fn laneIdentity(
    kind: LaneKind,
    child_index: usize,
    source_program_sha256: digest.Digest,
    graph_sha256: digest.Digest,
) digest.Digest {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(LANE_DOMAIN);
    hashInt(&hash, u8, @intFromEnum(kind));
    hashInt(&hash, u8, child_index);
    hash.update(&source_program_sha256);
    hash.update(&graph_sha256);
    return hash.finalResult();
}

fn programIdentity(value: *const ArithmeticRowsAuthorityV2) digest.Digest {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(PROGRAM_DOMAIN);
    hashInt(&hash, u16, FORMAT_VERSION);
    hashInt(&hash, u16, SCHEMA_VERSION);
    hash.update(&value.composition_program_sha256);
    hash.update(&value.fri_program_sha256);
    hash.update(&value.rows.reference.authority_digest);
    hash.update(&value.rows.plan.authority_digest);
    hash.update(&value.rows.authority_digest);
    for (value.rows.log_sizes) |log_size| hashInt(&hash, u32, log_size);
    return hash.finalResult();
}

fn hashInt(hash: anytype, comptime T: type, value: anytype) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, @intCast(value), .little);
    hash.update(&bytes);
}

comptime {
    if (FORMAT_VERSION != 2 or SCHEMA_VERSION != 1 or
        CHILD_COUNT != 2 or LANE_COUNT != 7)
    {
        @compileError("heterogeneous arithmetic rows contract drifted");
    }
}
