//! Canonical transport projection of one heterogeneous rows-20--29 program.
//!
//! This is a required subauthority of a future complete node verifier program,
//! not a claim that the outer program is complete. Minting is
//! possible only after `FriRowsAuthorityV2` cold-reconstructs all ten row
//! families from trusted lane inputs. Re-admission repeats that compilation;
//! serialized hashes never route or select a verifier program by themselves.

const std = @import("std");
const m31 = @import("stwo_core").fields.m31;
const subject = @import("fri_rows_authority_heterogeneous_v2.zig");
const pcs = @import("pcs_deep_input_witness.zig");
const schedule = @import("verifier_schedule.zig");

pub const FORMAT_VERSION: u16 = 2;
pub const SCHEMA_VERSION: u16 = 1;
pub const LANE_COUNT: usize = subject.LANE_COUNT;
pub const ENCODED_BYTE_COUNT: usize = 428;
const LANE_DOMAIN = "stwo-zig/typed-air/recursion-fri-rows-lane/v2\x00";
const DESCRIPTOR_DOMAIN =
    "stwo-zig/typed-air/recursion-fri-rows-program-descriptor/v2\x00";
const NATIVE_DIGEST_DOMAIN =
    "stwo-zig/typed-air/recursion-fri-rows-native-digest/v2\x00";

pub const LaneV2 = struct {
    verifier_id: u8,
    plan_schema: schedule.Schema,
    padding: u8 = 0,
    pcs_circuit_id: u32,
    fri_circuit_id: u32,
    schedule_sha256: [32]u8,
    lane_program_sha256: [32]u8,
    lane_sha256: [32]u8,

    pub fn validate(self: *const LaneV2, expected_lane: usize) !void {
        if (self.verifier_id != expected_lane or self.padding != 0 or
            self.pcs_circuit_id >= m31.Modulus or
            self.fri_circuit_id >= m31.Modulus)
        {
            return error.InvalidFriRowsProgramDescriptor;
        }
        try requireSha(self.schedule_sha256);
        try requireSha(self.lane_program_sha256);
        if (!std.mem.eql(u8, &self.lane_sha256, &laneIdentity(self)))
            return error.InvalidFriRowsProgramDescriptor;
    }
};

pub const FriRowsProgramDescriptorV2 = struct {
    format_version: u16 = FORMAT_VERSION,
    schema_version: u16 = SCHEMA_VERSION,
    lane_count: u8 = LANE_COUNT,
    row_count: u8 = subject.ROW_COUNT,
    proof_kind: u8 = @intFromEnum(subject.PROOF_KIND),
    reserved: u8 = 0,
    lanes: [LANE_COUNT]LaneV2,
    semantic_suite_sha256: [32]u8,
    program_sha256: [32]u8,
    descriptor_sha256: [32]u8,

    pub fn mint(
        authority: *const subject.FriRowsAuthorityV2,
        program: subject.ProgramInputV2,
    ) !FriRowsProgramDescriptorV2 {
        try authority.validateProgramAgainst(program);
        const result = mintUnchecked(authority, program);
        try result.validateAgainst(authority, program);
        return result;
    }

    pub fn validate(self: *const FriRowsProgramDescriptorV2) !void {
        if (self.format_version != FORMAT_VERSION or
            self.schema_version != SCHEMA_VERSION or
            self.lane_count != LANE_COUNT or self.row_count != subject.ROW_COUNT or
            self.proof_kind != @intFromEnum(subject.PROOF_KIND) or self.reserved != 0)
        {
            return error.InvalidFriRowsProgramDescriptor;
        }
        for (&self.lanes, 0..) |*lane, lane_index| try lane.validate(lane_index);
        if (self.lanes[0].plan_schema != .vm)
            return error.InvalidFriRowsProgramDescriptor;
        try requireSha(self.semantic_suite_sha256);
        try requireSha(self.program_sha256);
        if (!std.mem.eql(
            u8,
            &self.descriptor_sha256,
            &descriptorIdentity(self),
        )) return error.InvalidFriRowsProgramDescriptor;
    }

    pub fn validateAgainst(
        self: *const FriRowsProgramDescriptorV2,
        authority: *const subject.FriRowsAuthorityV2,
        program: subject.ProgramInputV2,
    ) !void {
        try self.validate();
        try authority.validateProgramAgainst(program);
        const expected = mintUnchecked(authority, program);
        if (!std.meta.eql(self.*, expected))
            return error.FriRowsProgramDescriptorMismatch;
    }

    pub fn encodeCanonical(
        self: *const FriRowsProgramDescriptorV2,
    ) ![ENCODED_BYTE_COUNT]u8 {
        try self.validate();
        var bytes: [ENCODED_BYTE_COUNT]u8 = undefined;
        var writer = Writer{ .bytes = &bytes };
        writer.u16Value(self.format_version);
        writer.u16Value(self.schema_version);
        writer.u8Value(self.lane_count);
        writer.u8Value(self.row_count);
        writer.u8Value(self.proof_kind);
        writer.u8Value(self.reserved);
        for (self.lanes) |lane| {
            writer.u8Value(lane.verifier_id);
            writer.u16Value(@intFromEnum(lane.plan_schema));
            writer.u8Value(lane.padding);
            writer.u32Value(lane.pcs_circuit_id);
            writer.u32Value(lane.fri_circuit_id);
            writer.sha(lane.schedule_sha256);
            writer.sha(lane.lane_program_sha256);
            writer.sha(lane.lane_sha256);
        }
        writer.sha(self.semantic_suite_sha256);
        writer.sha(self.program_sha256);
        writer.sha(self.descriptor_sha256);
        std.debug.assert(writer.at == bytes.len);
        return bytes;
    }

    pub fn decodeCanonical(bytes: []const u8) !FriRowsProgramDescriptorV2 {
        if (bytes.len != ENCODED_BYTE_COUNT)
            return error.InvalidFriRowsProgramDescriptor;
        var reader = Reader{ .bytes = bytes };
        var result = FriRowsProgramDescriptorV2{
            .format_version = reader.u16Value(),
            .schema_version = reader.u16Value(),
            .lane_count = reader.u8Value(),
            .row_count = reader.u8Value(),
            .proof_kind = reader.u8Value(),
            .reserved = reader.u8Value(),
            .lanes = undefined,
            .semantic_suite_sha256 = undefined,
            .program_sha256 = undefined,
            .descriptor_sha256 = undefined,
        };
        for (&result.lanes) |*lane| lane.* = .{
            .verifier_id = reader.u8Value(),
            .plan_schema = std.meta.intToEnum(
                schedule.Schema,
                reader.u16Value(),
            ) catch return error.InvalidFriRowsProgramDescriptor,
            .padding = reader.u8Value(),
            .pcs_circuit_id = reader.u32Value(),
            .fri_circuit_id = reader.u32Value(),
            .schedule_sha256 = reader.sha(),
            .lane_program_sha256 = reader.sha(),
            .lane_sha256 = reader.sha(),
        };
        result.semantic_suite_sha256 = reader.sha();
        result.program_sha256 = reader.sha();
        result.descriptor_sha256 = reader.sha();
        if (reader.at != bytes.len)
            return error.InvalidFriRowsProgramDescriptor;
        try result.validate();
        const canonical = try result.encodeCanonical();
        if (!std.mem.eql(u8, bytes, &canonical))
            return error.InvalidFriRowsProgramDescriptor;
        return result;
    }
};

fn mintUnchecked(
    authority: *const subject.FriRowsAuthorityV2,
    program: subject.ProgramInputV2,
) FriRowsProgramDescriptorV2 {
    var result = FriRowsProgramDescriptorV2{
        .lanes = undefined,
        .semantic_suite_sha256 = subject.semanticSuiteSha256(),
        .program_sha256 = authority.program_sha256,
        .descriptor_sha256 = undefined,
    };
    for (&result.lanes, program.lanes, 0..) |*destination, lane, lane_index| {
        destination.* = .{
            .verifier_id = @intCast(lane_index),
            .plan_schema = lane.plan.schema,
            .pcs_circuit_id = lane.pcs.circuit_id,
            .fri_circuit_id = lane.fri_circuit_id,
            .schedule_sha256 = nativeDigestSha256(lane.plan.authority_digest),
            .lane_program_sha256 = laneProgramIdentity(lane),
            .lane_sha256 = undefined,
        };
        destination.lane_sha256 = laneIdentity(destination);
    }
    result.descriptor_sha256 = descriptorIdentity(&result);
    return result;
}

fn laneProgramIdentity(lane: subject.LaneProgramV2) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(LANE_DOMAIN);
    hashInt(&hash, u16, @intFromEnum(lane.plan.schema));
    hash.update(&nativeDigestSha256(lane.plan.authority_digest));
    hashMapping(&hash, lane);
    hashTrace(&hash, lane);
    hashFri(&hash, lane);
    hashPcs(&hash, lane.pcs);
    hashInt(&hash, u32, lane.fri_circuit_id);
    hash.update(&lane.fri_circuit.profile_digest);
    hash.update(&lane.fri_circuit.graph_digest);
    hash.update(&lane.fri_circuit.identity_digest);
    return hash.finalResult();
}

fn laneIdentity(lane: *const LaneV2) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(LANE_DOMAIN);
    hashInt(&hash, u8, lane.verifier_id);
    hashInt(&hash, u16, @intFromEnum(lane.plan_schema));
    hashInt(&hash, u32, lane.pcs_circuit_id);
    hashInt(&hash, u32, lane.fri_circuit_id);
    hash.update(&lane.schedule_sha256);
    hash.update(&lane.lane_program_sha256);
    return hash.finalResult();
}

fn descriptorIdentity(value: *const FriRowsProgramDescriptorV2) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(DESCRIPTOR_DOMAIN);
    hashInt(&hash, u16, value.format_version);
    hashInt(&hash, u16, value.schema_version);
    hashInt(&hash, u8, value.lane_count);
    hashInt(&hash, u8, value.row_count);
    hashInt(&hash, u8, value.proof_kind);
    for (value.lanes) |lane| hash.update(&lane.lane_sha256);
    hash.update(&value.semantic_suite_sha256);
    hash.update(&value.program_sha256);
    return hash.finalResult();
}

fn hashMapping(hash: anytype, lane: subject.LaneProgramV2) void {
    hashInt(hash, u32, lane.mapping.query_count);
    hashInt(hash, u32, lane.mapping.lifting_log_size);
    hashInt(hash, u32, lane.mapping.tree_heights.len);
    for (lane.mapping.tree_heights) |value| hashInt(hash, u32, value);
    hashInt(hash, u32, lane.mapping.fri_fold_widths.len);
    for (lane.mapping.fri_fold_widths) |value| hashInt(hash, u32, value);
}

fn hashTrace(hash: anytype, lane: subject.LaneProgramV2) void {
    hashInt(hash, u32, lane.trace.query_count);
    hashInt(hash, u32, lane.trace.lifting_log_size);
    hashInt(hash, u32, lane.trace.trees.len);
    for (lane.trace.trees) |tree| {
        hashInt(hash, u32, tree.height);
        hashInt(hash, u32, tree.column_log_sizes.len);
        for (tree.column_log_sizes) |value| hashInt(hash, u32, value);
    }
    hashInt(hash, u32, lane.trace.fri_fold_widths.len);
    for (lane.trace.fri_fold_widths) |value| hashInt(hash, u32, value);
}

fn hashFri(hash: anytype, lane: subject.LaneProgramV2) void {
    hashInt(hash, u32, lane.fri.query_count);
    hashInt(hash, u32, lane.fri.lifting_log_size);
    hashInt(hash, u32, lane.fri.layers.len);
    for (lane.fri.layers) |layer| {
        hashInt(hash, u32, layer.width);
        hashInt(hash, u32, layer.tree_height);
    }
}

fn hashPcs(hash: anytype, lane: pcs.Lane) void {
    hashInt(hash, u32, lane.verifier_id);
    hashInt(hash, u32, lane.circuit_id);
    hashInt(hash, u32, lane.profile.sample_count);
    hashInt(hash, u32, lane.profile.query_count);
    hashInt(hash, u32, lane.profile.lifting_log_size);
    hashInt(hash, u32, lane.profile.trees.len);
    for (lane.profile.trees) |tree| {
        hashInt(hash, u32, tree.column_log_sizes.len);
        for (tree.column_log_sizes) |value| hashInt(hash, u32, value);
    }
    hash.update(&lane.graph.identity_digest);
    hashInt(hash, u32, lane.bindings.len);
    for (lane.bindings) |binding| {
        hashInt(hash, u32, binding.node_id);
        hashPcsSource(hash, binding.source);
    }
}

fn hashPcsSource(hash: anytype, source: pcs.Source) void {
    const tag = std.meta.activeTag(source);
    hashInt(hash, u8, @intFromEnum(tag));
    switch (source) {
        .active_selector => {},
        .sampled_value_word => |value| {
            hashInt(hash, u32, value.sample);
            hashInt(hash, u32, value.word);
        },
        .queried_value => |value| {
            hashInt(hash, u32, value.tree);
            hashInt(hash, u32, value.column);
            hashInt(hash, u32, value.query);
        },
        .oods_seed_word, .deep_randomness_word, .query_position => |value| hashInt(hash, u32, value),
        .query_bit => |value| {
            hashInt(hash, u32, value.query);
            hashInt(hash, u32, value.bit);
        },
        .answer_word => |value| {
            hashInt(hash, u32, value.query);
            hashInt(hash, u32, value.word);
        },
    }
}

fn nativeDigestSha256(value: [8]u32) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(NATIVE_DIGEST_DOMAIN);
    for (value) |word| hashInt(&hash, u32, word);
    return hash.finalResult();
}

fn requireSha(value: [32]u8) !void {
    if (std.mem.allEqual(u8, &value, 0))
        return error.InvalidFriRowsProgramDescriptor;
}

const Writer = struct {
    bytes: []u8,
    at: usize = 0,

    fn u8Value(self: *Writer, value: u8) void {
        self.bytes[self.at] = value;
        self.at += 1;
    }

    fn u16Value(self: *Writer, value: u16) void {
        std.mem.writeInt(u16, self.bytes[self.at..][0..2], value, .little);
        self.at += 2;
    }

    fn u32Value(self: *Writer, value: u32) void {
        std.mem.writeInt(u32, self.bytes[self.at..][0..4], value, .little);
        self.at += 4;
    }

    fn sha(self: *Writer, value: [32]u8) void {
        @memcpy(self.bytes[self.at..][0..32], &value);
        self.at += 32;
    }
};

const Reader = struct {
    bytes: []const u8,
    at: usize = 0,

    fn u8Value(self: *Reader) u8 {
        defer self.at += 1;
        return self.bytes[self.at];
    }

    fn u16Value(self: *Reader) u16 {
        defer self.at += 2;
        return std.mem.readInt(u16, self.bytes[self.at..][0..2], .little);
    }

    fn u32Value(self: *Reader) u32 {
        defer self.at += 4;
        return std.mem.readInt(u32, self.bytes[self.at..][0..4], .little);
    }

    fn sha(self: *Reader) [32]u8 {
        defer self.at += 32;
        return self.bytes[self.at..][0..32].*;
    }
};

fn hashInt(hash: anytype, comptime T: type, value: anytype) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, @intCast(value), .little);
    hash.update(&bytes);
}

comptime {
    if (FORMAT_VERSION != 2 or SCHEMA_VERSION != 1 or LANE_COUNT != 3 or
        ENCODED_BYTE_COUNT != 428)
    {
        @compileError("heterogeneous FRI rows descriptor contract drifted");
    }
}
