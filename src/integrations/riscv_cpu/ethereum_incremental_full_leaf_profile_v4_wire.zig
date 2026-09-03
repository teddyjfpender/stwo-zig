//! Canonical metadata codec for the joined V4 profile and role-aware public IO.
//!
//! These values are transport inputs only. Decoding validates canonical bytes
//! and typed identities, but cannot mint a fresh proof capability.

const std = @import("std");
const frontend = @import("stwo_riscv_frontend");

const profile_mod = @import("ethereum_incremental_full_leaf_profile_v4.zig");

const public_data = frontend.air.public_data;
const statement_v2 = frontend.air.statement_v2;
const incremental_public = frontend.air.incremental_public_logup_v4;
const ethereum_statement = frontend.air.guest_precompile.ethereum_statement;
const base_wire = frontend.prover_mod.guest_precompile.proof_artifact_wire;

pub const OwnedRolePublicTransportV4 = struct {
    allocator: std.mem.Allocator,
    input_words: []u32,
    output_words: []public_data.OutputWord,
    value: public_data.PublicData,

    pub fn deinit(self: *OwnedRolePublicTransportV4) void {
        self.allocator.free(self.output_words);
        self.allocator.free(self.input_words);
        self.* = undefined;
    }

    pub fn validateAgainst(
        self: *const OwnedRolePublicTransportV4,
        native: *const statement_v2.RiscVStatementV2,
    ) !void {
        if (self.value.io_entries.input_words.ptr != self.input_words.ptr or
            self.value.io_entries.input_words.len != self.input_words.len or
            self.value.io_entries.output_words.ptr != self.output_words.ptr or
            self.value.io_entries.output_words.len != self.output_words.len)
        {
            return error.InvalidIncrementalRolePublicTransportV4;
        }
        try incremental_public.validateSharedAuthority(
            &native.public_data,
            &self.value,
        );
    }
};

pub fn encodeRolePublic(
    writer: anytype,
    value: *const public_data.PublicData,
) !void {
    try value.validate();
    inline for (.{ value.initial_pc, value.final_pc, value.clock }) |field|
        try base_wire.writeInt(writer, u32, field);
    try writeU32s(writer, &value.initial_regs);
    try writeU32s(writer, &value.final_regs);
    try writeU32s(writer, &value.reg_last_clock);
    try writeOptionalU32(writer, value.program_root);
    try writeOptionalU32(writer, value.initial_rw_root);
    try writeOptionalU32(writer, value.final_rw_root);
    if (value.completion) |completion| {
        try base_wire.writeInt(writer, u8, 1);
        try base_wire.writeInt(writer, u32, @intFromEnum(completion.kind));
        try base_wire.writeInt(writer, u32, completion.address);
        try base_wire.writeInt(writer, u32, completion.value);
        try base_wire.writeInt(writer, u32, completion.clock);
    } else {
        try base_wire.writeInt(writer, u8, 0);
    }
    const io = value.io_entries;
    try base_wire.writeInt(writer, u32, io.input_start);
    try base_wire.writeInt(writer, u32, io.input_len);
    try base_wire.writeInt(writer, u64, @intCast(io.input_words.len));
    try writeU32s(writer, io.input_words);
    try base_wire.writeInt(writer, u32, io.output_len);
    try base_wire.writeInt(writer, u32, io.output_len_addr);
    try base_wire.writeInt(writer, u32, io.output_data_addr);
    try base_wire.writeInt(writer, u64, @intCast(io.output_words.len));
    for (io.output_words) |word| {
        try base_wire.writeInt(writer, u32, word.addr);
        try base_wire.writeInt(writer, u32, word.value);
        try base_wire.writeInt(writer, u32, word.clock);
    }
}

pub fn decodeRolePublic(
    allocator: std.mem.Allocator,
    bytes: []const u8,
    native: *const statement_v2.RiscVStatementV2,
    limits: base_wire.Limits,
) !OwnedRolePublicTransportV4 {
    try limits.validate();
    var cursor = base_wire.Cursor.init(bytes);
    var value: public_data.PublicData = undefined;
    value.initial_pc = try cursor.readInt(u32);
    value.final_pc = try cursor.readInt(u32);
    value.clock = try cursor.readInt(u32);
    try cursor.readU32Array(&value.initial_regs);
    try cursor.readU32Array(&value.final_regs);
    try cursor.readU32Array(&value.reg_last_clock);
    value.program_root = try readOptionalU32(&cursor);
    value.initial_rw_root = try readOptionalU32(&cursor);
    value.final_rw_root = try readOptionalU32(&cursor);
    value.completion = switch (try cursor.readInt(u8)) {
        0 => null,
        1 => public_data.Completion{
            .kind = try cursor.readKnownEnum(public_data.CompletionKind),
            .address = try cursor.readInt(u32),
            .value = try cursor.readInt(u32),
            .clock = try cursor.readInt(u32),
        },
        else => return error.InvalidIncrementalRolePublicTransportV4,
    };
    value.io_entries.input_start = try cursor.readInt(u32);
    value.io_entries.input_len = try cursor.readInt(u32);
    const input_count = try boundedCount(&cursor, bytes.len, @sizeOf(u32));
    const max_input_words = std.math.divCeil(
        usize,
        limits.max_input_bytes,
        @sizeOf(u32),
    ) catch return error.IncrementalFullLeafArtifactResourceLimitExceeded;
    if (input_count > max_input_words)
        return error.IncrementalFullLeafArtifactResourceLimitExceeded;
    const input_words = try allocator.alloc(u32, input_count);
    errdefer allocator.free(input_words);
    for (input_words) |*word| word.* = try cursor.readInt(u32);
    value.io_entries.input_words = input_words;
    value.io_entries.output_len = try cursor.readInt(u32);
    value.io_entries.output_len_addr = try cursor.readInt(u32);
    value.io_entries.output_data_addr = try cursor.readInt(u32);
    const output_count = try boundedCount(
        &cursor,
        bytes.len,
        @sizeOf(public_data.OutputWord),
    );
    const max_output_words = std.math.add(
        usize,
        std.math.divCeil(
            usize,
            limits.max_output_bytes,
            @sizeOf(u32),
        ) catch return error.IncrementalFullLeafArtifactResourceLimitExceeded,
        1,
    ) catch return error.IncrementalFullLeafArtifactResourceLimitExceeded;
    if (output_count > max_output_words)
        return error.IncrementalFullLeafArtifactResourceLimitExceeded;
    const output_words = try allocator.alloc(public_data.OutputWord, output_count);
    errdefer allocator.free(output_words);
    for (output_words) |*word| word.* = .{
        .addr = try cursor.readInt(u32),
        .value = try cursor.readInt(u32),
        .clock = try cursor.readInt(u32),
    };
    value.io_entries.output_words = output_words;
    try cursor.requireDone();
    var result = OwnedRolePublicTransportV4{
        .allocator = allocator,
        .input_words = input_words,
        .output_words = output_words,
        .value = value,
    };
    try result.validateAgainst(native);
    return result;
}

pub fn encodeProfile(
    writer: anytype,
    value: *const profile_mod.AuthorityV4,
    native: *const statement_v2.RiscVStatementV2,
    extension: *const ethereum_statement.Statement,
    role_aware: *const public_data.PublicData,
) !void {
    try value.validateAgainstStatement(native, extension, role_aware);
    try base_wire.writeInt(writer, u16, value.format_version);
    try base_wire.writeInt(writer, u16, value.schema_version);
    try writeBool(writer, value.production_active);
    try writeBool(writer, value.proof_admissible);
    try writeBool(writer, value.fresh_verification_available);
    try base_wire.writeInt(writer, u8, value.reserved);
    try writeEnum(writer, value.statement_family);
    try writeEnum(writer, value.boundary_policy);
    try base_wire.writeInt(writer, u32, value.coordinate.segment_index);
    try base_wire.writeInt(writer, u32, value.coordinate.segment_count);
    try writeU32s(writer, &value.segment_public_wire_id);
    try base_wire.writeInt(writer, u32, value.continuation_roots.entry);
    try base_wire.writeInt(writer, u32, value.continuation_roots.exit);
    try writer.writeAll(&value.boundary_artifact_content_sha256);
    try encodeBaseGeometry(writer, &value.base_geometry);
    try writer.writeAll(&value.ethereum_identity_sha256);
    try writer.writeAll(&value.public_boundary_identity_sha256);
    try encodeBridgeGeometry(writer, &value.bridge_geometry);
    try encodeProtocol(writer, &value.protocol);
    try writer.writeAll(&value.identity_sha256);
}

pub fn decodeProfile(
    bytes: []const u8,
    native: *const statement_v2.RiscVStatementV2,
    extension: *const ethereum_statement.Statement,
    role_aware: *const public_data.PublicData,
) !profile_mod.AuthorityV4 {
    var cursor = base_wire.Cursor.init(bytes);
    var result: profile_mod.AuthorityV4 = undefined;
    result.format_version = try cursor.readInt(u16);
    result.schema_version = try cursor.readInt(u16);
    result.production_active = try readBool(&cursor);
    result.proof_admissible = try readBool(&cursor);
    result.fresh_verification_available = try readBool(&cursor);
    result.reserved = try cursor.readInt(u8);
    result.statement_family = try cursor.readKnownEnum(@TypeOf(result.statement_family));
    result.boundary_policy = try cursor.readKnownEnum(@TypeOf(result.boundary_policy));
    result.coordinate.segment_index = try cursor.readInt(u32);
    result.coordinate.segment_count = try cursor.readInt(u32);
    try cursor.readU32Array(&result.segment_public_wire_id);
    result.continuation_roots.entry = try cursor.readInt(u32);
    result.continuation_roots.exit = try cursor.readInt(u32);
    try cursor.readExact(&result.boundary_artifact_content_sha256);
    try decodeBaseGeometry(&cursor, &result.base_geometry);
    result.ethereum = extension.*;
    try cursor.readExact(&result.ethereum_identity_sha256);
    try cursor.readExact(&result.public_boundary_identity_sha256);
    try decodeBridgeGeometry(&cursor, &result.bridge_geometry);
    try decodeProtocol(&cursor, &result.protocol);
    try cursor.readExact(&result.identity_sha256);
    try cursor.requireDone();
    try result.validateAgainstStatement(native, extension, role_aware);
    return result;
}

fn encodeBaseGeometry(writer: anytype, value: anytype) !void {
    try base_wire.writeInt(writer, u32, value.component_count);
    try base_wire.writeInt(writer, u32, value.infrastructure_count);
    try writeU32s(writer, &value.compatibility_tree_columns);
    try writeU32s(writer, &value.physical_tree_columns);
    try base_wire.writeInt(writer, u32, value.maximum_column_log_size);
    try writeU32s(writer, &value.statement_authority_id);
    const activation = value.lookup_activation;
    try base_wire.writeInt(writer, u16, activation.format_version);
    try writer.writeAll(&activation.manifest_identity);
    try writer.writeAll(&activation.statement_identity);
    try writer.writeAll(&activation.activation_identity);
    try base_wire.writeInt(writer, u32, activation.component_count);
    try base_wire.writeInt(writer, u32, activation.opcode_main_columns);
    try base_wire.writeInt(writer, u32, activation.opcode_interaction_columns);
    try base_wire.writeInt(writer, u32, activation.detailed_claim_count);
    try writer.writeAll(&value.identity_sha256);
}

fn decodeBaseGeometry(cursor: *base_wire.Cursor, value: anytype) !void {
    value.component_count = try cursor.readInt(u32);
    value.infrastructure_count = try cursor.readInt(u32);
    try cursor.readU32Array(&value.compatibility_tree_columns);
    try cursor.readU32Array(&value.physical_tree_columns);
    value.maximum_column_log_size = try cursor.readInt(u32);
    try cursor.readU32Array(&value.statement_authority_id);
    const activation = &value.lookup_activation;
    activation.format_version = try cursor.readInt(u16);
    try cursor.readExact(&activation.manifest_identity);
    try cursor.readExact(&activation.statement_identity);
    try cursor.readExact(&activation.activation_identity);
    activation.component_count = try cursor.readInt(u32);
    activation.opcode_main_columns = try cursor.readInt(u32);
    activation.opcode_interaction_columns = try cursor.readInt(u32);
    activation.detailed_claim_count = try cursor.readInt(u32);
    try cursor.readExact(&value.identity_sha256);
}

fn encodeBridgeGeometry(writer: anytype, value: anytype) !void {
    try base_wire.writeInt(writer, u16, value.format_version);
    try base_wire.writeInt(writer, u32, value.n_rows);
    try base_wire.writeInt(writer, u32, value.log_size);
    try base_wire.writeInt(writer, u64, @intCast(value.placement.is_first_col_idx));
    try base_wire.writeInt(writer, u64, @intCast(value.placement.is_active_col_idx));
    try base_wire.writeInt(writer, u64, @intCast(value.placement.main_col_offset));
    try base_wire.writeInt(writer, u64, @intCast(value.placement.interaction_col_offset));
    try base_wire.writeInt(writer, u32, value.total_preprocessed_columns);
    try base_wire.writeInt(writer, u32, value.total_main_columns);
    try base_wire.writeInt(writer, u32, value.total_interaction_columns);
    try writer.writeAll(&value.identity_sha256);
}

fn decodeBridgeGeometry(cursor: *base_wire.Cursor, value: anytype) !void {
    value.format_version = try cursor.readInt(u16);
    value.n_rows = try cursor.readInt(u32);
    value.log_size = try cursor.readInt(u32);
    value.placement.is_first_col_idx = try readUsize(cursor);
    value.placement.is_active_col_idx = try readUsize(cursor);
    value.placement.main_col_offset = try readUsize(cursor);
    value.placement.interaction_col_offset = try readUsize(cursor);
    value.total_preprocessed_columns = try cursor.readInt(u32);
    value.total_main_columns = try cursor.readInt(u32);
    value.total_interaction_columns = try cursor.readInt(u32);
    try cursor.readExact(&value.identity_sha256);
}

fn encodeProtocol(writer: anytype, value: anytype) !void {
    try writeU32s(writer, &value.profile_words);
    try writeU32s(writer, &value.protocol_id);
    try writer.writeAll(&value.proof_security_identity_sha256);
    inline for (.{
        value.pcs.pow_bits,
        value.pcs.log_blowup_factor,
        value.pcs.query_count,
        value.pcs.fold_step,
        value.pcs.log_last_layer_degree_bound,
        value.pcs.lifting_mode,
        value.pcs.configured_security_bits,
    }) |field| try base_wire.writeInt(writer, u32, field);
    try writer.writeAll(&value.pcs.identity_sha256);
    try writer.writeAll(&value.identity_sha256);
}

fn decodeProtocol(cursor: *base_wire.Cursor, value: anytype) !void {
    try cursor.readU32Array(&value.profile_words);
    try cursor.readU32Array(&value.protocol_id);
    try cursor.readExact(&value.proof_security_identity_sha256);
    value.pcs.pow_bits = try cursor.readInt(u32);
    value.pcs.log_blowup_factor = try cursor.readInt(u32);
    value.pcs.query_count = try cursor.readInt(u32);
    value.pcs.fold_step = try cursor.readInt(u32);
    value.pcs.log_last_layer_degree_bound = try cursor.readInt(u32);
    value.pcs.lifting_mode = try cursor.readInt(u32);
    value.pcs.configured_security_bits = try cursor.readInt(u32);
    try cursor.readExact(&value.pcs.identity_sha256);
    try cursor.readExact(&value.identity_sha256);
}

fn writeOptionalU32(writer: anytype, value: ?u32) !void {
    if (value) |present| {
        try base_wire.writeInt(writer, u8, 1);
        try base_wire.writeInt(writer, u32, present);
    } else {
        try base_wire.writeInt(writer, u8, 0);
    }
}

fn readOptionalU32(cursor: *base_wire.Cursor) !?u32 {
    return switch (try cursor.readInt(u8)) {
        0 => null,
        1 => try cursor.readInt(u32),
        else => error.InvalidIncrementalRolePublicTransportV4,
    };
}

fn boundedCount(
    cursor: *base_wire.Cursor,
    section_bytes: usize,
    minimum_item_bytes: usize,
) !usize {
    const value = std.math.cast(usize, try cursor.readInt(u64)) orelse
        return error.IncrementalFullLeafArtifactResourceLimitExceeded;
    if (value > section_bytes / minimum_item_bytes)
        return error.IncrementalFullLeafArtifactResourceLimitExceeded;
    return value;
}

fn writeBool(writer: anytype, value: bool) !void {
    try base_wire.writeInt(writer, u8, @intFromBool(value));
}

fn readBool(cursor: *base_wire.Cursor) !bool {
    return switch (try cursor.readInt(u8)) {
        0 => false,
        1 => true,
        else => error.InvalidBoolean,
    };
}

fn writeEnum(writer: anytype, value: anytype) !void {
    const T = @TypeOf(value);
    try base_wire.writeInt(
        writer,
        @typeInfo(T).@"enum".tag_type,
        @intFromEnum(value),
    );
}

fn writeU32s(writer: anytype, values: []const u32) !void {
    for (values) |value| try base_wire.writeInt(writer, u32, value);
}

fn readUsize(cursor: *base_wire.Cursor) !usize {
    return std.math.cast(usize, try cursor.readInt(u64)) orelse
        error.IncrementalFullLeafArtifactResourceLimitExceeded;
}
