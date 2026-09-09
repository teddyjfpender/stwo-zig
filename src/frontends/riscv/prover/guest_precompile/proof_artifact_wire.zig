//! Canonical fixed-width metadata codec for guest-precompile proof artifacts.
//!
//! The STARK proof itself keeps the shared postcard encoding.  This module
//! owns only the verifier metadata around it: the public core statement, the
//! authenticated extension, and every active interaction claim.  Counts are
//! encoded redundantly where they protect an independently owned value (for
//! example a claim descriptor) and are checked against statement authority on
//! decode.  Inactive fixed-capacity slots are never placed on the wire.

const std = @import("std");
const core = @import("stwo_core");
const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
const m31 = core.fields.m31;
const caller_component = @import("../../air/guest_precompile/caller_component.zig");
const component_registry = @import("../../air/guest_precompile/component_registry.zig");
const provider_component = @import("../../air/guest_precompile/provider_component.zig");
const guest_statement = @import("../../air/guest_precompile/statement.zig");
const opcode_entries = @import("../../air/lookups/opcode_entries.zig");
const public_data = @import("../../air/public_data.zig");
const base_statement = @import("../../air/statement.zig");
const profile_types = @import("types.zig");

pub const extension_encoded_size: usize = 278;

/// Resource limits enforced before their corresponding allocation.
///
/// The I/O defaults match the released base artifact policy.  They are kept
/// here as values rather than imported from that JSON publication schema: the
/// profile binary envelope and the release publication contract are separate
/// versioned protocols.
pub const Limits = struct {
    max_artifact_bytes: usize = 256 * 1024 * 1024,
    max_proof_bytes: usize = 128 * 1024 * 1024,
    max_input_bytes: usize = 16 * 1024 * 1024,
    max_output_bytes: usize = 16 * 1024 * 1024,
    max_queries: usize = 1024,
    max_pow_bits: u32 = 128,

    pub fn validate(self: Limits) !void {
        if (self.max_artifact_bytes == 0 or self.max_proof_bytes == 0 or
            self.max_proof_bytes > self.max_artifact_bytes or
            self.max_input_bytes > std.math.maxInt(u32) or
            self.max_output_bytes > std.math.maxInt(u32) or
            self.max_queries == 0)
        {
            return error.InvalidResourceLimits;
        }
    }

    fn maxInputWords(self: Limits) !usize {
        return std.math.divCeil(usize, self.max_input_bytes, @sizeOf(u32)) catch
            return error.InvalidResourceLimits;
    }

    fn maxOutputWords(self: Limits) !usize {
        const data = std.math.divCeil(
            usize,
            self.max_output_bytes,
            @sizeOf(u32),
        ) catch return error.InvalidResourceLimits;
        return std.math.add(usize, data, 1) catch
            return error.InvalidResourceLimits;
    }
};

/// A decoded core statement and the two allocations borrowed by its slices.
pub const OwnedStatement = struct {
    value: base_statement.RiscVStatement,
    input_words: []u32,
    output_words: []public_data.OutputWord,

    pub fn deinit(self: *OwnedStatement, allocator: std.mem.Allocator) void {
        allocator.free(self.input_words);
        allocator.free(self.output_words);
        self.* = undefined;
    }
};

pub fn encodeStatement(
    writer: anytype,
    statement: *const base_statement.RiscVStatement,
    limits: Limits,
) !void {
    if (statement.n_components > base_statement.MAX_COMPONENTS or
        statement.n_infra > base_statement.MAX_INFRA_COMPONENTS)
    {
        return error.InvalidComponentCount;
    }
    try statement.public_data.validate();
    try validateIoResources(&statement.public_data, limits);

    try writeInt(writer, u32, statement.n_components);
    for (statement.component_descs[0..statement.n_components]) |descriptor| {
        try writeEnum(writer, descriptor.family);
        try writeInt(writer, u32, descriptor.log_size);
        try writeInt(writer, u32, descriptor.n_rows);
        try writeInt(writer, u32, descriptor.n_columns);
    }
    try writeInt(writer, u32, statement.initial_pc);
    try writeInt(writer, u32, statement.final_pc);
    try writeInt(writer, u32, statement.total_steps);
    try writeInt(writer, u32, statement.n_infra);
    for (statement.infra_descs[0..statement.n_infra]) |descriptor| {
        try writeEnum(writer, descriptor.kind);
        try writeInt(writer, u32, descriptor.log_size);
        try writeInt(writer, u32, descriptor.n_rows);
        try writeInt(writer, u32, descriptor.n_columns);
    }

    const public = statement.public_data;
    try writeInt(writer, u32, public.initial_pc);
    try writeInt(writer, u32, public.final_pc);
    try writeInt(writer, u32, public.clock);
    try writeU32Array(writer, &public.initial_regs);
    try writeU32Array(writer, &public.final_regs);
    try writeU32Array(writer, &public.reg_last_clock);
    try writeOptionalU32(writer, public.program_root);
    try writeOptionalU32(writer, public.initial_rw_root);
    try writeOptionalU32(writer, public.final_rw_root);
    if (public.completion) |completion| {
        try writer.writeByte(1);
        try writeEnum(writer, completion.kind);
        try writeInt(writer, u32, completion.address);
        try writeInt(writer, u32, completion.value);
        try writeInt(writer, u32, completion.clock);
    } else {
        try writer.writeByte(0);
    }

    const io = public.io_entries;
    try writeInt(writer, u32, io.input_start);
    try writeInt(writer, u32, io.input_len);
    try writeCount(writer, io.input_words.len);
    try writeU32Array(writer, io.input_words);
    try writeInt(writer, u32, io.output_len);
    try writeInt(writer, u32, io.output_len_addr);
    try writeInt(writer, u32, io.output_data_addr);
    try writeCount(writer, io.output_words.len);
    for (io.output_words) |word| {
        try writeInt(writer, u32, word.addr);
        try writeInt(writer, u32, word.value);
        try writeInt(writer, u32, word.clock);
    }
}

pub fn decodeStatement(
    allocator: std.mem.Allocator,
    bytes: []const u8,
    limits: Limits,
) !OwnedStatement {
    var cursor = Cursor.init(bytes);
    var result: base_statement.RiscVStatement = undefined;
    result.initializeDescriptorStorage();
    result.n_components = try cursor.readInt(u32);
    if (result.n_components > base_statement.MAX_COMPONENTS)
        return error.InvalidComponentCount;
    for (result.component_descs[0..result.n_components]) |*descriptor| {
        descriptor.* = .{
            .family = try cursor.readKnownEnum(@TypeOf(descriptor.family)),
            .log_size = try cursor.readInt(u32),
            .n_rows = try cursor.readInt(u32),
            .n_columns = try cursor.readInt(u32),
        };
    }
    result.initial_pc = try cursor.readInt(u32);
    result.final_pc = try cursor.readInt(u32);
    result.total_steps = try cursor.readInt(u32);
    result.n_infra = try cursor.readInt(u32);
    if (result.n_infra > base_statement.MAX_INFRA_COMPONENTS)
        return error.InvalidInfrastructureCount;
    for (result.infra_descs[0..result.n_infra]) |*descriptor| {
        descriptor.* = .{
            .kind = try cursor.readKnownEnum(base_statement.InfraKind),
            .log_size = try cursor.readInt(u32),
            .n_rows = try cursor.readInt(u32),
            .n_columns = try cursor.readInt(u32),
        };
    }

    var public: public_data.PublicData = undefined;
    public.initial_pc = try cursor.readInt(u32);
    public.final_pc = try cursor.readInt(u32);
    public.clock = try cursor.readInt(u32);
    try cursor.readU32Array(&public.initial_regs);
    try cursor.readU32Array(&public.final_regs);
    try cursor.readU32Array(&public.reg_last_clock);
    public.program_root = try cursor.readOptionalU32();
    public.initial_rw_root = try cursor.readOptionalU32();
    public.final_rw_root = try cursor.readOptionalU32();
    public.completion = switch (try cursor.readByte()) {
        0 => null,
        1 => .{
            .kind = try cursor.readKnownEnum(public_data.CompletionKind),
            .address = try cursor.readInt(u32),
            .value = try cursor.readInt(u32),
            .clock = try cursor.readInt(u32),
        },
        else => return error.InvalidOptionTag,
    };

    const input_start = try cursor.readInt(u32);
    const input_len = try cursor.readInt(u32);
    const input_count = try cursor.readCount();
    if (input_len > limits.max_input_bytes or
        input_count > try limits.maxInputWords())
    {
        return error.IoResourceLimitExceeded;
    }
    const expected_input = std.math.divCeil(usize, input_len, @sizeOf(u32)) catch
        return error.InvalidIoCount;
    if (input_count != expected_input) return error.InvalidIoCount;
    const input_words = try allocator.alloc(u32, input_count);
    errdefer allocator.free(input_words);
    try cursor.readU32Array(input_words);

    const output_len = try cursor.readInt(u32);
    const output_len_addr = try cursor.readInt(u32);
    const output_data_addr = try cursor.readInt(u32);
    const output_count = try cursor.readCount();
    if (output_len > limits.max_output_bytes or
        output_count > try limits.maxOutputWords())
    {
        return error.IoResourceLimitExceeded;
    }
    try validateOutputCount(output_len, output_data_addr, output_count);
    const output_words = try allocator.alloc(public_data.OutputWord, output_count);
    errdefer allocator.free(output_words);
    for (output_words) |*word| {
        word.* = .{
            .addr = try cursor.readInt(u32),
            .value = try cursor.readInt(u32),
            .clock = try cursor.readInt(u32),
        };
    }

    public.io_entries = .{
        .input_start = input_start,
        .input_len = input_len,
        .input_words = input_words,
        .output_len = output_len,
        .output_len_addr = output_len_addr,
        .output_data_addr = output_data_addr,
        .output_words = output_words,
    };
    try public.validate();
    result.public_data = public;
    try cursor.requireDone();
    return .{
        .value = result,
        .input_words = input_words,
        .output_words = output_words,
    };
}

fn validateIoResources(public: *const public_data.PublicData, limits: Limits) !void {
    const io = public.io_entries;
    if (io.input_len > limits.max_input_bytes or
        io.input_words.len > try limits.maxInputWords() or
        io.output_len > limits.max_output_bytes or
        io.output_words.len > try limits.maxOutputWords())
    {
        return error.IoResourceLimitExceeded;
    }
}

fn validateOutputCount(
    output_len: u32,
    output_data_addr: u32,
    output_count: usize,
) !void {
    if (output_count == 0) {
        if (output_len != 0) return error.InvalidIoCount;
        return;
    }
    const data_count: usize = if (output_len == 0)
        0
    else blk: {
        const end = std.math.add(u32, output_data_addr, output_len) catch
            return error.InvalidIoCount;
        const start_aligned = output_data_addr & ~@as(u32, 3);
        const end_aligned = (@as(u64, end) + 3) & ~@as(u64, 3);
        break :blk std.math.cast(usize, (end_aligned - start_aligned) / 4) orelse
            return error.InvalidIoCount;
    };
    const expected = std.math.add(usize, data_count, 1) catch
        return error.InvalidIoCount;
    if (output_count != expected) return error.InvalidIoCount;
}

pub fn encodeExtension(
    writer: anytype,
    extension: *const guest_statement.ExtensionStatement,
) !void {
    try writeEnum(writer, extension.profile);
    try writeInt(writer, u16, extension.abi_version);
    try writeInt(writer, u16, extension.statement_version);
    try writeEnum(writer, extension.active_prefix);
    try writeEnum(writer, extension.memory_policy);
    try writer.writeAll(&extension.manifest_digest);
    try writer.writeAll(&extension.semantic_digest);
    try writeInt(writer, u32, extension.counts.n_guest);
    try writeInt(writer, u32, extension.counts.custom_retirements);
    try writeInt(writer, u32, extension.counts.frozen_call_count);
    for (extension.components) |descriptor| try encodeDescriptor(writer, descriptor);

    const admission = extension.admission;
    try writeInt(writer, u64, admission.n_base);
    try writeInt(writer, u64, admission.total_steps);
    try writeInt(writer, u64, admission.n_guest);
    try writeInt(writer, u64, admission.clock_update_rows);
    try writeInt(writer, u64, admission.memory_rows);
    try writeInt(writer, u64, admission.memory_relation_terms);
    for (admission.base_fixed_table_bounds) |value| try writeInt(writer, u64, value);
    for (admission.extended_fixed_table_bounds) |value| try writeInt(writer, u64, value);
}

pub fn decodeExtension(bytes: []const u8) !guest_statement.ExtensionStatement {
    if (bytes.len != extension_encoded_size) return error.InvalidExtensionLength;
    var cursor = Cursor.init(bytes);
    var result: guest_statement.ExtensionStatement = undefined;
    result.profile = try cursor.readKnownEnum(@TypeOf(result.profile));
    result.abi_version = try cursor.readInt(u16);
    result.statement_version = try cursor.readInt(u16);
    result.active_prefix = try cursor.readKnownEnum(@TypeOf(result.active_prefix));
    result.memory_policy = try cursor.readKnownEnum(@TypeOf(result.memory_policy));
    try cursor.readExact(&result.manifest_digest);
    try cursor.readExact(&result.semantic_digest);
    result.counts = .{
        .n_guest = try cursor.readInt(u32),
        .custom_retirements = try cursor.readInt(u32),
        .frozen_call_count = try cursor.readInt(u32),
    };
    for (&result.components) |*descriptor| descriptor.* = try decodeDescriptor(&cursor);
    result.admission.n_base = try cursor.readInt(u64);
    result.admission.total_steps = try cursor.readInt(u64);
    result.admission.n_guest = try cursor.readInt(u64);
    result.admission.clock_update_rows = try cursor.readInt(u64);
    result.admission.memory_rows = try cursor.readInt(u64);
    result.admission.memory_relation_terms = try cursor.readInt(u64);
    for (&result.admission.base_fixed_table_bounds) |*value|
        value.* = try cursor.readInt(u64);
    for (&result.admission.extended_fixed_table_bounds) |*value|
        value.* = try cursor.readInt(u64);
    try cursor.requireDone();
    return result;
}

pub fn encodeClaim(
    writer: anytype,
    statement: *const base_statement.RiscVStatement,
    claim: *const profile_types.InteractionClaim,
) !void {
    if (!claim.finalized) return error.InteractionClaimNotFinalized;
    try writer.writeByte(1);
    try encodeBaseClaim(writer, statement, &claim.base);
    try encodeComponentClaim(writer, claim.caller);
    try encodeComponentClaim(writer, claim.provider);
}

/// Encode the active prefix of the fixed-capacity base interaction claim.
/// This is the canonical base-claim wire shared by every append-only guest
/// profile; callers remain responsible for framing their profile claims.
pub fn encodeBaseClaim(
    writer: anytype,
    statement: *const base_statement.RiscVStatement,
    claim: *const base_statement.RiscVInteractionClaim,
) !void {
    _ = try claim.canonical(statement);
    try writeInt(writer, u32, claim.n_components);
    for (statement.component_descs[0..statement.n_components], 0..) |descriptor, index| {
        try writeEnum(writer, descriptor.family);
        const sums = try claim.opcodeClaims(descriptor.family, index);
        try writeSmallCount(writer, sums.len);
        for (sums) |sum| try writeQm31(writer, sum);
    }
    try writeInt(writer, u32, claim.n_infra);
    for (statement.infra_descs[0..statement.n_infra], 0..) |descriptor, index| {
        try writeEnum(writer, descriptor.kind);
        const count = base_statement.nClaimedSumsForInfra(descriptor.kind);
        try writeSmallCount(writer, count);
        for (0..count) |sum_index| {
            try writeQm31(writer, try claim.infraClaim(
                descriptor.kind,
                index,
                sum_index,
            ));
        }
    }
    try writeInt(writer, u64, claim.interaction_pow);
}

pub fn decodeClaim(
    allocator: std.mem.Allocator,
    bytes: []const u8,
    statement: *const base_statement.RiscVStatement,
    extension: *const guest_statement.ExtensionStatement,
) !*profile_types.InteractionClaim {
    var cursor = Cursor.init(bytes);
    if (try cursor.readByte() != 1) return error.InteractionClaimNotFinalized;
    const n_components = try cursor.readInt(u32);
    if (n_components != statement.n_components) return error.BaseClaimCountMismatch;

    const claim = try profile_types.InteractionClaim.initBaseInto(
        allocator,
        statement,
        extension,
    );
    errdefer claim.destroy(allocator);
    try decodeBaseClaimAfterCount(&cursor, statement, &claim.base, n_components);
    claim.caller = try decodeCallerClaim(&cursor);
    claim.provider = try decodeProviderClaim(&cursor);
    claim.finalized = true;
    try cursor.requireDone();
    try claim.validate(statement, extension);
    return claim;
}

/// Decode a complete canonical base claim into caller-owned fixed-capacity
/// storage. No large temporary claim is allocated.
pub fn decodeBaseClaimInto(
    cursor: *Cursor,
    statement: *const base_statement.RiscVStatement,
    claim: *base_statement.RiscVInteractionClaim,
) !void {
    const n_components = try cursor.readInt(u32);
    if (n_components != statement.n_components) return error.BaseClaimCountMismatch;
    try decodeBaseClaimAfterCount(cursor, statement, claim, n_components);
}

fn decodeBaseClaimAfterCount(
    cursor: *Cursor,
    statement: *const base_statement.RiscVStatement,
    claim: *base_statement.RiscVInteractionClaim,
    n_components: u32,
) !void {
    claim.initZeroInto();
    claim.n_components = n_components;
    for (statement.component_descs[0..statement.n_components], 0..) |descriptor, index| {
        const family = try cursor.readKnownEnum(@TypeOf(descriptor.family));
        if (family != descriptor.family) return error.ClaimDescriptorMismatch;
        const count = try cursor.readSmallCount();
        const expected = opcode_entries.batchCount(descriptor.family);
        if (count != expected) return error.InvalidClaimCount;
        for (0..count) |sum_index| {
            claim.opcode_claims[index][sum_index] = try cursor.readQm31();
        }
    }

    const n_infra = try cursor.readInt(u32);
    if (n_infra != statement.n_infra) return error.BaseClaimCountMismatch;
    claim.n_infra = n_infra;
    for (statement.infra_descs[0..statement.n_infra], 0..) |descriptor, index| {
        const kind = try cursor.readKnownEnum(base_statement.InfraKind);
        if (kind != descriptor.kind) return error.ClaimDescriptorMismatch;
        const count = try cursor.readSmallCount();
        const expected = base_statement.nClaimedSumsForInfra(descriptor.kind);
        if (count != expected) return error.InvalidClaimCount;
        for (0..count) |sum_index| try claim.setInfraClaim(
            descriptor.kind,
            index,
            sum_index,
            try cursor.readQm31(),
        );
    }
    claim.interaction_pow = try cursor.readInt(u64);
    _ = try claim.canonical(statement);
}

fn encodeComponentClaim(writer: anytype, claim: anytype) !void {
    try encodeDescriptor(writer, claim.descriptor);
    try writeSmallCount(writer, claim.batch_sums.len);
    for (claim.batch_sums) |sum| try writeQm31(writer, sum);
    try writeQm31(writer, claim.component_sum);
}

fn decodeCallerClaim(cursor: *Cursor) !caller_component.Claim {
    const descriptor = try decodeDescriptor(cursor);
    const count = try cursor.readSmallCount();
    if (count != caller_component.batch_count) return error.InvalidClaimCount;
    var sums: [caller_component.batch_count]QM31 = undefined;
    for (&sums) |*sum| sum.* = try cursor.readQm31();
    return .{
        .descriptor = descriptor,
        .batch_sums = sums,
        .component_sum = try cursor.readQm31(),
    };
}

fn decodeProviderClaim(cursor: *Cursor) !provider_component.Claim {
    const descriptor = try decodeDescriptor(cursor);
    const count = try cursor.readSmallCount();
    if (count != provider_component.batch_count) return error.InvalidClaimCount;
    var sums: [provider_component.batch_count]QM31 = undefined;
    for (&sums) |*sum| sum.* = try cursor.readQm31();
    return .{
        .descriptor = descriptor,
        .batch_sums = sums,
        .component_sum = try cursor.readQm31(),
    };
}

fn encodeDescriptor(writer: anytype, descriptor: component_registry.Descriptor) !void {
    try writeEnum(writer, descriptor.slot);
    try writeEnum(writer, descriptor.kind);
    try writeInt(writer, u16, descriptor.version);
    try writeInt(writer, u32, descriptor.n_rows);
    try writeInt(writer, u32, descriptor.log_size);
    try writeInt(writer, u16, descriptor.preprocessed_columns);
    try writeInt(writer, u16, descriptor.main_columns);
    try writeInt(writer, u16, descriptor.interaction_columns);
}

fn decodeDescriptor(cursor: *Cursor) !component_registry.Descriptor {
    return .{
        .slot = try cursor.readKnownEnum(component_registry.Slot),
        .kind = try cursor.readKnownEnum(component_registry.Kind),
        .version = try cursor.readInt(u16),
        .n_rows = try cursor.readInt(u32),
        .log_size = try cursor.readInt(u32),
        .preprocessed_columns = try cursor.readInt(u16),
        .main_columns = try cursor.readInt(u16),
        .interaction_columns = try cursor.readInt(u16),
    };
}

pub fn writeQm31(writer: anytype, value: QM31) !void {
    for (value.toM31Array()) |coordinate|
        try writeInt(writer, u32, coordinate.toU32());
}

fn writeEnum(writer: anytype, value: anytype) !void {
    const T = @TypeOf(value);
    const Tag = @typeInfo(T).@"enum".tag_type;
    try writeInt(writer, Tag, @intFromEnum(value));
}

fn writeOptionalU32(writer: anytype, value: ?u32) !void {
    if (value) |present| {
        try writer.writeByte(1);
        try writeInt(writer, u32, present);
    } else {
        try writer.writeByte(0);
    }
}

fn writeU32Array(writer: anytype, values: []const u32) !void {
    for (values) |value| try writeInt(writer, u32, value);
}

fn writeCount(writer: anytype, value: usize) !void {
    try writeInt(
        writer,
        u32,
        std.math.cast(u32, value) orelse return error.CountOverflow,
    );
}

fn writeSmallCount(writer: anytype, value: anytype) !void {
    try writeInt(
        writer,
        u16,
        std.math.cast(u16, value) orelse return error.CountOverflow,
    );
}

pub fn writeInt(writer: anytype, comptime T: type, value: T) !void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, value, .little);
    try writer.writeAll(&bytes);
}

/// Bounds-checking cursor shared with the envelope header decoder.
pub const Cursor = struct {
    bytes: []const u8,
    position: usize = 0,

    pub fn init(bytes: []const u8) Cursor {
        return .{ .bytes = bytes };
    }

    pub fn readByte(self: *Cursor) !u8 {
        if (self.position == self.bytes.len) return error.EndOfStream;
        const result = self.bytes[self.position];
        self.position += 1;
        return result;
    }

    pub fn readInt(self: *Cursor, comptime T: type) !T {
        const raw = try self.take(@sizeOf(T));
        return std.mem.readInt(T, raw[0..@sizeOf(T)], .little);
    }

    pub fn readKnownEnum(self: *Cursor, comptime T: type) !T {
        const Tag = @typeInfo(T).@"enum".tag_type;
        const raw = try self.readInt(Tag);
        inline for (std.meta.fields(T)) |field| {
            if (raw == field.value) return @enumFromInt(raw);
        }
        return error.InvalidEnumTag;
    }

    pub fn readOptionalU32(self: *Cursor) !?u32 {
        return switch (try self.readByte()) {
            0 => null,
            1 => try self.readInt(u32),
            else => error.InvalidOptionTag,
        };
    }

    pub fn readCount(self: *Cursor) !usize {
        return @intCast(try self.readInt(u32));
    }

    pub fn readSmallCount(self: *Cursor) !usize {
        return @intCast(try self.readInt(u16));
    }

    pub fn readU32Array(self: *Cursor, destination: []u32) !void {
        for (destination) |*value| value.* = try self.readInt(u32);
    }

    pub fn readQm31(self: *Cursor) !QM31 {
        var coordinates: [4]M31 = undefined;
        for (&coordinates) |*coordinate| {
            const raw = try self.readInt(u32);
            if (raw >= m31.Modulus) return error.NonCanonicalM31;
            coordinate.* = M31.fromCanonical(raw);
        }
        return QM31.fromM31Array(coordinates);
    }

    pub fn readExact(self: *Cursor, destination: []u8) !void {
        @memcpy(destination, try self.take(destination.len));
    }

    pub fn take(self: *Cursor, count: usize) ![]const u8 {
        const end = std.math.add(usize, self.position, count) catch
            return error.InvalidArtifactLength;
        if (end > self.bytes.len) return error.EndOfStream;
        const result = self.bytes[self.position..end];
        self.position = end;
        return result;
    }

    pub fn requireDone(self: *const Cursor) !void {
        if (self.position != self.bytes.len) return error.TrailingSectionBytes;
    }
};

comptime {
    const descriptor_size = @sizeOf(u16) + @sizeOf(u32) + @sizeOf(u16) +
        2 * @sizeOf(u32) + 3 * @sizeOf(u16);
    const admission_size = (6 + 2 * guest_statement.fixed_table_count) * @sizeOf(u64);
    const expected = 3 * @sizeOf(u16) + 2 * @sizeOf(u32) +
        2 * @sizeOf(guest_statement.Digest) + 3 * @sizeOf(u32) +
        component_registry.extension_component_count * descriptor_size + admission_size;
    if (extension_encoded_size != expected)
        @compileError("guest extension wire size drifted");
    if (caller_component.batch_count != 77 or provider_component.batch_count != 2)
        @compileError("guest claim wire geometry drifted");
}
