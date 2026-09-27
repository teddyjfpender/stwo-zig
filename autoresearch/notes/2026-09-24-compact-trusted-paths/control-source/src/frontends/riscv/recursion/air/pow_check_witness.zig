//! One-allocation preparation and allocation-free SoA writer for PoW row 6.
//!
//! The cold path snapshots transcript checks and seals every source field.
//! The hot path validates the immutable receipt, rejects all source/header/
//! destination aliases before its first store, then writes the canonical M31
//! bit decomposition and prefix-active difficulty mask directly into final
//! column-major storage.

const std = @import("std");
const stwo_core = @import("stwo_core");
const M31 = stwo_core.fields.m31.M31;
const m31 = stwo_core.fields.m31;
const digest = @import("../../air/lang/digest.zig");
const direct = @import("../../air/lang/direct_witness_executor.zig");
const types = @import("../../air/lang/types.zig");
const component = @import("pow_check.zig");

pub const MAIN_COLUMN_COUNT: usize = component.PHYSICAL_MAIN_COLUMN_COUNT;
pub const RelationRow = [component.LOGICAL_INPUT_COUNT]M31;
pub const BINDING_FORMAT_VERSION: u16 = 1;
pub const BINDING_DOMAIN =
    "stwo-zig/typed-air/recursion-pow-check-witness/v1\x00";
pub const BINDING_DIGEST_HEX =
    "79e406171e5be40e5f85760f310bb7c86bda79cf2bdbd614859ee234a25f512b";
pub const BINDING_DIGEST = hexDigest(
    BINDING_DIGEST_HEX,
    "invalid recursion PoW-check witness-binding digest",
);
pub const PREPARED_BATCH_FORMAT_VERSION: u16 = 1;
pub const PREPARED_BATCH_DOMAIN =
    "stwo-zig/typed-air/recursion-pow-check-batch/v1\x00";

pub const PowKind = component.PowKind;

/// Exact source record emitted by the transcript backend.  `nonce` is sealed
/// even though it is deliberately absent from the AIR relation: this prevents
/// a prepared check from being detached from its audited source receipt.
pub const Check = struct {
    call_id: u32,
    nonce: u64,
    bits: u32,
    word: M31,
};

pub const Invocation = struct {
    verifier_id: u32,
    kind: PowKind,
    check: Check,
};

pub const Slot = struct {
    column: u8,
    value: types.ValueId,
    source: u8,
};

pub const Binding = struct {
    format_version: u16,
    semantic_format_version: u16,
    semantic_digest: digest.Digest,
    source_authority_digest: digest.Digest,
    main: [MAIN_COLUMN_COUNT]Slot,

    pub fn canonical(
        definition: *const component.Definition,
    ) ConstructionError!Binding {
        try definition.validate();
        var main: [MAIN_COLUMN_COUNT]Slot = undefined;
        for (&main, definition.main.physical(), 0..) |*slot, value, column| {
            slot.* = .{
                .column = @intCast(column),
                .value = value,
                .source = @intCast(column),
            };
        }
        return .{
            .format_version = BINDING_FORMAT_VERSION,
            .semantic_format_version = digest.typed_effect_format_version,
            .semantic_digest = component.SEMANTIC_DIGEST,
            .source_authority_digest = component.SOURCE_AUTHORITY_DIGEST,
            .main = main,
        };
    }

    pub fn identityDigest(self: *const Binding) digest.Digest {
        var hash = std.crypto.hash.sha2.Sha256.init(.{});
        hash.update(BINDING_DOMAIN);
        hashInt(&hash, u16, self.format_version);
        hashInt(&hash, u16, self.semantic_format_version);
        hash.update(&self.semantic_digest);
        hash.update(&self.source_authority_digest);
        hashInt(&hash, u16, self.main.len);
        for (self.main) |slot| {
            hashInt(&hash, u8, slot.column);
            hashInt(&hash, u32, @intFromEnum(slot.value));
            hashInt(&hash, u8, slot.source);
        }
        return hash.finalResult();
    }
};

pub const ConstructionError = component.ValidationError || error{
    InvalidWitnessBinding,
};
pub const Error = direct.Error || std.mem.Allocator.Error || error{
    AuthorityMismatch,
    BitsOutOfRange,
    InvalidFieldElement,
    InvalidWitnessBinding,
};

pub const Executor = struct {
    binding: Binding,
    binding_digest: digest.Digest,

    pub fn init(
        definition: *const component.Definition,
        supplied: *const Binding,
    ) ConstructionError!Executor {
        const expected = try Binding.canonical(definition);
        if (!std.meta.eql(expected, supplied.*))
            return error.InvalidWitnessBinding;
        const binding_digest = supplied.identityDigest();
        if (!std.mem.eql(u8, &binding_digest, &BINDING_DIGEST))
            return error.InvalidWitnessBinding;
        return .{ .binding = supplied.*, .binding_digest = binding_digest };
    }

    pub fn validate(self: *const Executor) Error!void {
        const actual = self.binding.identityDigest();
        if (!std.mem.eql(u8, &actual, &self.binding_digest) or
            !std.mem.eql(u8, &actual, &BINDING_DIGEST) or
            !std.mem.eql(
                u8,
                &self.binding.source_authority_digest,
                &component.SOURCE_AUTHORITY_DIGEST,
            ))
        {
            return error.InvalidWitnessBinding;
        }
    }

    pub fn generateMainInto(
        self: *const Executor,
        batch: *const PreparedBatch,
        columns: *[MAIN_COLUMN_COUNT][]M31,
        log_size: u32,
    ) Error!void {
        try self.validate();
        try batch.validate();
        try protectBatchHeader(columns, batch);
        return direct.generateMainInto(
            M31,
            Invocation,
            MAIN_COLUMN_COUNT,
            columns,
            batch.invocations,
            log_size,
            M31.zero(),
            self,
            validateInvocation,
            writeMainRow,
        );
    }
};

/// Immutable source snapshot.  For every non-empty batch `init` performs
/// exactly one allocation: the invocation slice itself.
pub const PreparedBatch = struct {
    allocator: std.mem.Allocator,
    invocations: []Invocation,
    authority_digest: digest.Digest,

    pub fn init(
        allocator: std.mem.Allocator,
        source_invocations: []const Invocation,
    ) Error!PreparedBatch {
        try component.SourceAuthority.pinned().validate();
        for (source_invocations) |invocation| try validateSource(invocation);
        const invocations = try allocator.dupe(Invocation, source_invocations);
        errdefer allocator.free(invocations);
        return .{
            .allocator = allocator,
            .invocations = invocations,
            .authority_digest = batchDigest(invocations),
        };
    }

    pub fn deinit(self: *PreparedBatch) void {
        self.allocator.free(self.invocations);
        self.* = undefined;
    }

    pub fn validate(self: *const PreparedBatch) Error!void {
        try component.SourceAuthority.pinned().validate();
        for (self.invocations) |invocation| try validateSource(invocation);
        const actual = batchDigest(self.invocations);
        if (!std.mem.eql(u8, &actual, &self.authority_digest))
            return error.AuthorityMismatch;
    }

    pub fn validateAgainstSource(
        self: *const PreparedBatch,
        source_invocations: []const Invocation,
    ) Error!void {
        try self.validate();
        if (self.invocations.len != source_invocations.len)
            return error.AuthorityMismatch;
        for (source_invocations) |invocation| try validateSource(invocation);
        for (self.invocations, source_invocations) |snapshot, source_value| {
            if (!std.meta.eql(snapshot, source_value))
                return error.AuthorityMismatch;
        }
    }

    pub fn row(self: *const PreparedBatch, index: usize) Error!RelationRow {
        try self.validate();
        if (index >= self.invocations.len) return error.InvalidTraceRow;
        return mainRow(self.invocations[index]);
    }

    pub inline fn preparedRow(self: *const PreparedBatch, index: usize) RelationRow {
        std.debug.assert(index < self.invocations.len);
        return mainRowUnchecked(self.invocations[index]);
    }
};

pub fn mainRow(invocation: Invocation) direct.Error!RelationRow {
    try validateInvocation(invocation);
    return mainRowUnchecked(invocation);
}

pub inline fn mainRowUnchecked(invocation: Invocation) RelationRow {
    var result: RelationRow = undefined;
    result[0] = M31.one();
    result[1] = M31.fromCanonical(invocation.verifier_id);
    result[2] = M31.fromCanonical(@intFromEnum(invocation.kind));
    result[3] = M31.fromCanonical(invocation.check.call_id);
    result[4] = M31.fromCanonical(invocation.check.bits);
    result[5] = invocation.check.word;
    inline for (0..component.M31_BIT_COUNT) |bit| {
        result[6 + bit] = M31.fromCanonical(
            (invocation.check.word.v >> @intCast(bit)) & 1,
        );
        result[6 + component.M31_BIT_COUNT + bit] = M31.fromCanonical(
            @intFromBool(bit < invocation.check.bits),
        );
    }
    return result;
}

pub inline fn writeMainRow(
    columns: *[MAIN_COLUMN_COUNT][]M31,
    row_index: usize,
    invocation: Invocation,
) void {
    const row = mainRowUnchecked(invocation);
    inline for (0..MAIN_COLUMN_COUNT) |column|
        columns[column][row_index] = row[column];
}

fn validateSource(invocation: Invocation) Error!void {
    if (invocation.verifier_id >= m31.Modulus or
        invocation.check.call_id >= m31.Modulus)
    {
        return error.InvalidFieldElement;
    }
    if (invocation.check.bits > component.M31_BIT_COUNT)
        return error.BitsOutOfRange;
    if (invocation.check.word.v >= m31.Modulus)
        return error.InvalidFieldElement;
}

fn validateInvocation(invocation: Invocation) direct.Error!void {
    validateSource(invocation) catch return error.InvalidTraceRow;
}

fn batchDigest(invocations: []const Invocation) digest.Digest {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(PREPARED_BATCH_DOMAIN);
    hashInt(&hash, u16, PREPARED_BATCH_FORMAT_VERSION);
    hash.update(&component.SOURCE_AUTHORITY_DIGEST);
    hashInt(&hash, u64, invocations.len);
    for (invocations) |invocation| {
        hashInt(&hash, u32, invocation.verifier_id);
        hashInt(&hash, u32, @intFromEnum(invocation.kind));
        hashInt(&hash, u32, invocation.check.call_id);
        hashInt(&hash, u64, invocation.check.nonce);
        hashInt(&hash, u32, invocation.check.bits);
        hashInt(&hash, u32, invocation.check.word.v);
    }
    return hash.finalResult();
}

fn protectBatchHeader(
    columns: *const [MAIN_COLUMN_COUNT][]M31,
    batch: *const PreparedBatch,
) direct.Error!void {
    const descriptors = try objectRange(columns);
    const batch_header = try objectRange(batch);
    if (descriptors.overlaps(batch_header)) return error.AliasedInput;
    for (columns) |column| {
        const destination = (try sliceRange(M31, column)) orelse continue;
        if (destination.overlaps(batch_header)) return error.AliasedDestination;
    }
}

const AddressRange = struct {
    start: usize,
    end: usize,

    inline fn overlaps(self: AddressRange, other: AddressRange) bool {
        return self.start < other.end and other.start < self.end;
    }
};

fn sliceRange(comptime T: type, values: []const T) direct.Error!?AddressRange {
    if (values.len == 0) return null;
    const byte_len = std.math.mul(usize, values.len, @sizeOf(T)) catch
        return error.AddressOverflow;
    const start = @intFromPtr(values.ptr);
    return .{
        .start = start,
        .end = std.math.add(usize, start, byte_len) catch
            return error.AddressOverflow,
    };
}

fn objectRange(pointer: anytype) direct.Error!AddressRange {
    const info = @typeInfo(@TypeOf(pointer));
    if (info != .pointer or info.pointer.size != .one)
        @compileError("protected storage must be a single-item pointer");
    const start = @intFromPtr(pointer);
    return .{
        .start = start,
        .end = std.math.add(usize, start, @sizeOf(info.pointer.child)) catch
            return error.AddressOverflow,
    };
}

fn hashInt(hash: anytype, comptime T: type, value: anytype) void {
    var encoded: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &encoded, @intCast(value), .little);
    hash.update(&encoded);
}

fn hexDigest(comptime value: []const u8, comptime message: []const u8) digest.Digest {
    var result: digest.Digest = undefined;
    _ = std.fmt.hexToBytes(&result, value) catch @compileError(message);
    return result;
}

comptime {
    if (MAIN_COLUMN_COUNT != 68 or @sizeOf(Slot) > 12)
        @compileError("PoW-check witness geometry drifted");
}
