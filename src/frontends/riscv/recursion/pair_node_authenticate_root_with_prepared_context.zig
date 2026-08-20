//! Internal pair node authority shard; use pair_node.zig publicly.

const dependency_0 = @import("pair_node_contract.zig");
const dependency_1 = @import("pair_node_child_evidence_v1.zig");

const AUTHENTICATION_PERMUTATION_CALL_TREE_V1 = dependency_0.AUTHENTICATION_PERMUTATION_CALL_TREE_V1;
const AUTHORITY_CONTEXT_PREIMAGE_WORD_COUNT = dependency_0.AUTHORITY_CONTEXT_PREIMAGE_WORD_COUNT;
const AuthenticationAllocationCostV1 = dependency_0.AuthenticationAllocationCostV1;
const AuthenticationPermutationCostV1 = dependency_0.AuthenticationPermutationCostV1;
const CHILD_ENCODED_LEN = dependency_0.CHILD_ENCODED_LEN;
const ChildEvidenceV1 = dependency_1.ChildEvidenceV1;
const ChildPosition = dependency_0.ChildPosition;
const ChildRole = dependency_0.ChildRole;
const Digest = dependency_0.Digest;
const ENCODED_LEN = dependency_0.ENCODED_LEN;
const Error = dependency_0.Error;
const FORMAT_ID_PREIMAGE_WORD_COUNT = dependency_0.FORMAT_ID_PREIMAGE_WORD_COUNT;
const HEADER_ENCODED_LEN = dependency_0.HEADER_ENCODED_LEN;
const MAGIC = dependency_0.MAGIC;
const MAX_KAPPA = dependency_0.MAX_KAPPA;
const MAX_PAIR_INDEX = dependency_0.MAX_PAIR_INDEX;
const NODE_ID_PREIMAGE_WORD_COUNT = dependency_0.NODE_ID_PREIMAGE_WORD_COUNT;
const ORDINARY_IDENTITY_FOLD_PREIMAGE_WORD_COUNT = dependency_0.ORDINARY_IDENTITY_FOLD_PREIMAGE_WORD_COUNT;
const PairNodeRecordV1 = dependency_1.PairNodeRecordV1;
const PreparedAuthorityV1 = dependency_0.PreparedAuthorityV1;
const PreparedRootContextV1 = dependency_1.PreparedRootContextV1;
const RECORD_ID_DOMAIN = dependency_0.RECORD_ID_DOMAIN;
const RootAuthenticatedPairV1 = dependency_1.RootAuthenticatedPairV1;
const RootVkPinV1 = dependency_1.RootVkPinV1;
const SUMMARY_IDENTITY_FOLD_PREIMAGE_WORD_COUNT = dependency_0.SUMMARY_IDENTITY_FOLD_PREIMAGE_WORD_COUNT;
const VERIFICATION_KEY_ID_DOMAIN = dependency_0.VERIFICATION_KEY_ID_DOMAIN;
const VerifierAuthorityV1 = dependency_1.VerifierAuthorityV1;
const authenticatePairFromPreparedAuthority = dependency_1.authenticatePairFromPreparedAuthority;
const channel = dependency_0.channel;
const protocol = dependency_0.protocol;
const requirePreparedRootContext = dependency_1.requirePreparedRootContext;
const std = dependency_0.std;

/// Hot root authentication for repeated use of one immutable verifier-owned
/// authority. This performs no suite/context hashes and no heap allocation.
/// The original authority and pin remain explicit so mutation after admission
/// is detected before the record is consumed.
pub fn authenticateRootWithPreparedContext(
    prepared: *const PreparedRootContextV1,
    authority: *const VerifierAuthorityV1,
    record: *const PairNodeRecordV1,
    pin: *const RootVkPinV1,
) Error!RootAuthenticatedPairV1 {
    try requirePreparedRootContext(prepared, authority, pin);
    const derived = PreparedAuthorityV1{
        .session_id = prepared.authority_snapshot.context.session_id,
        .challenge_context_id = prepared.challenge_context_id,
        .authority_context_id = prepared.authority_context_id,
    };
    const pair = try authenticatePairFromPreparedAuthority(
        &prepared.authority_snapshot,
        derived,
        record,
    );
    if (!std.meta.eql(
        pair.aggregator_vk_id,
        prepared.root_pin_snapshot.expected_aggregator_vk_id,
    )) return error.RootVkMismatch;
    return .{ .pair = pair };
}

pub fn encodeInto(
    record: *const PairNodeRecordV1,
    destination: *[ENCODED_LEN]u8,
) Error!void {
    if (slicesOverlap(std.mem.asBytes(record), destination))
        return error.AliasedBuffer;
    try record.validate();
    writeRecord(destination, record);
}

pub fn decodeInto(
    destination: *PairNodeRecordV1,
    encoded: *const [ENCODED_LEN]u8,
) Error!void {
    if (slicesOverlap(std.mem.asBytes(destination), encoded))
        return error.AliasedBuffer;
    const decoded = try readRecord(encoded);
    try decoded.validate();
    destination.* = decoded;
}

pub fn recordId(record: *const PairNodeRecordV1) Error!Digest {
    try record.validate();
    return recordIdUnchecked(record);
}

/// Identity of the canonical aggregator verification-key encoding. The caller
/// chooses the codec by protocol version; empty encodings are never valid VKs.
pub fn verificationKeyId(canonical_vk_bytes: []const u8) Error!Digest {
    if (canonical_vk_bytes.len == 0) return error.EmptyVerificationKey;
    if (canonical_vk_bytes.len > std.math.maxInt(u32))
        return error.VerificationKeyTooLarge;
    return channel.hashBytes(canonical_vk_bytes, VERIFICATION_KEY_ID_DOMAIN);
}

pub fn recordIdUnchecked(record: *const PairNodeRecordV1) Digest {
    var encoded: [ENCODED_LEN]u8 = undefined;
    writeRecord(&encoded, record);
    return channel.hashBytes(&encoded, RECORD_ID_DOMAIN);
}

pub fn writeRecord(destination: *[ENCODED_LEN]u8, record: *const PairNodeRecordV1) void {
    var writer = Writer{ .bytes = destination };
    writer.writeBytes(&record.magic);
    writer.writeInt(u16, record.version);
    writer.writeInt(u16, record.flags);
    writer.writeInt(u8, record.child_count);
    writer.writeBytes(&record.header_padding);
    writer.writeInt(u32, record.pair_index);
    writer.writeInt(u32, record.first_leaf_index);
    writer.writeInt(u32, record.claimed_leaf_count);
    writer.writeInt(u32, record.kappa_bound);
    writer.writeDigest(record.aggregator_vk_id);
    writer.writeDigest(record.authority_context_id);
    for (&record.children) |*child| writer.writeChild(child);
    std.debug.assert(writer.offset == destination.len);
}

pub fn readRecord(encoded: *const [ENCODED_LEN]u8) Error!PairNodeRecordV1 {
    var reader = Reader{ .bytes = encoded };
    var result: PairNodeRecordV1 = undefined;
    result.magic = reader.readBytes(MAGIC.len).*;
    result.version = reader.readInt(u16);
    result.flags = reader.readInt(u16);
    result.child_count = reader.readInt(u8);
    result.header_padding = reader.readBytes(3).*;
    result.pair_index = reader.readInt(u32);
    result.first_leaf_index = reader.readInt(u32);
    result.claimed_leaf_count = reader.readInt(u32);
    result.kappa_bound = reader.readInt(u32);
    result.aggregator_vk_id = reader.readDigest();
    result.authority_context_id = reader.readDigest();
    for (&result.children) |*child| child.* = try reader.readChild();
    std.debug.assert(reader.offset == encoded.len);
    return result;
}

pub const Writer = struct {
    bytes: *[ENCODED_LEN]u8,
    offset: usize = 0,

    fn writeInt(self: *Writer, comptime T: type, value: T) void {
        std.mem.writeInt(T, self.bytes[self.offset..][0..@sizeOf(T)], value, .little);
        self.offset += @sizeOf(T);
    }

    fn writeBytes(self: *Writer, bytes: []const u8) void {
        @memcpy(self.bytes[self.offset..][0..bytes.len], bytes);
        self.offset += bytes.len;
    }

    fn writeDigest(self: *Writer, value: Digest) void {
        for (value) |word| self.writeInt(u32, word);
    }

    fn writeChild(self: *Writer, child: *const ChildEvidenceV1) void {
        self.writeInt(u8, child.present);
        self.writeInt(u8, @intCast(@intFromEnum(child.position)));
        self.writeInt(u8, @intCast(@intFromEnum(child.role)));
        self.writeInt(u8, child.padding);
        self.writeInt(u32, child.leaf_index);
        self.writeInt(u32, child.pair_index);
        self.writeInt(u32, child.leaf_count);
        self.writeDigest(child.protocol_id);
        self.writeDigest(child.session_id);
        self.writeDigest(child.challenge_context_id);
        self.writeDigest(child.authority_context_id);
        self.writeDigest(child.parent_vk_id);
        self.writeDigest(child.statement_id);
        self.writeDigest(child.proof_id);
        self.writeDigest(child.transcript_id);
        self.writeDigest(child.summary_id);
        self.writeInt(u64, child.event_count);
        for (child.signed_relation_total.limbs) |limb| self.writeInt(u32, limb);
    }
};

pub const Reader = struct {
    bytes: *const [ENCODED_LEN]u8,
    offset: usize = 0,

    fn readInt(self: *Reader, comptime T: type) T {
        const result = std.mem.readInt(T, self.bytes[self.offset..][0..@sizeOf(T)], .little);
        self.offset += @sizeOf(T);
        return result;
    }

    fn readBytes(self: *Reader, comptime count: usize) *const [count]u8 {
        const result: *const [count]u8 = self.bytes[self.offset..][0..count];
        self.offset += count;
        return result;
    }

    fn readDigest(self: *Reader) Digest {
        var result: Digest = undefined;
        for (&result) |*word| word.* = self.readInt(u32);
        return result;
    }

    fn readChild(self: *Reader) Error!ChildEvidenceV1 {
        const present = self.readInt(u8);
        const position = std.meta.intToEnum(
            ChildPosition,
            self.readInt(u8),
        ) catch return error.ChildOrderMismatch;
        const role = std.meta.intToEnum(
            ChildRole,
            self.readInt(u8),
        ) catch return error.ChildRoleMismatch;
        const padding = self.readInt(u8);
        const leaf_index = self.readInt(u32);
        const pair_index = self.readInt(u32);
        const leaf_count = self.readInt(u32);
        const protocol_id = self.readDigest();
        const session_id = self.readDigest();
        const challenge_context_id = self.readDigest();
        const authority_context_id = self.readDigest();
        const parent_vk_id = self.readDigest();
        const statement_id = self.readDigest();
        const proof_id = self.readDigest();
        const transcript_id = self.readDigest();
        const summary_id = self.readDigest();
        const event_count = self.readInt(u64);
        var limbs: [4]u32 = undefined;
        for (&limbs) |*limb| limb.* = self.readInt(u32);
        return .{
            .present = present,
            .position = position,
            .role = role,
            .padding = padding,
            .leaf_index = leaf_index,
            .pair_index = pair_index,
            .leaf_count = leaf_count,
            .protocol_id = protocol_id,
            .session_id = session_id,
            .challenge_context_id = challenge_context_id,
            .authority_context_id = authority_context_id,
            .parent_vk_id = parent_vk_id,
            .statement_id = statement_id,
            .proof_id = proof_id,
            .transcript_id = transcript_id,
            .summary_id = summary_id,
            .event_count = event_count,
            .signed_relation_total = .{ .limbs = limbs },
        };
    }
};

pub fn slicesOverlap(left: []const u8, right: []const u8) bool {
    if (left.len == 0 or right.len == 0) return false;
    const left_start = @intFromPtr(left.ptr);
    const right_start = @intFromPtr(right.ptr);
    const left_end = std.math.add(usize, left_start, left.len) catch return true;
    const right_end = std.math.add(usize, right_start, right.len) catch return true;
    return left_start < right_end and right_start < left_end;
}

comptime {
    if (MAX_KAPPA != 1024 or MAX_PAIR_INDEX != 511 or
        HEADER_ENCODED_LEN != 96 or CHILD_ENCODED_LEN != 328 or
        ENCODED_LEN != 752)
    {
        @compileError("pair-node V1 fixed geometry drifted");
    }
    if (FORMAT_ID_PREIMAGE_WORD_COUNT != 50 or
        AUTHORITY_CONTEXT_PREIMAGE_WORD_COUNT != 78 or
        ORDINARY_IDENTITY_FOLD_PREIMAGE_WORD_COUNT != 51 or
        SUMMARY_IDENTITY_FOLD_PREIMAGE_WORD_COUNT != 67 or
        NODE_ID_PREIMAGE_WORD_COUNT != 60 or
        AUTHENTICATION_PERMUTATION_CALL_TREE_V1.len != 13 or
        AuthenticationPermutationCostV1.suite_preparation != 39 or
        AuthenticationPermutationCostV1.context_preparation != 17 or
        AuthenticationPermutationCostV1.successful_context_prepared_root != 38 or
        AuthenticationPermutationCostV1.successful_prepared_root != 55 or
        AuthenticationPermutationCostV1.successful_convenience_root != 94)
    {
        @compileError("pair-node V1 Poseidon cost ledger drifted");
    }
    if (AuthenticationAllocationCostV1.suite_preparation != 0 or
        AuthenticationAllocationCostV1.context_preparation != 0 or
        AuthenticationAllocationCostV1.successful_context_prepared_root != 0)
    {
        @compileError("pair-node V1 allocation ledger drifted");
    }
    assertPointerFreeType(PairNodeRecordV1);
    assertPointerFreeType(PreparedRootContextV1);
}

pub fn assertPointerFreeType(comptime T: type) void {
    switch (@typeInfo(T)) {
        .pointer, .optional, .error_union, .@"union" => @compileError("pair-node fixed storage may not contain dynamic state"),
        .array => |array| assertPointerFreeType(array.child),
        .@"struct" => |info| inline for (info.fields) |field|
            assertPointerFreeType(field.type),
        else => {},
    }
}
