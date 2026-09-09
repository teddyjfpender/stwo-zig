//! Fixed Ethereum transcript/publication coordinates and raw-wire topology.
const raw_layout = @import("segment_statement_v2_transcript_layout.zig");
pub const STATEMENT_SCOPE: u32 = 1114;
pub const NativeField = enum(u8) { statement_authority, wire_id, protocol_id, completion };
pub const NativeIdentityPhase = enum(u1) { raw_wire, native_authority };
pub const RAW_WIRE_HASH_SCOPE: u32 = 1120;
pub const NATIVE_AUTHORITY_HASH_SCOPE: u32 = 1121;
pub const RAW_V2_SOURCE_BASE: u32 = 256;
/// Split/scalar source words of the exhaustive schema4 frame plan. This
/// disjoint range is indexed by immutable flattened descriptor position.
pub const FIELD_FRAME_SOURCE_BASE: u32 = 0x1000_0000;
pub fn fieldFrameSourceIndex(flat_index: u32) ?u32 {
    return if (flat_index < FIELD_FRAME_SOURCE_BASE) FIELD_FRAME_SOURCE_BASE + flat_index else null;
}
pub const ROOT_SOURCE_USES: u32 = 2;
pub const ROOT_JOIN_ROW_COUNT: usize = 2;
pub const RootCoordinate = struct { side: raw_layout.Side, limb: u1 };
pub const RootSource = struct { raw_word_index: u32, source_index: u32, uses: u32 = ROOT_SOURCE_USES };
pub const RawExport = struct { scope: u32, index: u32, uses: u32 };

pub fn nativeIdentityHashScope(phase: NativeIdentityPhase) u32 {
    return switch (phase) {
        .raw_wire => RAW_WIRE_HASH_SCOPE,
        .native_authority => NATIVE_AUTHORITY_HASH_SCOPE,
    };
}

/// Each raw root limb feeds the existing hash-source row and canonical join.
/// All other raw words feed the wire hash directly, with exactly one publisher.
pub fn rootSource(side: raw_layout.Side, limb: u1) RootSource {
    const start = if (side == .entry) raw_layout.fixed_layout.entry_continuation_root else raw_layout.fixed_layout.exit_continuation_root;
    const index: u32 = @intCast(start + @as(usize, limb));
    return .{ .raw_word_index = index, .source_index = RAW_V2_SOURCE_BASE + index };
}

pub fn rootSourceForRawIndex(index: usize) ?RootSource {
    for ([_]raw_layout.Side{ .entry, .exit }) |side| {
        for (0..2) |limb| {
            const value = rootSource(side, @intCast(limb));
            if (value.raw_word_index == index) return value;
        }
    }
    return null;
}

pub fn rawHashProvidedDirectly(raw_index: u32) bool {
    return rootSourceForRawIndex(raw_index) == null;
}

pub fn exportForRawWord(raw_index: u32) RawExport {
    if (rootSourceForRawIndex(raw_index)) |source|
        return .{ .scope = STATEMENT_SCOPE, .index = source.source_index, .uses = source.uses };
    return .{ .scope = RAW_WIRE_HASH_SCOPE, .index = raw_index, .uses = 1 };
}

pub fn operationOrdinal(field: NativeField) u32 {
    return switch (field) {
        .statement_authority => 14,
        .wire_id => 2,
        .protocol_id => 17,
        .completion => 54,
    };
}

pub fn payloadWordCount(field: NativeField) u32 {
    return if (field == .completion) 8 else 16;
}

/// Digests use paired u16 inputs. Completion kind is paired; address/value/
/// clock limbs are already the individual u16 words in source positions42..47.
pub fn rawIndex(field: NativeField, payload_index: u32) ?u32 {
    if (payload_index >= payloadWordCount(field)) return null;
    return switch (field) {
        .statement_authority => 32 + payload_index,
        .wire_id => 48 + payload_index,
        .protocol_id => 64 + payload_index,
        .completion => if (payload_index < 2) 82 + payload_index else 80 + 2 * payload_index,
    };
}

pub fn isNativePayloadIndex(index: u32) bool {
    inline for (.{ NativeField.statement_authority, NativeField.wire_id, NativeField.protocol_id, NativeField.completion }) |field| {
        for (0..payloadWordCount(field)) |payload_index| {
            if (rawIndex(field, @intCast(payload_index)).? == index) return true;
        }
    }
    return false;
}

pub fn commitmentIndex(tree: u32, limb: u32) ?u32 {
    if (tree >= 4 or limb >= 8) return null;
    return 2 * (62 + 8 * tree + limb);
}

pub fn terminalIndex(limb: u32) ?u32 {
    if (limb >= 8) return null;
    return 2 * (53 + limb);
}
