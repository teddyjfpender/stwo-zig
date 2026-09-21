//! Inactive two-phase native identity hash plan. Raw V2 auxiliary bytes are
//! committed as supplied, without claiming full V2 document validity. Every
//! hash-word consumer retains a typed source obligation for later AIR routing.
const std = @import("std");
const core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");
const routing = frontend.recursion.ethereum_publication_routing_v1;
const shared = @import("recursive_public_hash_rows_v1.zig");
const native = frontend.air.statement_v2;
const preimage = native.authority_preimage;
const raw = frontend.recursion.segment_statement_v2_transcript_layout;
const segment = frontend.recursion.segment_statement_v2;
const span = frontend.recursion.span_statement.canonical_layout;
const Air = frontend.recursion.air.ethereum_publication_hash_v1;
const M31 = core.fields.m31.M31;
pub const Phase = routing.NativeIdentityPhase;
pub const Row = Air.Relation.Row;
pub const Call = shared.Call;
pub const Digest = shared.Digest;
pub const SCHEMA_VERSION: u32 = 1;
pub const ACTIVE_COHORT_INTEGRATED = false;
pub const RAW_V2_DOCUMENT_VALIDITY_PROVEN = false;
pub const EXTERNAL_SESSION_JOB_POSITION_BINDINGS_ESTABLISHED = false;
pub const Source = union(enum) {
    /// Classification describes the exact raw coordinate. Dynamic values
    /// require canonical witnesses and any separately selected semantic
    /// equality; this plan does not turn auxiliary copies into providers.
    raw_word: struct { index: u32, classification: raw.Word },
    native_authority: preimage.Source,
};
pub const PhaseDescriptor = struct {
    phase: Phase,
    preimage_word_count: u32,
    first_row: u32,
    row_count: u32,
    first_step: u32,
    output_digest: Digest,
};

pub const hashScope = routing.nativeIdentityHashScope;
pub fn hashDomain(phase: Phase) u32 {
    return switch (phase) {
        .raw_wire => segment.WIRE_ID_DOMAIN,
        .native_authority => preimage.DOMAIN,
    };
}

pub const OwnedPlan = opaque {
    /// The caller independently admits geometry and provides the canonical
    /// statement scalars. These checks establish hash/custody consistency,
    /// not proof admission or session/job/position authentication.
    pub fn initAdmitted(allocator: std.mem.Allocator, raw_words: []const M31, layout: raw.Layout, authority: preimage.Input, expected_authority: Digest, first_step: u32) !*OwnedPlan {
        try authority.validate();
        const checked_layout = try raw.Layout.init(layout.counts);
        if (!std.meta.eql(layout, checked_layout) or raw_words.len != layout.wordCount())
            return error.InvalidEthereumNativeIdentityLayout;
        try validateSpanScalars(raw_words, authority);
        const authority_count = try preimage.wordCount(authority.component_descs.len, authority.infra_descs.len);
        const counts = [_]usize{ try shared.rowCount(raw_words.len), try shared.rowCount(authority_count) };
        const row_count = try std.math.add(usize, counts[0], counts[1]);
        const prepared_rows = try allocator.alloc(Row, row_count);
        errdefer allocator.free(prepared_rows);
        const provider_calls = try allocator.alloc(Call, row_count);
        errdefer allocator.free(provider_calls);
        const sources = try allocator.alloc(preimage.Source, authority_count);
        errdefer allocator.free(sources);
        const words = try allocator.alloc(u32, @max(raw_words.len, authority_count));
        defer allocator.free(words);
        const legacy_rows = try allocator.alloc(shared.Row, @max(counts[0], counts[1]));
        defer allocator.free(legacy_rows);
        var phase_descriptors: [2]PhaseDescriptor = undefined;
        var row_at: usize = 0;
        for (std.enums.values(Phase), counts) |phase, count| {
            const length = if (phase == .raw_wire) raw_words.len else authority_count;
            if (phase == .raw_wire) {
                for (raw_words, words[0..length], 0..) |word, *destination, index| {
                    const value = word.toU32();
                    if (value >= core.fields.m31.Modulus) return error.InvalidEthereumNativeIdentityWord;
                    switch (try layout.word(index)) {
                        .fixed => |expected| if (value != expected) return error.InvalidEthereumNativeIdentityWord,
                        .geometry => |geometry| if (value != geometry.value) return error.InvalidEthereumNativeIdentityWord,
                        .data => {},
                    }
                    destination.* = value;
                }
            } else {
                var sink = AuthoritySink{ .words = words[0..length], .sources = sources };
                preimage.emit(&sink, authority);
                std.debug.assert(sink.at == length);
            }
            const step = try std.math.add(u32, first_step, std.math.cast(u32, row_at) orelse return error.ArithmeticOverflow);
            const digest = try shared.write(words[0..length], .{
                .domain = hashDomain(phase),
                .scope = hashScope(phase),
                .verifier = hashScope(phase),
                .input_kind = frontend.recursion.air.field_public_word_v3.DIGEST_INPUT_KIND,
            }, step, legacy_rows[0..count], provider_calls[row_at..][0..count]);
            const expected = if (phase == .raw_wire) authority.wire_id else expected_authority;
            if (!std.meta.eql(digest, expected)) return error.EthereumNativeIdentityDigestMismatch;
            for (prepared_rows[row_at..][0..count], legacy_rows[0..count]) |*destination, row| destination.* = Air.fromLegacy(row);
            phase_descriptors[@intFromEnum(phase)] = .{
                .phase = phase,
                .preimage_word_count = @intCast(length),
                .first_row = @intCast(row_at),
                .row_count = @intCast(count),
                .first_step = step,
                .output_digest = digest,
            };
            row_at += count;
        }
        const backing = try allocator.create(Storage);
        backing.* = .{ .allocator = allocator, .rows = prepared_rows, .calls = provider_calls, .sources = sources, .layout = layout, .phases = phase_descriptors };
        return @ptrCast(backing);
    }

    pub fn deinit(self: *OwnedPlan) void {
        const value: *Storage = @ptrCast(@alignCast(self));
        const allocator = value.allocator;
        allocator.free(value.sources);
        allocator.free(value.calls);
        allocator.free(value.rows);
        allocator.destroy(value);
    }
    pub fn rows(self: *const OwnedPlan) []const Row {
        return storage(self).rows;
    }
    pub fn calls(self: *const OwnedPlan) []const Call {
        return storage(self).calls;
    }
    pub fn phases(self: *const OwnedPlan) *const [2]PhaseDescriptor {
        return &storage(self).phases;
    }
    pub fn sourceForWord(self: *const OwnedPlan, phase: Phase, index: usize) !Source {
        const value = storage(self);
        if (index >= value.phases[@intFromEnum(phase)].preimage_word_count) return error.InvalidEthereumNativeIdentityWord;
        return switch (phase) {
            .raw_wire => .{ .raw_word = .{ .index = @intCast(index), .classification = try value.layout.word(index) } },
            .native_authority => .{ .native_authority = value.sources[index] },
        };
    }
    const Storage = struct {
        allocator: std.mem.Allocator,
        rows: []Row,
        calls: []Call,
        sources: []preimage.Source,
        layout: raw.Layout,
        phases: [2]PhaseDescriptor,
    };
    fn storage(self: *const OwnedPlan) *const Storage {
        return @ptrCast(@alignCast(self));
    }
};

const AuthoritySink = struct {
    words: []u32,
    sources: []preimage.Source,
    at: usize = 0,
    pub fn word(self: *AuthoritySink, source: preimage.Source, value: u32) void {
        self.words[self.at] = value;
        self.sources[self.at] = source;
        self.at += 1;
    }
};

pub fn spanScalarWord(field: preimage.SpanScalar, limb: u1) u32 {
    const start = switch (field) {
        .initial_pc => span.entry_state_start + span.machine_state_pc_start_offset,
        .final_pc => span.exit_state_start + span.machine_state_pc_start_offset,
        .cycle_count => span.executed_cycle_count_start,
    };
    return @intCast(start + limb);
}
fn validateSpanScalars(words: []const M31, authority: preimage.Input) !void {
    if (words.len < raw.FIXED_WORD_COUNT) return error.InvalidEthereumNativeIdentityLayout;
    for (std.enums.values(preimage.SpanScalar), [_]u32{ authority.initial_pc, authority.final_pc, authority.cycle_count }) |field, value| {
        for (0..2) |limb| {
            const at = raw.fixed_layout.base_statement + spanScalarWord(field, @intCast(limb));
            const expected: u16 = @truncate(value >> @as(u5, @intCast(16 * limb)));
            if (words[at].toU32() != expected) return error.EthereumNativeIdentityScalarMismatch;
        }
    }
    const cycle_start = raw.fixed_layout.base_statement + span.executed_cycle_count_start;
    if (!words[cycle_start + 2].isZero() or !words[cycle_start + 3].isZero()) return error.EthereumNativeIdentityScalarMismatch;
}

test "Ethereum native identity hashes preserve native digests and typed sources" {
    const allocator = std.testing.allocator;
    const layout = try raw.Layout.init(.{ 0, 0, 0, 0 });
    const words = try testWire(allocator, layout);
    defer allocator.free(words);
    const authority = testAuthority(words);
    const expected = try preimage.hash(authority);
    const plan = try OwnedPlan.initAdmitted(allocator, words, layout, authority, expected, 31);
    defer plan.deinit();
    try std.testing.expectEqual(authority.wire_id, plan.phases()[0].output_digest);
    try std.testing.expectEqual(expected, plan.phases()[1].output_digest);
    try std.testing.expectEqual(try shared.rowCount(words.len), plan.phases()[1].first_row);
    try std.testing.expectEqual(plan.rows().len, plan.calls().len);
    try std.testing.expectEqualDeep(Source{ .native_authority = .{ .span_scalar = .{ .field = .initial_pc, .limb = 0 } } }, try plan.sourceForWord(.native_authority, 8));
    try std.testing.expectEqualDeep(Source{ .native_authority = .{ .wire_hash_digest = 0 } }, try plan.sourceForWord(.native_authority, 14));
    const session = try plan.sourceForWord(.raw_wire, raw.fixed_layout.session_id);
    try std.testing.expectEqual(raw.DigestField.session_id, session.raw_word.classification.data.digest.field);
    try std.testing.expectError(error.InvalidEthereumNativeIdentityWord, plan.sourceForWord(.native_authority, 22));
    var stale = authority;
    stale.initial_pc += 4;
    try std.testing.expectError(error.EthereumNativeIdentityScalarMismatch, OwnedPlan.initAdmitted(allocator, words, layout, stale, expected, 31));
    var wrong_digest = expected;
    wrong_digest[0] ^= 1;
    try std.testing.expectError(error.EthereumNativeIdentityDigestMismatch, OwnedPlan.initAdmitted(allocator, words, layout, authority, wrong_digest, 31));
    words[raw.fixed_layout.session_id] = M31.fromCanonical(42);
    try std.testing.expectError(error.EthereumNativeIdentityDigestMismatch, OwnedPlan.initAdmitted(allocator, words, layout, authority, expected, 31));
}

test "Ethereum native identity auxiliary bytes remain private with explicit hash custody" {
    const allocator = std.testing.allocator;
    const layout = try raw.Layout.init(.{ 1, 0, 0, 0 });
    const words = try testWire(allocator, layout);
    defer allocator.free(words);
    const authority = testAuthority(words);
    const plan = try OwnedPlan.initAdmitted(allocator, words, layout, authority, try preimage.hash(authority), 0);
    defer plan.deinit();
    const index = layout.section(.entry_snapshot).payload_start + 2;
    const original_source = try plan.sourceForWord(.raw_wire, index);
    try std.testing.expectEqual(raw.RetainedField.value, original_source.raw_word.classification.data.retained.field);
    words[index] = M31.fromCanonical(99);
    const changed_authority = testAuthority(words);
    const changed = try OwnedPlan.initAdmitted(allocator, words, layout, changed_authority, try preimage.hash(changed_authority), 0);
    defer changed.deinit();
    try std.testing.expectEqualDeep(original_source, try changed.sourceForWord(.raw_wire, index));
    try std.testing.expect(!std.meta.eql(plan.phases()[0].output_digest, changed.phases()[0].output_digest));
    try std.testing.expect(!RAW_V2_DOCUMENT_VALIDITY_PROVEN and !EXTERNAL_SESSION_JOB_POSITION_BINDINGS_ESTABLISHED);
}

/// A structural fixture, deliberately not an authenticated V2 document.
fn testWire(allocator: std.mem.Allocator, layout: raw.Layout) ![]M31 {
    const words = try allocator.alloc(M31, layout.wordCount());
    errdefer allocator.free(words);
    for (words, 0..) |*word, index| word.* = M31.fromCanonical(switch (try layout.word(index)) {
        .fixed => |value| value,
        .geometry => |value| value.value,
        .data => 0,
    });
    return words;
}
fn testAuthority(words: []const M31) preimage.Input {
    return .{ .initial_pc = 0, .final_pc = 0, .cycle_count = 0, .wire_id = frontend.recursion.poseidon2_channel.hashCanonicalWords(words, segment.WIRE_ID_DOMAIN), .component_descs = &.{}, .infra_descs = &.{} };
}
