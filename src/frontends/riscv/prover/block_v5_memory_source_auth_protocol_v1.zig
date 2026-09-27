//! Candidate source-authentication equation protocol. This module admits
//! independent source pins and derives challenges; it emits no proof receipt.
//! A future source proof/recursive aggregate must verify every chunk and the
//! closure equations before these sources may discharge global obligations.
const std = @import("std");
const core = @import("stwo_core");
const Q = core.fields.qm31.QM31;
const initial = @import("block_v5_initial_sources_v1.zig");
const endpoint = @import("block_v5_rw_endpoint_sources_v1.zig");
const word = @import("block_v5_word_memory_protocol_v1.zig");
const relations = @import("../air/relation_challenges.zig");
pub const VERSION: u32 = 1;
pub const TAG: u32 = 0x42355341; // B5SA, distinct from file-pin and word ABI
pub const Stream = enum(u32) { public_input = 1, input_words = 2, rw_words = 3, first_touches = 4, endpoints = 5 };
pub const Edit = enum(u32) { insert_input = 1, insert_rw = 2, update = 3 };
pub const Limits = struct {
    max_stream_bytes: u64 = 160_000_000,
    max_records: u64 = 10_000_000,
    max_nodes: usize = 1_000_000,
    max_chunk_heap_bytes: usize = 128 * 1024 * 1024,
};
pub const Admitted = struct {
    pins: endpoint.Pins,
    sealed_digest: [32]u8,
    identity: [32]u8,
    limits: Limits,
    pub fn byteLength(self: *const Admitted, stream: Stream) u64 {
        return switch (stream) {
            .public_input => self.pins.initial.public_input_len,
            .input_words => self.pins.initial.input_words.records * 8,
            .rw_words => self.pins.initial.rw_words.records * 8,
            .first_touches => self.pins.initial.first_touches.records * 9,
            .endpoints => self.pins.endpoints.records * 16,
        };
    }
    pub fn records(self: *const Admitted, stream: Stream) u64 {
        return switch (stream) {
            .public_input => (self.pins.initial.public_input_len + 3) / 4,
            .input_words => self.pins.initial.input_words.records,
            .rw_words => self.pins.initial.rw_words.records,
            .first_touches => self.pins.initial.first_touches.records,
            .endpoints => self.pins.endpoints.records,
        };
    }
    pub fn digest(self: *const Admitted, stream: Stream) [32]u8 {
        return switch (stream) {
            .public_input => self.pins.initial.public_input_sha256,
            .input_words => self.pins.initial.input_words.sha256,
            .rw_words => self.pins.initial.rw_words.sha256,
            .first_touches => self.pins.initial.first_touches.sha256,
            .endpoints => self.pins.endpoints.sha256,
        };
    }
    pub fn require(self: *const Admitted) !void {
        const rebuilt = try make(self.pins, self.sealed_digest, self.limits);
        if (!std.mem.eql(u8, &rebuilt.identity, &self.identity)) return error.InvalidMemorySourceAdmission;
    }
};
/// Complete-source mode is strict RAM. Counts are independently pinned; the
/// touch and final files have identical RAM-only address censuses.
pub fn make(pins: endpoint.Pins, sealed_digest: [32]u8, limits: Limits) !Admitted {
    try pins.initial.validate();
    const pin_digest = try pins.digest();
    if (pins.endpoints.records != pins.initial.first_touches.records or limits.max_records == 0 or limits.max_nodes == 0 or limits.max_nodes >= core.fields.m31.Modulus or limits.max_chunk_heap_bytes == 0 or std.mem.allEqual(u8, &sealed_digest, 0)) return error.InvalidMemorySourceAdmission;
    var result = Admitted{ .pins = pins, .sealed_digest = sealed_digest, .identity = undefined, .limits = limits };
    inline for (std.meta.tags(Stream)) |stream| {
        if (result.byteLength(stream) > limits.max_stream_bytes or result.records(stream) > limits.max_records) return error.MemorySourceResourceLimit;
    }
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo-zig/block-v5/memory-source-equations/v1\x00");
    hash.update(&pin_digest);
    hash.update(&sealed_digest);
    hash.update("strict-ram;full-u32-words;u64-clocks;sha256-full-padding;blake3-tree-v2;shared-siblings;streaming-chunks;no-proof-authority\x00");
    result.identity = hash.finalResult();
    return result;
}
pub fn admit(pins: endpoint.Pins, seal_pins: anytype, entries: anytype, sealed: anytype, limits: Limits) !Admitted {
    try sealed.require(seal_pins, entries);
    if (seal_pins.register_custody_mode != 1 or !std.mem.eql(u8, &seal_pins.initial_source_plan_digest, &(try pins.initial.digest())) or !std.mem.eql(u8, &seal_pins.rw_endpoint_plan_digest, &(try pins.digest())) or !std.mem.eql(u8, &seal_pins.memory_plan_digest, &pins.memory_plan_digest) or !std.mem.eql(u8, &seal_pins.expected_final_rw_root, &pins.expected_final_rw_root)) return error.InvalidMemorySourceAdmission;
    return make(pins, sealed.digest, limits);
}
pub const Challenges = struct {
    word: word.Challenges,
    /// SHA raw bytes vs decoded canonical records, including exact offset.
    bytes: relations.RelationElements(6),
    /// Nonzero input words derived from hashed public input vs sparse records.
    input: relations.RelationElements(4),
    /// Complete initial-image insertion values vs source records.
    insertion: relations.RelationElements(5),
    /// Shared-sibling final edit before and after values vs touch/final files.
    before: relations.RelationElements(4),
    after: relations.RelationElements(8),
    /// Leaf -> height0..29 -> root routing, including edit ordinal/address.
    route: relations.RelationElements(71),
    roots: relations.RelationElements(36),
    ordering: relations.RelationElements(7),
    sha_chain: relations.RelationElements(37),
    pub fn draw(a: std.mem.Allocator, sealed: anytype) !Challenges {
        var channel = sealed.sharedChannel();
        const prefix = try word.Challenges.drawFromChannel(a, &channel);
        channel.mixU32s(&.{ TAG, VERSION, 6, 4, 5, 4, 8, 71, 36, 7, 37 });
        const draws = try channel.drawSecureFelts(a, 18);
        defer a.free(draws);
        return .{ .word = prefix, .bytes = .init(draws[0], draws[1]), .input = .init(draws[2], draws[3]), .insertion = .init(draws[4], draws[5]), .before = .init(draws[6], draws[7]), .after = .init(draws[8], draws[9]), .route = .init(draws[10], draws[11]), .roots = .init(draws[12], draws[13]), .ordering = .init(draws[14], draws[15]), .sha_chain = .init(draws[16], draws[17]) };
    }
};
pub const Sums = struct {
    bytes: Q = Q.zero(),
    input: Q = Q.zero(),
    insertion: Q = Q.zero(),
    before: Q = Q.zero(),
    after: Q = Q.zero(),
    route: Q = Q.zero(),
    initial: Q = Q.zero(),
    endpoint: Q = Q.zero(),
    roots: Q = Q.zero(),
    ordering: Q = Q.zero(),
    sha_chain: Q = Q.zero(),
};
