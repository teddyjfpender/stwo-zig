//! One independently pinned sorted-memory authority. Canonical mode1 admits
//! genuine two-event lane proofs; mode0 retains the explicit word protocol.
const std = @import("std");
const Seal = @import("block_v5_source_seal_v1.zig");
const Word = @import("block_v5_word_memory_receiver_v1.zig");
const Lanes = @import("block_v5_ram_lanes_receiver_v1.zig");
const LaneProof = @import("block_v5_ram_lanes_proof_v1.zig");
const Endpoint = @import("block_v5_rw_endpoint_sources_v1.zig");
const Registers = @import("block_v5_register_endpoints_v1.zig");
pub const Pins = union(enum) {
    word: Word.Pins,
    lanes: Lanes.Pins,
    /// Explicit source migration for scoped old fixtures. A canonical mode1
    /// receiver still rejects the word variant; this creates no proof receipt.
    pub fn fromWord(pin: Word.Pins) Pins {
        return .{ .word = pin };
    }
    pub fn sealPins(self: Pins) Seal.Pins {
        return switch (self) {
            .word => |pin| pin.seal,
            .lanes => |pin| pin.seal,
        };
    }
    pub fn expectedSealDigest(self: Pins) [32]u8 {
        return switch (self) {
            .word => |pin| pin.expected_seal_digest,
            .lanes => |pin| pin.expected_seal_digest,
        };
    }
    pub fn firstRound(self: Pins) []const Seal.Entry {
        return switch (self) {
            .word => |pin| pin.first_round,
            .lanes => |pin| pin.first_round,
        };
    }
    pub fn source(self: Pins) Endpoint.Pins {
        return switch (self) {
            .word => |pin| pin.source,
            .lanes => |pin| pin.source,
        };
    }
    pub fn totalEvents(self: Pins) u64 {
        return switch (self) {
            .word => |pin| pin.expected_total_events,
            .lanes => |pin| pin.expected_total_events,
        };
    }
    pub fn instanceCount(self: Pins) usize {
        return switch (self) {
            .word => |pin| pin.claims.len,
            .lanes => |pin| pin.pins.len,
        };
    }
    pub fn rangeRoots(self: Pins) []const [2][32]u8 {
        return switch (self) {
            .word => |pin| pin.range_roots,
            .lanes => |pin| pin.range_roots,
        };
    }
    pub fn registerEndpoints(self: Pins) ?Registers.Pins {
        return switch (self) {
            .word => |pin| pin.register_endpoints,
            .lanes => null,
        };
    }
    pub fn requireStructure(self: Pins) !void {
        const seal = self.sealPins();
        if (self.instanceCount() > std.math.maxInt(u32) or self.instanceCount() != seal.counts[@intFromEnum(Seal.Family.memory) - 1] or
            self.rangeRoots().len != seal.counts[@intFromEnum(Seal.Family.memory_range) - 1]) return error.InvalidV5SortedMemoryCorrespondence;
        if (self.instanceCount() == 0 and (self.totalEvents() != 0 or self.rangeRoots().len != 0)) return error.InvalidV5SortedMemoryCorrespondence;
        switch (self) {
            .word => |pin| if (pin.claims.len != pin.memory_roots.len or pin.claims.len != pin.request_counts.len) {
                return error.InvalidV5SortedMemoryCorrespondence;
            },
            .lanes => |pin| for (pin.pins, 0..) |instance, index| {
                try instance.validate();
                if (instance.index != index or instance.claim.total_events != pin.expected_total_events or !std.meta.eql(instance.config, seal.config)) return error.InvalidV5SortedMemoryCorrespondence;
            },
        }
    }
    pub fn requireCanonical(self: Pins, mode: u32) !void {
        try self.requireStructure();
        if (self.sealPins().register_custody_mode != mode) return error.MixedV5SortedMemoryMode;
        switch (self) {
            .word => if (mode != 0) return error.NoncanonicalV5WordMemoryProtocol,
            .lanes => if (mode != 1) return error.NoncanonicalV5RamLanesProtocol,
        }
    }
};
pub const Loader = struct {
    context: *anyopaque,
    take_memory: ?*const fn (*anyopaque, u32) anyerror!@import("block_v5_word_memory_proof_v1.zig").Proof = null,
    take_lanes: ?*const fn (*anyopaque, u32) anyerror!LaneProof.Proof = null,
    take_range: *const fn (*anyopaque, u32) anyerror!@import("block_v5_range16_proof_v1.zig").Proof,
    pub fn fromWord(loader: Word.Loader) Loader {
        return .{ .context = loader.context, .take_memory = loader.take_memory, .take_range = loader.take_range };
    }
};
pub fn verify(comptime Backend: type, a: std.mem.Allocator, pins: Pins, input: []const u8, files: Endpoint.Sources, loader: Loader, sealed: Seal.Sealed) !Word.Scoped {
    try pins.requireCanonical(sealed.register_custody_mode);
    return switch (pins) {
        .word => |pin| Word.verify(Backend, a, pin, input, files, .{ .context = loader.context, .take_memory = loader.take_memory orelse return error.MissingV5WordMemoryLoader, .take_range = loader.take_range }, sealed),
        .lanes => |pin| Lanes.verify(Backend, a, pin, input, files, .{ .context = loader.context, .take_memory = loader.take_lanes orelse if (pin.pins.len == 0) unexpectedEmptyLaneLoad else return error.MissingV5RamLanesLoader, .take_range = loader.take_range }, sealed, pin.limits),
    };
}

fn unexpectedEmptyLaneLoad(_: *anyopaque, _: u32) anyerror!LaneProof.Proof {
    return error.UnexpectedV5EmptyRamLoad;
}
