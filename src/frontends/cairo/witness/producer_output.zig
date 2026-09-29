//! Owned subcomponent and lookup feeds retained from one Cairo witness writer.

const std = @import("std");
const interaction_residency = @import("interaction_residency.zig");

pub const ProducerOutput = struct {
    label: []const u8,
    row_count: u32,
    active_rows: u32,
    words_per_row: u32,
    words: []u32,
    lookup_words_per_row: u32,
    lookup_words: []u32,
    lookup_allocation: ?interaction_residency.LookupAllocation = null,

    /// The dependency graph and implicit multiplicities have consumed these
    /// words. Interaction generation retains only the separate lookup slab.
    pub fn releaseSubcomponentWords(self: *ProducerOutput, allocator: std.mem.Allocator) void {
        allocator.free(self.words);
        self.words = &.{};
    }

    /// The component's interaction has consumed this feed. Clear its owner so
    /// ordinary execution teardown remains valid after incremental release.
    pub fn releaseLookupWords(self: *ProducerOutput, allocator: std.mem.Allocator) void {
        var lookup = interaction_residency.RetainedLookup{
            .words = self.lookup_words,
            .allocation = self.lookup_allocation,
        };
        lookup.deinit(allocator);
        self.lookup_words = &.{};
        self.lookup_allocation = null;
    }

    pub fn deinit(self: ProducerOutput, allocator: std.mem.Allocator) void {
        var owned = self;
        owned.releaseLookupWords(allocator);
        allocator.free(self.words);
    }

    pub fn lookupResidency(self: ProducerOutput) ?interaction_residency.Residency {
        return if (self.lookup_allocation) |allocation|
            allocation.residency
        else
            null;
    }
};
