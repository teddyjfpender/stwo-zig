//! Exact sparse caller policy ownership for the canonical driver lifetime.
//! The original source roster chooses the execution indices. Catalog entries
//! outlive caller sessions, durable leaf stores and joined hierarchy readers.
const std = @import("std");
const PairModule = @import("block_v5_caller_recursive_admission_pair_v1.zig");
const Pipeline = @import("block_v5_caller_recursive_pipeline_v1.zig");
const Caller = @import("block_v5_caller_pipeline_v1.zig");
const Seal = @import("block_v5_source_seal_v1.zig");
const Roster = @import("block_v5_recursive_leaf_store_core_v1.zig").Roster;
pub const Limits = struct {
    pair: PairModule.Limits = .{},
    max_callers: usize = 1 << 16,
    max_slot_bytes: usize = 64 << 20,
};
pub const Entry = struct { index: u32, admissions: *PairModule.Pair };
pub const Catalog = struct {
    a: std.mem.Allocator,
    entries: []Entry,
    pub fn init(a: std.mem.Allocator, roster: Roster, sources: []const ?PairModule.Pin, limits: Limits) !Catalog {
        try roster.require();
        const counts = roster.pins.counts;
        if (sources.len != counts[@intFromEnum(Seal.Family.execution) - 1])
            return error.UntrustedRecursiveCallerSourceCensus;
        const count = counts[@intFromEnum(Seal.Family.precompile) - 1];
        if (limits.max_callers == 0 or limits.max_slot_bytes == 0 or count > limits.max_callers or
            try std.math.mul(usize, count, @sizeOf(Entry)) > limits.max_slot_bytes)
            return error.RecursiveCallerCatalogResourceLimit;
        var present: usize = 0;
        for (sources) |source| if (source != null) {
            present += 1;
        };
        if (present != count) return error.IncompleteRecursiveCallerSources;
        const entries = try a.alloc(Entry, count);
        errdefer a.free(entries);
        var initialized: usize = 0;
        errdefer for (entries[0..initialized]) |entry| entry.admissions.deinit();
        for (roster.entries) |entry| if (entry.family == .precompile) {
            if (entry.index >= sources.len) return error.UntrustedRecursiveCallerSourceIndex;
            const pin = sources[entry.index] orelse return error.MissingRecursiveCallerSource;
            entries[initialized] = .{ .index = entry.index, .admissions = try PairModule.Pair.create(a, entry.index, pin, roster.sealed, roster.pins, roster.entries, limits.pair) };
            initialized += 1;
        };
        if (initialized != count) return error.IncompleteRecursiveCallerSources;
        return .{ .a = a, .entries = entries };
    }
    /// Direct bridge from the real assembled optional caller roster. Temporary
    /// pins are freed before return; each pair owns its statement and geometry.
    pub fn initFromBounds(a: std.mem.Allocator, roster: Roster, bounds: []const ?Caller.Bound, limits: Limits) !Catalog {
        try roster.require();
        if (bounds.len != roster.pins.counts[@intFromEnum(Seal.Family.execution) - 1])
            return error.UntrustedRecursiveCallerSourceCensus;
        const slots = try std.math.mul(usize, roster.pins.counts[@intFromEnum(Seal.Family.precompile) - 1], @sizeOf(Entry));
        const temporary = try std.math.mul(usize, bounds.len, @sizeOf(?PairModule.Pin));
        if (try std.math.add(usize, slots, temporary) > limits.max_slot_bytes)
            return error.RecursiveCallerCatalogResourceLimit;
        const sources = try a.alloc(?PairModule.Pin, bounds.len);
        defer a.free(sources);
        for (bounds, sources) |*bound, *source| {
            source.* = if (bound.*) |*caller| blk: {
                try caller.require(a);
                break :blk try Pipeline.pinFor(caller, roster.sealed);
            } else null;
        }
        return init(a, roster, sources, limits);
    }
    pub fn deinit(self: *Catalog) void {
        for (self.entries) |entry| entry.admissions.deinit();
        self.a.free(self.entries);
        self.* = undefined;
    }
    /// Lookup uses the independently admitted original index, not file ordinal.
    pub fn get(self: *const Catalog, index: u32) !*PairModule.Pair {
        var low: usize = 0;
        var high = self.entries.len;
        while (low < high) {
            const middle = low + (high - low) / 2;
            if (self.entries[middle].index < index) low = middle + 1 else high = middle;
        }
        if (low == self.entries.len or self.entries[low].index != index)
            return error.UnadmittedRecursiveCallerIndex;
        return self.entries[low].admissions;
    }
};
