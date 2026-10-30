//! Shared late epoch for a finite ordered endpoint roster and the global RAM
//! provider's first roots. Scope construction authenticates metadata ONLY.
//! Local STARKs and the global RAM proof remain independent proof obligations.
const std = @import("std");
const core = @import("stwo_core");
const E = @import("block_v7_execution_epoch_v1.zig");
const K = @import("block_v8_ram_endpoint_kernel_v1.zig");
const R = @import("block_v7_memory_relations_v1.zig");
const B = @import("block_v8_endpoint_global_bridge_component_v1.zig");
pub const MAX_SOURCES: usize = 4096;
/// The current PCS placement has at most 256 trace trees. This is a bridge
/// batch limit, NOT a limit or power-of-two rounding on the execution roster.
pub const MAX_BATCH_SOURCES: usize = 127;
pub const Source = struct {
    local_identity: [32]u8,
    local_epoch: [32]u8,
    endpoint_root: [32]u8,
    endpoint_count: u32,
    policy: K.Policy,
    pub fn log(self: Source) !u32 {
        try self.policy.validate();
        if (self.endpoint_count == 0 or self.endpoint_count > 1 << 24) return error.InvalidEndpointBridgeGeometry;
        return @max(@as(u32, 4), std.math.log2_int_ceil(u32, self.endpoint_count));
    }
    pub fn identity(self: Source) ![32]u8 {
        _ = try self.log();
        for ([_][32]u8{ self.local_identity, self.local_epoch, self.endpoint_root }) |digest| if (std.mem.allEqual(u8, &digest, 0)) return error.InvalidEndpointBridgeSource;
        var ch = core.proof_suites.Blake3.Channel{};
        ch.mixU32s(&.{ 0x42384542, 1, 1, B.Spec.MAIN_COUNT, self.endpoint_count, self.policy.source_ordinal, self.policy.max_local_clock });
        ch.mixRoot(self.local_identity);
        ch.mixRoot(self.local_epoch);
        ch.mixRoot(self.endpoint_root);
        return ch.digestBytes();
    }
};
pub const Owned = struct {
    a: std.mem.Allocator,
    sources: []Source,
    entries: []E.Entry,
    epoch: E.Epoch,
    endpoint_count: u64,
    batch_start: u32 = 0,
    roster_count: u32,
    pub fn init(a: std.mem.Allocator, block_statement: [32]u8, config: core.pcs.PcsConfig, sources: []const Source, global_memory: E.Entry) !Owned {
        if (sources.len == 0 or sources.len > MAX_SOURCES or std.mem.allEqual(u8, &block_statement, 0)) return error.InvalidEndpointBridgeRoster;
        if ((global_memory.family != .memory_joint and global_memory.family != .window_memory_joint) or global_memory.index != 0) return error.InvalidEndpointBridgeGlobalProvider;
        try global_memory.validate();
        const entries = try a.alloc(E.Entry, sources.len + 1);
        errdefer a.free(entries);
        var total: u64 = 0;
        for (sources, 0..) |source, ordinal| {
            // The complete block roster is exact, never power-of-two rounded.
            if (source.policy.source_ordinal != ordinal) return error.InvalidEndpointBridgeOrder;
            entries[ordinal] = try E.Entry.init(.native, @intCast(ordinal), try source.identity(), &.{source.endpoint_root});
            total = try std.math.add(u64, total, source.endpoint_count);
        }
        // A count vanishing in the base field would invalidate census checks.
        if (total >= core.fields.m31.Modulus) return error.EndpointBridgeCountExceedsField;
        entries[sources.len] = global_memory;
        var counts: E.Counts = @splat(0);
        counts[@intFromEnum(E.Family.native)] = @intCast(sources.len);
        counts[@intFromEnum(global_memory.family)] = 1;
        // Keep the independently admitted global policy digest as statement so
        // the existing global provider reconstructs the SAME epoch. The new
        // B8 domain is in every source identity and bridge proof framing; do
        // not invent a second challenge stream for the memory proof.
        const epoch = try E.Epoch.init(block_statement, config, counts, entries, sources.len + 1);
        return .{ .a = a, .sources = try a.dupe(Source, sources), .entries = entries, .epoch = epoch, .endpoint_count = total, .roster_count = @intCast(sources.len) };
    }
    pub fn deinit(self: *Owned) void {
        self.a.free(self.sources);
        self.a.free(self.entries);
        self.* = undefined;
    }
    pub fn traceTrees(self: Owned) usize {
        return 1 + 2 * self.sources.len;
    }
    /// Each batch keeps the COMPLETE epoch/first-root roster. Independently
    /// drawing a new epoch for each slice would prevent adding their claims.
    /// A coordinator must cover [0,roster_count) exactly once before closure.
    pub fn batch(self: Owned, a: std.mem.Allocator, first: u32, count: u32) !Owned {
        if (self.batch_start != 0 or self.sources.len != self.roster_count or count == 0 or count > MAX_BATCH_SOURCES or
            first > self.sources.len or count > self.sources.len - first) return error.InvalidEndpointBridgeBatch;
        const sources = try a.dupe(Source, self.sources[first..][0..count]);
        errdefer a.free(sources);
        return .{ .a = a, .sources = sources, .entries = try a.dupe(E.Entry, self.entries), .epoch = self.epoch, .endpoint_count = self.endpoint_count, .batch_start = first, .roster_count = self.roster_count };
    }
    /// All physical source claims are bound before ANY interaction commitment.
    /// No aggregate-only transcript is permitted.
    pub fn afterClaims(self: Owned, drawn: E.Drawn, claims: []const R.Q) !core.proof_suites.Blake3.Channel {
        var ch = drawn.channel;
        try self.recordAfterDraws(&ch, claims);
        return ch;
    }
    /// The exact same post-draw framing is used by the original and recursive
    /// verifiers. The complete shared epoch channel continues without reset.
    pub fn recordAfterDraws(self: Owned, ch: anytype, claims: []const R.Q) !void {
        if (claims.len != self.sources.len or self.sources.len > MAX_BATCH_SOURCES) return error.InvalidEndpointBridgeClaims;
        ch.mixU32s(&.{ 0x42384542, 1, 3, self.roster_count, self.batch_start, @intCast(claims.len) });
        for (claims) |claim| {
            if (!@import("../recursion/air/universal_provider_relations.zig").secureIsCanonical(&claim)) return error.InvalidEndpointBridgeClaims;
            ch.mixFelts(&.{claim});
        }
    }
};
