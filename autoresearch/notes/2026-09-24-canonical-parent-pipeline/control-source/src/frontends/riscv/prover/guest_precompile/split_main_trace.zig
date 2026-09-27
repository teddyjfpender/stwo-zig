//! Detached caller/provider main-trace ownership for R-008.
//!
//! Production continues to use the combined C-007 generator. This module
//! performs the same immutable authority preflight, admits every caller and
//! provider destination before mutation, then exposes two infallible role
//! fills that may run concurrently. It is differential and performance
//! substrate, not an activated split proof path.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const base_statement = @import("../../air/statement.zig");
const component_registry = @import("../../air/guest_precompile/component_registry.zig");
const guest_main_trace = @import("../../air/guest_precompile/main_trace.zig");
const guest_statement = @import("../../air/guest_precompile/statement.zig");
const call_buffer = @import("../../runner/guest_precompile/call_buffer.zig");
const guest_runner = @import("../../runner/guest_precompile/poseidon2_v1.zig");
const aggregation_hash = @import("../../aggregation/hash.zig");

pub const RESEARCH_ONLY = true;
pub const ACTIVATES_PRODUCTION_PROOF = false;
pub const ALLOWS_PARALLEL_ROLE_FILL = true;
pub const VERIFIES_SPLIT_STARKS = false;

pub const caller_column_count = guest_main_trace.caller_main_column_count;
pub const provider_column_count = guest_main_trace.provider_main_column_count;
pub const total_column_count = caller_column_count + provider_column_count;
pub const CallerDestinations = guest_main_trace.CallerMainDestinations;
pub const ProviderDestinations = guest_main_trace.ProviderMainDestinations;
pub const CallerCommittedColumns = [caller_column_count][]const M31;
pub const ProviderCommittedColumns = [provider_column_count][]const M31;
pub const Digest = aggregation_hash.Digest;

pub const caller_trace_digest_domain =
    "stwo-zig/riscv/split/caller-main-trace/v1\x00";
pub const provider_trace_digest_domain =
    "stwo-zig/riscv/split/provider-main-trace/v1\x00";

/// Pair-wide admission copies slice descriptors by value after checking exact
/// shape and global disjointness. All subsequent work is infallible; therefore
/// no malformed second role can leave the first role partially generated.
pub const PreparedDestinationsV1 = struct {
    authority: guest_main_trace.ShadowSplitMainAuthorityV1,
    caller: CallerDestinations,
    provider: ProviderDestinations,

    /// Zero and fill only caller-owned columns. No provider cell is touched.
    pub fn finishCaller(self: *const PreparedDestinationsV1) void {
        for (self.caller) |destination| @memset(destination, M31.zero());
        guest_main_trace.fillShadowCallerMainAssumeAdmittedV1(
            self.authority,
            &self.caller,
        );
    }

    /// Zero and fill only provider-owned columns. No caller cell is touched.
    pub fn finishProvider(self: *const PreparedDestinationsV1) void {
        for (self.provider) |destination| @memset(destination, M31.zero());
        guest_main_trace.fillShadowProviderMainAssumeAdmittedV1(
            self.authority,
            &self.provider,
        );
    }

    pub fn workProfile(self: *const PreparedDestinationsV1) WorkProfile {
        const caller_cells = std.math.mul(
            usize,
            caller_column_count,
            self.authority.domain_size,
        ) catch unreachable;
        const provider_cells = std.math.mul(
            usize,
            provider_column_count,
            self.authority.domain_size,
        ) catch unreachable;
        return .{
            .n_rows = self.authority.n_rows,
            .domain_size = self.authority.domain_size,
            .caller_cells = caller_cells,
            .provider_cells = provider_cells,
            .serial_destination_cells = caller_cells + provider_cells,
            .parallel_destination_span_cells = @max(caller_cells, provider_cells),
            .construction_allocations = 0,
            .hot_path_allocations = 0,
            .hot_path_dynamic_dispatches = 0,
        };
    }
};

pub const WorkProfile = struct {
    n_rows: u32,
    domain_size: usize,
    caller_cells: usize,
    provider_cells: usize,
    serial_destination_cells: usize,
    parallel_destination_span_cells: usize,
    construction_allocations: usize,
    hot_path_allocations: usize,
    hot_path_dynamic_dispatches: usize,
};

/// Preflight the same statement, construction authority, frozen logs, and row
/// semantics as the combined production generator, then admit both role
/// destination sets without allocating or changing a cell.
pub fn prepareInto(
    core: *const base_statement.RiscVStatement,
    extension: *const guest_statement.ExtensionStatement,
    calls: *const call_buffer.Frozen,
    execution_rows: *const guest_runner.FrozenExecutionRows,
    caller: *const CallerDestinations,
    provider: *const ProviderDestinations,
) !PreparedDestinationsV1 {
    const authority = try guest_main_trace.prepareShadowSplitMainV1(
        core,
        extension,
        calls,
        execution_rows,
    );
    return admitPrepared(authority, caller, provider);
}

/// Admit already-preflighted authority. This is the ownership handoff used by
/// the two-allocation owned constructor and by a future shared work-pool seam.
pub fn admitPrepared(
    authority: guest_main_trace.ShadowSplitMainAuthorityV1,
    caller: *const CallerDestinations,
    provider: *const ProviderDestinations,
) !PreparedDestinationsV1 {
    try validateAuthority(authority);
    try validateDestinations(authority.domain_size, caller, provider);
    return .{
        .authority = authority,
        .caller = caller.*,
        .provider = provider.*,
    };
}

/// Sequential reference over the two independently owned finish operations.
/// Parallel execution calls the same two infallible methods from sibling tasks.
pub fn generateInto(
    core: *const base_statement.RiscVStatement,
    extension: *const guest_statement.ExtensionStatement,
    calls: *const call_buffer.Frozen,
    execution_rows: *const guest_runner.FrozenExecutionRows,
    caller: *const CallerDestinations,
    provider: *const ProviderDestinations,
) !void {
    const prepared = try prepareInto(
        core,
        extension,
        calls,
        execution_rows,
        caller,
        provider,
    );
    prepared.finishCaller();
    prepared.finishProvider();
}

fn OwnedColumnsV1(comptime column_count: usize) type {
    return struct {
        const Self = @This();

        allocator: std.mem.Allocator,
        storage: []M31,
        log_size: u32,
        n_rows: u32,
        domain_size: usize,

        fn init(
            allocator: std.mem.Allocator,
            authority: guest_main_trace.ShadowSplitMainAuthorityV1,
        ) !Self {
            const cells = std.math.mul(
                usize,
                column_count,
                authority.domain_size,
            ) catch return error.TraceSizeOverflow;
            _ = std.math.mul(usize, cells, @sizeOf(M31)) catch
                return error.TraceSizeOverflow;
            return .{
                .allocator = allocator,
                .storage = try allocator.alloc(M31, cells),
                .log_size = authority.log_size,
                .n_rows = authority.n_rows,
                .domain_size = authority.domain_size,
            };
        }

        pub fn deinit(self: *Self) void {
            if (self.storage.len != 0) self.allocator.free(self.storage);
            self.* = undefined;
        }

        /// Transfers the one contiguous role arena exactly once. The caller
        /// must either pass the returned allocation to `Engine.commitWithBacking`
        /// or free it with the same allocator. Keeping this move primitive on
        /// the owner prevents a real PCS handoff from copying 286/445 columns
        /// merely to change their ownership representation.
        pub fn takeStorage(self: *Self) ![]M31 {
            if (self.storage.len == 0)
                return error.SplitMainStorageAlreadyTransferred;
            const result = self.storage;
            self.storage = &.{};
            return result;
        }

        pub fn committedCells(self: *const Self) []const M31 {
            return self.storage;
        }

        pub fn column(self: *const Self, index: usize) []const M31 {
            std.debug.assert(index < column_count);
            const start = index * self.domain_size;
            return self.storage[start..][0..self.domain_size];
        }

        fn mutableDestinations(self: *Self) [column_count][]M31 {
            var result: [column_count][]M31 = undefined;
            for (&result, 0..) |*destination, index| {
                const start = index * self.domain_size;
                destination.* = self.storage[start..][0..self.domain_size];
            }
            return result;
        }

        pub fn committedColumns(self: *const Self) [column_count][]const M31 {
            var result: [column_count][]const M31 = undefined;
            for (&result, 0..) |*column_view, index| {
                column_view.* = self.column(index);
            }
            return result;
        }
    };
}

pub const CallerOwnedV1 = OwnedColumnsV1(caller_column_count);
pub const ProviderOwnedV1 = OwnedColumnsV1(provider_column_count);

pub const OwnedPairV1 = struct {
    caller: CallerOwnedV1,
    provider: ProviderOwnedV1,

    pub fn deinit(self: *OwnedPairV1) void {
        self.provider.deinit();
        self.caller.deinit();
        self.* = undefined;
    }

    pub fn workProfile(self: *const OwnedPairV1) WorkProfile {
        return .{
            .n_rows = self.caller.n_rows,
            .domain_size = self.caller.domain_size,
            .caller_cells = self.caller.storage.len,
            .provider_cells = self.provider.storage.len,
            .serial_destination_cells = self.caller.storage.len + self.provider.storage.len,
            .parallel_destination_span_cells = @max(self.caller.storage.len, self.provider.storage.len),
            .construction_allocations = 2,
            .hot_path_allocations = 0,
            .hot_path_dynamic_dispatches = 0,
        };
    }
};

/// Build only the caller-owned trace from an authority that has already
/// passed the exact production witness preflight. The returned value has no
/// pointer back into this stack frame and may be moved between worker-owned
/// queues while its single backing allocation remains stable.
pub fn generateCallerOwnedFromAuthority(
    allocator: std.mem.Allocator,
    authority: guest_main_trace.ShadowSplitMainAuthorityV1,
) !CallerOwnedV1 {
    try validateAuthority(authority);
    var caller = try CallerOwnedV1.init(allocator, authority);
    errdefer caller.deinit();
    const destinations = caller.mutableDestinations();
    for (destinations) |destination| @memset(destination, M31.zero());
    guest_main_trace.fillShadowCallerMainAssumeAdmittedV1(
        authority,
        &destinations,
    );
    return caller;
}

/// Provider counterpart to `generateCallerOwnedFromAuthority`. Each role uses
/// exactly one independent allocation and touches no sibling-owned storage.
pub fn generateProviderOwnedFromAuthority(
    allocator: std.mem.Allocator,
    authority: guest_main_trace.ShadowSplitMainAuthorityV1,
) !ProviderOwnedV1 {
    try validateAuthority(authority);
    var provider = try ProviderOwnedV1.init(allocator, authority);
    errdefer provider.deinit();
    const destinations = provider.mutableDestinations();
    for (destinations) |destination| @memset(destination, M31.zero());
    guest_main_trace.fillShadowProviderMainAssumeAdmittedV1(
        authority,
        &destinations,
    );
    return provider;
}

/// Preflight occurs before allocation. Successful construction uses exactly
/// two independent allocations, one per role; every failure rolls back both.
pub fn generateOwned(
    allocator: std.mem.Allocator,
    core: *const base_statement.RiscVStatement,
    extension: *const guest_statement.ExtensionStatement,
    calls: *const call_buffer.Frozen,
    execution_rows: *const guest_runner.FrozenExecutionRows,
) !OwnedPairV1 {
    const authority = try guest_main_trace.prepareShadowSplitMainV1(
        core,
        extension,
        calls,
        execution_rows,
    );
    try validateAuthority(authority);

    var caller = try generateCallerOwnedFromAuthority(allocator, authority);
    errdefer caller.deinit();
    var provider = try generateProviderOwnedFromAuthority(allocator, authority);
    errdefer provider.deinit();
    return .{ .caller = caller, .provider = provider };
}

/// Allocation-free digest for differential evidence. This is not a PCS root
/// and must not be used as a proof commitment.
pub fn callerTraceDigest(
    log_size: u32,
    n_rows: u32,
    columns: *const CallerCommittedColumns,
) !Digest {
    return traceDigest(
        caller_trace_digest_domain,
        log_size,
        n_rows,
        caller_column_count,
        columns,
    );
}

/// Allocation-free digest for differential evidence. This is not a PCS root.
pub fn providerTraceDigest(
    log_size: u32,
    n_rows: u32,
    columns: *const ProviderCommittedColumns,
) !Digest {
    return traceDigest(
        provider_trace_digest_domain,
        log_size,
        n_rows,
        provider_column_count,
        columns,
    );
}

fn traceDigest(
    domain: []const u8,
    log_size: u32,
    n_rows: u32,
    comptime column_count: usize,
    columns: *const [column_count][]const M31,
) !Digest {
    if (log_size >= @bitSizeOf(usize)) return error.TraceSizeOverflow;
    const domain_size = @as(usize, 1) << @intCast(log_size);
    if (n_rows > domain_size) return error.InvalidShadowAuthority;
    var sink = aggregation_hash.HashSink.init(domain);
    try aggregation_hash.writeU32(&sink, 1);
    try aggregation_hash.writeU32(&sink, log_size);
    try aggregation_hash.writeU32(&sink, n_rows);
    try aggregation_hash.writeU32(&sink, column_count);
    try aggregation_hash.writeU64(&sink, domain_size);
    for (columns.*) |column| {
        if (column.len != domain_size) return error.InvalidDestinationShape;
        for (column) |value| {
            const bytes = value.toBytesLe();
            try sink.writeAll(&bytes);
        }
    }
    return sink.finalize();
}

fn validateAuthority(
    authority: guest_main_trace.ShadowSplitMainAuthorityV1,
) !void {
    if (authority.log_size < component_registry.minimum_log_size or
        authority.log_size >= @bitSizeOf(usize))
    {
        return error.InvalidShadowAuthority;
    }
    const expected_domain = @as(usize, 1) << @intCast(authority.log_size);
    if (authority.domain_size != expected_domain or
        authority.n_rows != authority.records.len or
        authority.records.len > authority.domain_size)
    {
        return error.InvalidShadowAuthority;
    }
}

const AddressRange = struct {
    start: usize,
    end: usize,
};

/// O(C log C) cold admission with a fixed stack array. The existing combined
/// oracle intentionally remains unchanged; its legacy pairwise scan is useful
/// as an independent comparison path.
fn validateDestinations(
    domain_size: usize,
    caller: *const CallerDestinations,
    provider: *const ProviderDestinations,
) !void {
    const column_bytes = std.math.mul(usize, domain_size, @sizeOf(M31)) catch
        return error.TraceSizeOverflow;
    var ranges: [total_column_count]AddressRange = undefined;
    var cursor: usize = 0;
    try appendRanges(&ranges, &cursor, caller, domain_size, column_bytes);
    try appendRanges(&ranges, &cursor, provider, domain_size, column_bytes);
    std.debug.assert(cursor == ranges.len);
    std.mem.sortUnstable(AddressRange, &ranges, {}, rangeLessThan);
    for (ranges[1..], ranges[0 .. ranges.len - 1]) |current, previous| {
        if (current.start < previous.end) return error.OverlappingDestinations;
    }
}

fn appendRanges(
    ranges: *[total_column_count]AddressRange,
    cursor: *usize,
    destinations: anytype,
    domain_size: usize,
    column_bytes: usize,
) !void {
    for (destinations.*) |destination| {
        if (destination.len != domain_size)
            return error.InvalidDestinationShape;
        const start = @intFromPtr(destination.ptr);
        const end = std.math.add(usize, start, column_bytes) catch
            return error.TraceSizeOverflow;
        ranges[cursor.*] = .{ .start = start, .end = end };
        cursor.* += 1;
    }
}

fn rangeLessThan(_: void, left: AddressRange, right: AddressRange) bool {
    return if (left.start == right.start)
        left.end < right.end
    else
        left.start < right.start;
}

comptime {
    if (!guest_main_trace.SPLIT_MAIN_TRACE_SHADOW_ONLY or
        caller_column_count != 286 or provider_column_count != 445 or
        total_column_count != 731)
    {
        @compileError("R-008 split main-trace geometry drifted");
    }
}
