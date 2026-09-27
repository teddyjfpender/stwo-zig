//! Public fixed roster and private interaction-column layout for RW first touches.
const std = @import("std");
const core = @import("stwo_core");
const tree = @import("../air/memory_commitment/blake3_state_tree.zig");
const memory_state = @import("../runner/memory_state.zig");
const spans = @import("../recursion/span_statement_blake3.zig");
const framework = @import("../recursion/air/framework_interaction.zig");
const air = @import("block_rw_initial_air_v2.zig");
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const Layout = air.Layout;
const Row = air.Row;
pub const Trace = struct {
    allocator: std.mem.Allocator,
    log_size: u32,
    fixed: [10][]M,
    main: [4][]M,
    storage: []M,
    pub fn deinit(self: *Trace) void {
        self.allocator.free(self.storage);
        self.* = undefined;
    }
};
pub const FixedTrace = struct {
    allocator: std.mem.Allocator,
    log_size: u32,
    columns: [10][]M,
    storage: []M,
    pub fn deinit(self: *FixedTrace) void {
        self.allocator.free(self.storage);
        self.* = undefined;
    }
};

pub fn digestRoster(root: tree.Digest, addresses: []const u32, caller_base: u32, path_namespace: u32) [32]u8 {
    return digestRosterMode(root, addresses, caller_base, path_namespace, false);
}
pub fn digestCompleteSparseRoster(root: tree.Digest, addresses: []const u32, caller_base: u32, path_namespace: u32) [32]u8 {
    return digestRosterMode(root, addresses, caller_base, path_namespace, true);
}
pub fn digestZeroQueryRoster(root: tree.Digest, addresses: []const u32, caller_base: u32, path_namespace: u32) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo.riscv.block.rw-initial-zero-query-roster.v2\x00");
    hash.update(&digestRoster(root, addresses, caller_base, path_namespace));
    return hash.finalResult();
}
pub fn digestSparseShardRoster(full_root: tree.Digest, subroot: tree.Digest, coordinate: tree.Coordinate, addresses: []const u32, caller_base: u32, path_namespace: u32) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo.riscv.block.rw-initial-complete-sparse-shard.v2\x00");
    hash.update(&full_root.bytes);
    hash.update(&subroot.bytes);
    var word: [4]u8 = undefined;
    for ([_]u32{ coordinate.level, coordinate.index }) |value| {
        std.mem.writeInt(u32, &word, value, .little);
        hash.update(&word);
    }
    const roster = digestCompleteSparseRoster(full_root, addresses, caller_base, path_namespace);
    hash.update(&roster);
    return hash.finalResult();
}
fn digestRosterMode(root: tree.Digest, addresses: []const u32, caller_base: u32, path_namespace: u32, complete_sparse: bool) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(if (complete_sparse) "stwo.riscv.block.rw-initial-complete-sparse-roster.v2\x00" else "stwo.riscv.block.rw-initial-roster.v2\x00");
    hash.update(&root.bytes);
    var bytes: [4]u8 = undefined;
    for ([_]u32{ @intCast(addresses.len), caller_base, path_namespace }) |word| {
        std.mem.writeInt(u32, &bytes, word, .little);
        hash.update(&bytes);
    }
    for (addresses) |address| {
        std.mem.writeInt(u32, &bytes, address, .little);
        hash.update(&bytes);
    }
    return hash.finalResult();
}

/// B2SS seals one ordered digest for all independently proved chunks. The
/// receiver recomputes each chunk digest from the public roster and root.
pub fn digestRosterSet(digests: []const [32]u8) ![32]u8 {
    if (digests.len == 0 or digests.len > std.math.maxInt(u32)) return error.InvalidInitialRwRosterSet;
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo.riscv.block.rw-initial-roster-set.v2\x00");
    var count: [4]u8 = undefined;
    std.mem.writeInt(u32, &count, @intCast(digests.len), .little);
    hash.update(&count);
    for (digests) |digest| hash.update(&digest);
    return hash.finalResult();
}

/// Reconstruct the nine public fixed columns without reading private values
/// or opening witness files. A receiver uses these to pin Tree0 exactly.
pub fn trustedFixedTrace(
    a: std.mem.Allocator,
    job: spans.JobContext,
    layout: memory_state.MemoryLayout,
    addresses: []const u32,
    caller_base: u32,
    path_namespace: u32,
    expected_digest: [32]u8,
) !FixedTrace {
    return trustedFixedTraceMode(a, job, layout, addresses, caller_base, path_namespace, expected_digest, false, false);
}
pub fn trustedCompleteSparseFixedTrace(
    a: std.mem.Allocator,
    job: spans.JobContext,
    layout: memory_state.MemoryLayout,
    addresses: []const u32,
    caller_base: u32,
    path_namespace: u32,
    expected_digest: [32]u8,
) !FixedTrace {
    return trustedFixedTraceMode(a, job, layout, addresses, caller_base, path_namespace, expected_digest, true, false);
}
pub fn trustedZeroQueryFixedTrace(a: std.mem.Allocator, job: spans.JobContext, layout: memory_state.MemoryLayout, addresses: []const u32, caller_base: u32, path_namespace: u32, expected_digest: [32]u8) !FixedTrace {
    return trustedFixedTraceMode(a, job, layout, addresses, caller_base, path_namespace, expected_digest, false, true);
}
pub fn trustedSparseShardFixedTrace(a: std.mem.Allocator, job: spans.JobContext, layout: memory_state.MemoryLayout, addresses: []const u32, caller_base: u32, path_namespace: u32, coordinate: tree.Coordinate, subroot: tree.Digest, expected_digest: [32]u8) !FixedTrace {
    const full_root = tree.Digest{ .bytes = job.complete.initial_state.rw_memory.bytes };
    const digest = digestSparseShardRoster(full_root, subroot, coordinate, addresses, caller_base, path_namespace);
    if (!std.mem.eql(u8, &digest, &expected_digest)) return error.UntrustedInitialRwRoster;
    return trustedFixedTraceMode(a, job, layout, addresses, caller_base, path_namespace, digestCompleteSparseRoster(full_root, addresses, caller_base, path_namespace), true, false);
}
fn trustedFixedTraceMode(
    a: std.mem.Allocator,
    job: spans.JobContext,
    layout: memory_state.MemoryLayout,
    addresses: []const u32,
    caller_base: u32,
    path_namespace: u32,
    expected_digest: [32]u8,
    complete_sparse: bool,
    zero_query: bool,
) !FixedTrace {
    try job.validate();
    if (addresses.len == 0) return error.EmptyInitialRwRoster;
    if (addresses.len > air.MAX_FIRST_TOUCH_KEYS_PER_CHUNK) return error.InitialRwChunkTooLarge;
    const upper = try std.math.add(u32, caller_base, std.math.cast(u32, addresses.len) orelse return error.InitialRwCallerOverflow);
    if (upper > path_namespace or path_namespace >= core.fields.m31.Modulus) return error.InitialRwCallerOverlap;
    const root = tree.Digest{ .bytes = job.complete.initial_state.rw_memory.bytes };
    const digest = if (zero_query) digestZeroQueryRoster(root, addresses, caller_base, path_namespace) else digestRosterMode(root, addresses, caller_base, path_namespace, complete_sparse);
    if (!std.mem.eql(u8, &digest, &expected_digest)) return error.UntrustedInitialRwRoster;
    for (addresses, 0..) |address, i| {
        if (address & 3 != 0 or address >= tree.ADDRESS_LIMIT or
            !(layout.isRwAddr(address) or layout.isInputAddr(address)) or layout.isProgramAddr(address)) return error.InvalidInitialRwAddress;
        if (i != 0 and addresses[i - 1] >= address) return error.UnsortedInitialRwRoster;
    }
    const log_size: u32 = @max(2, std.math.log2_int_ceil(usize, addresses.len));
    const size: usize = @as(usize, 1) << @intCast(log_size);
    const storage = try a.alloc(M, 10 * size);
    @memset(storage, M.zero());
    var result: FixedTrace = .{ .allocator = a, .log_size = log_size, .columns = undefined, .storage = storage };
    for (&result.columns, 0..) |*column, i| column.* = storage[i * size ..][0..size];
    for (0..size) |logical| {
        const committed = framework.committedRow(logical, log_size);
        result.columns[9][committed] = M.fromCanonical(@intFromBool(logical + 1 == size));
        if (logical >= addresses.len) continue;
        const row = try air.fixedRowWithSelectors(addresses[logical], caller_base, @intCast(logical), !zero_query, true);
        for (0..4) |i| result.columns[i][committed] = row[Layout.address + i];
        result.columns[4][committed] = row[Layout.circuit];
        result.columns[5][committed] = row[Layout.wire];
        result.columns[6][committed] = row[Layout.active];
        result.columns[7][committed] = row[Layout.initial_emit];
        result.columns[8][committed] = M.fromCanonical(@intFromBool(logical == 0));
    }
    return result;
}

pub fn writeSecure(columns: *[8][]M, offset: usize, index: usize, value: Q) void {
    const limbs = value.toM31Array();
    for (0..4) |i| columns[offset + i][index] = limbs[i];
}
pub fn readSecure(columns: *const [8][]M, offset: usize, index: usize) Q {
    var limbs: [4]M = undefined;
    for (&limbs, 0..) |*limb, i| limb.* = columns[offset + i][index];
    return Q.fromM31Array(limbs);
}
