//! Canonical batched page multiproof and net updates. Native verification is
//! independent of the producer's snapshot, supplied only expected roots/pages.
//! This substrate does not yet prove CPU/page consistency or continuation.
const std = @import("std");
const ram = @import("commitment.zig");
const image = @import("image.zig");
const Memory = @import("../../memory.zig").Memory;
pub const NetUpdate = struct { address: u64, value: u64, byte_mask: u8 };
pub const Opening = struct { index: u64, before: ram.Page, after: ram.Page };
pub const Side = struct { height: u6, index: u64, digest: ram.Digest };
const Pair = struct { index: u64, before: ram.Digest, after: ram.Digest };

pub const Witness = struct {
    allocator: std.mem.Allocator,
    pages: []Opening,
    sides: []Side,
    before: ram.Digest,
    after: ram.Digest,

    pub fn deinit(self: *Witness) void {
        self.allocator.free(self.pages);
        self.allocator.free(self.sides);
        self.* = undefined;
    }

    /// Writes are canonical net changes, one per cell; untouched bytes and all
    /// permissions stay fixed. Access ordering and intermediate writes belong
    /// to the batch-local RAM relation, not this architectural commitment.
    pub fn build(a: std.mem.Allocator, memory: *const Memory, touched_pages: []const u64, updates: []const NetUpdate) !Witness {
        var snapshot = try image.snapshot(a, memory);
        defer snapshot.deinit();
        return buildFromSnapshot(a, memory, &snapshot, touched_pages, updates);
    }

    pub fn buildFromSnapshot(a: std.mem.Allocator, memory: *const Memory, snapshot: *const ram.Snapshot, touched_pages: []const u64, updates: []const NetUpdate) !Witness {
        if (touched_pages.len == 0) return error.EmptyRamTransition;
        const pages = try a.alloc(Opening, touched_pages.len);
        errdefer a.free(pages);
        for (touched_pages, 0..) |index, i| {
            if (index >= @as(u64, 1) << ram.PAGE_DEPTH or (i != 0 and touched_pages[i - 1] >= index))
                return error.NoncanonicalTouchedPages;
            const page = try image.readPage(memory, index);
            pages[i] = .{ .index = index, .before = page, .after = page };
        }
        var page_at: usize = 0;
        for (updates, 0..) |update, i| {
            if (update.address & 7 != 0 or update.byte_mask == 0 or (i > 0 and updates[i - 1].address >= update.address))
                return error.NoncanonicalNetUpdates;
            const page_index = update.address >> ram.PAGE_BITS;
            while (page_at < pages.len and pages[page_at].index < page_index) page_at += 1;
            if (page_at == pages.len or pages[page_at].index != page_index) return error.UntouchedUpdatePage;
            const cell = &pages[page_at].after[@intCast((update.address & 4095) >> 3)];
            for (0..8) |byte| {
                const shift: u6 = @intCast(byte * 8);
                if (update.byte_mask & (@as(u8, 1) << @intCast(byte)) == 0) {
                    if ((cell.value >> shift) & 255 != (update.value >> shift) & 255) return error.NoncanonicalMaskedUpdate;
                    continue;
                }
                if ((cell.permissions >> @intCast(byte * 3)) & 2 == 0) return error.RamWriteDenied;
            }
            cell.value = update.value;
        }
        var sides: std.ArrayList(Side) = .empty;
        errdefer sides.deinit(a);
        const roots = try fold(a, pages, &snapshot.zero, &.{}, snapshot, &sides, null, null);
        if (!ram.equal(roots.before, snapshot.root())) return error.RamBeforeRootMismatch;
        return .{ .allocator = a, .pages = pages, .sides = try sides.toOwnedSlice(a), .before = roots.before, .after = roots.after };
    }

    /// expected_before must be independently initialized or authenticated by
    /// the prior batch; expected_after comes from the receiver's next boundary.
    /// expected_pages must come from the batch's closed RAM access relation.
    pub fn verify(self: *const Witness, a: std.mem.Allocator, expected_before: ram.Digest, expected_after: ram.Digest, expected_pages: []const u64) !void {
        try self.validateOpenings(expected_pages);
        try self.verifyRoots(a, expected_before, expected_after);
    }

    fn verifyRoots(self: *const Witness, a: std.mem.Allocator, expected_before: ram.Digest, expected_after: ram.Digest) !void {
        const zero = try ram.defaults();
        const roots = try fold(a, self.pages, &zero, self.sides, null, null, null, null);
        if (!ram.equal(roots.before, expected_before) or !ram.equal(roots.before, self.before)) return error.RamBeforeRootMismatch;
        if (!ram.equal(roots.after, expected_after) or !ram.equal(roots.after, self.after)) return error.RamAfterRootMismatch;
    }

    pub fn validateOpenings(self: *const Witness, expected_pages: []const u64) !void {
        if (self.pages.len == 0 or self.pages.len != expected_pages.len) return error.InvalidRamOpeningCoverage;
        for (self.pages, expected_pages, 0..) |page, expected, i| {
            if (page.index != expected or expected >= @as(u64, 1) << ram.PAGE_DEPTH or (i > 0 and expected_pages[i - 1] >= expected))
                return error.InvalidRamOpeningCoverage;
            for (page.before, page.after) |before, after| {
                try before.validate();
                try after.validate();
                if (before.permissions != after.permissions) return error.RamPermissionMutation;
                for (0..8) |byte| {
                    const shift: u6 = @intCast(8 * byte);
                    if ((before.value >> shift) & 255 != (after.value >> shift) & 255 and
                        ((before.permissions >> @intCast(3 * byte)) & 2) == 0) return error.RamWriteDenied;
                }
            }
        }
    }

    /// Close the byte changes against independently supplied net updates, not
    /// merely a producer's page set. The future CPU/service RAM bus owns them.
    pub fn validateNetUpdates(self: *const Witness, updates: []const NetUpdate) !void {
        for (updates, 0..) |update, i| {
            if (update.address & 7 != 0 or update.byte_mask == 0 or (i > 0 and updates[i - 1].address >= update.address)) return error.NoncanonicalNetUpdates;
        }
        var at: usize = 0;
        for (self.pages) |page| {
            if (page.index >= @as(u64, 1) << ram.PAGE_DEPTH) return error.NoncanonicalTouchedPages;
            for (page.before, page.after, 0..) |before, after, cell_index| {
                const address = (page.index << ram.PAGE_BITS) | (@as(u64, @intCast(cell_index)) << 3);
                if (at < updates.len and updates[at].address < address) return error.UntouchedUpdatePage;
                if (at < updates.len and updates[at].address == address) {
                    const update = updates[at];
                    if (after.value != update.value) return error.RamNetUpdateMismatch;
                    for (0..8) |byte| {
                        const shift: u6 = @intCast(byte * 8);
                        if (update.byte_mask & (@as(u8, 1) << @intCast(byte)) == 0) {
                            if ((before.value >> shift) & 255 != (after.value >> shift) & 255) return error.NoncanonicalMaskedUpdate;
                        } else if ((before.permissions >> @intCast(byte * 3)) & 2 == 0) return error.RamWriteDenied;
                    }
                    at += 1;
                } else if (before.value != after.value) return error.UnexpectedRamNetUpdate;
            }
        }
        if (at != updates.len) return error.UntouchedUpdatePage;
    }

    pub fn verifyUpdates(self: *const Witness, a: std.mem.Allocator, expected_before: ram.Digest, expected_after: ram.Digest, expected_pages: []const u64, updates: []const NetUpdate) !void {
        try self.validateOpenings(expected_pages);
        try self.validateNetUpdates(updates);
        try self.verifyRoots(a, expected_before, expected_after);
    }

    /// Incremental native preparation: hashes only touched pages and the shared
    /// ancestor frontier, then publishes all cached node changes atomically.
    pub fn advance(self: *const Witness, a: std.mem.Allocator, snapshot: *ram.Snapshot, expected_pages: []const u64) !void {
        try self.validateOpenings(expected_pages);
        if (!ram.equal(self.before, snapshot.root())) return error.RamBeforeRootMismatch;
        var patches: std.ArrayList(ram.Patch) = .empty;
        defer patches.deinit(a);
        const roots = try fold(a, self.pages, &snapshot.zero, self.sides, null, null, null, &patches);
        if (!ram.equal(roots.before, self.before) or !ram.equal(roots.after, self.after)) return error.InvalidRamRecordedRoot;
        try snapshot.applyPatch(patches.items);
    }

    /// Full-I/O calls use the existing Poseidon STARK's atomic relation. This
    /// materializer is NOT a proof: the page absorption and multiproof graph
    /// caller AIR must still be integrated and balance these requests.
    pub fn recordHashCalls(self: *const Witness, a: std.mem.Allocator) !ram.Recorder {
        var recorder = ram.Recorder{ .allocator = a };
        errdefer recorder.deinit();
        const zero = try ram.defaults();
        const roots = try fold(a, self.pages, &zero, self.sides, null, null, &recorder, null);
        if (!ram.equal(roots.before, self.before) or !ram.equal(roots.after, self.after)) return error.InvalidRamRecordedRoot;
        return recorder;
    }

    /// Reconstruct the authenticated request bus from public output states.
    /// No witness-dependent permutation is executed here. The provider STARK
    /// must close the resulting full-I/O requests after this ledger is sealed.
    pub fn replayHashCalls(self: *const Witness, a: std.mem.Allocator, outputs: []const @import("../../../air/memory_commitment/poseidon2.zig").State) !ram.Recorder {
        var recorder = ram.Recorder{ .allocator = a, .replay = outputs };
        errdefer recorder.deinit();
        const zero = try ram.defaults();
        const roots = try fold(a, self.pages, &zero, self.sides, null, null, &recorder, null);
        if (recorder.replay_cursor != outputs.len) return error.TrailingRamHashLedger;
        if (!ram.equal(roots.before, self.before) or !ram.equal(roots.after, self.after)) return error.InvalidRamRecordedRoot;
        return recorder;
    }
};

const Roots = struct { before: ram.Digest, after: ram.Digest };

fn hashNode(height: u6, left: ram.Digest, right: ram.Digest, zero: *const [ram.PAGE_DEPTH + 1]ram.Digest, recorder: ?*ram.Recorder) !ram.Digest {
    if (ram.equal(left, zero[height]) and ram.equal(right, zero[height])) return zero[height + 1];
    return ram.hashRecorded(height, left, right, recorder);
}

fn fold(a: std.mem.Allocator, pages: []const Opening, zero: *const [ram.PAGE_DEPTH + 1]ram.Digest, proof: []const Side, snapshot: ?*const ram.Snapshot, output: ?*std.ArrayList(Side), recorder: ?*ram.Recorder, patches: ?*std.ArrayList(ram.Patch)) !Roots {
    if (pages.len == 0) return error.EmptyRamTransition;
    const frontier = try a.alloc(Pair, pages.len);
    defer a.free(frontier);
    for (pages, frontier) |*page, *entry| {
        const before = try ram.hashPage(&page.before, recorder);
        const after = if (std.meta.eql(page.before, page.after)) before else try ram.hashPage(&page.after, recorder);
        entry.* = .{ .index = page.index, .before = before, .after = after };
        if (patches) |out| try out.append(a, .{ .height = 0, .index = page.index, .before = before, .after = after });
    }
    var used = pages.len;
    var side_at: usize = 0;
    for (0..ram.PAGE_DEPTH) |height| {
        var read: usize = 0;
        var write: usize = 0;
        while (read < used) {
            const first = frontier[read];
            read += 1;
            var sibling: Pair = undefined;
            if (read < used and first.index & 1 == 0 and frontier[read].index == first.index + 1) {
                sibling = frontier[read];
                read += 1;
            } else {
                const sibling_index = first.index ^ 1;
                var digest: ram.Digest = undefined;
                if (snapshot) |tree| {
                    digest = ram.find(tree.pageSiblings(height), sibling_index) orelse zero[height];
                    try output.?.append(a, .{ .height = @intCast(height), .index = sibling_index, .digest = digest });
                } else {
                    if (side_at >= proof.len or proof[side_at].height != height or proof[side_at].index != sibling_index)
                        return error.NoncanonicalRamMultiproof;
                    digest = proof[side_at].digest;
                    for (digest) |word| if (word >= @import("stwo_core").fields.m31.Modulus) return error.NonCanonicalDigest;
                    side_at += 1;
                }
                sibling = .{ .index = sibling_index, .before = digest, .after = digest };
            }
            const left = if (first.index & 1 == 0) first else sibling;
            const right = if (first.index & 1 == 0) sibling else first;
            const before = try hashNode(@intCast(height), left.before, right.before, zero, recorder);
            const after = if (ram.equal(left.before, left.after) and ram.equal(right.before, right.after)) before else try hashNode(@intCast(height), left.after, right.after, zero, recorder);
            frontier[write] = .{ .index = first.index >> 1, .before = before, .after = after };
            if (patches) |out| try out.append(a, .{ .height = @intCast(height + 1), .index = first.index >> 1, .before = before, .after = after });
            write += 1;
        }
        used = write;
    }
    if (snapshot == null and side_at != proof.len) return error.NoncanonicalRamMultiproof;
    if (used != 1 or frontier[0].index != 0) return error.InvalidRamRootGeometry;
    return .{ .before = frontier[0].before, .after = frontier[0].after };
}
