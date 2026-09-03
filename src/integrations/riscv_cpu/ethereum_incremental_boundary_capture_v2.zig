//! Process-local capture owner for ordered incremental-memory transports.
//!
//! The complete sparse tree is built exactly once from the first segment's
//! authenticated entry snapshot.  Later calls open only replay-touched words
//! plus the first/final public-boundary words required by the typed statement.
//! The returned V1 authority remains transport-only; a role-aware native AIR
//! must cold-validate and constrain it before proof or recursion admission.

const std = @import("std");
const frontend = @import("stwo_riscv_frontend");

const authority_mod = @import("ethereum_incremental_boundary_authority_v1.zig");
const memory_state = frontend.runner.memory_state;

pub const SCHEMA = "stwo.ethereum.incremental-boundary-capture.v2";
pub const PRODUCTION_ACTIVE = false;
pub const RECURSIVE_ADMISSIBLE = false;

pub const SessionCaptureV2 = struct {
    allocator: std.mem.Allocator,
    session_identity: [32]u8,
    tree: authority_mod.SessionTree,
    poisoned: bool = false,

    pub fn init(
        allocator: std.mem.Allocator,
        session_identity: [32]u8,
        first_segment_index: u32,
        first_snapshot: *const memory_state.Snapshot,
        expected_entry_root: u32,
    ) !SessionCaptureV2 {
        try validateSnapshotWords(first_snapshot.words);
        var initial: std.ArrayList(authority_mod.SparseWordV1) = .empty;
        defer initial.deinit(allocator);
        try initial.ensureTotalCapacity(allocator, first_snapshot.words.len);
        for (first_snapshot.words) |word| {
            if (word.initial_word == 0) continue;
            initial.appendAssumeCapacity(.{
                .address = word.addr,
                .value = word.initial_word,
            });
        }
        return .{
            .allocator = allocator,
            .session_identity = session_identity,
            .tree = try authority_mod.SessionTree.init(
                allocator,
                session_identity,
                first_segment_index,
                initial.items,
                expected_entry_root,
            ),
        };
    }

    pub fn deinit(self: *SessionCaptureV2) void {
        self.tree.deinit();
        self.* = undefined;
    }

    pub fn currentRoot(self: *const SessionCaptureV2) u32 {
        return self.tree.currentRoot();
    }

    pub fn sessionIdentity(self: *const SessionCaptureV2) [32]u8 {
        return self.session_identity;
    }

    pub fn nextSegmentIndex(self: *const SessionCaptureV2) u32 {
        return self.tree.nextSegmentIndex();
    }

    pub fn priorAuthorityId(self: *const SessionCaptureV2) [32]u8 {
        return self.tree.priorAuthorityId();
    }

    /// Capture one ordered transition from the exact live snapshot.
    ///
    /// `replay_touched_addresses` is a canonical sorted set obtained from the
    /// typed retirement/precompile observer.  Public-role addresses are added
    /// here as a capture convenience so the future role-aware AIR can bind its
    /// public boundary tuples to Merkle membership.  The flags themselves are
    /// not proof authority and must be recomputed by that AIR's admission.
    pub fn apply(
        self: *SessionCaptureV2,
        segment_index: u32,
        snapshot: *const memory_state.Snapshot,
        replay_touched_addresses: []const u32,
        expected_entry_root: u32,
        expected_exit_root: u32,
    ) !authority_mod.IncrementalBoundaryAuthorityV1 {
        if (self.poisoned) return error.IncrementalCaptureSessionPoisoned;
        if (segment_index != self.tree.nextSegmentIndex())
            return error.SegmentIndexMismatch;
        if (expected_entry_root != self.tree.currentRoot())
            return error.EntryRootMismatch;
        try validateSnapshotWords(snapshot.words);
        try validateAddressSet(replay_touched_addresses);

        var addresses: std.ArrayList(u32) = .empty;
        defer addresses.deinit(self.allocator);
        try addresses.ensureTotalCapacity(
            self.allocator,
            replay_touched_addresses.len + snapshot.words.len,
        );
        addresses.appendSliceAssumeCapacity(replay_touched_addresses);
        for (snapshot.words) |word| {
            if (hasPublicRole(word.role)) addresses.appendAssumeCapacity(word.addr);
        }
        std.mem.sort(u32, addresses.items, {}, lessThan);
        deduplicateSorted(&addresses);

        const touched = try self.allocator.alloc(
            authority_mod.TouchedWordV1,
            addresses.items.len,
        );
        defer self.allocator.free(touched);
        var word_index: usize = 0;
        for (addresses.items, touched) |address, *destination| {
            while (word_index < snapshot.words.len and
                snapshot.words[word_index].addr < address)
            {
                word_index += 1;
            }
            if (word_index == snapshot.words.len or
                snapshot.words[word_index].addr != address)
            {
                return error.MissingIncrementalBoundaryWord;
            }
            const word = snapshot.words[word_index];
            destination.* = .{
                .address = word.addr,
                .old_word = word.initial_word,
                .new_word = word.final_word,
                .final_clock = word.final_clock,
            };
        }

        var authority = self.tree.apply(segment_index, touched) catch |err| {
            self.poisoned = true;
            return err;
        };
        errdefer authority.deinit();
        if (authority.entry_root != expected_entry_root or
            authority.exit_root != expected_exit_root)
        {
            self.poisoned = true;
            return error.IncrementalCaptureRootMismatch;
        }
        return authority;
    }
};

fn validateSnapshotWords(words: []const memory_state.WordState) !void {
    var previous: ?u32 = null;
    for (words) |word| {
        if ((word.addr & 3) != 0 or
            word.addr > authority_mod.MAX_ADDRESS_EXCLUSIVE - 4)
        {
            return error.InvalidIncrementalBoundaryAddress;
        }
        if (previous) |address| {
            if (word.addr <= address)
                return error.NonCanonicalIncrementalBoundaryOrder;
        }
        previous = word.addr;
    }
}

fn validateAddressSet(addresses: []const u32) !void {
    var previous: ?u32 = null;
    for (addresses) |address| {
        if ((address & 3) != 0 or
            address > authority_mod.MAX_ADDRESS_EXCLUSIVE - 4)
        {
            return error.InvalidIncrementalBoundaryAddress;
        }
        if (previous) |prior| {
            if (address <= prior)
                return error.NonCanonicalIncrementalBoundaryOrder;
        }
        previous = address;
    }
}

fn hasPublicRole(role: memory_state.WordRole) bool {
    return role.is_public_input or
        role.is_public_output or
        role.is_public_completion;
}

fn lessThan(_: void, left: u32, right: u32) bool {
    return left < right;
}

fn deduplicateSorted(addresses: *std.ArrayList(u32)) void {
    if (addresses.items.len < 2) return;
    var write: usize = 1;
    for (addresses.items[1..]) |address| {
        if (address == addresses.items[write - 1]) continue;
        addresses.items[write] = address;
        write += 1;
    }
    addresses.shrinkRetainingCapacity(write);
}

test "incremental capture opens replay and public-role words once" {
    const allocator = std.testing.allocator;
    const words = [_]memory_state.WordState{
        .{
            .addr = 0x1000,
            .initial_word = 0x0102_0304,
            .final_word = 0x0506_0708,
            .final_clock = 9,
        },
        .{
            .addr = 0x2000,
            .initial_word = 0x1112_1314,
            .final_word = 0x1112_1314,
            .final_clock = 0,
            .role = .{ .is_public_input = true },
        },
    };
    const entry_words = [_]authority_mod.SparseWordV1{
        .{ .address = words[0].addr, .value = words[0].initial_word },
        .{ .address = words[1].addr, .value = words[1].initial_word },
    };
    const exit_words = [_]authority_mod.SparseWordV1{
        .{ .address = words[0].addr, .value = words[0].final_word },
        .{ .address = words[1].addr, .value = words[1].final_word },
    };
    const entry_root = try testing.fullRoot(allocator, &entry_words);
    const exit_root = try testing.fullRoot(allocator, &exit_words);
    var capture = try SessionCaptureV2.init(
        allocator,
        [_]u8{0x71} ** 32,
        0,
        &snapshotFixture(&words, .{ .is_first = true, .is_last = false }),
        entry_root,
    );
    defer capture.deinit();
    var authority = try capture.apply(
        0,
        &snapshotFixture(&words, .{ .is_first = true, .is_last = false }),
        &.{0x1000},
        entry_root,
        exit_root,
    );
    defer authority.deinit();
    try std.testing.expectEqual(@as(usize, 2), authority.touched_words.len);
    try std.testing.expectEqual(@as(u32, 0x1000), authority.touched_words[0].address);
    try std.testing.expectEqual(@as(u32, 0x2000), authority.touched_words[1].address);
    try std.testing.expectEqual(exit_root, capture.currentRoot());
    try std.testing.expect(!PRODUCTION_ACTIVE);
    try std.testing.expect(!RECURSIVE_ADMISSIBLE);
}

test "incremental capture poisons incomplete changed inventory" {
    const allocator = std.testing.allocator;
    const words = [_]memory_state.WordState{.{
        .addr = 0x3000,
        .initial_word = 5,
        .final_word = 6,
        .final_clock = 1,
    }};
    const entry_words = [_]authority_mod.SparseWordV1{.{
        .address = words[0].addr,
        .value = words[0].initial_word,
    }};
    const exit_words = [_]authority_mod.SparseWordV1{.{
        .address = words[0].addr,
        .value = words[0].final_word,
    }};
    const entry_root = try testing.fullRoot(allocator, &entry_words);
    const exit_root = try testing.fullRoot(allocator, &exit_words);
    var capture = try SessionCaptureV2.init(
        allocator,
        [_]u8{0x72} ** 32,
        4,
        &snapshotFixture(&words, .{ .is_first = false, .is_last = false }),
        entry_root,
    );
    defer capture.deinit();
    try std.testing.expectError(
        error.IncrementalCaptureRootMismatch,
        capture.apply(
            4,
            &snapshotFixture(&words, .{ .is_first = false, .is_last = false }),
            &.{},
            entry_root,
            exit_root,
        ),
    );
    try std.testing.expectError(
        error.IncrementalCaptureSessionPoisoned,
        capture.apply(
            5,
            &snapshotFixture(&words, .{ .is_first = false, .is_last = false }),
            &.{0x3000},
            entry_root,
            exit_root,
        ),
    );
}

fn snapshotFixture(
    words: []const memory_state.WordState,
    role: memory_state.SegmentRole,
) memory_state.Snapshot {
    return .{
        .layout = std.mem.zeroes(memory_state.MemoryLayout),
        .segment_role = role,
        .words = @constCast(words),
    };
}

pub const testing = struct {
    pub fn fullRoot(
        allocator: std.mem.Allocator,
        words: []const authority_mod.SparseWordV1,
    ) !u32 {
        const sparse_merkle = frontend.air.memory_commitment.sparse_merkle;
        var leaves: std.ArrayList(sparse_merkle.Leaf) = .empty;
        defer leaves.deinit(allocator);
        try leaves.ensureTotalCapacity(allocator, words.len * 4);
        for (words) |word| for (0..4) |limb| {
            const shift: u5 = @intCast(limb * 8);
            const value: u8 = @truncate(word.value >> shift);
            if (value != 0) leaves.appendAssumeCapacity(.{
                .index = word.address + @as(u32, @intCast(limb)),
                .value = value,
            });
        };
        var tree = try sparse_merkle.build(allocator, leaves.items);
        defer tree.deinit(allocator);
        return tree.root;
    }
};
