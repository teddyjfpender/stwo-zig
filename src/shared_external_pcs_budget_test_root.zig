//! Device-free actual PCS tree/backing teardown, with a local resource-only
//! backend. This backend cannot make a proof or a Merkle commitment.
const std = @import("std");
const core = @import("stwo_core");
const prover = @import("stwo_prover_engine");
const Budget = prover.host_budget_allocator.SharedHostBudget;
const M = core.fields.m31.M31;
const H = core.vcs_lifted.blake2_merkle.Blake2sMerkleHasher;
const State = struct { released: usize = 0, heap_at_release: usize = 0 };
const ResourceBackend = struct {
    pub fn MerkleTree(comptime Hasher: type) type {
        return struct {
            reservation: Budget.ExternalReservation,
            state: *State,
            pub fn deinit(self: *@This(), _: std.mem.Allocator) void {
                self.state.heap_at_release = self.reservation.owner.?.snapshot().host_live_bytes;
                self.state.released += 1;
                self.reservation.deinit();
            }
            pub fn root(_: @This()) Hasher.Hash {
                return std.mem.zeroes(Hasher.Hash);
            }
            pub fn maxLogSize(_: @This()) u32 {
                return 2;
            }
            pub fn decommit() void {
                unreachable; // Resource fixture has no proof authority.
            }
            pub fn readHashes() void {
                unreachable;
            }
        };
    }
    pub fn commitMerkle(comptime Hasher: type, _: std.mem.Allocator, _: []const []const M) !MerkleTree(Hasher) {
        return error.ResourceFixtureCannotCommit;
    }
};
const Tree = prover.pcs.CommitmentTreeProverForBackend(ResourceBackend, H);
fn make(owner: *Budget, state: *State) !Tree {
    const a = owner.allocator();
    const values = try a.alloc(M, 4);
    errdefer a.free(values);
    @memset(values, M.zero());
    const columns = try a.alloc(prover.pcs.ColumnEvaluation, 1);
    errdefer a.free(columns);
    columns[0] = .{ .log_size = 2, .values = values };
    var reservation = try owner.reserveExternal(64);
    defer reservation.deinit();
    return Tree.initPrecommitted(columns, null, null, null, .{ .reservation = reservation.take(), .state = state });
}
fn rejectOwned(tree: *Tree, a: std.mem.Allocator) !void {
    defer tree.deinit(a);
    return error.RejectedPublication;
}
test "shared external PCS: final device token drops before backing with original root released" {
    for ([_]bool{ false, true }) |shared| {
        const owner = try Budget.create(std.testing.allocator, 1 << 20);
        var root_owned = true;
        defer if (root_owned) owner.destroy();
        var state = State{};
        var tree = try make(owner, &state);
        const a = owner.allocator();
        var tree_owned = true;
        defer if (tree_owned) tree.deinit(a);
        if (shared) try tree.share(a);
        owner.destroy();
        root_owned = false;
        tree_owned = false;
        tree.deinit(a);
        try std.testing.expectEqual(@as(usize, 1), state.released);
        try std.testing.expect(state.heap_at_release > 0);
    }
}
test "shared external PCS: failed publication joins final shared owner backing teardown" {
    const owner = try Budget.create(std.testing.allocator, 1 << 20);
    var root_owned = true;
    defer if (root_owned) owner.destroy();
    var state = State{};
    var tree = try make(owner, &state);
    const a = owner.allocator();
    var tree_owned = true;
    defer if (tree_owned) tree.deinit(a);
    try tree.share(a);
    var lease = tree.retainShared();
    var lease_owned = true;
    defer if (lease_owned) lease.deinit(a);
    owner.destroy();
    root_owned = false;
    tree_owned = false;
    tree.deinit(a);
    try std.testing.expectEqual(@as(usize, 0), state.released);
    lease_owned = false;
    try std.testing.expectError(error.RejectedPublication, rejectOwned(&lease, a));
    try std.testing.expectEqual(@as(usize, 1), state.released);
    try std.testing.expect(state.heap_at_release > 0);
}
