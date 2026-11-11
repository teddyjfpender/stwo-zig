//! Generic FRI pending-tree scheduler tests.

const std = @import("std");
const CpuBackend = @import("stwo_cpu_backend").CpuBackend;
const core_fri = @import("stwo_core").fri;
const m31 = @import("stwo_core").fields.m31;
const qm31 = @import("stwo_core").fields.qm31;
const canonic = @import("stwo_core").poly.circle.canonic;
const fri = @import("stwo_prover_engine").fri;
const prover_line = @import("stwo_prover_engine").line;
const secure_column = @import("stwo_prover_engine").secure_column;

const M31 = m31.M31;
const QM31 = qm31.QM31;

var fold_tree_calls: usize = 0;

const FoldTreeTestBackend = struct {
    pub fn MerkleTree(comptime H: type) type {
        return CpuBackend.MerkleTree(H);
    }

    pub fn commitMerkle(
        comptime H: type,
        allocator: std.mem.Allocator,
        columns: []const []const M31,
    ) !MerkleTree(H) {
        return CpuBackend.commitMerkle(H, allocator, columns);
    }

    pub fn foldCircleIntoLine(
        allocator: std.mem.Allocator,
        dst: []QM31,
        src_columns: [qm31.SECURE_EXTENSION_DEGREE][]const M31,
        src_domain: anytype,
        alpha: QM31,
        workspace: *core_fri.FoldCircleWorkspace,
    ) !void {
        return CpuBackend.foldCircleIntoLine(
            allocator,
            dst,
            src_columns,
            src_domain,
            alpha,
            workspace,
        );
    }

    pub fn foldLineN(
        allocator: std.mem.Allocator,
        evaluation: []QM31,
        domain: anytype,
        alpha: QM31,
        workspace: *core_fri.FoldLineWorkspace,
        n_folds: u32,
    ) !core_fri.FoldLineResult {
        return CpuBackend.foldLineN(
            allocator,
            evaluation,
            domain,
            alpha,
            workspace,
            n_folds,
        );
    }

    pub fn foldLineAndCommitNext(
        comptime H: type,
        allocator: std.mem.Allocator,
        evaluation: prover_line.LineEvaluation,
        alpha: QM31,
        workspace: *core_fri.FoldLineWorkspace,
        n_folds: u32,
    ) !fri.FoldLineAndCommitResult(MerkleTree(H)) {
        fold_tree_calls += 1;
        const folded = try core_fri.foldLineNWithWorkspace(
            allocator,
            evaluation.values,
            evaluation.domain(),
            alpha,
            workspace,
            n_folds,
        );
        errdefer allocator.free(folded.values);

        var coords = try secure_column.SecureColumnByCoords.fromSecureSlice(
            allocator,
            folded.values,
        );
        errdefer coords.deinit(allocator);
        const columns = [_][]const M31{
            coords.columns[0],
            coords.columns[1],
            coords.columns[2],
            coords.columns[3],
        };
        var tree = try CpuBackend.commitMerkle(H, allocator, columns[0..]);
        errdefer tree.deinit(allocator);
        return .{
            .evaluation = try prover_line.LineEvaluation.initOwned(folded.domain, folded.values),
            .column = coords,
            .tree = tree,
        };
    }
};

test "prover fri: pending tree hook preserves commitments and proof" {
    const Hasher = @import("stwo_core").vcs_lifted.blake2_merkle.Blake2sMerkleHasher;
    const MerkleChannel = @import("stwo_core").vcs_lifted.blake2_merkle.Blake2sMerkleChannel;
    const Channel = @import("stwo_core").channel.blake2s.Blake2sChannel;
    const FallbackProver = fri.FriProver(CpuBackend, Hasher, MerkleChannel);
    const HookProver = fri.FriProver(FoldTreeTestBackend, Hasher, MerkleChannel);
    const allocator = std.testing.allocator;

    const config = try core_fri.FriConfig.init(0, 1, 4);
    const domain = canonic.CanonicCoset.new(7).circleDomain();
    const values = try allocator.alloc(QM31, domain.size());
    defer allocator.free(values);
    @memset(values, QM31.fromU32Unchecked(7, 0, 0, 0));

    const fallback_column = try secure_column.SecureColumnByCoords.fromSecureSlice(allocator, values);
    const hook_column = try secure_column.SecureColumnByCoords.fromSecureSlice(allocator, values);
    var fallback_channel = Channel{};
    var hook_channel = Channel{};
    var fallback_prover = try FallbackProver.commit(
        allocator,
        &fallback_channel,
        config,
        domain,
        fallback_column,
    );
    fold_tree_calls = 0;
    var hook_prover = try HookProver.commit(
        allocator,
        &hook_channel,
        config,
        domain,
        hook_column,
    );

    try std.testing.expectEqual(@as(usize, 4), fold_tree_calls);
    try std.testing.expectEqualSlices(
        u8,
        fallback_channel.digestBytes()[0..],
        hook_channel.digestBytes()[0..],
    );

    var fallback_result = try fallback_prover.decommit(allocator, &fallback_channel);
    defer fallback_result.deinit(allocator);
    var hook_result = try hook_prover.decommit(allocator, &hook_channel);
    defer hook_result.deinit(allocator);
    try std.testing.expectEqualDeep(fallback_result, hook_result);
}
