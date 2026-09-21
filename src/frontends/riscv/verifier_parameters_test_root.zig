//! Focused fixed-parameter ABI regression, independent of witness construction.
const std = @import("std");
const parameters = @import("recursion/air/verifier_component_parameters.zig");
const profile = @import("recursion/air/query_bits_profile.zig");
const ProofKind = @import("recursion/air/proof_kind.zig").ProofKind;

test "verifier parameters preserve all branch protocol words" {
    const vm = profile.LaneProfile{ .query_count = 2, .lifting_log_size = 12, .trace_tree_count = 4, .fri_layer_count = 2 };
    var recursive = vm;
    recursive.lifting_log_size = 10;
    const reference = try profile.Reference.seal(vm, recursive);
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    inline for (.{ ProofKind.segment_leaf, ProofKind.binary_node, ProofKind.empty_leaf }) |kind| {
        inline for (.{ parameters.vmInputParameters(kind), parameters.merkleRootParameters(kind), parameters.traceMerkleParameters(kind), parameters.friLeafParameters(kind), parameters.friAnchorParameters(kind), try parameters.queryBitsParameters(reference, kind), parameters.queryMappingParameters(kind), parameters.controlParameters(kind), parameters.inputParameters(kind), parameters.pcsParameters(kind) }) |words| {
            for (words) |word| {
                var bytes: [4]u8 = undefined;
                std.mem.writeInt(u32, &bytes, word.toU32(), .little);
                hash.update(&bytes);
            }
        }
    }
    var expected: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected, "45d94b24b6a6dcb00003274ac45727c99def2c3b9a9ea3b2e3d4772f50b63d51");
    try std.testing.expectEqualSlices(u8, &expected, &hash.finalResult());
}
