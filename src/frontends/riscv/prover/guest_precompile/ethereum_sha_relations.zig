//! One extension draw order for Ethereum and SHA, sharing native VM buses.
const std = @import("std");
const core = @import("stwo_core");
const universal = @import("../../recursion/air/universal_challenges.zig");
const providers = @import("../../recursion/air/universal_provider_relations.zig");
const ethereum = @import("ethereum_transcript.zig");
const sha = @import("../../air/guest_precompile/sha256_relations.zig");
pub const draw_count = 26 + sha.draw_count;
pub const Relations = struct {
    pub const fromVmDraws = fromDraws;
    ethereum: ethereum.Relations,
    sha: universal.UniversalRelations,

    /// Draw only after the complete main commitment and shared VM challenges.
    pub fn drawAfterVm(a: std.mem.Allocator, channel: anytype, vm: universal.UniversalRelations) !Relations {
        const shared = try providers.SharedProviderRelations.init(&vm);
        const eth = try ethereum.Relations.drawAfterBase(a, channel, shared.native);
        return .{ .ethereum = eth, .sha = try sha.draw(a, channel, vm) };
    }

    /// Replay captured draws in exactly the same extension order. Transcript
    /// replay still owns the SHAW frame between the Ethereum and SHA draws.
    pub fn fromDraws(vm: universal.UniversalRelations, values: []const core.fields.qm31.QM31) !Relations {
        if (values.len != draw_count) return error.InvalidChallengeDraw;
        const shared = try providers.SharedProviderRelations.init(&vm);
        return .{
            .ethereum = try ethereum.Relations.fromDraws(shared.native, values[0..26]),
            .sha = try sha.fromDraws(vm, values[26..][0..sha.draw_count].*),
        };
    }

    pub fn draws(self: *const Relations) [draw_count]core.fields.qm31.QM31 {
        const wire = self.sha.get(.recursion_wire);
        return self.ethereum.draws() ++ .{ wire.z, wire.alpha };
    }
};

test "SHA provider combined relations preserve shared VM buses and replay all extension draws" {
    const a = std.testing.allocator;
    var channel = core.proof_suites.Blake3.Channel{};
    const vm = try universal.UniversalRelations.draw(a, &channel);
    var verifier = channel;
    const actual = try Relations.drawAfterVm(a, &channel, vm);
    const expected = try Relations.drawAfterVm(a, &verifier, vm);
    try std.testing.expect(std.meta.eql(actual, expected));
    const captured = actual.draws();
    try std.testing.expect(std.meta.eql(actual, try Relations.fromDraws(vm, &captured)));
    try std.testing.expectError(error.InvalidChallengeDraw, Relations.fromDraws(vm, captured[0..27]));
    const sha_shared = try providers.SharedProviderRelations.init(&actual.sha);
    try std.testing.expect(std.meta.eql(actual.ethereum.base, sha_shared.native));
    try std.testing.expect(!std.meta.eql(vm.get(.recursion_wire), actual.sha.get(.recursion_wire)));
    try std.testing.expectEqualDeep(channel.digestBytes(), verifier.digestBytes());
}
