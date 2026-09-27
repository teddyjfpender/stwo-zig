//! Shared caller-admitted extension assembly for recursive geometry.
pub fn ForProfile(comptime Profile: type) type {
    return struct {
        const std = @import("std");
        const core = @import("stwo_core");
        const Joined = @import("../../prover/blake3_execution_components.zig").Owner;
        const Assembly = Profile.Assembly(.verifier);
        const Relations = Profile.Relations;
        const Owner = @This();
        allocator: std.mem.Allocator,
        joined: *Joined,
        assembly: *Assembly,
        relations: Relations,
        pub fn init(a: std.mem.Allocator, admitted: anytype, capture: anytype, expected: [32]u8) !*Owner {
            try capture.validate(admitted, expected);
            const self = try a.create(Owner);
            errdefer a.destroy(self);
            self.allocator = a;
            const shared = try @import("universal_provider_relations.zig").SharedProviderRelations.init(&capture.relations);
            self.relations = try Relations.fromDraws(shared.native, &capture.extension_draws);
            self.joined = try Joined.initWithExternal(a, &admitted.native, capture.native_claims, capture.relations, admitted.admission(), Profile.externalCount(&admitted.extension));
            errdefer self.joined.deinit();
            if (admitted.range_components) |ranges| try self.joined.bindCompactCommitments(admitted.hashes.?, capture.hash_claims, ranges, capture.compact_claims) else try self.joined.bindCommitments(admitted.hashes.?, capture.hash_claims);
            var prefix: std.ArrayList(core.air.components.Component) = .empty;
            defer prefix.deinit(a);
            try prefix.appendSlice(a, self.joined.verifying.components.active());
            try prefix.appendSlice(a, &(try admitted.hashes.?.verifiers()));
            self.assembly = try Assembly.createBlake3WithRanges(a, &admitted.native, &admitted.extension, admitted.admission(), admitted.hashes.?.logs, &self.relations, prefix.items, &capture.extension_claims, admitted.ranges);
            errdefer self.assembly.destroy(a);
            if (!std.meta.eql(self.assembly.extensionPlacements(), capture.extension_placements)) return error.InvalidExecutionCapture;
            return self;
        }
        pub fn deinit(self: *Owner) void {
            self.assembly.destroy(self.allocator);
            self.joined.deinit();
            self.allocator.destroy(self);
        }
    };
}
