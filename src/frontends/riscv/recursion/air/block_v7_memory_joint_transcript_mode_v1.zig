//! Exact v7 shared epoch draw and joint-original transcript. Only its actual
//! Word52 + interval pair is traversed; compatibility byte draws are a separate
//! native channel and never influence the original proof channel.
//! Finite protocol variants share implementation; window mode is a distinct key.
pub fn ForMode(comptime window: bool) type {
    return struct {
        const std = @import("std");
        const core = @import("stwo_core");
        const Profile = @import("../block_v7_memory_joint_fixed_profile_v1.zig").ForMode(window);
        const Joint = if (window) @import("../../prover/block_v7_window_memory_joint_v1.zig") else @import("../../prover/block_v7_memory_joint_proof_v1.zig");
        const Protocol = if (window) @import("../../prover/block_v7_window_memory_joint_protocol_v1.zig") else @import("../../prover/block_v7_memory_joint_protocol_v1.zig");
        const E = @import("../../prover/block_v7_execution_epoch_v1.zig");
        const Word = @import("../../prover/block_v5_word_memory_protocol_v1.zig");
        const Universal = @import("universal_challenges.zig");
        const Statement = @import("block_v7_memory_joint_statement_v1.zig").ForMode(window);
        const Recorder = @import("blake3_native_recorder.zig");
        const Sink = @import("blake3_fixed_operation_recorder_v1.zig");
        const Shared = @import("blake3_native_transcript.zig");
        pub const RELATION_PAIRS: usize = 53;
        fn begin(r: anytype, profile: *const Profile.Owned, statement: *const Statement.Statement) !void {
            r.mixU32s(&.{ profile.input.epoch.sharedTag(), E.VERSION, 2 });
            r.mixPublicRoot(.{ .circuit = Statement.PUBLIC_CIRCUIT, .first_wire = statement.sealed_offset }, profile.input.epoch.digest);
            try r.skipCommittedRoots(2);
        }
        pub fn prefixFixed(a: std.mem.Allocator, r: *Sink.Recorder, profile: *const Profile.Owned, statement: *const Statement.Statement) !void {
            try begin(r, profile, statement);
            try @import("block_v7_epoch_transcript_v1.zig").fixed(a, r);
            try statement.recordAt(r, statement.claims, Statement.PUBLIC_CIRCUIT);
        }
        pub fn prefix(a: std.mem.Allocator, r: *Recorder.Recorder, profile: *const Profile.Owned, statement: *const Statement.Statement) !void {
            if (!r.universal_relations or r.root_count != 0 or r.relation_count != 0) return error.InvalidJointMemoryTranscript;
            try begin(r, profile, statement);
            try @import("block_v7_epoch_transcript_v1.zig").live(a, r);
            try statement.recordAt(r, statement.claims, Statement.PUBLIC_CIRCUIT);
            try r.check();
            if (r.relation_count != RELATION_PAIRS or r.root_count != 2) return error.InvalidJointMemoryTranscript;
            const drawn = try profile.input.epoch.draw(a);
            const pin = try Protocol.entry(profile.input.policy, &profile.layout, profile.input.roots);
            const expected = try Protocol.proofChannel(drawn, pin, &profile.layout, profile.input.claims);
            if (!std.meta.eql(expected, r.native)) return error.InvalidJointMemoryTranscript;
        }
        pub fn planReplay(a: std.mem.Allocator, profile: *const Profile.Owned, capture: *const Joint.VerifiedCapture, capacity: u32) !Shared.Planned {
            if (capacity == 0 or capture.proof.commitments.len != 4 or !std.meta.eql(capture.roots, profile.input.roots) or !std.meta.eql(capture.interval, profile.input.claims.interval) or !std.meta.eql(capture.range16, profile.input.claims.range16) or capture.ram.len != profile.input.claims.ram.len or capture.interval_log != profile.input.interval_log) return error.InvalidJointMemoryTranscript;
            if (!window and !std.meta.eql(capture.terminal, profile.input.claims.terminal)) return error.InvalidJointMemoryTranscript;
            for (capture.ram, profile.input.claims.ram) |got, want| if (!std.meta.eql(got, want)) return error.InvalidJointMemoryTranscript;
            var arena = std.heap.ArenaAllocator.init(a);
            var owned = true;
            defer if (owned) arena.deinit();
            const temp = arena.allocator();
            var statement = try Statement.init(temp, profile);
            // The completed replay owns this arena, including statement storage.
            defer if (owned) statement.deinit();
            var r = Recorder.Recorder{ .a = temp, .universal_relations = true };
            try prefix(temp, &r, profile, &statement);
            r.mixRoot(capture.proof.commitments[2]);
            try r.check();
            var result = try Shared.finishReplay(a, &arena, &r, &capture.proof, profile.config, capacity);
            owned = false;
            errdefer result.deinit();
            if (!std.meta.eql(result.end, capture.final_channel)) return error.InvalidJointMemoryTranscript;
            return result;
        }
    };
}
