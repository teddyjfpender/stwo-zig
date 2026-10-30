//! Actual v7 epoch followed by caller suffix and all physical claims. The
//! exported order preserves original arithmetic/word circuit ports; actual
//! consumption order is Universal47, Word5, two single interval draws, then14.
//! Shared implementation: default and finite active caller families.
pub fn For(comptime Policy: type) type {
    return struct {
        const std = @import("std");
        const core = @import("stwo_core");
        const E = @import("../../prover/block_v7_execution_epoch_v1.zig");
        const Source = Policy.Source;
        const Admission = Policy.Admission;
        const Capture = Policy.Capture;
        const Profile = @import("../../prover/blake3_ethereum_sha_profile.zig");
        const Word = @import("../../prover/block_v5_word_memory_protocol_v1.zig");
        const Universal = @import("universal_challenges.zig");
        const Statement = Policy.Statement;
        const Recorder = @import("blake3_native_recorder.zig");
        const Fixed = @import("blake3_fixed_operation_recorder_v1.zig");
        const EpochDraw = @import("block_v7_epoch_transcript_v1.zig");
        const Shared = @import("blake3_native_transcript.zig");
        pub const RELATION_COUNT: usize = 67;
        fn begin(r: anytype, admitted: *const Admission.Prepared, statement: *const Statement.Statement) !void {
            r.mixU32s(&.{ admitted.epoch.sharedTag(), E.VERSION, 2 });
            r.mixPublicRoot(.{ .circuit = Statement.PUBLIC_CIRCUIT, .first_wire = statement.sealed_offset }, admitted.epoch.digest);
            try r.skipCommittedRoots(3);
        }
        pub fn prefixFixed(a: std.mem.Allocator, r: *Fixed.Recorder, admitted: *const Admission.Prepared, statement: *const Statement.Statement) !void {
            try begin(r, admitted, statement);
            try Word.Challenges.drawWith(a, r, FixedWord);
            try EpochDraw.intervalFixed(r, 66);
            try statement.recordAt(r, statement.first, Statement.PUBLIC_CIRCUIT);
            try r.universalPairs(47, 13);
            r.mixU32s(&.{ 0x53484157, 1 });
            try r.universalPairs(60, 1);
            try statement.recordAt(r, statement.claims, Statement.PUBLIC_CIRCUIT);
            try r.check();
        }
        const FixedWord = struct {
            pub const Output = void;
            pub fn universal(_: std.mem.Allocator, r: *Fixed.Recorder) !void {
                try Universal.requireDrawSchema();
                try r.universalPairs(0, Universal.RELATION_COUNT);
            }
            pub fn extra(_: std.mem.Allocator, r: *Fixed.Recorder, _: void) !void {
                try r.universalPairs(61, 5);
            }
        };
        const LiveWord = struct {
            pub const Output = Universal.UniversalRelations;
            pub fn universal(a: std.mem.Allocator, r: *Recorder.Recorder) !Universal.UniversalRelations {
                return Universal.UniversalRelations.draw(a, r);
            }
            pub fn extra(a: std.mem.Allocator, r: *Recorder.Recorder, initial: Universal.UniversalRelations) !Universal.UniversalRelations {
                if (r.relation_count != 47) return error.InvalidV7CallerTranscript;
                r.relation_count = 61;
                const values = try r.drawSecureFelts(a, 10);
                defer a.free(values);
                return initial;
            }
        };
        pub fn prefix(a: std.mem.Allocator, r: *Recorder.Recorder, admitted: *const Admission.Prepared, statement: *const Statement.Statement) !void {
            if (r.root_count != 0 or r.relation_count != 0 or !r.universal_relations) return error.InvalidV7CallerTranscript;
            try begin(r, admitted, statement);
            const universal = try Word.Challenges.drawWith(a, r, LiveWord);
            try EpochDraw.intervalLive(r, 66);
            try statement.recordAt(r, statement.first, Statement.PUBLIC_CIRCUIT);
            r.relation_count = 47;
            _ = try Profile.Relations.drawAfterVm(a, r, universal);
            if (r.relation_count != 61) return error.InvalidV7CallerTranscript;
            r.relation_count = RELATION_COUNT;
            try statement.recordAt(r, statement.claims, Statement.PUBLIC_CIRCUIT);
            try r.check();
        }
        pub fn planReplay(a: std.mem.Allocator, admitted: *const Admission.Prepared, capture: *const Capture.VerifiedCapture, expected: [32]u8, capacity: u32) !Shared.Planned {
            return planReplayWithCompiled(a, admitted, capture, expected, capacity, null);
        }
        /// Optional independently compiled plan; all request operations and
        /// original channel comparisons remain fresh and mandatory.
        pub fn planReplayWithCompiled(a: std.mem.Allocator, admitted: *const Admission.Prepared, capture: *const Capture.VerifiedCapture, expected: [32]u8, capacity: u32, compiled: ?*const @import("blake3_transcript_plan.zig").Plan) !Shared.Planned {
            try capture.validate(admitted, expected);
            var arena = std.heap.ArenaAllocator.init(a);
            var owned = true;
            defer if (owned) arena.deinit();
            const temp = arena.allocator();
            var statement = try Statement.init(temp, admitted, &capture.original.arithmetic, &capture.original.claims);
            // The completed replay owns this arena, including statement storage.
            defer if (owned) statement.deinit();
            var r = Recorder.Recorder{ .a = temp, .universal_relations = true };
            try prefix(temp, &r, admitted, &statement);
            const entry = try admitted.pin().require(temp, admitted.epoch, admitted.entries);
            const drawn = try Source.draw(temp, admitted.epoch, entry);
            const channel = try Source.channel(&drawn, admitted.pin(), entry, &admitted.relations.schedule, &capture.original.arithmetic, &capture.original.claims);
            if (!std.meta.eql(channel, r.native) or r.root_count != 3 or r.relation_count != RELATION_COUNT) return error.InvalidV7CallerTranscript;
            r.mixRoot(capture.original.proof.commitments[3]);
            r.mixRoot(capture.original.proof.commitments[4]);
            try r.check();
            var result = if (compiled) |trusted| try Shared.finishReplayForCommitmentsWithPlan(6, a, &arena, &r, &capture.original.proof, admitted.arithmetic.config, capacity, trusted) else try Shared.finishReplayForCommitments(6, a, &arena, &r, &capture.original.proof, admitted.arithmetic.config, capacity);
            owned = false;
            errdefer result.deinit();
            if (!std.meta.eql(result.end, capture.original.final_channel)) return error.InvalidV7CallerTranscript;
            return result;
        }
    };
}
