//! Exact original compact public-frame byte routing, shared by live and fixed setup.
//! No transcript absorption or key identity is changed by this generic adapter.
const std = @import("std");
const Q = @import("stwo_core").fields.qm31.QM31;
pub fn ForRecorder(comptime RecorderType: type, comptime PUBLIC_CIRCUIT: u32) type {
    return struct {
        const Replay = @This();
        recorder: *RecorderType,
        cursor: u32 = 0,
        fn next(self: *Replay, len: usize) @import("air/blake3_transcript_witness.zig").Caller {
            const first = self.cursor;
            self.cursor = std.math.add(u32, self.cursor, std.math.cast(u32, len) orelse {
                self.recorder.failure = error.InputRequestNodeResourceLimit;
                return .{ .circuit = PUBLIC_CIRCUIT, .first_wire = first };
            }) catch {
                self.recorder.failure = error.InputRequestNodeResourceLimit;
                return .{ .circuit = PUBLIC_CIRCUIT, .first_wire = first };
            };
            return .{ .circuit = PUBLIC_CIRCUIT, .first_wire = first };
        }
        pub fn mixU32s(self: *Replay, words: []const u32) void {
            self.recorder.mixPublicWords(self.next(words.len), words);
        }
        pub fn mixRoot(self: *Replay, root: [32]u8) void {
            self.recorder.mixPublicRoot(self.next(8), root);
        }
        pub fn mixFelts(self: *Replay, values: []const Q) void {
            const count = std.math.mul(usize, values.len, 4) catch {
                self.recorder.failure = error.InputRequestNodeResourceLimit;
                return;
            };
            self.recorder.mixPublicFelts(self.next(count), values);
        }
    };
}
