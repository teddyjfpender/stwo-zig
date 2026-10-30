//! Device-only original execution-parent transcript. Host-visible counters are
//! schedule state, never challenges, roots, samples, hashes or proof nonces.
const std = @import("std");
const core = @import("stwo_core");
const cuda = @import("stwo_cuda_backend");
const common = cuda.runtime.stages.common;
const B3 = cuda.runtime.stages.blake3;
const ABI = cuda.abi.stages.blake3;
const Stage = cuda.runtime.telemetry.Stage;
const Program = @import("resident_parent_program_v1.zig");
const Protocol = @import("../../frontends/riscv/recursion/blake3_execution_parent_protocol.zig");
const Universal = @import("../../frontends/riscv/recursion/air/universal_challenges.zig");

pub const Static = struct {
    words: []const u32,
    frames: []const Program.PrefixPlan.Frame,
    config_words: u32,
    key_start: u32,
    claims_start: u32,
    count: u32,
    pub fn derive(program: *const Program.Owned) !Static {
        const p = program.view();
        try p.validate();
        const c = p.admission.key.config;
        const config_words: u32 = if (c.fri_config.fold_step != core.fri.FOLD_STEP or c.lifting_log_size != null) 8 else 4;
        if (p.transcript_prefix.words.len > std.math.maxInt(u32)) return error.InvalidResidentParentTranscript;
        return .{ .words = p.transcript_prefix.words, .frames = p.transcript_prefix.frames, .config_words = config_words, .key_start = 3 + config_words, .claims_start = p.transcript_prefix.claims_start, .count = @intCast(p.transcript_prefix.words.len) };
    }
};
pub const Bindings = struct { state: B3.Channels, static_words: common.Words };
pub fn Sink(comptime Session: type, comptime Ops: type) type {
    return struct {
        const Self = @This();
        session: *Session,
        program: *const Program.Owned,
        bindings: Bindings,
        static: Static,
        next: u32 = 0,
        fri_layers: u32 = 0,
        fri_cursor: u32 = 0,
        primed: bool = false,
        grind_limit: u64 = @as(u64, 1) << 36,
        grind_blocks: u32 = 256,
        pub fn init(session: *Session, program: *const Program.Owned, bindings: Bindings) !Self {
            const static = try Static.derive(program);
            if (bindings.state.len != 1 or bindings.static_words.len != static.count or bindings.state.owner != bindings.static_words.owner or bindings.state.generation != bindings.static_words.generation) return error.InvalidResidentParentTranscript;
            return .{ .session = session, .program = program, .bindings = bindings, .static = static };
        }
        pub fn prime(self: *Self) !void {
            if (self.primed) return error.InvalidResidentParentTranscript;
            try self.session.context.uploadSlice(u32, self.bindings.static_words, self.static.words[0..self.static.count]);
            self.primed = true;
        }
        fn require(self: *const Self, expected: u32) !void {
            if (!self.primed or self.next != expected) return error.InvalidResidentParentTranscript;
        }
        fn channel(self: *Self, stage: Stage, value: common.Words, count: usize, op: ABI.Operation) !void {
            try Ops.channel(self.session, stage, self.bindings.state, value, @intCast(count), op, 1024);
        }
        fn draw(self: *Self, stage: Stage, output: common.SecureFields, count: usize) !void {
            if (output.len != count) return error.InvalidResidentParentTranscript;
            try self.channel(stage, try output.cast(u32), count, .secure);
        }
        pub fn initialize(self: *Self) !void {
            try self.require(0);
            try self.channel(.trace_commit, try self.bindings.static_words.sub(0, 0), 0, .init);
            for (self.static.frames) |frame| {
                const op: ABI.Operation = switch (frame.kind) {
                    .words => .words,
                    .felts => .felts,
                    .root => .root,
                };
                try self.channel(.trace_commit, try self.bindings.static_words.sub(frame.first, frame.count), frame.count, op);
            }
            self.next = 1;
        }
        pub fn mixTraceRoot(self: *Self, index: u32, root: common.Words) !void {
            const expected: u32 = switch (index) {
                0 => 1,
                1 => 2,
                2 => 5,
                3 => 7,
                else => return error.InvalidResidentParentTranscript,
            };
            try self.require(expected);
            if (root.len != 8) return error.InvalidResidentParentTranscript;
            try self.channel(if (index == 3) .constraint_evaluation else .trace_commit, root, 8, .root);
            self.next += 1;
        }
        pub fn drawRelations(self: *Self, output: common.SecureFields) !void {
            try self.require(3);
            try self.draw(.trace_commit, output, Universal.DRAW_COUNT);
            self.next = 4;
        }
        pub fn mixClaims(self: *Self, claims: common.SecureFields) !void {
            try self.require(4);
            if (claims.len != Program.COMPONENT_COUNT) return error.InvalidResidentParentTranscript;
            try self.channel(.trace_commit, try self.bindings.static_words.sub(self.static.claims_start, 3), 3, .words);
            try self.channel(.trace_commit, try claims.cast(u32), 4 * claims.len, .felts);
            self.next = 5;
        }
        pub fn drawCompositionAlpha(self: *Self, output: common.SecureFields) !void {
            try self.require(6);
            try self.draw(.constraint_evaluation, output, 1);
            self.next = 7;
        }
        pub fn drawOodsParameter(self: *Self, output: common.SecureFields) !void {
            try self.require(8);
            try self.draw(.oods, output, 1);
            self.next = 9;
        }
        pub fn mixSamples(self: *Self, samples: common.SecureFields, expected_count: usize) !void {
            try self.require(9);
            if (samples.len != expected_count or expected_count == 0) return error.InvalidResidentParentTranscript;
            try self.channel(.oods, try samples.cast(u32), samples.len * 4, .felts);
            self.next = 10;
        }
        pub fn drawQuotientAlpha(self: *Self, output: common.SecureFields) !void {
            try self.require(10);
            try self.draw(.quotient, output, 1);
            self.next = 11;
        }
        pub fn setFriLayers(self: *Self, count: u32) !void {
            try self.require(11);
            if (count != self.program.view().fri_layers.len) return error.InvalidResidentParentTranscript;
            self.fri_layers = count;
            self.next = 12;
        }
        pub fn mixFriRoot(self: *Self, root: common.Words) !void {
            try self.require(12);
            if (self.fri_cursor >= self.fri_layers or root.len != 8) return error.InvalidResidentParentTranscript;
            try self.channel(.fri_commit, root, 8, .root);
            self.next = 13;
        }
        pub fn drawFriAlpha(self: *Self, output: common.SecureFields) !void {
            try self.require(13);
            try self.draw(.fri_commit, output, 1);
            self.fri_cursor += 1;
            self.next = 12;
        }
        pub fn mixLastLayer(self: *Self, coefficients: common.SecureFields) !void {
            try self.require(12);
            if (self.fri_cursor != self.fri_layers or coefficients.len != @as(usize, 1) << @intCast(self.program.view().admission.key.config.fri_config.log_last_layer_degree_bound)) return error.InvalidResidentParentTranscript;
            try self.channel(.fri_commit, try coefficients.cast(u32), coefficients.len * 4, .felts);
            self.next = 14;
        }
        /// Canonical minimum nonce is found and absorbed entirely on device.
        /// Exhaustion poisons the channel; the terminal seal rejects publication.
        pub fn absorbQueryPow(self: *Self, nonce: common.Nonce) !void {
            try self.require(14);
            if (nonce.len != 1 or self.grind_limit == 0 or self.grind_blocks == 0) return error.InvalidResidentParentTranscript;
            try Ops.grind(self.session, self.bindings.state, self.program.view().admission.key.config.pow_bits, self.grind_limit, self.grind_blocks, nonce);
            self.next = 16;
        }
        pub fn drawQueries(self: *Self, output: common.Words, log_domain: u32) !void {
            try self.require(16);
            const p = self.program.view();
            if (output.len != p.admission.key.config.fri_config.n_queries or log_domain != p.fri_log) return error.InvalidResidentParentTranscript;
            try Ops.drawQueries(self.session, self.bindings.state, log_domain, output);
            self.next = 17;
        }
        /// OR into the device witness/FRI verdict, never overwrite another error.
        pub fn sealVerdict(self: *Self, terminal: common.Words) !void {
            try self.require(17);
            try Ops.sealError(self.session, self.bindings.state, terminal);
            self.next = 18;
        }
        pub fn requireComplete(self: *const Self) !void {
            try self.require(18);
        }
    };
}
pub const NativeSink = Sink(cuda.runtime.NativeSession, B3.Native);

test "resident parent transcript static framing equals original admission" {
    const program = try Program.Owned.derive(std.testing.allocator, try Program.fixtureAdmission(), .{});
    defer program.deinit();
    const static = try Static.derive(program);
    var expected = core.channel.blake3.Channel{};
    try program.view().admission.mix(&expected);
    var actual = core.channel.blake3.Channel{};
    actual.mixU32s(static.words[0..3]);
    var config: [2]core.fields.qm31.QM31 = undefined;
    for (config[0 .. static.config_words / 4], 0..) |*out, i| out.* = core.fields.qm31.QM31.fromU32Unchecked(static.words[3 + 4 * i], static.words[4 + 4 * i], static.words[5 + 4 * i], static.words[6 + 4 * i]);
    actual.mixFelts(config[0 .. static.config_words / 4]);
    actual.mixU32s(static.words[static.key_start..][0..8]);
    try std.testing.expectEqualDeep(expected, actual);
}
