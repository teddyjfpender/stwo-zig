//! Fresh initial state is derived by the canonical loader, never accepted as
//! an arbitrary retained snapshot. No instructions are executed here. This is
//! boundary policy, NOT proof verification or a qualified whole-block theorem.
const std = @import("std");
const Capture = @import("../prover/block_v7_real_window_capture_v1.zig");
const Initial = @import("../prover/block_v7_initial_intervals_v1.zig");
const Chain = @import("block_v8_window_chain_v1.zig");
const Runner = @import("../runner/mod.zig");
pub const Limits = struct {
    initial: Initial.Limits = .{},
    max_input_bytes: usize = 4 << 20,
    max_snapshot_words: usize = 8_000_000,
};
const State = struct {
    allocator: std.mem.Allocator,
    elf: Chain.Digest,
    input: Chain.Digest,
    program: Chain.Digest,
    snapshot: Chain.Digest,
};
pub const Fresh = opaque {
    pub fn derive(a: std.mem.Allocator, elf: []const u8, input: []const u8, pins: Capture.Pins, limits: Limits) !*Fresh {
        if (elf.len > limits.initial.max_elf_bytes or input.len > limits.max_input_bytes) return error.WindowChainResourceLimit;
        if (!std.meta.eql(Capture.sha(elf), pins.elf) or !std.meta.eql(Capture.sha(input), pins.input)) return error.UntrustedWindowChainSource;
        var initial = try Initial.Owned.derive(a, elf, pins.elf, .rv32im_zkvm_ethereum_sha_v1, limits.initial);
        defer initial.deinit();
        var image = try @import("../prover/block_v7_program_image_v1.zig").Owned.init(a, elf, &initial, limits.initial);
        defer image.deinit();
        var session = try Runner.EthereumShaExecutionSession.init(a, elf, .{ .input = input, .trace_retention = .segment_owned, .clock_frame = .leaf_local, .stop_on_halt_flag = true, .require_current_output_accesses = false });
        defer session.deinit();
        var snapshot = try Capture.snapshot(a, session.cpu, &session.memory, .{ .max_snapshot_words = limits.max_snapshot_words });
        defer snapshot.deinit(a);
        const owned = try a.create(State);
        owned.* = .{ .allocator = a, .elf = pins.elf, .input = pins.input, .program = image.root.bytes, .snapshot = snapshot.identity() };
        return @ptrCast(owned);
    }
    pub fn deinit(self: *Fresh) void {
        const owned = self.state();
        owned.allocator.destroy(owned);
    }
    pub fn requireStart(self: *const Fresh, span: Chain.Span) !void {
        try span.validate();
        const expected = self.state();
        if (span.begin != 0 or !std.meta.eql(span.elf, expected.elf) or
            !std.meta.eql(span.program, expected.program) or !std.meta.eql(span.incoming, expected.snapshot))
            return error.UntrustedWindowChainInitialState;
    }
    pub fn initialIdentity(self: *const Fresh) Chain.Digest {
        return self.state().snapshot;
    }
    pub fn inputIdentity(self: *const Fresh) Chain.Digest {
        return self.state().input;
    }
    pub fn programIdentity(self: *const Fresh) Chain.Digest {
        return self.state().program;
    }
    fn state(self: *const Fresh) *State {
        return @ptrCast(@alignCast(@constCast(self)));
    }
};
