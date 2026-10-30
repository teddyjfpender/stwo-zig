//! Owned original-verifier grammar BEFORE NativeParent row materialization.
//! This is compiler input, never a proof/key/verification-success receipt.
const std = @import("std");
const core = @import("stwo_core");
const Frames = @import("block_v5_recursive_statement_frames_v1.zig");
const Cold = @import("blake3_fixed_operation_recorder_v1.zig");
const Sequence = @import("blake3_transcript_witness.zig");
const Native = @import("blake3_transcript_plan.zig");
pub const production_active = false;
pub const Owned = struct {
    backing: std.mem.Allocator,
    arena: *std.heap.ArenaAllocator,
    frame: Frames.Statement,
    operations: []const Sequence.Operation,
    config: Native.Config,
    profile_seal: [32]u8,
    public_circuit: u32,
    first_root_count: usize,
    limits: Cold.Limits,
    seal: [32]u8,

    /// All nested payloads and frame arrays are copied. Their producer arena
    /// can be destroyed immediately. The heap-stable arena also keeps the
    /// allocator embedded in Frame valid when this owner moves by value.
    pub fn capture(a: std.mem.Allocator, frame: *const Frames.Statement, recorder: *const Cold.Recorder, config: Native.Config, public_circuit: u32, profile_seal: [32]u8) !Owned {
        try recorder.check();
        if (config.attempt_capacity == 0 or recorder.limits.max_operations == 0 or recorder.limits.max_routed_words == 0 or recorder.operations.items.len > recorder.limits.max_operations or recorder.routed_words > recorder.limits.max_routed_words or recorder.skipped_roots < 2 or recorder.skipped_roots > 256) return error.InvalidOriginalOpSchedule;
        // Match the existing original Frame.Builder ceilings, rather than
        // tightening old accepted metadata by combining independent limits.
        // Appended first-root words are not all transcript routed payloads.
        if (frame.words.len > (1 << 20) or frame.felts.len > (1 << 18)) return error.OriginalOpScheduleResourceLimit;
        const arena = try a.create(std.heap.ArenaAllocator);
        errdefer a.destroy(arena);
        arena.* = std.heap.ArenaAllocator.init(a);
        errdefer arena.deinit();
        const own = arena.allocator();
        const operations = try own.alloc(Sequence.Operation, recorder.operations.items.len);
        for (operations, recorder.operations.items) |*out, operation| out.* = switch (operation) {
            .routed_words => |v| .{ .routed_words = .{ .values = try own.dupe(u32, v.values), .source = v.source } },
            .routed_felts => |v| .{ .routed_felts = .{ .values = try own.dupe(core.fields.qm31.QM31, v.values), .source = v.source } },
            .words => |v| .{ .words = try own.dupe(u32, v) },
            .felts => |v| .{ .felts = try own.dupe(core.fields.qm31.QM31, v) },
            .queries => |v| .{ .queries = .{ .log_domain_size = v.log_domain_size, .values = try own.dupe(u32, v.values), .export_outputs = v.export_outputs } },
            else => operation,
        };
        var out: Owned = .{ .backing = a, .arena = arena, .frame = try frame.clone(own), .operations = operations, .config = config, .profile_seal = profile_seal, .public_circuit = public_circuit, .first_root_count = recorder.skipped_roots, .limits = recorder.limits, .seal = undefined };
        out.seal = out.identity();
        return out;
    }
    pub fn deinit(self: *Owned) void {
        self.arena.deinit();
        self.backing.destroy(self.arena);
        self.* = undefined;
    }
    pub fn validate(self: *const Owned) !void {
        if (self.config.attempt_capacity == 0 or self.operations.len > self.limits.max_operations or !std.meta.eql(self.seal, self.identity())) return error.MutatedOriginalOpSchedule;
    }
    /// Exact old row compiler, with no changed operation/config/framing bytes.
    /// New circuit adapters consume operations directly and must NOT call this.
    pub fn compileNative(self: *const Owned, a: std.mem.Allocator) !Native.Plan {
        try self.validate();
        return Native.Plan.initCompact(a, self.config, self.operations);
    }
    /// First roots are the final contiguous root words appended by every
    /// original statement factory, including the variable bridge roster.
    pub fn firstRootOffset(self: *const Owned, tree: usize) !u32 {
        try self.validate();
        const count = try std.math.mul(usize, self.first_root_count, 8);
        if (tree >= self.first_root_count or count > self.frame.words.len) return error.InvalidOriginalOpScheduleRoot;
        return std.math.cast(u32, self.frame.words.len - count + 8 * tree) orelse error.InvalidOriginalOpScheduleRoot;
    }
    fn identity(self: *const Owned) [32]u8 {
        var ch = core.proof_suites.Blake3.Channel{};
        ch.mixU32s(&.{ 0x4f505331, 1, self.public_circuit, self.config.namespace, self.config.attempt_capacity });
        ch.mixRoot(self.profile_seal);
        ch.mixU64(self.first_root_count);
        ch.mixU32s(self.frame.words);
        ch.mixFelts(self.frame.felts);
        ch.mixU32s(&(.{self.frame.sealed_offset} ++ self.frame.roots_offset));
        mixSteps(&ch, self.frame.first);
        mixSteps(&ch, self.frame.claims);
        ch.mixU64(self.operations.len);
        for (self.operations) |operation| {
            ch.mixU32s(&.{@intFromEnum(std.meta.activeTag(operation))});
            switch (operation) {
                .restart => |v| ch.mixU32s(&.{v}),
                .integer => |v| ch.mixU64(v),
                .routed_integer => |v| {
                    mixCaller(&ch, v.source);
                    ch.mixU64(v.value);
                },
                .routed_words => |v| {
                    mixCaller(&ch, v.source);
                    ch.mixU32s(v.values);
                },
                .routed_felts => |v| {
                    mixCaller(&ch, v.source);
                    ch.mixFelts(v.values);
                },
                .words => |v| ch.mixU32s(v),
                .felts => |v| ch.mixFelts(v),
                .root => |v| ch.mixRoot(v),
                .routed_root => |v| {
                    mixCaller(&ch, v.source);
                    ch.mixRoot(v.value);
                },
                .pow => |v| {
                    ch.mixU32s(&.{ v.bits, @intFromBool(v.nonce_source != null) });
                    ch.mixU64(v.nonce);
                    if (v.nonce_source) |source| mixCaller(&ch, source);
                },
                .queries => |v| {
                    ch.mixU32s(&.{ v.log_domain_size, @intFromBool(v.export_outputs) });
                    ch.mixU32s(v.values);
                },
                .secure => |v| {
                    ch.mixU32s(&.{ @intFromBool(v.output != null), @intFromBool(v.discard_output), v.attempts, @intFromEnum(v.consumption) });
                    if (v.output) |role| {
                        ch.mixU32s(&.{@intFromEnum(std.meta.activeTag(role))});
                        switch (role) {
                            .universal, .fri, .riscv_relation => |i| ch.mixU64(i),
                            .universal_half => |half| ch.mixU32s(&.{ @intCast(half.relation), half.half }),
                            else => {},
                        }
                    }
                    var words: [8]u32 = undefined;
                    for (&words, v.values) |*word, value| word.* = value.v;
                    ch.mixU32s(&words);
                },
            }
        }
        return ch.digestBytes();
    }
};
fn mixCaller(ch: anytype, caller: Sequence.Caller) void {
    ch.mixU32s(&.{ caller.circuit, caller.first_wire });
}
fn mixSteps(ch: anytype, steps: []const Frames.Step) void {
    ch.mixU64(steps.len);
    for (steps) |step| {
        ch.mixU32s(&.{@intFromEnum(std.meta.activeTag(step))});
        switch (step) {
            .words, .felts => |span| ch.mixU32s(&.{ span.first, span.len }),
            .root, .integer => |offset| ch.mixU32s(&.{offset}),
        }
    }
}

// IMPORTANT lowering contract:
// routed_* payloads, pow.nonce, queries.values and secure.values contain the
// old fixed compiler's ZERO placeholders. Resolve their source ports against
// the SAME proof/public variables; never constrain real proofs to those zeros.
// secure.attempts==0 means a verifier-owned bounded config.attempt_capacity,
// NOT zero attempts or host-authorized acceptance. Earlier rejection and final
// acceptance must remain circuit constraints. In particular relation52 uses
// two .one draws with universal_half outputs, not one .two draw. Mixed extends
// all53 epoch pairs by14 more pairs; no NativeParent47-pair shortcut is valid.
