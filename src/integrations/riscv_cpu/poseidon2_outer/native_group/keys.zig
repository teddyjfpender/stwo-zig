//! Stable source-owned group/fold key custody. The existing Ref/Captured types
//! select known R6/R7 verifiers; no wire-selected format or generic VK import.
const std = @import("std");
const Engine = @import("stwo_prover_engine");
const C = @import("../context.zig");
const Keys = @import("../native_dot/execution_keys.zig");
const Base = @import("source.zig");
const Dot = @import("../native_dot/group_source.zig");
const Fold = @import("../native_dot/fold.zig");
const Profile = @import("../op_profile.zig").Profile;
pub const Ref = Keys.Ref;
pub const Captured = Keys.Captured;
pub const Format = std.meta.Tag(Ref);
/// One concrete source stream selected by receiver policy, not proof headers.
pub const Stream = union(Format) {
    r6: Base.Stream,
    r7: Dot.Stream,
    pub fn init(a: std.mem.Allocator, trace_only: bool, first: u32, count: u32, profile: Profile, manifest: [36]u8, format: Format) !Stream {
        return switch (format) {
            .r6 => .{ .r6 = try Base.Stream.init(a, trace_only, first, count, profile, manifest) },
            .r7 => .{ .r7 = try Dot.Stream.init(a, trace_only, first, count, profile, manifest) },
        };
    }
    pub fn base(self: *Stream) *Base.Stream {
        return switch (self.*) {
            .r6 => |*v| v,
            .r7 => |*v| &v.inner,
        };
    }
    pub fn deinit(self: *Stream) void {
        switch (self.*) {
            inline else => |*v| v.deinit(),
        }
        self.* = undefined;
    }
    pub fn append(self: *Stream, member: Base.Member) !void {
        switch (self.*) {
            inline else => |*v| try v.append(member),
        }
    }
    pub fn finish(self: *Stream) !@import("../../rv64_recursion/om31_poseidon/common.zig").PoseidonContext {
        return switch (self.*) {
            inline else => |*v| v.finish(),
        };
    }
    pub fn expectedOutput(self: *const Stream) !Fold.Digest {
        return switch (self.*) {
            inline else => |*v| v.expectedOutput(),
        };
    }
};
pub const Cost = union(Format) {
    r6: @import("cost.zig").Model,
    r7: Dot.Cost,
    pub fn derive(ctx: *const C.Context, format: Format) !Cost {
        return switch (format) {
            .r6 => .{ .r6 = try @import("cost.zig").Model.derive(ctx) },
            .r7 => .{ .r7 = try Dot.Cost.derive(ctx) },
        };
    }
};
/// Place an Owner in stable storage before publishing Ref pointers; every Ref
/// remains borrowed until this Owner is destroyed or moved. Request statements,
/// witnesses and transcripts stay outside immutable key construction.
pub const Owner = union(Format) {
    r6: @import("../native_omul/authority.zig").Key,
    r7: @import("../native_dot/outer_authority.zig").Key,
    pub fn fromSelectedStreamWithProfile(a: std.mem.Allocator, source: *Stream, outer_profile: Profile) !Owner {
        return fromSelectedStreamWithCost(a, source, outer_profile, null);
    }
    pub fn fromSelectedStreamWithCost(a: std.mem.Allocator, source: *Stream, outer_profile: Profile, cost: ?*Cost) !Owner {
        if (outer_profile == .reference_b2_q24_p0) return error.InvalidOpPurePoseidonProfile;
        if (!source.base().trace_only) return error.NativeGroupSourceTraceRequired;
        const format = std.meta.activeTag(source.*);
        var trace = try source.finish();
        defer trace.deinit();
        if (cost) |out| out.* = try Cost.derive(&trace, format);
        return switch (format) {
            .r6 => .{ .r6 = try @import("../native_omul/authority.zig").Key.init(a, &trace, outer_profile) },
            .r7 => .{ .r7 = try @import("../native_dot/outer_authority.zig").Key.init(a, &trace, outer_profile) },
        };
    }
    pub fn fromStream(a: std.mem.Allocator, source: *Base.Stream) !Owner {
        return fromStreamWithProfile(a, source, source.profile);
    }
    /// Outer terminal policy may differ from the native source proof profile.
    /// Caller supplies independent policy; this is never inferred from bytes.
    pub fn fromStreamWithProfile(a: std.mem.Allocator, source: *Base.Stream, outer_profile: Profile) !Owner {
        if (outer_profile == .reference_b2_q24_p0) return error.InvalidOpPurePoseidonProfile;
        if (!source.trace_only) return error.NativeGroupSourceTraceRequired;
        var trace = try source.finish();
        defer trace.deinit();
        return .{ .r6 = try @import("../native_omul/authority.zig").Key.init(a, &trace, outer_profile) };
    }
    pub fn fromNativeDotStream(a: std.mem.Allocator, source: *Dot.Stream) !Owner {
        return fromNativeDotStreamWithProfile(a, source, source.inner.profile);
    }
    pub fn fromNativeDotStreamWithProfile(a: std.mem.Allocator, source: *Dot.Stream, outer_profile: Profile) !Owner {
        if (outer_profile == .reference_b2_q24_p0) return error.InvalidOpPurePoseidonProfile;
        if (!source.inner.trace_only) return error.NativeGroupSourceTraceRequired;
        var trace = try source.finish();
        defer trace.deinit();
        return .{ .r7 = try @import("../native_dot/outer_authority.zig").Key.init(a, &trace, outer_profile) };
    }
    /// Known source keys alone select the canonical fold topology. No child
    /// witness, root proof or producer-declared verifier key is an input.
    pub fn canonicalFold(a: std.mem.Allocator, children: [2]Ref, outer_profile: Profile) !Owner {
        if (outer_profile == .reference_b2_q24_p0 or children[0].profile() == .reference_b2_q24_p0 or children[1].profile() == .reference_b2_q24_p0) return error.InvalidOpPurePoseidonProfile;
        if (children[0].nOutputs() != 9 or children[1].nOutputs() != 9) return error.FoldSourceOutputArity;
        var trace = try (Fold.TraceSource{ .keys = children }).buildCanonicalTree(a);
        defer trace.deinit();
        return .{ .r7 = try @import("../native_dot/outer_authority.zig").Key.init(a, &trace, outer_profile) };
    }
    pub fn deinit(self: *Owner) void {
        switch (self.*) {
            inline else => |*key| key.deinit(),
        }
        self.* = undefined;
    }
    pub fn ref(self: *const Owner) Ref {
        return switch (self.*) {
            .r6 => |*key| .{ .r6 = key },
            .r7 => |*key| .{ .r7 = key },
        };
    }
    pub fn retireProverData(self: *Owner) void {
        switch (self.*) {
            .r6 => |*key| @import("../native_omul/verifier_key.zig").retireProverData(key),
            .r7 => |*key| @import("../native_omul/verifier_key.zig").retireProverData(&key.core),
        }
    }
    pub fn prove(self: *const Owner, a: std.mem.Allocator, ctx: *const C.Context, output: []const C.Q, recorder: *Engine.stage_profile.Recorder) ![]u8 {
        return self.ref().prove(a, ctx, output, recorder);
    }
    pub fn verify(self: *const Owner, a: std.mem.Allocator, output: []const C.Q, bytes: []const u8) !void {
        return self.ref().verify(a, output, bytes);
    }
    pub fn verifyCaptured(self: *const Owner, a: std.mem.Allocator, output: []const C.Q, bytes: []const u8) !Captured {
        return self.ref().verifyCaptured(a, output, bytes);
    }
};
