//! Direct native-verifier groups. No recursive child proof is wrapped here.
//! This is a closed source-cost experiment, not complete execution admission.
const std = @import("std");
const C = @import("../full_p2_common.zig");
const P = @import("../../rv64_recursion/om31_poseidon/common.zig");
const Scope = @import("../native_omul/scope.zig");
const Sponge = @import("../sponge.zig").ForContext(P.PoseidonContext);
const Fold = @import("../native_omul/fold.zig");
const Profile = @import("../op_profile.zig").Profile;
pub const Member = @import("../sponge_cpu/source_view.zig").View;
pub const Binding = struct { ordinal: u32, fixed_identity: [32]u8 };

/// Append callbacks synchronously and release each native capture afterwards.
/// No global builder scope survives a callback; unrelated source builders can
/// run between appends. The context retains only its own graph/value metadata.
pub const Stream = struct {
    allocator: std.mem.Allocator,
    owner: P.PoseidonContext,
    owns: bool = true,
    poisoned: bool = false,
    trace_only: bool,
    first: u32,
    count: u32,
    appended: u32 = 0,
    profile: Profile,
    manifest: [36]u8,
    roots: [4][9]C.Var = undefined,
    expected_roots: [4]Fold.Digest = undefined,
    mutation_ports: [4][4]C.Var = undefined,
    bindings: [4]Binding = @splat(.{ .ordinal = 0, .fixed_identity = @splat(0) }),
    pub fn init(a: std.mem.Allocator, trace_only: bool, first: u32, count: u32, profile: Profile, manifest: [36]u8) !Stream {
        if ((count != 1 and count != 2 and count != 4) or first >= 256 or @as(u64, first) + count > 256 or first % count != 0) return error.NativeGroupCoverage;
        if (profile == .reference_b2_q24_p0) return error.InvalidOpPurePoseidonProfile;
        _ = try @import("stwo_core").crypto.poseidon2_m31_sponge.decode(manifest);
        return .{ .allocator = a, .owner = if (trace_only) try P.PoseidonContext.initTraceOnly(a, 9) else try P.PoseidonContext.init(a, 9), .trace_only = trace_only, .first = first, .count = count, .profile = profile, .manifest = manifest };
    }
    pub fn deinit(self: *Stream) void {
        if (self.owns) self.owner.deinit();
        self.* = undefined;
    }
    pub fn append(self: *Stream, member: Member) !void {
        if (!self.owns or self.poisoned or self.appended >= self.count) return error.NativeGroupPhase;
        errdefer self.poisoned = true;
        if (member.ordinal() != self.first + self.appended or member.profile() != self.profile or !std.mem.eql(u8, &self.manifest, &member.manifest())) return error.NativeGroupSourceAuthority;
        var arena = std.heap.ArenaAllocator.init(self.allocator);
        defer arena.deinit();
        const source = try member.normalized(arena.allocator());
        var structural = @import("../../rv64_recursion/circuit_lane.zig").StructuralScope.init();
        defer structural.deinit();
        var native = Scope.begin();
        defer native.deinit();
        P.begin(&self.owner);
        var active = true;
        defer if (active) P.finish() catch {};
        const emitted = try source.emit(self.allocator, self.owner.algebra(), self.trace_only);
        self.roots[self.appended] = emitted.output;
        self.mutation_ports[self.appended] = emitted.mutation_ports;
        self.expected_roots[self.appended] = try source.expected(self.allocator);
        self.bindings[self.appended] = .{ .ordinal = source.ordinal(), .fixed_identity = source.fixedIdentity() };
        try P.finish();
        active = false;
        self.appended += 1;
    }
    pub fn expectedOutput(self: *const Stream) !Fold.Digest {
        if (self.poisoned or self.appended != self.count) return error.NativeGroupCoverage;
        return Fold.treeDigest(self.allocator, self.expected_roots[0..self.count]);
    }
    /// Transfers the finalized context on success. Callers must independently
    /// derive a key from the same known source group before proving/verifying.
    pub fn finish(self: *Stream) !P.PoseidonContext {
        return self.finishMode(false);
    }
    /// Explicit source experiment only. The typed R7 wrapper installs the dot
    /// scope per member; all output folding and final custody remain shared.
    pub fn finishForNativeDot(self: *Stream) !P.PoseidonContext {
        return self.finishMode(true);
    }
    fn finishMode(self: *Stream, comptime native_dot: bool) !P.PoseidonContext {
        if (!self.owns or self.poisoned) return error.NativeGroupPhase;
        errdefer self.poisoned = true;
        if (self.poisoned or self.appended != self.count) return error.NativeGroupCoverage;
        var structural = @import("../../rv64_recursion/circuit_lane.zig").StructuralScope.init();
        defer structural.deinit();
        var native = Scope.begin();
        defer native.deinit();
        P.begin(&self.owner);
        var active = true;
        defer if (active) P.finish() catch {};
        var count: usize = self.count;
        while (count > 1) {
            for (0..count / 2) |i| {
                var sponge = try Sponge.init(&self.owner, .words);
                for ([_]u32{ 0x4f504632, 1, 2 }) |tag| try sponge.absorbConstU32(tag);
                try sponge.absorbMany(&self.roots[2 * i]);
                try sponge.absorbMany(&self.roots[2 * i + 1]);
                self.roots[i] = try sponge.finish();
            }
            count /= 2;
        }
        try P.finish();
        active = false;
        try self.owner.setOutputs(&self.roots[0]);
        if (native_dot) try self.owner.finalizeForNativeDot() else try self.owner.finalize();
        if (!self.trace_only) for (self.roots[0], try self.expectedOutput()) |port, expected| if (!self.owner.algebra().get(port).eql(expected)) return error.NativeGroupOutputMismatch;
        if (self.owner.algebra().circuit.blake_g_gate.items.len != 0) return error.NativeGroupUnexpectedBlake;
        self.owns = false;
        return self.owner;
    }
};
