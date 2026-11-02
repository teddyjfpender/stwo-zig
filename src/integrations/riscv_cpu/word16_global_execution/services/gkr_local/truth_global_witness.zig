//! Truth-specific query projection on the shared bounded classic witness driver.
const core = @import("stwo_core");
const A = @import("stwo_riscv_frontend").rv64_air;
const O = core.fields.om31.OM31;
const M = core.fields.m31.M31;
const K = A.crypto.keccak;
const S = A.crypto.secp256k1;
const Metadata = @import("truth_global_metadata.zig");
const Frame = @import("truth_frame.zig");
const Classic = @import("classic_witness.zig");
pub const Witness = Classic.Witness;
pub const Challenges = struct { io: K.equations.IoFor(O), wire: S.equations.WireFor(O) };
const Sink = struct {
    challenges: *const Challenges,
    role: Frame.Role,
    d: []O,
    n: []Classic.Numerator,
    count: usize = 0,
    invalid: bool = false,
    pub fn emitIo(self: *@This(), tuple: [11]M, weight: M) void {
        if (self.role != .keccak or self.count >= self.d.len) {
            self.invalid = true;
            return;
        }
        self.d[self.count] = self.challenges.io.denominatorBase(&tuple);
        self.n[self.count] = .{ .base = weight };
        self.count += 1;
    }
    pub fn emitWire(self: *@This(), tuple: [35]M, weight: M) void {
        if ((self.role != .product and self.role != .linear) or self.count >= self.d.len) {
            self.invalid = true;
            return;
        }
        self.d[self.count] = self.challenges.wire.denominatorBase(&tuple);
        self.n[self.count] = .{ .base = weight };
        self.count += 1;
    }
};
const Provider = struct {
    /// Validated metadata and challenge inputs are immutable; fill allocates nothing.
    pub const PARALLEL_SAFE = true;
    metadata: *const Metadata.Provider,
    challenges: *const Challenges,
    role: Frame.Role,
    pub fn fill(self: @This(), logical: usize, d: []O, n: []Classic.Numerator) !void {
        var sink = Sink{ .challenges = self.challenges, .role = self.role, .d = d, .n = n };
        try self.metadata.emit(self.role, logical, &sink);
        if (sink.invalid or sink.count != d.len) return error.TruthGlobalQueryCountMismatch;
    }
};
pub fn inverseCount(role: Frame.Role) usize {
    return switch (role) {
        .keccak => 25,
        .product, .linear => 3,
        else => 0,
    };
}
pub fn inverseCountFor(instance: Frame.Instance) usize {
    return if (instance.role == .keccak) instance.keccak_policy.ioLookups() else inverseCount(instance.role);
}
pub fn generate(allocator: @import("std").mem.Allocator, metadata: *const Metadata.Provider, role: Frame.Role, challenges: *const Challenges, budget: usize) !Witness {
    const count = if (role == .keccak and metadata.source.* == .keccak) (try Frame.keccakPolicy(metadata.source)).ioLookups() else inverseCount(role);
    if (count == 0) return error.InvalidTruthGlobalRole;
    const log = switch (metadata.source.*) {
        .keccak => |s| if (role == .keccak) s.permutation.log_size else return error.InvalidTruthGlobalRole,
        .secp => |s| if (role == .product) s.batch.product.log_size else if (role == .linear) s.batch.linear.log_size else return error.InvalidTruthGlobalRole,
        else => return error.GkrV3ServiceUnsupported,
    };
    return Witness.initTruth(allocator, log, &.{.{ .inverses = @intCast(count) }}, Provider{ .metadata = metadata, .challenges = challenges, .role = role }, budget);
}
