//! Closed homogeneous G2 transition. Independently challenged relations
//! have separate closure checks; neither may cancel debt against the other.
//! Numerical GKR acceptance is pending until every terminal binds physical MAIN.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const A = @import("stwo_riscv_frontend").rv64_air;
const D = A.crypto.bn254_dense;
const G = A.crypto.bn254_g2;
const S = G.spec;
const C = G.fixture;
pub const Q = C.Q;
pub const M = C.M;
pub const Channel = core.channel.poseidon2_m31.Om31ChannelV2;
const GP = engine.lookups.gkr_prover.ForField(Q);
pub const GV = engine.lookups.gkr_verifier.ForField(Q);
const Base = @import("../../poseidon2_outer/pure_p2_native.zig");
const Framing = @import("../../poseidon2_outer/pure_p2_framing.zig");
const Closure = @import("../../word16_global_execution/services/gkr_local/closure.zig");
const Wire = @import("../../word16_global_execution/services/gkr_local/wire.zig");
pub const Family = enum { bytes, ssa };
pub const Role = C.Role;
pub const Instance = struct {
    family: Family,
    role: Role,
    row_log: u32,
    lane_log: u32,
    pub fn variables(self: @This()) !u32 {
        return self.row_log + self.lane_log;
    }
    pub fn lanes(self: @This()) usize {
        return @as(usize, 1) << @intCast(self.lane_log);
    }
    pub fn rows(self: @This()) usize {
        return @as(usize, 1) << @intCast(self.row_log);
    }
    pub fn facts(self: @This()) usize {
        return self.rows() * self.lanes();
    }
};
pub const INSTANCES = [_]Instance{
    .{ .family = .bytes, .role = .arithmetic, .row_log = 8, .lane_log = 9 },
    .{ .family = .bytes, .role = .table, .row_log = 8, .lane_log = 0 },
    .{ .family = .ssa, .role = .arithmetic, .row_log = 8, .lane_log = 4 },
    .{ .family = .ssa, .role = .frontier, .row_log = 5, .lane_log = 0 },
};
pub const MAGIC = "G2LOCAL1";
pub const Scope = struct { statement: [32]u8, fixed: [32]u8, main: [32]u8 };
fn raw(channel: anytype, data: [32]u8) void {
    var words: [8]u32 = undefined;
    for (&words, 0..) |*v, i| v.* = std.mem.readInt(u32, data[4 * i ..][0..4], .little);
    channel.mixU32s(&words);
}
pub fn statement(comptime kind: S.Kind, public: []const u256) [32]u8 {
    var h = std.crypto.hash.sha2.Sha256.init(.{});
    h.update("closed-homogeneous-g2/v1");
    h.update(&D.sourceDigest());
    h.update(&G.sourceDigest());
    h.update(@embedFile("native.zig"));
    h.update(@embedFile("component.zig"));
    h.update(@embedFile("projection.zig"));
    h.update(@embedFile("trace.zig"));
    h.update(&.{@intFromEnum(kind)});
    for (public) |v| {
        var bytes: [32]u8 = undefined;
        std.mem.writeInt(u256, &bytes, v, .little);
        h.update(&bytes);
    }
    return h.finalResult();
}
pub fn begin(scope: Scope) Channel {
    var channel = Channel.init();
    channel.mixU32s(&.{ 0x47325353, 1, 4, 2 });
    for (INSTANCES) |i| channel.mixU32s(&.{ @intFromEnum(i.family), @intFromEnum(i.role), i.row_log, i.lane_log });
    raw(&channel, scope.statement);
    raw(&channel, scope.fixed);
    raw(&channel, scope.main);
    return channel;
}
pub fn validateArtifact(artifact: *const GV.GkrArtifact) !void {
    if (artifact.n_variables_by_instance.len != INSTANCES.len or artifact.claims_to_verify_by_instance.len != INSTANCES.len or artifact.ood_point.len != 17) return error.DenseSsaShape;
    for (INSTANCES, artifact.n_variables_by_instance, artifact.claims_to_verify_by_instance) |i, variables, claims| if (variables != try i.variables() or claims.len != 2) return error.DenseSsaShape;
}
pub fn receipt(scope: Scope, proof: *const GV.GkrBatchProof, marginals: []const []const Q) !core.crypto.poseidon2_m31_sponge.Digest {
    var vars: [4]u32 = undefined;
    var writer = Base.ReceiptWriter{};
    writer.tag(0x47325353);
    writer.integer(1);
    writer.rawDigest(scope.statement);
    writer.rawDigest(scope.fixed);
    writer.rawDigest(scope.main);
    for (INSTANCES, &vars) |i, *v| {
        v.* = try i.variables();
        writer.integer(@intFromEnum(i.family));
        writer.integer(@intFromEnum(i.role));
        writer.integer(i.row_log);
        writer.integer(i.lane_log);
    }
    try Framing.emitPayload(proof, &vars, marginals, &writer);
    return writer.finish();
}
pub fn close(a: std.mem.Allocator, proof: *const GV.GkrBatchProof) !void {
    if (proof.output_claims_by_instance.len != 4) return error.DenseSsaShape;
    try Closure.close(a, proof.output_claims_by_instance[0..2]);
    try Closure.close(a, proof.output_claims_by_instance[2..4]);
}
pub fn Reader(comptime kind: S.Kind) type {
    return struct {
        const Self = @This();
        witness: *const C.Model(kind),
        instance: Instance,
        beta: Q,
        ssa: C.Wire,
        pub fn read(ctx: *const anyopaque, first: usize, n: []M, d: []Q) error{ OutOfMemory, ShapeMismatch, InvalidLayerStructure }!void {
            const self: *const Self = @ptrCast(@alignCast(ctx));
            const i = self.instance;
            if (n.len != d.len or n.len > 512 or first > i.facts() or n.len > i.facts() - first) return error.ShapeMismatch;
            for (n, d, 0..) |*nn, *dd, j| {
                const fact = first + j;
                const physical = fact / i.lanes();
                const lane = fact % i.lanes();
                const row = core.utils.circleDomainIndexToCosetIndex(core.utils.bitReverseIndex(physical, i.row_log), i.row_log);
                var pair: struct { Q, Q } = undefined;
                if (i.family == .bytes) pair = switch (i.role) {
                    .arithmetic => blk: {
                        const v = self.witness.view(.arithmetic, row);
                        break :blk C.byteFraction(kind, .arithmetic, Q, &v, self.beta, lane);
                    },
                    .table => blk: {
                        const v = self.witness.view(.table, row);
                        break :blk C.byteFraction(kind, .table, Q, &v, self.beta, lane);
                    },
                    else => return error.InvalidLayerStructure,
                } else pair = switch (i.role) {
                    .arithmetic => blk: {
                        const v = self.witness.view(.arithmetic, row);
                        break :blk C.ssaFraction(kind, .arithmetic, Q, &v, self.ssa, lane);
                    },
                    .frontier => blk: {
                        const v = self.witness.view(.frontier, row);
                        break :blk C.ssaFraction(kind, .frontier, Q, &v, self.ssa, lane);
                    },
                    else => return error.InvalidLayerStructure,
                };
                const coordinates = pair[0].toM31Array();
                for (coordinates[1..]) |x| if (x.v != 0) return error.InvalidLayerStructure;
                nn.* = coordinates[0];
                dd.* = pair[1];
            }
        }
        pub fn source(self: *const Self) GP.MultiplicitiesSource {
            return .{ .variables = self.instance.variables() catch unreachable, .context = self, .wide_reads = true, .read_fn = read };
        }
    };
}
pub const Pending = struct {
    artifact: GV.GkrArtifact,
    beta: Q,
    ssa: C.Wire,
    eta: Q,
    digest: core.crypto.poseidon2_m31_sponge.Digest,
    pub fn deinit(self: *@This(), a: std.mem.Allocator) void {
        self.artifact.deinit(a);
        self.* = undefined;
    }
};
pub fn verify(a: std.mem.Allocator, scope: Scope, proof: *const GV.GkrBatchProof) !Pending {
    var channel = begin(scope);
    const beta = channel.drawSecureFelt();
    const ssa = C.Wire.draw(&channel);
    var artifact = try GV.partiallyVerifyBatch(a, &.{ .LogUp, .LogUp, .LogUp, .LogUp }, proof, &channel);
    errdefer artifact.deinit(a);
    try validateArtifact(&artifact);
    try close(a, proof);
    return .{ .artifact = artifact, .beta = beta, .ssa = ssa, .eta = channel.drawSecureFelt(), .digest = try receipt(scope, proof, artifact.claims_to_verify_by_instance) };
}
pub const Unbound = struct {
    result: GP.ProveBatchResult,
    beta: Q,
    ssa: C.Wire,
    eta: Q,
    digest: core.crypto.poseidon2_m31_sponge.Digest,
    pub fn deinit(self: *@This(), a: std.mem.Allocator) void {
        self.result.deinit(a);
        self.* = undefined;
    }
};
pub fn prove(comptime kind: S.Kind, a: std.mem.Allocator, scope: Scope, witness: *const C.Model(kind)) !Unbound {
    var channel = begin(scope);
    const beta = channel.drawSecureFelt();
    const ssa = C.Wire.draw(&channel);
    var readers: [4]Reader(kind) = undefined;
    var sources: [4]GP.MultiplicitiesSource = undefined;
    for (INSTANCES, &readers, &sources) |instance, *r, *s| {
        r.* = .{ .witness = witness, .instance = instance, .beta = beta, .ssa = ssa };
        s.* = r.source();
    }
    var result = try GP.proveBatchSourceCheckpointedWithOptions(a, &channel, &sources, .{ .coefficient_encoding = .fixed4 });
    errdefer result.deinit(a);
    try validateArtifact(&result.artifact);
    try close(a, &result.proof);
    return .{ .result = result, .beta = beta, .ssa = ssa, .eta = channel.drawSecureFelt(), .digest = try receipt(scope, &result.proof, result.artifact.claims_to_verify_by_instance) };
}
pub fn encode(a: std.mem.Allocator, proof: *const GV.GkrBatchProof) ![]u8 {
    return Wire.encodeFor(a, &INSTANCES, proof, MAGIC);
}
pub fn decode(a: std.mem.Allocator, bytes: []const u8) !Wire.Owned {
    return Wire.decodeFor(a, &INSTANCES, bytes, MAGIC);
}
