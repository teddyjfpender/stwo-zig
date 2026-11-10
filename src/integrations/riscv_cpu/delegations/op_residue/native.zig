//! Conditional positive-residue certificate. Independently challenged relations
//! have separate closure checks; neither may cancel debt against the other.
//! Numerical GKR acceptance is pending until every terminal binds physical MAIN.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const A = @import("stwo_riscv_frontend").rv64_air;
const D = A.crypto.bn254_dense;
const G = A.crypto.bn254_residue;
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
    .{ .family = .bytes, .role = .square, .row_log = 10, .lane_log = 9 }, .{ .family = .bytes, .role = .multiply, .row_log = 9, .lane_log = 9 }, .{ .family = .bytes, .role = .hint, .row_log = 5, .lane_log = 6 }, .{ .family = .bytes, .role = .table, .row_log = 8, .lane_log = 0 },
    .{ .family = .ssa, .role = .square, .row_log = 10, .lane_log = 4 },   .{ .family = .ssa, .role = .multiply, .row_log = 9, .lane_log = 5 },   .{ .family = .ssa, .role = .hint, .row_log = 5, .lane_log = 0 },   .{ .family = .ssa, .role = .frontier, .row_log = 6, .lane_log = 0 },
};
pub const MAGIC = "RESIDUE1";
pub const Scope = struct { statement: [32]u8, fixed: [32]u8, main: [32]u8 };
fn raw(channel: anytype, data: [32]u8) void {
    var words: [8]u32 = undefined;
    for (&words, 0..) |*v, i| v.* = std.mem.readInt(u32, data[4 * i ..][0..4], .little);
    channel.mixU32s(&words);
}
pub fn statement(public: []const u256) [32]u8 {
    var h = std.crypto.hash.sha2.Sha256.init(.{});
    h.update("closed-positive-residue/v1");
    h.update(&D.sourceDigest());
    h.update(&G.sourceDigest());
    h.update(@embedFile("native.zig"));
    h.update(@embedFile("component.zig"));
    h.update(@embedFile("projection.zig"));
    h.update(@embedFile("trace.zig"));
    for (public) |v| {
        var bytes: [32]u8 = undefined;
        std.mem.writeInt(u256, &bytes, v, .little);
        h.update(&bytes);
    }
    return h.finalResult();
}
pub fn begin(scope: Scope) Channel {
    var channel = Channel.init();
    channel.mixU32s(&.{ 0x52534445, 1, 8, 4 });
    for (INSTANCES) |i| channel.mixU32s(&.{ @intFromEnum(i.family), @intFromEnum(i.role), i.row_log, i.lane_log });
    raw(&channel, scope.statement);
    raw(&channel, scope.fixed);
    raw(&channel, scope.main);
    return channel;
}
pub fn validateArtifact(artifact: *const GV.GkrArtifact) !void {
    if (artifact.n_variables_by_instance.len != INSTANCES.len or artifact.claims_to_verify_by_instance.len != INSTANCES.len or artifact.ood_point.len != 19) return error.DenseSsaShape;
    for (INSTANCES, artifact.n_variables_by_instance, artifact.claims_to_verify_by_instance) |i, variables, claims| if (variables != try i.variables() or claims.len != 2) return error.DenseSsaShape;
}
pub fn receipt(scope: Scope, proof: *const GV.GkrBatchProof, marginals: []const []const Q) !core.crypto.poseidon2_m31_sponge.Digest {
    var vars: [8]u32 = undefined;
    var writer = Base.ReceiptWriter{};
    writer.tag(0x52534445);
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
    if (proof.output_claims_by_instance.len != 8) return error.DenseSsaShape;
    try Closure.close(a, proof.output_claims_by_instance[0..4]);
    try Closure.close(a, proof.output_claims_by_instance[4..8]);
}
pub fn Reader() type {
    return struct {
        const Self = @This();
        witness: *const C.Model,
        instance: Instance,
        beta: Q,
        ssa: C.Wire,
        lie_zero_reads: bool = false,
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
                const View = struct {
                    reader: *const Self,
                    row: usize,
                    role: Role,
                    lie: bool = false,
                    pub fn main(v: *const @This(), c: usize) Q {
                        const L = G.physical_witness.Layout(.multiply);
                        if (v.lie and c >= L.INPUT + 18 * 32 and c < L.INPUT + 24 * 32) return Q.zero();
                        const view = v.reader.witness.view(v.role, v.row);
                        return view.main(c);
                    }
                    pub fn fixed(v: *const @This(), c: usize) Q {
                        const view = v.reader.witness.view(v.role, v.row);
                        return view.fixed(c);
                    }
                };
                const lie = self.lie_zero_reads and i.family == .ssa and i.role == .multiply and row < S.MULTIPLY_ROWS and G.physical_witness.Physical.nodeAt(.multiply, row).writer >= G.witness.ROM.scaled[0] and G.physical_witness.Physical.nodeAt(.multiply, row).writer < G.witness.ROM.scaled[0] + 12;
                const v = View{ .reader = self, .row = row, .role = i.role, .lie = lie };
                if (i.family == .bytes) pair = switch (i.role) {
                    .square => C.byteFraction(.square, Q, &v, self.beta, lane),
                    .multiply => C.byteFraction(.multiply, Q, &v, self.beta, lane),
                    .hint => C.byteFraction(.hint, Q, &v, self.beta, lane),
                    .table => C.byteFraction(.table, Q, &v, self.beta, lane),
                    else => return error.InvalidLayerStructure,
                } else pair = switch (i.role) {
                    .square => C.ssaFraction(.square, Q, &v, self.ssa, lane),
                    .multiply => C.ssaFraction(.multiply, Q, &v, self.ssa, lane),
                    .hint => C.ssaFraction(.hint, Q, &v, self.ssa, lane),
                    .frontier => C.ssaFraction(.frontier, Q, &v, self.ssa, lane),
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
    var artifact = try GV.partiallyVerifyBatch(a, &.{ .LogUp, .LogUp, .LogUp, .LogUp, .LogUp, .LogUp, .LogUp, .LogUp }, proof, &channel);
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
pub fn prove(a: std.mem.Allocator, scope: Scope, witness: *const C.Model) !Unbound {
    return proveMode(a, scope, witness, false);
}
pub fn proveLyingForTesting(a: std.mem.Allocator, scope: Scope, witness: *const C.Model) !Unbound {
    if (!@import("builtin").is_test) @compileError("test-only source fact attack");
    return proveMode(a, scope, witness, true);
}
fn proveMode(a: std.mem.Allocator, scope: Scope, witness: *const C.Model, lie: bool) !Unbound {
    var channel = begin(scope);
    const beta = channel.drawSecureFelt();
    const ssa = C.Wire.draw(&channel);
    var readers: [8]Reader() = undefined;
    var sources: [8]GP.MultiplicitiesSource = undefined;
    for (INSTANCES, &readers, &sources) |instance, *r, *s| {
        r.* = .{ .witness = witness, .instance = instance, .beta = beta, .ssa = ssa, .lie_zero_reads = lie };
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
