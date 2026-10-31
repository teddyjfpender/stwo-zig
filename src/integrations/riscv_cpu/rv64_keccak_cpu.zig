//! Explicit service ABI: CPU, immutable ROM, DIV, Keccak and RAM lane bridge
//! share one PCS transaction. Public cells are a boundary control profile.
const std = @import("std");
const This = @This();
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const frontend = @import("stwo_riscv_frontend");
const rv = frontend.rv64_air;
const Full = @import("rv64_full.zig");
const S = Full.Support;
const B = S.Backend;
const P = rv.protocol;
const D = rv.arithmetic.division;
const Mul = rv.arithmetic.multiplication;
const K = rv.crypto.keccak;
const Bridge = K.bridge;
const Sources = @import("rv64_keccak_sources.zig");
const SecpCtx = @import("rv64_ethereum_secp_context.zig");
const Secp = rv.crypto.secp256k1;
pub const MAX_COMPONENTS = 17;
pub const Roster = Sources.Roster;
pub const ArithmeticRoster = enum(u32) { none = 0, present = 1 };
pub const BorrowedArithmetic = @import("rv64_borrowed_services.zig").Arithmetic;
pub const BorrowedMain = @import("rv64_borrowed_services.zig").Main;
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const Column = engine.pcs.ColumnEvaluation;
const Scheme = engine.pcs.CommitmentSchemeProver(B, P.Hasher, P.MerkleChannel);
const Verifier = core.pcs.verifier.CommitmentSchemeVerifier(P.Hasher, P.MerkleChannel);
pub const Public = struct {
    control_policy: rv.control_policy.Policy = .bytes_v1,
    execution_profile: frontend.rv64.execution_profile.Profile = .keccak_service_v1,
    secp: SecpCtx.Metadata = .{},
    arithmetic_policy: D.policy.Policy = .division_service_v2,
    division_roster: ArithmeticRoster = .present,
    multiplication_roster: ArithmeticRoster = .present,
    multiplication_requests: u32 = 0,
    multiplication_log: u32 = 5,
    roster: Roster = .paired,
    state_policy: rv.state_policy.Policy = .inverse_v1,
    statement: Full.Statement,
    division_requests: u32,
    keccak_calls: u32,
    first_call_id: u32 = 1,
    division_log: u32 = 5,
    keccak_log: u32 = 5,
    bridge_log: u32 = 5,
    pub fn validate(self: Public) !void {
        return self.validateWithExpectedOpcodes(null);
    }
    /// Caller must first bind the program to independently derived immutable
    /// authority. This skips only repeated ROM decoding, never request checks.
    pub fn validateWithAdmittedOpcodes(self: Public, admitted: *const [65]bool) !void {
        return self.validateWithExpectedOpcodes(admitted);
    }
    fn validateWithExpectedOpcodes(self: Public, expected: ?*const [65]bool) !void {
        if (self.execution_profile != .keccak_service_v1 and self.execution_profile != .ethereum_services_v1 and self.execution_profile != .ethereum_services_v2) return error.InvalidRv64ServiceProfile;
        try self.statement.validateWithProfile(self.execution_profile);
        const secp_mass = try self.secp.validate(self.execution_profile, self.statement.steps);
        if (@as(u64, self.keccak_calls) + self.secp.add.calls + self.secp.double.calls > self.statement.steps or 8 * @as(u64, self.statement.steps) + 50 * @as(u64, self.keccak_calls) + secp_mass.ram_queries >= core.fields.m31.Modulus) return error.InvalidRv64ServicePublic;
        const admitted = if (expected) |known| known.* else try rv.program.opcode_policy.derive(self.statement.program, self.execution_profile);
        if (!std.mem.eql(bool, &admitted, &self.statement.opcodes)) return error.InvalidRv64ServiceOpcodePolicy;
        if (self.division_requests > self.statement.steps or self.keccak_calls > self.statement.steps or self.division_log < 5 or self.division_log > 22 or self.division_requests > (@as(u32, 1) << @intCast(self.division_log))) return error.InvalidRv64ServicePublic;
        if (self.division_roster == .none and (self.division_requests != 0 or self.division_log != 5)) return error.InvalidRv64ArithmeticRoster;
        if (self.multiplication_roster == .none and (self.arithmetic_policy != .division_multiplication_services_v3 or self.multiplication_requests != 0 or self.multiplication_log != 5)) return error.InvalidRv64ArithmeticRoster;
        switch (self.arithmetic_policy) {
            .division_service_v2 => if (self.multiplication_requests != 0 or self.multiplication_log != 5) return error.InvalidRv64ServiceArithmetic,
            .division_multiplication_services_v3 => if (self.multiplication_log < 5 or self.multiplication_log > 22 or self.multiplication_requests > self.statement.steps or self.multiplication_requests > (@as(u32, 1) << @intCast(self.multiplication_log))) return error.InvalidRv64ServiceArithmetic,
            else => return error.InvalidRv64ServiceArithmetic,
        }
        if (self.roster == .none) {
            if (self.keccak_calls != 0 or self.keccak_log != 5 or self.bridge_log != 5 or self.first_call_id == 0 or self.first_call_id >= core.fields.m31.Modulus) return error.InvalidRv64ServiceRoster;
        } else {
            try K.layout.validateGeometry(self.keccak_calls, self.first_call_id, self.keccak_log);
            try Bridge.trace.validateGeometry(self.keccak_calls, self.first_call_id, self.bridge_log);
        }
        var plan = try Full.planForStatementWithControl(self.statement, self.arithmetic_policy, self.execution_profile, self.control_policy);
        plan.setStatePolicy(self.state_policy);
        _ = try K.layout.admitRoster(&.{self.keccak_calls}, &.{ (@as(u64, 1) << @intCast(self.statement.logSize())) * plan.range_count, if (self.roster == .paired) 40 * (@as(u64, 1) << @intCast(self.bridge_log)) else 0, if (self.arithmetic_policy == .division_multiplication_services_v3 and self.multiplication_roster == .present) 96 * (@as(u64, 1) << @intCast(self.multiplication_log)) else 0, secp_mass.byte_queries });
    }
};
pub const Claims = struct { secp_header: Q = Q.zero(), secp_add: SecpCtx.Claims = .{}, secp_double: SecpCtx.Claims = .{}, multiplication: Q = Q.zero(), multiplication_provider: Q = Q.zero(), cpu: Full.Claims, division: Q, header: Q, permutation: Q, chi: Q, xor5: Q, bridge: Q, bytes: Q };
pub const Bundle = struct {
    claims: Claims,
    proof: P.Proof,
    pub fn deinit(self: *Bundle, a: std.mem.Allocator) void {
        self.proof.deinit(a);
        self.* = undefined;
    }
};
const Challenges = struct { secp: ?SecpCtx.Source.Challenges = null, multiplication: ?Mul.provider.Challenges = null, cpu: rv.full.component.Challenges, division: D.provider.Challenges, keccak: K.equations.Challenges, bridge: Bridge.equations.Challenges };
fn draw(channel: *P.Channel, setup: *const PreparedMaterials) Challenges {
    return drawView(channel, setup.verificationView());
}
fn drawView(channel: *P.Channel, setup: VerificationView) Challenges {
    const cpu = S.challengesView(channel, setup.base);
    const division = D.provider.Challenges.draw(channel);
    const multiplication = if (setup.base.plan.arithmetic_policy == .division_multiplication_services_v3) Mul.provider.Challenges.draw(channel) else null;
    const keccak = K.equations.Challenges.draw(channel);
    const bridge = Bridge.equations.Challenges{ .io = keccak.io, .call = Bridge.equations.CallChallenges.draw(channel), .ram = cpu.state, .bytes = cpu.bytes };
    return .{ .multiplication = multiplication, .secp = if (setup.base.plan.execution_profile != .keccak_service_v1) SecpCtx.Source.Challenges.draw(channel, cpu.bytes, cpu.state) else null, .cpu = cpu, .division = division, .keccak = keccak, .bridge = bridge };
}
fn mixPublic(channel: *P.Channel, setup: *const PreparedMaterials, public: Public) !void {
    return mixPublicView(channel, setup.verificationView(), public);
}
fn mixPublicView(channel: *P.Channel, setup: VerificationView, public: Public) !void {
    channel.mixU32s(&.{ 0x52564b43, 1, @intFromEnum(public.arithmetic_policy), public.division_requests, public.keccak_calls, public.first_call_id, public.division_log, public.keccak_log, public.bridge_log });
    if (public.arithmetic_policy == .division_multiplication_services_v3) channel.mixU32s(&.{ 0x4d554c43, 1, public.multiplication_requests, public.multiplication_log });
    if (public.roster != .paired) channel.mixU32s(&.{ 0x4b524f53, 1, @intFromEnum(public.roster) });
    if (public.state_policy != .inverse_v1) channel.mixU32s(&.{ 0x43535441, 2, @intFromEnum(public.state_policy) });
    if (public.control_policy != .bytes_v1) channel.mixU32s(&.{ 0x4354524c, 2, @intFromEnum(public.control_policy) });
    public.secp.mix(channel, public.execution_profile);
    if (public.division_roster == .none or public.multiplication_roster == .none) channel.mixU32s(&.{ 0x41524f53, 1, @intFromEnum(public.division_roster), @intFromEnum(public.multiplication_roster) });
    try public.statement.mixWithProfile(channel, setup.base.program.identity, public.execution_profile);
}
fn mixClaims(channel: *P.Channel, claims: Claims, public: Public) void {
    S.mix(channel, claims.cpu);
    channel.mixU32s(&.{ 0x4b434c4d, 1, 7 });
    channel.mixFelts(&.{ claims.division, claims.header, claims.permutation, claims.chi, claims.xor5, claims.bridge, claims.bytes });
    if (public.execution_profile != .keccak_service_v1) {
        channel.mixU32s(&.{ 0x53454350, 1 });
        channel.mixFelts(&.{ claims.secp_header, claims.secp_add.product, claims.secp_add.linear, claims.secp_add.bridge, claims.secp_double.product, claims.secp_double.linear, claims.secp_double.bridge });
    }
    if (public.arithmetic_policy == .division_multiplication_services_v3) {
        channel.mixU32s(&.{ 0x4d554c43, 1 });
        channel.mixFelts(&.{ claims.multiplication, claims.multiplication_provider });
    }
}
fn validateEncoding(setup: *const PreparedMaterials, public: Public, claims: Claims) !void {
    return validateEncodingView(setup.verificationView(), public, claims);
}
fn validateEncodingView(setup: VerificationView, public: Public, claims: Claims) !void {
    try S.validateEncodingView(setup.base, claims.cpu);
    try SecpCtx.validateClaims(public.secp, public.execution_profile, claims.secp_header, .{ claims.secp_add, claims.secp_double });
    for ([_]Q{ claims.division, claims.header, claims.permutation, claims.chi, claims.xor5, claims.bridge, claims.bytes, claims.multiplication, claims.multiplication_provider }) |claim| for (claim.toM31Array()) |limb| if (limb.v >= core.fields.m31.Modulus) return error.InvalidRv64ServiceClaim;
    if (public.division_roster == .none and !claims.division.isZero()) return error.Rv64ServiceOmittedClaim;
    if (public.multiplication_roster == .none and (!claims.multiplication.isZero() or !claims.multiplication_provider.isZero())) return error.Rv64ServiceOmittedClaim;
    if (public.roster == .none) for ([_]Q{ claims.header, claims.permutation, claims.chi, claims.xor5, claims.bridge }) |claim| if (!claim.isZero()) return error.Rv64ServiceOmittedClaim;
    if (public.arithmetic_policy == .division_service_v2 and (!claims.multiplication.isZero() or !claims.multiplication_provider.isZero())) return error.Rv64ServiceOmittedClaim;
}
fn effect(claims: Claims) Q {
    return claims.cpu.state.add(claims.cpu.bytes).add(claims.header).add(claims.permutation).add(claims.chi).add(claims.xor5).add(claims.bridge).add(claims.bytes).add(claims.multiplication).add(claims.multiplication_provider).add(claims.secp_header).add(claims.secp_add.sum()).add(claims.secp_double.sum());
}
fn validateClaims(setup: *const PreparedMaterials, public: Public, claims: Claims, ch: Challenges) !void {
    try validateEncoding(setup, public, claims);
    if (!effect(claims).eql(try public.statement.expectedStateWithProfile(ch.cpu.state, public.execution_profile))) return error.Rv64ServiceGlobalClosure;
}

/// Count-independent component geometry. No preprocessing buffers, channels,
/// claims, endpoints or per-request service counts are retained here.
pub const VerificationGeometry = struct {
    log_size: u32,
    program_log: u32,
    program_identity: [32]u8,
    has_and: bool,
    has_shift: bool,
    division_log: u32,
    multiplication_log: u32,
    keccak_log: u32,
    bridge_log: u32,
    has_division: bool,
    has_multiplication: bool,
    has_crypto: bool,
    secp: [2]?SecpCtx.Source.Geometry,
    pub fn view(self: VerificationGeometry, plan: *const rv.encoding.Plan) VerificationView {
        return .{ .base = .{ .plan = plan, .log_size = self.log_size, .program = .{ .log_size = self.program_log, .identity = self.program_identity }, .has_and = self.has_and, .has_shift = self.has_shift }, .division_log = self.division_log, .multiplication_log = self.multiplication_log, .keccak_log = self.keccak_log, .bridge_log = self.bridge_log, .has_division = self.has_division, .has_multiplication = self.has_multiplication, .has_crypto = self.has_crypto, .secp = self.secp };
    }
};
pub const VerificationView = struct {
    base: Full.VerificationView,
    division_log: u32,
    multiplication_log: u32,
    keccak_log: u32,
    bridge_log: u32,
    has_division: bool,
    has_multiplication: bool,
    has_crypto: bool,
    secp: [2]?SecpCtx.Source.Geometry,
    pub fn validate(self: VerificationView, public: Public) !void {
        try public.validate();
        try self.validateGeometry(public);
    }
    pub fn validateBound(self: VerificationView, public: Public) !void {
        try public.validateWithAdmittedOpcodes(&self.base.plan.allowed_opcodes);
        try self.validateGeometry(public);
    }
    fn validateGeometry(self: VerificationView, public: Public) !void {
        const plan = self.base.plan;
        if (plan.control_policy != public.control_policy or plan.state_policy != public.state_policy or plan.execution_profile != public.execution_profile or plan.arithmetic_policy != public.arithmetic_policy or self.base.log_size != public.statement.logSize() or !std.mem.eql(bool, &plan.allowed_opcodes, &public.statement.opcodes)) return error.InvalidRv64ServiceSetup;
        if (self.has_division != (public.division_roster == .present) or self.has_multiplication != (public.arithmetic_policy == .division_multiplication_services_v3 and public.multiplication_roster == .present) or self.has_crypto != (public.roster == .paired) or self.division_log != public.division_log or self.multiplication_log != public.multiplication_log or self.keccak_log != public.keccak_log or self.bridge_log != public.bridge_log) return error.InvalidRv64ServiceSetup;
        for (self.secp, public.secp.groups()) |actual, expected| {
            if ((actual != null) != (expected.roster == .present)) return error.InvalidSecpSourceShape;
            if (actual) |geometry| if (!std.meta.eql(geometry, expected.geometry)) return error.InvalidSecpSourceShape;
        }
    }
};
pub const PreparedMaterials = struct {
    base: Full.PreparedMaterials,
    division_log: u32,
    keccak_log: u32,
    bridge_log: u32,
    division_fixed: ?[]M,
    multiplication_fixed: ?[]M,
    multiplication_log: u32,
    crypto: ?Sources.Materials,
    secp: SecpCtx.Materials,
    pub fn init(a: std.mem.Allocator, public: Public) !PreparedMaterials {
        return initBase(a, public, null);
    }
    /// Authority outlives these geometry materials and every borrowed trace.
    pub fn initWithAuthority(a: std.mem.Allocator, public: Public, authority: *const Full.ProgramAuthority) !PreparedMaterials {
        return initBase(a, public, authority);
    }
    fn initBase(a: std.mem.Allocator, public: Public, authority: ?*const Full.ProgramAuthority) !PreparedMaterials {
        if (authority) |owner| {
            try Full.validateAuthorityProgram(owner, public.statement.program);
            try public.validateWithAdmittedOpcodes(&owner.opcodes);
        } else try public.validate();
        if (authority) |value| if (value.profile != public.execution_profile or value.control_policy != public.control_policy) return error.InvalidRv64ServiceSetup;
        var base = if (authority) |value| try Full.PreparedMaterials.initWithAuthority(a, public.statement, public.arithmetic_policy, public.state_policy, value) else try Full.PreparedMaterials.initWithControl(a, public.statement, public.arithmetic_policy, public.execution_profile, public.state_policy, public.control_policy);
        errdefer base.deinit();
        const division_fixed = if (public.division_roster == .present) try D.trace.fixedColumns(a, public.division_requests, public.division_log) else null;
        errdefer if (division_fixed) |fixed| a.free(fixed);
        const multiplication_fixed = if (public.arithmetic_policy == .division_multiplication_services_v3 and public.multiplication_roster == .present) try Mul.trace.fixedColumnsForLog(a, public.multiplication_log) else null;
        errdefer if (multiplication_fixed) |fixed| a.free(fixed);
        var crypto: ?Sources.Materials = if (public.roster == .paired) try Sources.Materials.init(a, public.keccak_log, public.bridge_log) else null;
        errdefer if (crypto) |*value| value.deinit();
        var secp = try SecpCtx.Materials.init(a, public.secp);
        errdefer secp.deinit();
        const self = PreparedMaterials{ .base = base, .division_log = public.division_log, .keccak_log = public.keccak_log, .bridge_log = public.bridge_log, .division_fixed = division_fixed, .multiplication_fixed = multiplication_fixed, .multiplication_log = public.multiplication_log, .crypto = crypto, .secp = secp };
        return self;
    }
    pub fn verificationGeometry(self: *const PreparedMaterials) VerificationGeometry {
        var groups: [2]?SecpCtx.Source.Geometry = .{ null, null };
        for (self.secp.groups, 0..) |group, i| if (group) |value| {
            groups[i] = value.geometry;
        };
        return .{ .log_size = self.base.log_size, .program_log = self.base.program.log_size, .program_identity = self.base.program.identity, .has_and = self.base.and_table != null, .has_shift = self.base.shift_table != null, .division_log = self.division_log, .multiplication_log = self.multiplication_log, .keccak_log = self.keccak_log, .bridge_log = self.bridge_log, .has_division = self.division_fixed != null, .has_multiplication = self.multiplication_fixed != null, .has_crypto = self.crypto != null, .secp = groups };
    }
    pub fn verificationView(self: *const PreparedMaterials) VerificationView {
        return self.verificationGeometry().view(&self.base.plan);
    }
    pub fn deinit(self: *PreparedMaterials) void {
        const a = self.base.allocator;
        if (self.division_fixed) |fixed| a.free(fixed);
        if (self.multiplication_fixed) |fixed| a.free(fixed);
        if (self.crypto) |*value| value.deinit();
        self.secp.deinit();
        self.base.deinit();
        self.* = undefined;
    }
    /// Hint only: receivers still derive materials/root from expected program.
    /// Counts, IDs and execution endpoints intentionally do not enter this key.
    pub fn cacheIdentity(self: *const PreparedMaterials, root: [32]u8) [32]u8 {
        const H = if (@hasDecl(std.crypto.hash, "Blake2s256")) std.crypto.hash.Blake2s256 else std.crypto.hash.blake2.Blake2s256;
        var hash = H.init(.{});
        hash.update("stwo-zig/rv64/keccak-cpu-setup/v1\x00");
        hash.update(&self.base.program.identity);
        hash.update(&root);
        if (self.multiplication_fixed != null) {
            var bytes: [4]u8 = undefined;
            std.mem.writeInt(u32, &bytes, self.multiplication_log, .little);
            hash.update("mul-v1\x00");
            hash.update(&bytes);
        }
        if (self.division_fixed == null) hash.update("division-none-v1\x00");
        if (self.base.plan.arithmetic_policy == .division_multiplication_services_v3 and self.multiplication_fixed == null) hash.update("multiplication-none-v1\x00");
        if (self.crypto == null) hash.update("roster-none\x00");
        if (self.base.plan.state_policy != .inverse_v1) {
            var bytes: [4]u8 = undefined;
            std.mem.writeInt(u32, &bytes, @intFromEnum(self.base.plan.state_policy), .little);
            hash.update(&bytes);
        }
        for ([_]u32{ self.base.log_size, self.division_log, self.keccak_log, self.bridge_log, @intFromEnum(self.base.plan.arithmetic_policy), @intFromEnum(self.base.plan.execution_profile) }) |value| {
            var bytes: [4]u8 = undefined;
            std.mem.writeInt(u32, &bytes, value, .little);
            hash.update(&bytes);
        }
        if (self.base.plan.execution_profile != .keccak_service_v1) {
            hash.update("secp-roster-v1\x00");
            for (self.secp.groups) |g| {
                const words: [4]u32 = if (g) |value| .{ 1, value.geometry.product_log, value.geometry.linear_log, value.geometry.bridge_log } else .{ 0, 5, 5, 5 };
                for (words) |value| {
                    var bytes: [4]u8 = undefined;
                    std.mem.writeInt(u32, &bytes, value, .little);
                    hash.update(&bytes);
                }
            }
        }
        var allowed: [65]u8 = undefined;
        for (&allowed, self.base.plan.allowed_opcodes) |*byte, yes| byte.* = @intFromBool(yes);
        hash.update(&allowed);
        var result: [32]u8 = undefined;
        hash.final(&result);
        return result;
    }
    pub fn validate(self: *const PreparedMaterials, public: Public) !void {
        if (self.base.plan.control_policy != public.control_policy) return error.InvalidRv64ServiceSetup;
        try public.validate();
        try S.validateSetup(&self.base, public.statement);
        try self.secp.validate(public.secp);
        if ((self.division_fixed != null) != (public.division_roster == .present) or (self.multiplication_fixed != null) != (public.arithmetic_policy == .division_multiplication_services_v3 and public.multiplication_roster == .present) or (self.crypto != null) != (public.roster == .paired) or self.base.plan.state_policy != public.state_policy or self.base.plan.execution_profile != public.execution_profile or self.base.plan.arithmetic_policy != public.arithmetic_policy or self.multiplication_log != public.multiplication_log or self.division_log != public.division_log or self.keccak_log != public.keccak_log or self.bridge_log != public.bridge_log) return error.InvalidRv64ServiceSetup;
    }
    pub fn fixedColumns(self: *const PreparedMaterials, a: std.mem.Allocator) ![]Column {
        const base = try self.base.fixedColumns(a);
        defer a.free(base);
        const out = try a.alloc(Column, base.len + (if (self.division_fixed != null) @as(usize, D.layout.FIXED) else 0) + (if (self.multiplication_fixed != null) @as(usize, Mul.layout.FIXED) else 0) + (if (self.crypto != null) @as(usize, Sources.FIXED) else 0) + self.secp.count() * SecpCtx.Source.FIXED);
        @memcpy(out[0..base.len], base);
        var at = base.len;
        if (self.division_fixed) |fixed| append(out, &at, fixed, self.division_log);
        if (self.multiplication_fixed) |fixed| append(out, &at, fixed, self.multiplication_log);
        if (self.crypto) |*value| value.appendFixed(out, &at);
        try self.secp.appendFixed(out, &at);
        return out;
    }
    pub fn logs(self: *const PreparedMaterials, a: std.mem.Allocator, public: Public, tree: u2) ![]u32 {
        const cpu_main = self.base.plan.main_count + rv.full.frame.widthWithControl(public.execution_profile, public.control_policy);
        // Component shape depends on geometry/policy, never on witness claims.
        const q = Q.one();
        const absent = rv.providers.tables.Challenges{ .offset = q, .coefficients = @splat(Q.zero()) };
        const ch = Challenges{ .secp = if (self.base.plan.execution_profile != .keccak_service_v1) .{ .arithmetic = .{ .polynomial = q, .bytes = q, .wire = .{ .offset = q, .coefficients = @splat(Q.zero()) } }, .call = .{ .offset = q, .coefficients = @splat(Q.zero()) }, .ram = .{ .offset = q, .coefficients = @splat(Q.zero()) } } else null, .multiplication = if (self.base.plan.arithmetic_policy == .division_multiplication_services_v3) .{ .offset = q, .coefficients = @splat(Q.zero()) } else null, .cpu = .{ .state = .{ .offset = q, .coefficients = @splat(Q.zero()) }, .rom = .{ .offset = q, .coefficients = @splat(Q.zero()) }, .bytes = q, .bitwise = absent, .shifts = absent }, .division = .{ .offset = q, .coefficients = @splat(Q.zero()) }, .keccak = .{ .chi = .{ .offset = q, .coefficients = @splat(Q.zero()) }, .xor5 = .{ .offset = q, .coefficients = @splat(Q.zero()) }, .io = .{ .offset = q, .coefficients = @splat(Q.zero()) } }, .bridge = .{ .io = .{ .offset = q, .coefficients = @splat(Q.zero()) }, .call = .{ .offset = q, .coefficients = @splat(Q.zero()) }, .ram = .{ .offset = q, .coefficients = @splat(Q.zero()) }, .bytes = q } };
        const z = Q.zero();
        const components = try Components.init(self, public, .{ .cpu = .{ .state = z, .rom = z, .bytes = z, .bitwise = z, .shifts = z }, .division = z, .header = z, .permutation = z, .chi = z, .xor5 = z, .bridge = z, .bytes = z }, ch);
        const base_count = if (tree == 1) cpu_main else components.base.cpu.interactionCount();
        const dc: usize = if (self.division_fixed == null) 0 else if (tree == 1) D.layout.MAIN else D.layout.INTERACTION;
        const kc: usize = if (tree == 1) K.layout.MAIN else K.layout.INTERACTION;
        const tc: usize = if (tree == 1) 1 else 4;
        const bc: usize = if (tree == 1) Bridge.layout.MAIN else Bridge.layout.INTERACTION;
        const pc: usize = if (tree == 1) 1 else 8;
        const out = try a.alloc(u32, base_count + self.base.providerCount() * pc + dc + (if (self.multiplication_fixed != null) @as(usize, if (tree == 1) Mul.layout.MAIN else Mul.layout.INTERACTION) else 0) + (if (self.crypto != null) kc + 2 * tc + bc else 0) + self.secp.count() * @as(usize, if (tree == 1) SecpCtx.Source.MAIN else SecpCtx.Source.INTERACTION));
        var at: usize = 0;
        fill(out, &at, base_count, self.base.log_size);
        fill(out, &at, pc, self.base.program.log_size);
        fill(out, &at, pc, 8);
        if (self.base.and_table != null) fill(out, &at, pc, 16);
        if (self.base.shift_table != null) fill(out, &at, pc, 11);
        fill(out, &at, dc, self.division_log);
        if (self.multiplication_fixed != null) fill(out, &at, if (tree == 1) Mul.layout.MAIN else Mul.layout.INTERACTION, self.multiplication_log);
        if (self.crypto != null) {
            fill(out, &at, kc, self.keccak_log);
            fill(out, &at, tc, 13);
            fill(out, &at, tc, 10);
            fill(out, &at, bc, self.bridge_log);
        }
        try self.secp.appendLogs(out, &at, tree);
        std.debug.assert(at == out.len);
        return out;
    }
};
pub const PreparedSetup = struct {
    materials: PreparedMaterials,
    root: [32]u8,
    pub fn init(a: std.mem.Allocator, public: Public) !PreparedSetup {
        var materials = try PreparedMaterials.init(a, public);
        errdefer materials.deinit();
        const fixed = try materials.fixedColumns(a);
        defer a.free(fixed);
        var scheme = try Scheme.init(a, P.config());
        defer scheme.deinit(a);
        var channel = P.Channel{};
        try scheme.commitBorrowedStreaming(a, fixed, 8, &channel);
        var roots = try scheme.roots(a);
        defer roots.deinit(a);
        return .{ .materials = materials, .root = roots.items[0] };
    }
    pub fn deinit(self: *PreparedSetup) void {
        self.materials.deinit();
        self.* = undefined;
    }
    pub fn cacheIdentity(self: *const PreparedSetup) [32]u8 {
        return self.materials.cacheIdentity(self.root);
    }
    pub fn verifyOwned(owner: *const PreparedSetup, a: std.mem.Allocator, public: Public, claims: Claims, proof_value: P.Proof) !void {
        const self = &owner.materials;
        var proof = proof_value;
        var owns = true;
        defer if (owns) proof.deinit(a);
        try self.validate(public);
        const pcs = &proof.commitment_scheme_proof;
        if (!std.meta.eql(pcs.config, P.config()) or pcs.revision_config != null or pcs.commitments.items.len != 4) return error.InvalidRv64ServiceConfig;
        if (!std.mem.eql(u8, &pcs.commitments.items[0], &owner.root)) return error.Rv64ServiceFixedRootMismatch;
        var verifier = try Verifier.init(a, P.config());
        defer verifier.deinit(a);
        var channel = P.Channel{};
        try mixPublic(&channel, self, public);
        const fixed = try self.fixedColumns(a);
        defer a.free(fixed);
        const fixed_logs = try a.alloc(u32, fixed.len);
        defer a.free(fixed_logs);
        for (fixed, fixed_logs) |column, *log| log.* = column.log_size;
        const main_logs = try self.logs(a, public, 1);
        defer a.free(main_logs);
        try verifier.commit(a, pcs.commitments.items[0], fixed_logs, &channel);
        try verifier.commit(a, pcs.commitments.items[1], main_logs, &channel);
        const ch = draw(&channel, self);
        try validateClaims(self, public, claims, ch);
        var components = try Components.init(self, public, claims, ch);
        const inter_logs = try self.logs(a, public, 2);
        defer a.free(inter_logs);
        mixClaims(&channel, claims, public);
        try verifier.commit(a, pcs.commitments.items[2], inter_logs, &channel);
        var handles: [MAX_COMPONENTS]core.air.components.Component = undefined;
        const n = components.verifiers(&handles);
        owns = false;
        try core.verifier.verify(P.Hasher, P.MerkleChannel, a, handles[0..n], &channel, &verifier, proof);
    }
};

pub const Trace = struct {
    cpu: Full.Trace,
    division: ?D.trace.Trace,
    indexed: []D.cpu_bus.IndexedRequest,
    multiplication: ?Mul.trace.Trace,
    multiplication_indexed: []Mul.cpu_bus.IndexedRequest,
    crypto: ?Sources.Trace,
    secp: SecpCtx.Trace,
    secp_headers: []Secp.cpu_bus.Call,
    pub fn init(a: std.mem.Allocator, records: []const frontend.rv64.machine.Retirement, calls: []const frontend.rv64.services.Call, public: Public, setup: *const PreparedMaterials) !Trace {
        try setup.validate(public);
        if (calls.len != public.keccak_calls) return error.InvalidRv64ServiceCallCount;
        if (public.execution_profile != .keccak_service_v1) return error.InvalidRv64ServiceConstructor;
        var cpu = try Full.Trace.initWithServiceCalls(a, records, calls, public.first_call_id, public.statement, &setup.base.program, &setup.base.plan);
        errdefer cpu.deinit();
        return fromCpu(a, cpu, public, setup);
    }
    pub fn initEthereum(a: std.mem.Allocator, records: []const frontend.rv64.machine.Retirement, calls: Full.Trace.CallBatch, public: Public, setup: *const PreparedMaterials) !Trace {
        try setup.validate(public);
        if (public.execution_profile == .keccak_service_v1 or calls.keccak.len != public.keccak_calls or calls.first_keccak != public.first_call_id or !std.mem.eql(u32, &calls.first_secp, &public.secp.firstIds())) return error.InvalidRv64ServiceConstructor;
        var cpu = try Full.Trace.initWithEthereumCalls(a, records, calls, public.statement, &setup.base.program, &setup.base.plan);
        errdefer cpu.deinit();
        return fromCpu(a, cpu, public, setup);
    }
    pub fn initCompact(a: std.mem.Allocator, tape: *const frontend.rv64.compact_tape.Tape, public: Public, setup: *const PreparedMaterials) !Trace {
        try setup.validate(public);
        if (tape.service_calls.items.len != public.keccak_calls) return error.InvalidRv64ServiceCallCount;
        var cpu = if (public.execution_profile == .keccak_service_v1) try Full.Trace.initWithCompactTape(a, tape, public.first_call_id, public.statement, &setup.base.program, &setup.base.plan) else try Full.Trace.initWithEthereumTape(a, tape, public.first_call_id, public.secp.firstIds(), public.statement, &setup.base.program, &setup.base.plan);
        errdefer cpu.deinit();
        return fromCpu(a, cpu, public, setup);
    }
    /// Consumes CPU ownership on success; caller retains it on failure.
    pub fn fromCpu(a: std.mem.Allocator, cpu: Full.Trace, public: Public, setup: *const PreparedMaterials) !Trace {
        return fromCpuStorage(a, cpu, public, setup, null);
    }
    /// CPU ownership transfers only on success. Every supplied main vector
    /// remains caller-owned; metadata/fixed/interactions use the real allocator.
    pub fn fromCpuBorrowed(a: std.mem.Allocator, cpu: Full.Trace, public: Public, setup: *const PreparedMaterials, buffers: BorrowedMain) !Trace {
        try buffers.validate(a, &cpu, public, setup);
        return fromCpuStorage(a, cpu, public, setup, buffers);
    }
    fn fromCpuStorage(a: std.mem.Allocator, cpu: Full.Trace, public: Public, setup: *const PreparedMaterials, borrowed: ?BorrowedMain) !Trace {
        const indexed = try cpu.divisionRequests(a);
        errdefer a.free(indexed);
        if (indexed.len != public.division_requests) return error.InvalidRv64ServiceDivisionCount;
        const requests = try a.alloc(D.trace.Request, indexed.len);
        defer a.free(requests);
        for (indexed, requests) |request, *out| out.* = request.request;
        var division: ?D.trace.Trace = if (public.division_roster == .present) (if (borrowed) |buffers| try D.trace.Trace.initWithBorrowedMain(a, requests, setup.division_log, buffers.arithmetic.division.?) else try D.trace.Trace.initWithLog(a, requests, setup.division_log)) else null;
        errdefer if (division) |*value| value.deinit();
        const multiplication_indexed: []Mul.cpu_bus.IndexedRequest = if (public.arithmetic_policy == .division_multiplication_services_v3) try cpu.multiplicationRequests(a) else &.{};
        errdefer a.free(multiplication_indexed);
        if (multiplication_indexed.len != public.multiplication_requests) return error.InvalidRv64ServiceMultiplicationCount;
        var multiplication: ?Mul.trace.Trace = null;
        if (public.arithmetic_policy == .division_multiplication_services_v3 and public.multiplication_roster == .present) {
            const plain = try a.alloc(Mul.trace.Request, multiplication_indexed.len);
            defer a.free(plain);
            for (multiplication_indexed, plain) |indexed_request, *output| output.* = indexed_request.request;
            multiplication = if (borrowed) |buffers| try Mul.trace.Trace.initWithBorrowedMain(a, plain, public.multiplication_log, buffers.arithmetic.multiplication.?) else try Mul.trace.Trace.initWithLog(a, plain, public.multiplication_log);
        }
        errdefer if (multiplication) |*value| value.deinit();
        const calls: [2][]const SecpCtx.Source.Call = if (cpu.secp) |journal| .{ journal.rows[0], journal.rows[1] } else .{ &.{}, &.{} };
        var secp = if (borrowed) |buffers| try SecpCtx.Trace.initPreparedWithMainBuffers(a, &setup.secp, calls, public.secp, public.execution_profile, buffers.secp) else try SecpCtx.Trace.initPrepared(a, &setup.secp, calls, public.secp, public.execution_profile);
        errdefer secp.deinit();
        const secp_headers = try SecpCtx.headers(a, calls);
        errdefer a.free(secp_headers);
        return .{ .secp = secp, .secp_headers = secp_headers, .cpu = cpu, .division = division, .indexed = indexed, .multiplication = multiplication, .multiplication_indexed = multiplication_indexed, .crypto = if (public.roster == .paired) (if (borrowed) |buffers| try Sources.Trace.initWithMainBuffers(a, cpu.service_calls, public.first_call_id, public.keccak_log, public.bridge_log, buffers.keccak.?) else try Sources.Trace.init(a, cpu.service_calls, public.first_call_id, public.keccak_log, public.bridge_log)) else null };
    }
    pub fn deinit(self: *Trace) void {
        self.cpu.allocator.free(self.indexed);
        self.cpu.allocator.free(self.secp_headers);
        self.secp.deinit();
        self.cpu.allocator.free(self.multiplication_indexed);
        if (self.multiplication) |*value| value.deinit();
        if (self.crypto) |*value| value.deinit();
        if (self.division) |*value| value.deinit();
        self.cpu.deinit();
        self.* = undefined;
    }
};
const Components = struct {
    base: S.SharedComponents,
    division: ?D.component.Component,
    multiplication: ?Mul.component.Component = null,
    permutation: ?K.component.Component = null,
    chi: ?K.component.Component = null,
    xor5: ?K.component.Component = null,
    bridge: ?Bridge.component.Component = null,
    secp: [2]?SecpCtx.Source.Components = .{ null, null },
    /// A stage recorder is a serial hierarchy, never a shared worker sink.
    /// Bind stable private owners before launch and clear after the final join.
    pub fn setPrivateRecorders(self: *Components, owner: ?*@import("rv64_component_profiles.zig").Group) void {
        const Group = @import("rv64_component_profiles.zig").Group;
        self.base.cpu.stage_recorder = Group.next(owner);
        if (self.permutation) |*value| value.stage_recorder = Group.next(owner);
        if (self.chi) |*value| value.stage_recorder = Group.next(owner);
        if (self.xor5) |*value| value.stage_recorder = Group.next(owner);
        if (self.bridge) |*value| value.stage_recorder = Group.next(owner);
        for (&self.secp) |*group| if (group.*) |*value| {
            value.product.stage_recorder = Group.next(owner);
            value.linear.stage_recorder = Group.next(owner);
            value.bridge.stage_recorder = Group.next(owner);
        };
    }
    pub fn init(setup: *const PreparedMaterials, public: Public, claims: Claims, ch: Challenges) !Components {
        return initView(setup.verificationView(), public, claims, ch);
    }
    pub fn initView(setup: VerificationView, public: Public, claims: Claims, ch: Challenges) !Components {
        var base = try S.SharedComponents.initWithAllServicesView(setup.base, public.statement, ch.cpu, claims.cpu, .{ .challenges = ch.division, .claim = claims.division }, .{ .challenges = ch.bridge.call, .claim = claims.header, .calls = public.keccak_calls, .first_call_id = public.first_call_id }, if (ch.multiplication) |challenge| .{ .challenges = challenge, .claim = claims.multiplication } else null, if (ch.secp) |challenge| .{ .calls = public.secp.counts(), .first_ids = public.secp.firstIds(), .execution_profile = public.execution_profile, .challenges = challenge.call, .claim = claims.secp_header } else null);
        base.bytes.claim = claims.bytes;
        var f = setup.base.fixedCount();
        var m = base.cpu.mainCount() + setup.base.providerCount();
        var i = base.cpu.interactionCount() + 8 * setup.base.providerCount();
        var division: ?D.component.Component = null;
        if (setup.has_division) {
            division = .{ .log_size = setup.division_log, .count = public.division_requests, .fixed_offset = f, .main_offset = m, .interaction_offset = i, .challenges = ch.division, .claim = claims.division.neg() };
            f += D.layout.FIXED;
            m += D.layout.MAIN;
            i += D.layout.INTERACTION;
        }
        var multiplication: ?Mul.component.Component = null;
        if (setup.has_multiplication) {
            const challenge = ch.multiplication orelse return error.InvalidRv64ServiceArithmetic;
            multiplication = .{ .log_size = setup.multiplication_log, .count = public.multiplication_requests, .fixed_offset = f, .main_offset = m, .interaction_offset = i, .challenges = challenge, .byte_alpha = rv.range.cpu.PreparedAlpha.init(ch.cpu.bytes), .claim = claims.multiplication_provider };
            f += Mul.layout.FIXED;
            m += Mul.layout.MAIN;
            i += Mul.layout.INTERACTION;
        }
        var result = Components{ .base = base, .division = division, .multiplication = multiplication };
        if (public.roster == .none) {
            try result.initSecp(setup, public, ch, claims, .{ .fixed = f, .main = m, .interaction = i });
            return result;
        }
        const permutation = K.component.Component{ .kind = .permutation, .calls = public.keccak_calls, .first_call_id = public.first_call_id, .log_size = setup.keccak_log, .challenges = ch.keccak, .claim = claims.permutation, .offsets = .{ .fixed = f, .main = m, .interaction = i } };
        f += K.layout.FIXED;
        m += K.layout.MAIN;
        i += K.layout.INTERACTION;
        const chi = K.component.Component{ .kind = .chi, .log_size = 13, .challenges = ch.keccak, .claim = claims.chi, .offsets = .{ .fixed = f, .main = m, .interaction = i } };
        f += 7;
        m += 1;
        i += 4;
        const xor5 = K.component.Component{ .kind = .xor5, .log_size = 10, .challenges = ch.keccak, .claim = claims.xor5, .offsets = .{ .fixed = f, .main = m, .interaction = i } };
        f += 7;
        m += 1;
        i += 4;
        result.permutation = permutation;
        result.chi = chi;
        result.xor5 = xor5;
        result.bridge = .{ .calls = public.keccak_calls, .first_call_id = public.first_call_id, .log_size = setup.bridge_log, .challenges = ch.bridge, .claim = claims.bridge, .offsets = .{ .fixed = f, .main = m, .interaction = i } };
        try result.initSecp(setup, public, ch, claims, .{ .fixed = f + Bridge.layout.FIXED, .main = m + Bridge.layout.MAIN, .interaction = i + Bridge.layout.INTERACTION });
        return result;
    }
    fn initSecp(self: *Components, setup: VerificationView, public: Public, ch: Challenges, claims: Claims, initial: SecpCtx.Source.Offsets) !void {
        var at = initial;
        for (setup.secp, public.secp.groups(), [_]SecpCtx.Claims{ claims.secp_add, claims.secp_double }, 0..) |material, g, c, k| if (material != null) {
            self.secp[k] = try SecpCtx.Source.Components.init(if (k == 0) .add else .double, g.geometry, g.calls, g.first_id, if (public.execution_profile == .ethereum_services_v1) .big_endian_bytes_v1 else .little_endian_words_v2, at, ch.secp orelse return error.InvalidRv64SecpMetadata, c.source());
            at.fixed += SecpCtx.Source.FIXED;
            at.main += SecpCtx.Source.MAIN;
            at.interaction += SecpCtx.Source.INTERACTION;
        };
    }
    pub fn provers(self: *const Components, out: *[MAX_COMPONENTS]engine.air.component_prover.ComponentProver) usize {
        var n = self.base.proverHandles(out[0..5]);
        if (self.division) |*component| {
            out[n] = component.asProverComponent();
            n += 1;
        }
        if (self.multiplication) |*component| {
            out[n] = component.asProverComponent();
            n += 1;
        }
        if (self.permutation) |*component| {
            out[n] = component.asProverComponent();
            n += 1;
        }
        if (self.chi) |*component| {
            out[n] = component.asProverComponent();
            n += 1;
        }
        if (self.xor5) |*component| {
            out[n] = component.asProverComponent();
            n += 1;
        }
        if (self.bridge) |*component| {
            out[n] = component.asProverComponent();
            n += 1;
        }
        for (&self.secp) |*component| if (component.*) |*value| {
            value.appendProver(out, &n) catch unreachable;
        };
        return n;
    }
    pub fn verifiers(self: *const Components, out: *[MAX_COMPONENTS]core.air.components.Component) usize {
        var n = self.base.verifierHandles(out[0..5]);
        if (self.division) |*component| {
            out[n] = component.asVerifierComponent();
            n += 1;
        }
        if (self.multiplication) |*component| {
            out[n] = component.asVerifierComponent();
            n += 1;
        }
        if (self.permutation) |*component| {
            out[n] = component.asVerifierComponent();
            n += 1;
        }
        if (self.chi) |*component| {
            out[n] = component.asVerifierComponent();
            n += 1;
        }
        if (self.xor5) |*component| {
            out[n] = component.asVerifierComponent();
            n += 1;
        }
        if (self.bridge) |*component| {
            out[n] = component.asVerifierComponent();
            n += 1;
        }
        for (&self.secp) |*component| if (component.*) |*value| {
            value.appendVerifier(out, &n) catch unreachable;
        };
        return n;
    }
};
fn append(out: []Column, at: *usize, storage: []const M, log: u32) void {
    const count = storage.len >> @intCast(log);
    S.append(out[at.*..][0..count], storage, log);
    at.* += count;
}
fn fill(out: []u32, at: *usize, count: usize, log: u32) void {
    @memset(out[at.*..][0..count], log);
    at.* += count;
}
fn physical(a: std.mem.Allocator, setup: *const PreparedMaterials, public: Public, trace: *Trace) !void {
    try setup.validate(public);
    try trace.cpu.validateCommitAllocator(a);
    if (trace.cpu.log_size != setup.base.log_size) return error.InvalidRv64ServiceTracePhase;
    if (trace.cpu.main.len != (setup.base.plan.main_count + rv.full.frame.widthWithControl(public.execution_profile, public.control_policy)) * (@as(usize, 1) << @intCast(setup.base.log_size)) or
        (trace.crypto != null) != (public.roster == .paired)) return error.InvalidRv64ServiceTracePhase;
    if (trace.crypto) |*value| {
        if (value.permutation.log_size != setup.keccak_log or value.permutation.first_call_id != public.first_call_id or value.permutation.calls != public.keccak_calls or value.permutation.main.len != K.layout.MAIN * (@as(usize, 1) << @intCast(setup.keccak_log)) or value.bridge.log_size != setup.bridge_log or value.bridge.first_id != public.first_call_id or value.bridge.calls != public.keccak_calls or value.bridge.main.len != Bridge.layout.MAIN * (@as(usize, 1) << @intCast(setup.bridge_log)) or value.chi.main.len != 8192 or value.xor5.main.len != 1024) return error.InvalidRv64ServiceTracePhase;
    }
    if ((trace.division != null) != (setup.division_fixed != null)) return error.InvalidRv64ServiceTracePhase;
    if (trace.division) |*value| {
        if (!rv.memory.private_trace.sameAllocator(value.allocator, a)) return error.Rv64FullCommitAllocatorMismatch;
        if (value.log_size != setup.division_log or value.main.len != D.layout.MAIN * (@as(usize, 1) << @intCast(setup.division_log)) or value.count != public.division_requests) return error.InvalidRv64ServiceTracePhase;
    }
    if ((trace.multiplication != null) != (setup.multiplication_fixed != null)) return error.InvalidRv64ServiceTracePhase;
    if (trace.multiplication) |*value| {
        if (!rv.memory.private_trace.sameAllocator(value.allocator, a)) return error.Rv64FullCommitAllocatorMismatch;
        if (value.log_size != setup.multiplication_log or value.count != public.multiplication_requests or value.main.len != Mul.layout.MAIN * value.domainSize()) return error.InvalidRv64ServiceTracePhase;
    }
    for (&trace.secp.groups, public.secp.groups(), 0..) |*group, expected, k| {
        if ((group.* != null) != (expected.roster == .present)) return error.InvalidRv64ServiceTracePhase;
        if (group.*) |*value| {
            try value.validateMain();
            if (value.kind != (if (k == 0) SecpCtx.Source.Kind.add else SecpCtx.Source.Kind.double) or value.calls != expected.calls or value.first_id != expected.first_id or !std.meta.eql(value.geometry, expected.geometry) or value.format != (if (public.execution_profile == .ethereum_services_v1) SecpCtx.Source.Format.big_endian_bytes_v1 else SecpCtx.Source.Format.little_endian_words_v2)) return error.InvalidRv64ServiceTracePhase;
        }
    }
    if (trace.cpu.plan.control_policy != public.control_policy or trace.cpu.plan.arithmetic_policy != public.arithmetic_policy or trace.cpu.plan.state_policy != public.state_policy or trace.cpu.plan.execution_profile != public.execution_profile) return error.InvalidRv64ServiceTrace;
}
pub fn proveTrace(a: std.mem.Allocator, owner: *const PreparedSetup, public: Public, trace: *Trace) !Bundle {
    const setup = &owner.materials;
    try physical(a, setup, public, trace);
    var channel = P.Channel{};
    try mixPublic(&channel, setup, public);
    var scheme = try Scheme.init(a, P.config());
    scheme.setCompactPolynomialStorage(5);
    var owns_scheme = true;
    errdefer if (owns_scheme) scheme.deinit(a);
    const fixed = try setup.fixedColumns(a);
    defer a.free(fixed);
    try scheme.commitBorrowedStreaming(a, fixed, 8, &channel);
    var sources = try Support.ProvingSources.init(a, setup, public, trace, null);
    defer sources.deinit();
    const main = try sources.mainColumns();
    defer a.free(main);
    try scheme.commitBorrowedStreaming(a, main, 8, &channel);
    try sources.releaseMain();
    // Every main tree is sealed before any shared lookup challenge.
    const ch = draw(&channel, setup);
    const claims = try sources.generate(ch);
    try validateClaims(setup, public, claims, ch);
    var components = try Components.init(setup, public, claims, ch);
    const columns = try sources.interactionColumns();
    defer a.free(columns);
    mixClaims(&channel, claims, public);
    try scheme.commitBorrowedStreaming(a, columns, 8, &channel);
    var handles: [MAX_COMPONENTS]engine.air.component_prover.ComponentProver = undefined;
    const n = components.provers(&handles);
    owns_scheme = false;
    return .{ .claims = claims, .proof = try engine.prove.prove(B, P.Hasher, P.MerkleChannel, a, handles[0..n], &channel, scheme) };
}
/// Concrete source headers. Main remains trace-owned across commitment;
/// crypto interaction needs these rows after challenge drawing.
fn mainColumns(a: std.mem.Allocator, trace: *const Trace, providers: []const Column) ![]Column {
    const count = trace.cpu.main.len / trace.cpu.domainSize() + providers.len + (if (trace.division != null) @as(usize, D.layout.MAIN) else 0) + (if (trace.multiplication != null) @as(usize, Mul.layout.MAIN) else 0) + (if (trace.crypto != null) @as(usize, Sources.MAIN) else 0) + (if (trace.secp.groups[0] != null) @as(usize, SecpCtx.Source.MAIN) else 0) + (if (trace.secp.groups[1] != null) @as(usize, SecpCtx.Source.MAIN) else 0);
    const columns = try a.alloc(Column, count);
    errdefer a.free(columns);
    var at: usize = 0;
    append(columns, &at, trace.cpu.main, trace.cpu.log_size);
    @memcpy(columns[at..][0..providers.len], providers);
    at += providers.len;
    if (trace.division) |*value| append(columns, &at, value.main, value.log_size);
    if (trace.multiplication) |*value| append(columns, &at, value.main, value.log_size);
    if (trace.crypto) |*value| value.appendMain(columns, &at);
    try trace.secp.appendMain(columns, &at);
    return columns;
}

/// Concrete plumbing for the authenticated-RAM caller. No aggregate closure is
/// hidden here: the outer caller adds typed RAM effects and checks registers.
pub const Support = struct {
    pub const ProvingSources = @import("rv64_service_proving_sources.zig").ProvingSources;
    pub const MAX_COMPONENTS = This.MAX_COMPONENTS;
    pub const SecpContext = SecpCtx;
    pub const Challenges = This.Challenges;
    pub const Components = This.Components;
    pub const draw = This.draw;
    pub const drawView = This.drawView;
    pub const mixPublic = This.mixPublic;
    pub const mixPublicView = This.mixPublicView;
    pub const mixClaims = This.mixClaims;
    pub const validateEncoding = This.validateEncoding;
    pub const validateEncodingView = This.validateEncodingView;
    pub const effect = This.effect;
    pub const physical = This.physical;
    pub const mainColumns = This.mainColumns;
    pub const append = This.append;
    pub const fill = This.fill;
};
