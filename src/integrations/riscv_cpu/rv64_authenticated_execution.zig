//! One concrete CPU/crypto/private-RAM PCS statement. Physical state and range
//! obligations close in this transcript; standalone component receipts cannot
//! substitute for this join. Whole-execution adjacency is a separate receiver.
const std = @import("std");
pub const core = @import("stwo_core");
pub const engine = @import("stwo_prover_engine");
pub const frontend = @import("stwo_riscv_frontend");
pub const rv = frontend.rv64_air;
pub const CPU = @import("rv64_keccak_cpu.zig");
pub const RAM = @import("rv64_ram_private.zig");
pub const Full = @import("rv64_full.zig");
pub const CS = CPU.Support;
pub const R = rv.memory;
pub const I = R.private_interaction;
pub const T = R.private_trace;
pub const P = rv.protocol;
pub const B = Full.Support.Backend;
pub const Q = core.fields.qm31.QM31;
pub const Column = engine.pcs.ColumnEvaluation;
pub const Scheme = engine.pcs.CommitmentSchemeProver(B, P.Hasher, P.MerkleChannel);
const Verifier = core.pcs.verifier.CommitmentSchemeVerifier(P.Hasher, P.MerkleChannel);
/// Immutable component geometry is admitted before any wide witness exists.
/// RAM roots/endpoints remain request/transcript data, never setup authority.
pub const Layout = struct {
    cpu: CPU.Public,
    geometry: R.values.Geometry,
    policy_identity: [32]u8,
    ram: ?RAM.Counts,
    pub fn validate(self: Layout, expected_policy: *const R.policy.Policy) !void {
        return self.validateExpected(expected_policy, null);
    }
    pub fn validateWithAdmittedOpcodes(self: Layout, expected_policy: *const R.policy.Policy, admitted: *const [65]bool) !void {
        return self.validateExpected(expected_policy, admitted);
    }
    fn validateExpected(self: Layout, expected_policy: *const R.policy.Policy, admitted: ?*const [65]bool) !void {
        if (admitted) |known| try self.cpu.validateWithAdmittedOpcodes(known) else try self.cpu.validate();
        try expected_policy.validateImmutableExecution();
        if (!std.mem.eql(u8, &self.policy_identity, &expected_policy.identity) or self.cpu.statement.cells.len != 0 or self.cpu.statement.memory_clocks.len != 0) return error.InvalidAuthenticatedExecutionStatement;
        if (self.ram) |counts| _ = try counts.shapes(self.geometry);
        try self.admitRelations();
    }
    pub fn admitRelations(public: Layout) !void {
        var plan = try Full.planForStatementWithControl(public.cpu.statement, public.cpu.arithmetic_policy, public.cpu.execution_profile, public.cpu.control_policy);
        plan.setStatePolicy(public.cpu.state_policy);
        var mass = (@as(u64, 1) << @intCast(public.cpu.statement.logSize())) * plan.range_count;
        if (public.cpu.roster == .paired) mass = try std.math.add(u64, mass, 40 * (@as(u64, 1) << @intCast(public.cpu.bridge_log)));
        if (public.cpu.arithmetic_policy == .division_multiplication_services_v3 and public.cpu.multiplication_roster == .present) mass = try std.math.add(u64, mass, 96 * (@as(u64, 1) << @intCast(public.cpu.multiplication_log)));
        const secp_mass = try public.cpu.secp.validate(public.cpu.execution_profile, public.cpu.statement.steps);
        mass = try std.math.add(u64, mass, secp_mass.byte_queries);
        var state_mass = 62 + 8 * @as(u64, public.cpu.statement.steps) + 50 * @as(u64, public.cpu.keccak_calls) + secp_mass.ram_queries;
        if (public.ram) |counts| {
            const shape = try counts.shapes(public.geometry);
            if (try I.boundInternalMass(shape) >= core.fields.m31.Modulus) return error.AuthenticatedExecutionLookupMassExceeded;
            state_mass = try std.math.add(u64, state_mass, 2 * (@as(u64, shape.common_cells.size()) + shape.edge_cells.size()));
            mass = try std.math.add(u64, mass, try RAM.boundByteMass(shape));
        }
        if (mass >= core.fields.m31.Modulus or state_mass >= core.fields.m31.Modulus) return error.AuthenticatedExecutionLookupMassExceeded;
    }
};
pub const Public = struct {
    cpu: CPU.Public,
    geometry: R.values.Geometry,
    before: R.values.Digest,
    after: R.values.Digest,
    policy_identity: [32]u8,
    ram: ?RAM.Counts,
    pub fn layout(self: Public) Layout {
        return .{ .cpu = self.cpu, .geometry = self.geometry, .policy_identity = self.policy_identity, .ram = self.ram };
    }
    pub fn validate(self: Public, expected_policy: *const R.policy.Policy) !void {
        return self.validateExpected(expected_policy, null);
    }
    pub fn validateWithAdmittedOpcodes(self: Public, expected_policy: *const R.policy.Policy, admitted: *const [65]bool) !void {
        return self.validateExpected(expected_policy, admitted);
    }
    fn validateExpected(self: Public, expected_policy: *const R.policy.Policy, admitted: ?*const [65]bool) !void {
        if (admitted) |known| try self.layout().validateWithAdmittedOpcodes(expected_policy, known) else try self.layout().validate(expected_policy);
        for ([_]R.values.Digest{ self.before, self.after }) |digest| for (digest) |limb| if (limb >= core.fields.m31.Modulus) return error.NonCanonicalDigest;
        if (self.ram) |counts| {
            _ = try counts.shapes(self.geometry);
        } else if (!std.mem.eql(u32, &self.before, &self.after)) return error.UnchangedRamRootRequired;
    }
};
pub const Claims = struct { cpu: CPU.Claims, ram: ?RAM.Claims };
pub const Bundle = struct {
    claims: Claims,
    proof: P.Proof,
    pub fn deinit(self: *Bundle, a: std.mem.Allocator) void {
        self.proof.deinit(a);
        self.* = undefined;
    }
};
pub const Challenges = struct { cpu: CS.Challenges, ram: ?I.Challenges };
pub const VerificationView = struct { cpu: CPU.VerificationView, has_ram: bool };
pub const ReceiverKey = @import("rv64_execution_verifier_key.zig").ReceiverKey;
pub const Prepared = struct {
    allocator: std.mem.Allocator,
    cpu: CPU.PreparedMaterials,
    ram: ?RAM.Prepared,
    shapes: ?T.Shapes,
    policy: *const R.policy.Policy,
    root: [32]u8,
    pub fn init(a: std.mem.Allocator, public: Public, expected_policy: *const R.policy.Policy) !Prepared {
        return initBase(a, public, expected_policy, null);
    }
    pub fn initWithAuthority(a: std.mem.Allocator, public: Public, expected_policy: *const R.policy.Policy, authority: *const Full.ProgramAuthority) !Prepared {
        if (authority.profile != public.cpu.execution_profile) return error.InvalidAuthenticatedExecutionStatement;
        return initBase(a, public, expected_policy, authority);
    }
    fn initBase(a: std.mem.Allocator, public: Public, expected_policy: *const R.policy.Policy, authority: ?*const Full.ProgramAuthority) !Prepared {
        if (authority) |owner| {
            try Full.validateAuthorityProgram(owner, public.cpu.statement.program);
            try public.validateWithAdmittedOpcodes(expected_policy, &owner.opcodes);
        } else try public.validate(expected_policy);
        return initForLayout(a, public.layout(), expected_policy, authority);
    }
    /// No RAM root is needed to derive the independently sized fixed roster.
    pub fn initForLayout(a: std.mem.Allocator, public: Layout, expected_policy: *const R.policy.Policy, authority: ?*const Full.ProgramAuthority) !Prepared {
        if (authority) |owner| {
            try Full.validateAuthorityProgram(owner, public.cpu.statement.program);
            try public.validateWithAdmittedOpcodes(expected_policy, &owner.opcodes);
        } else try public.validate(expected_policy);
        if (authority) |value| if (value.profile != public.cpu.execution_profile) return error.InvalidAuthenticatedExecutionStatement;
        var cpu = if (authority) |value| try CPU.PreparedMaterials.initWithAuthority(a, public.cpu, value) else try CPU.PreparedMaterials.init(a, public.cpu);
        errdefer cpu.deinit();
        const shapes = if (public.ram) |counts| try counts.shapes(public.geometry) else null;
        var ram: ?RAM.Prepared = if (shapes) |shape| try RAM.Prepared.init(a, shape, expected_policy) else null;
        errdefer if (ram) |*value| value.deinit();
        var result = Prepared{ .allocator = a, .cpu = cpu, .ram = ram, .shapes = shapes, .policy = expected_policy, .root = undefined };
        const fixed = try result.fixedColumns(a);
        defer a.free(fixed);
        var scheme = try Scheme.init(a, P.config());
        defer scheme.deinit(a);
        var channel = P.Channel{};
        try scheme.commitBorrowedStreaming(a, fixed, 8, &channel);
        var roots = try scheme.roots(a);
        defer roots.deinit(a);
        result.root = roots.items[0];
        return result;
    }
    pub fn deinit(self: *Prepared) void {
        if (self.ram) |*value| value.deinit();
        self.cpu.deinit();
        self.* = undefined;
    }
    pub fn validate(self: *const Prepared, public: Public) !void {
        try public.validate(self.policy);
        try self.validateLayout(public.layout());
    }
    pub fn validateLayout(self: *const Prepared, public: Layout) !void {
        try public.validate(self.policy);
        try self.cpu.validate(public.cpu);
        if ((self.shapes != null) != (public.ram != null)) return error.InvalidAuthenticatedRamRoster;
        if (public.ram) |counts| if (!sameGeometry(self.shapes.?, try counts.shapes(public.geometry))) return error.InvalidAuthenticatedRamGeometry;
    }
    pub fn fixedColumns(self: *const Prepared, a: std.mem.Allocator) ![]Column {
        const cpu = try self.cpu.fixedColumns(a);
        defer a.free(cpu);
        const ram: []const Column = if (self.ram) |*value| value.columns() else &.{};
        return join(a, cpu, ram);
    }
    pub fn logs(self: *const Prepared, a: std.mem.Allocator, public: Public, tree: u2) ![]u32 {
        return self.logsForLayout(a, public.layout(), tree);
    }
    pub fn logsForLayout(self: *const Prepared, a: std.mem.Allocator, public: Layout, tree: u2) ![]u32 {
        const cpu = try self.cpu.logs(a, public.cpu, tree);
        defer a.free(cpu);
        const extra: usize = if (self.ram != null) (if (tree == 1) RAM.N_MAIN_WITHOUT_BYTE else RAM.N_INTERACTION_WITHOUT_BYTE) else 0;
        const result = try a.alloc(u32, cpu.len + extra);
        @memcpy(result[0..cpu.len], cpu);
        if (self.shapes) |shape| {
            var at = cpu.len;
            for (T.TABLES) |table| CS.fill(result, &at, if (tree == 1) T.mainWidth(table) else 4 * T.sumCount(table), T.tableLog(shape, table));
            CS.fill(result, &at, if (tree == 1) 303 else 8, shape.provider_log);
            CS.fill(result, &at, if (tree == 1) 1 else R.policy_provider.INTERACTION, self.ram.?.policy.shape.log_size);
            std.debug.assert(at == result.len);
        }
        return result;
    }
    pub fn offsets(self: *const Prepared, a: std.mem.Allocator, public: Public) !RAM.Offsets {
        const f = try self.cpu.fixedColumns(a);
        defer a.free(f);
        const m = try self.cpu.logs(a, public.cpu, 1);
        defer a.free(m);
        const i = try self.cpu.logs(a, public.cpu, 2);
        defer a.free(i);
        return .{ .fixed = f.len, .main = m.len, .interaction = i.len };
    }
    pub fn verificationView(self: *const Prepared) VerificationView {
        return .{ .cpu = self.cpu.verificationView(), .has_ram = self.ram != null };
    }
    pub fn verifyOwned(self: *const Prepared, a: std.mem.Allocator, public: Public, claims: Claims, proof_value: P.Proof) !void {
        var proof = proof_value;
        var owns = true;
        defer if (owns) proof.deinit(a);
        var key = try ReceiverKey.fromPrepared(a, self, public, null);
        defer key.deinit();
        owns = false;
        try key.verifyOwned(a, public, claims, proof);
    }
};
pub fn join(a: std.mem.Allocator, first: []const Column, second: []const Column) ![]Column {
    const result = try a.alloc(Column, first.len + second.len);
    @memcpy(result[0..first.len], first);
    @memcpy(result[first.len..], second);
    return result;
}
pub fn mixPublic(channel: *P.Channel, setup: *const Prepared, public: Public) !void {
    return mixPublicView(channel, setup.verificationView(), public);
}
pub fn mixPublicView(channel: *P.Channel, setup: VerificationView, public: Public) !void {
    channel.mixU32s(&.{ 0x52414558, 1, @intFromBool(public.ram != null), public.geometry.logBytes() });
    channel.mixU32s(&public.before);
    channel.mixU32s(&public.after);
    for (public.policy_identity) |byte| channel.mixU32s(&.{byte});
    if (public.ram) |c| channel.mixU32s(&.{ c.hashes, c.common_chunks, c.edge_chunks, c.nodes, c.sides, c.edge_permits });
    try CS.mixPublicView(channel, setup.cpu, public.cpu);
}
pub fn mixClaims(channel: *P.Channel, public: Public, claims: Claims) void {
    CS.mixClaims(channel, claims.cpu, public.cpu);
    if (claims.ram) |*value| value.mixWithoutByte(channel);
}
pub fn draw(a: std.mem.Allocator, channel: *P.Channel, setup: *const Prepared) !Challenges {
    return drawView(a, channel, setup.verificationView());
}
pub fn drawView(a: std.mem.Allocator, channel: *P.Channel, setup: VerificationView) !Challenges {
    const cpu = CS.drawView(channel, setup.cpu);
    return .{ .cpu = cpu, .ram = if (setup.has_ram) try I.Challenges.drawShared(a, channel, cpu.cpu.state, cpu.cpu.bytes) else null };
}
pub fn validateClaims(setup: *const Prepared, public: Public, claims: Claims, ch: *const Challenges) !void {
    return validateClaimsView(setup.verificationView(), public, claims, ch);
}
pub fn validateClaimsView(setup: VerificationView, public: Public, claims: Claims, ch: *const Challenges) !void {
    try CS.validateEncodingView(setup.cpu, public.cpu, claims.cpu);
    if ((claims.ram != null) != (public.ram != null)) return error.InvalidAuthenticatedRamClaims;
    var effect = CS.effect(claims.cpu);
    if (claims.ram) |*value| {
        // Only physical columns are permitted. Reject unused slots and the
        // absent per-RAM BYTE claim instead of leaving free statement fields.
        if (!value.bytes.isZero()) return error.InvalidAuthenticatedRamClaims;
        for (T.TABLES) |table| {
            const row = value.callers.tables[@intFromEnum(table)];
            for (row, 0..) |claim, index| {
                try canonical(claim);
                if (index >= T.sumCount(table) and !claim.isZero()) return error.InvalidAuthenticatedRamClaims;
            }
        }
        for (value.provider) |claim| try canonical(claim);
        try canonical(value.policy);
        const debt = try I.closeWithoutByte(public.before, public.after, public.geometry, &value.callers, value.provider, value.policy, &ch.ram.?);
        effect = effect.add(debt.state).add(debt.bytes);
    }
    if (!effect.eql(try public.cpu.statement.expectedStateWithProfile(ch.cpu.cpu.state, setup.cpu.base.plan.execution_profile))) return error.AuthenticatedExecutionGlobalClosure;
}
fn canonical(value: Q) !void {
    for (value.toM31Array()) |limb| if (limb.v >= core.fields.m31.Modulus) return error.InvalidAuthenticatedRamClaims;
}
pub const proveDiagnosed = @import("rv64_authenticated_prover.zig").proveDiagnosed;
pub const proveArena = @import("rv64_authenticated_prover.zig").proveArena;
pub const proveTrace = @import("rv64_authenticated_prover.zig").proveTrace;
pub const proveProfiled = @import("rv64_authenticated_prover.zig").proveProfiled;

/// Fixed RAM schedules depend on domains/geometry; active counts are per-request
/// constraints. Reusing a key must never silently reuse the previous counts.
pub fn sameGeometry(first: T.Shapes, second: T.Shapes) bool {
    if (first.chunk.geometry != second.chunk.geometry or first.provider_log != second.provider_log) return false;
    for (T.TABLES) |table| if (T.tableLog(first, table) != T.tableLog(second, table)) return false;
    return true;
}
