//! Receiver-derived root and component geometry only. No fixed polynomial
//! matrices, channel state, claims, component instances or request counts live
//! in this key. Borrowed program/policy owners must outlive every verification.
const std = @import("std");
const A = @import("rv64_authenticated_execution.zig");
const CPU = A.CPU;
const R = A.R;
const T = A.T;
const P = A.P;
const Plan = A.rv.encoding.Plan;
const Rom = A.rv.program.setup;
const Verifier = A.core.pcs.verifier.CommitmentSchemeVerifier(P.Hasher, P.MerkleChannel);
pub const RamGeometry = struct {
    geometry: R.values.Geometry,
    logs: [9]u32,
    policy_log: u32,
    pub fn fromShapes(shape: T.Shapes, policy_log: u32) RamGeometry {
        var logs: [9]u32 = undefined;
        for (T.TABLES, 0..) |table, i| logs[i] = T.tableLog(shape, table);
        logs[8] = shape.provider_log;
        return .{ .geometry = shape.chunk.geometry, .logs = logs, .policy_log = policy_log };
    }
};
pub const ReceiverKey = struct {
    allocator: std.mem.Allocator,
    plan: Plan,
    cpu_geometry: CPU.VerificationGeometry,
    ram_geometry: ?RamGeometry,
    geometry: R.values.Geometry,
    policy: *const R.policy.Policy,
    program: *const Rom.Setup,
    authority: ?*const A.Full.ProgramAuthority,
    root: [32]u8,
    fixed_logs: []u32,
    main_logs: []u32,
    interaction_logs: []u32,
    ram_offsets: A.RAM.Offsets,
    /// Without authority this key borrows the Prepared owner itself. With an
    /// authority it borrows ONLY that independently derived immutable owner,
    /// and the temporary wide Prepared may be destroyed immediately afterward.
    pub fn fromPrepared(a: std.mem.Allocator, setup: *const A.Prepared, public: A.Public, authority: ?*const A.Full.ProgramAuthority) !ReceiverKey {
        try validateProgram(if (authority) |owner| &owner.program else &setup.cpu.base.program, authority, public.cpu.statement.program);
        try public.validateWithAdmittedOpcodes(setup.policy, &setup.cpu.base.plan.allowed_opcodes);
        try setup.cpu.verificationView().validateBound(public.cpu);
        if ((setup.shapes != null) != (public.ram != null)) return error.InvalidAuthenticatedRamRoster;
        if (public.ram) |counts| if (!A.sameGeometry(setup.shapes.?, try counts.shapes(public.geometry))) return error.InvalidAuthenticatedRamGeometry;
        if (authority) |owner| {
            if (!setup.cpu.base.borrows_immutable or setup.cpu.base.program.rows.ptr != owner.program.rows.ptr or setup.cpu.base.program.rows.len != owner.program.rows.len or setup.cpu.base.program.addresses.ptr != owner.program.addresses.ptr or setup.cpu.base.rom_fixed.ptr != owner.rom_fixed.ptr or setup.cpu.base.program.log_size != owner.program.log_size or !std.mem.eql(u8, &setup.cpu.base.program.identity, &owner.program.identity) or setup.cpu.base.plan.execution_profile != owner.profile or setup.cpu.base.plan.control_policy != owner.control_policy or !std.mem.eql(bool, &setup.cpu.base.plan.allowed_opcodes, &owner.opcodes)) return error.InvalidReceiverKeyAuthority;
        }
        const fixed = try setup.fixedColumns(a);
        defer a.free(fixed);
        const fixed_logs = try a.alloc(u32, fixed.len);
        errdefer a.free(fixed_logs);
        for (fixed, fixed_logs) |column, *log| log.* = column.log_size;
        const main_logs = try setup.logs(a, public, 1);
        errdefer a.free(main_logs);
        const interaction_logs = try setup.logs(a, public, 2);
        errdefer a.free(interaction_logs);
        const offsets = try setup.offsets(a, public);
        return .{ .allocator = a, .plan = setup.cpu.base.plan, .cpu_geometry = setup.cpu.verificationGeometry(), .geometry = public.geometry, .ram_geometry = if (setup.shapes) |shape| RamGeometry.fromShapes(shape, setup.ram.?.policy.shape.log_size) else null, .policy = setup.policy, .program = if (authority) |owner| &owner.program else &setup.cpu.base.program, .authority = authority, .root = setup.root, .fixed_logs = fixed_logs, .main_logs = main_logs, .interaction_logs = interaction_logs, .ram_offsets = offsets };
    }
    pub fn deinit(self: *ReceiverKey) void {
        self.allocator.free(self.fixed_logs);
        self.allocator.free(self.main_logs);
        self.allocator.free(self.interaction_logs);
        self.* = undefined;
    }
    pub fn metadataBytes(self: *const ReceiverKey) usize {
        return @sizeOf(ReceiverKey) + @sizeOf(u32) * (self.fixed_logs.len + self.main_logs.len + self.interaction_logs.len);
    }
    pub fn view(self: *const ReceiverKey) A.VerificationView {
        return .{ .cpu = self.cpu_geometry.view(&self.plan), .has_ram = self.ram_geometry != null };
    }
    pub fn validate(self: *const ReceiverKey, public: A.Public) !void {
        try validateProgram(self.program, self.authority, public.cpu.statement.program);
        try public.validateWithAdmittedOpcodes(self.policy, &self.plan.allowed_opcodes);
        if (public.geometry != self.geometry) return error.InvalidAuthenticatedRamGeometry;
        try self.view().cpu.validateBound(public.cpu);
        if ((self.ram_geometry != null) != (public.ram != null)) return error.InvalidAuthenticatedRamRoster;
        if (public.ram) |counts| {
            const current = RamGeometry.fromShapes(try counts.shapes(public.geometry), self.ram_geometry.?.policy_log);
            if (!std.meta.eql(current, self.ram_geometry.?)) return error.InvalidAuthenticatedRamGeometry;
        }
    }
    /// Component instances for one request. `challenges` must outlive `out`:
    /// the RAM provider borrows its relation draws from it.
    pub fn buildComponents(self: *const ReceiverKey, public: A.Public, claims: A.Claims, challenges: *const A.Challenges, out: *Components) !void {
        const shape = self.view();
        out.cpu = try A.CS.Components.initView(shape.cpu, public.cpu, claims.cpu, challenges.cpu);
        out.ram = if (public.ram) |counts| try A.RAM.Components.initAt(try counts.shapes(public.geometry), self.policy, &challenges.ram.?, &claims.ram.?, self.ram_offsets) else null;
        var cpu_handles: [17]A.core.air.components.Component = undefined;
        const n = out.cpu.verifiers(&cpu_handles);
        @memcpy(out.handles[0..n], cpu_handles[0..n]);
        var extra: usize = 0;
        if (out.ram) |*value| {
            const rs = try value.verifiersWithoutByte();
            @memcpy(out.handles[n..][0..10], &rs);
            extra = 10;
        }
        out.count = n + extra;
    }
    /// Shape-only roster for an external verifier: challenges come from a
    /// fresh transcript and every claim is zero. Lane evaluation reads only
    /// offsets, log sizes, kinds and plans from these instances, never a scalar.
    pub fn shapeComponents(self: *const ReceiverKey, a: std.mem.Allocator, public: A.Public, challenges: *A.Challenges, out: *Components) !void {
        var channel = P.Channel{};
        challenges.* = try A.drawView(a, &channel, self.view());
        const claims = A.Claims{ .cpu = std.mem.zeroes(A.CPU.Claims), .ram = if (public.ram != null) std.mem.zeroes(A.RAM.Claims) else null };
        try self.buildComponents(public, claims, challenges, out);
    }
    /// Admits the request and replays the transcript up to the composition
    /// draw without consuming the proof; `verifyOwned` continues from here.
    pub fn openSession(self: *const ReceiverKey, a: std.mem.Allocator, public: A.Public, claims: A.Claims, proof: *const P.Proof, session: *Session) !void {
        try self.validate(public);
        const pcs = &proof.commitment_scheme_proof;
        if (!std.meta.eql(pcs.config, P.config()) or pcs.revision_config != null or pcs.commitments.items.len != 4) return error.InvalidAuthenticatedExecutionConfig;
        if (!std.mem.eql(u8, &pcs.commitments.items[0], &self.root)) return error.AuthenticatedExecutionFixedRootMismatch;
        session.verifier = try Verifier.init(a, P.config());
        errdefer session.verifier.deinit(a);
        session.channel = P.Channel{};
        const shape = self.view();
        try A.mixPublicView(&session.channel, shape, public);
        try session.verifier.commit(a, pcs.commitments.items[0], self.fixed_logs, &session.channel);
        try session.verifier.commit(a, pcs.commitments.items[1], self.main_logs, &session.channel);
        session.challenges = try A.drawView(a, &session.channel, shape);
        try A.validateClaimsView(shape, public, claims, &session.challenges);
        try self.buildComponents(public, claims, &session.challenges, &session.components);
        A.mixClaims(&session.channel, public, claims);
        try session.verifier.commit(a, pcs.commitments.items[2], self.interaction_logs, &session.channel);
    }
    /// Consumes proof on every path. Counts, challenges and all component
    /// instances come from this invocation; only root/shape metadata is reused.
    pub fn verifyOwned(self: *const ReceiverKey, a: std.mem.Allocator, public: A.Public, claims: A.Claims, proof_value: P.Proof) !void {
        var proof = proof_value;
        var owns = true;
        defer if (owns) proof.deinit(a);
        var session: Session = undefined;
        try self.openSession(a, public, claims, &proof, &session);
        defer session.verifier.deinit(a);
        owns = false;
        try A.core.verifier.verify(P.Hasher, P.MerkleChannel, a, session.components.verifiers(), &session.channel, &session.verifier, proof);
    }
};
/// Every component the native verifier evaluates, in its handle order.
/// Instances borrow the challenges they were built from.
pub const Components = struct {
    cpu: A.CS.Components,
    ram: ?A.RAM.Components,
    handles: [27]A.core.air.components.Component,
    count: usize,
    pub fn verifiers(self: *const Components) []const A.core.air.components.Component {
        return self.handles[0..self.count];
    }
};
/// Transcript state after the three trace commitments, exactly as the
/// native verifier reaches `core.verifier.verify`. Pinned in place because
/// the component instances borrow `challenges`.
pub const Session = struct {
    verifier: Verifier,
    channel: P.Channel,
    challenges: A.Challenges,
    components: Components,
    pub fn deinit(self: *Session, a: std.mem.Allocator) void {
        self.verifier.deinit(a);
        self.* = undefined;
    }
};
/// Only exact owner-borrowed headers take the constant-time fast path. Other
/// arrays are compared with independently decoded expected words/PCs, never a
/// producer key/identity. Both paths retain canonical full-u64 address checks.
pub fn validateProgram(program: *const Rom.Setup, authority: ?*const A.Full.ProgramAuthority, expected: Rom.Program) !void {
    try expected.validate();
    if (expected.words.len != program.rows.len or expected.base != program.addresses[0]) return error.Rv64FullSetupMismatch;
    if (authority) |owner| return A.Full.validateAuthorityProgram(owner, expected);
    for (expected.words, 0..) |word, i| {
        if (expected.pc(i) != program.addresses[i]) return error.Rv64FullSetupMismatch;
        for (0..4) |b| if (program.rows[i][Rom.field.raw + b].v != ((word >> @as(u5, @intCast(b * 8))) & 255)) return error.Rv64FullSetupMismatch;
    }
}
