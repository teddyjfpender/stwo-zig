//! Two-phase authority for the CPU-local-GKR / classic-truth OM31 profile.
//! The receiver supplies the COMPLETE roster and trusted statement/FIXED IDs.
//! Stage one binds every MAIN root and verifies each local child before any
//! global challenge is drawn. The result still requires ALL physical proofs,
//! terminal bindings and independent RAM/KIO/Wire closure; it is not acceptance.
const std = @import("std");
const core = @import("stwo_core");
const A = @import("stwo_riscv_frontend").rv64_air;
const O = core.fields.om31.OM31;
const C = core.channel.raw_mod_m31.Om31Channel;
const Child = @import("child.zig");
const Receipt = @import("receipt.zig");
const Frame = @import("frame.zig");
const Proof = @import("stwo_prover_engine").lookups.gkr_verifier.ForField(O).GkrBatchProof;
pub const MAX_WORKERS = 65535;
pub const PROFILE = "RV64-SERVICES-CPU-GKR-TRUTH-CLASSIC-OM31-V1";
pub const V3_PROFILE = "RV64-SERVICES-CPU-GKR-TRUTH-CLASSIC-OM31-V3";
pub const BULK_PROFILE = "RV64-SERVICES-CPU-GKR-BULK-OM31-V3-1";
pub const Kind = enum(u32) { cpu, keccak, secp_add, secp_double, delegation };
pub const Relations = struct {
    ram: bool,
    kio: bool,
    wire: bool,
    fn bits(self: Relations) usize {
        return @as(usize, @intFromBool(self.ram)) | (@as(usize, @intFromBool(self.kio)) << 1) | (@as(usize, @intFromBool(self.wire)) << 2);
    }
};
pub const Mass = struct { ram: u64, kio: u64, wire: u64 };
/// Native protocol `rv64-m5-native-chi-chain/v1` fields of one worker
/// (canon_native.zig, binding note 3.3): receiver-derived by
/// `execution.zig Inventory` from trusted setup and admitted requests, never
/// from producer bytes. All-null keeps the historical flat manifest digest.
pub const Chain = struct { family: u32, rung: u32, vkhash: [32]u8, stmt: [32]u8, s_in: [32]u8, s_out: [32]u8 };
const Canon = @import("../../ethereum/canon_native.zig");
pub const ExpectedWorker = struct {
    chain: ?Chain = null,
    kind: Kind,
    global_relations: Relations,
    mass: Mass,
    ordinal: u32,
    statement: [32]u8,
    fixed: [32]u8,
    local_instances: ?[]const Frame.Instance,
};
pub const Local = struct { proof: *const Proof, receipt_digest: [32]u8 };
pub const StageOne = struct { main: [32]u8, local: ?Local };
pub const Shared = struct {
    ram: A.memory.closed_ram.types.RamChallengesFor(O),
    kio: A.crypto.keccak.equations.IoFor(O),
    wire: A.crypto.secp256k1.equations.WireFor(O),
};
pub const Claims = struct { ram: O, kio: O, wire: O };
pub const Entry = struct { kind: Kind, global_relations: Relations, mass: Mass, scope: Receipt.Scope, local: ?Child.Pending, chain: ?Chain = null };
/// Metadata view for a root receiver AFTER the circuit proof has authenticated
/// the local receipt and terminal marginals. Constructing this is not local
/// GKR verification and must never replace Child.verifyPending on native paths.
pub const LocalCommitmentView = struct { digest: [32]u8, claims_to_verify_by_instance: []const []const O };
pub const CommitmentView = struct { kind: Kind, global_relations: Relations, mass: Mass, scope: Receipt.Scope, local: ?LocalCommitmentView, chain: ?Chain = null };
pub const PendingManifest = struct {
    entries: []Entry,
    digest: [32]u8,
    shared: Shared,
    pub fn deinit(self: *PendingManifest, a: std.mem.Allocator) void {
        for (self.entries) |*entry| if (entry.local) |*pending| pending.deinit(a);
        a.free(self.entries);
        self.* = undefined;
    }
    /// Invoke against independently verified PCS roots, for EVERY worker.
    pub fn checkPhysicalRoots(self: *const PendingManifest, ordinal: usize, fixed: [32]u8, main: [32]u8) !void {
        if (ordinal >= self.entries.len) return error.GlobalGkrManifestOrdinal;
        const scope = self.entries[ordinal].scope;
        if (!std.mem.eql(u8, &fixed, &scope.fixed) or !std.mem.eql(u8, &main, &scope.main)) return error.GlobalGkrPhysicalRootMismatch;
    }
    /// These values must come from ALL freshly verified physical claims.
    /// No cross-relation cancellation is allowed; this alone is not a verifier.
    pub fn checkGlobalClosure(self: *const PendingManifest, claims: []const Claims) !void {
        return checkClaimsClosure(self.entries, claims);
    }
};
/// Shared closure authority for freshly verified native claims and claims
/// authenticated by a recursive root. This checks algebraic debt only.
pub fn checkClaimsClosure(entries: anytype, claims: []const Claims) !void {
    if (claims.len != entries.len) return error.GlobalGkrManifestRoster;
    var sum = Claims{ .ram = O.zero(), .kio = O.zero(), .wire = O.zero() };
    for (claims, entries) |claim, entry| {
        inline for (.{ "ram", "kio", "wire" }) |name| {
            try canonical(@field(claim, name));
            if (!@field(entry.global_relations, name) and !@field(claim, name).isZero()) return error.NonzeroAbsentGlobalGkrClaim;
            @field(sum, name) = @field(sum, name).add(@field(claim, name));
        }
    }
    if (!sum.ram.isZero()) return error.UnclosedGlobalGkrRam;
    if (!sum.kio.isZero()) return error.UnclosedGlobalGkrKio;
    if (!sum.wire.isZero()) return error.UnclosedGlobalGkrWire;
}
fn canonical(value: O) !void {
    for (value.toM31Array()) |coordinate| if (coordinate.v >= core.fields.m31.Modulus) return error.NoncanonicalGlobalGkrCoordinate;
}
pub fn validateRoster(expected: []const ExpectedWorker) !void {
    return validateRosterFor(.flat, expected);
}
/// Protocol is selected by trusted receiver policy, never inferred from an
/// omitted local child. Native-GKR moves every local relation to stage two.
pub fn validateRosterFor(version: @import("chain.zig").Version, expected: []const ExpectedWorker) !void {
    const native_gkr = version == .m6_v2_gkr;
    if (native_gkr and expected.len > 256) return error.GlobalGkrManifestRoster;
    if (expected.len == 0 or expected.len > MAX_WORKERS or expected[0].kind != .cpu) return error.GlobalGkrManifestRoster;
    var previous: u32 = 0;
    var has_delegation = false;
    for (expected) |worker| has_delegation = has_delegation or worker.kind == .delegation;
    var seen_truth = false;
    var mass = Mass{ .ram = 0, .kio = 0, .wire = 0 };
    for (expected, 0..) |worker, i| {
        if (worker.ordinal != i or (!has_delegation and @intFromEnum(worker.kind) < previous) or (seen_truth and worker.kind == .cpu)) return error.GlobalGkrManifestOrdinal;
        previous = @intFromEnum(worker.kind);
        seen_truth = seen_truth or worker.kind != .cpu;
        const mask = worker.global_relations;
        inline for (.{ "ram", "kio", "wire" }) |name| {
            const bound = @field(worker.mass, name);
            if (!@field(mask, name) and bound != 0) return error.GlobalGkrRelationMass;
            if (bound >= core.fields.m31.Modulus) return error.GlobalGkrCharacteristicBound;
            @field(mass, name) = std.math.add(u64, @field(mass, name), bound) catch return error.GlobalGkrCharacteristicBound;
            if (@field(mass, name) >= core.fields.m31.Modulus) return error.GlobalGkrCharacteristicBound;
        }
        switch (worker.kind) {
            .cpu => if (!mask.ram) return error.GlobalGkrRelationRoster,
            .keccak => if (mask.ram or !mask.kio or mask.wire) return error.GlobalGkrRelationRoster,
            .secp_add, .secp_double, .delegation => if (mask.ram or mask.kio or !mask.wire) return error.GlobalGkrRelationRoster,
        }
        if (native_gkr) {
            if (worker.local_instances != null) return error.UnexpectedGlobalGkrLocalChild;
            const chain = worker.chain orelse return error.NativeChainMissing;
            if (!std.mem.eql(u8, &chain.stmt, &worker.statement)) return error.NativeGkrCompactStatementMismatch;
        } else if (worker.kind == .cpu) {
            const instances = worker.local_instances orelse return error.MissingGlobalGkrLocalChild;
            if (instances.len == 0 or instances.len > Receipt.MAX_INSTANCES) return error.MissingGlobalGkrLocalChild;
            for (instances) |instance| _ = try instance.variables();
        } else if (worker.local_instances != null) return error.UnexpectedGlobalGkrLocalChild;
    }
}
pub fn validateStageOneShape(expected: []const ExpectedWorker, stages: []const StageOne) !void {
    return validateStageOneShapeFor(.flat, expected, stages);
}
pub fn validateStageOneShapeFor(version: @import("chain.zig").Version, expected: []const ExpectedWorker, stages: []const StageOne) !void {
    try validateRosterFor(version, expected);
    if (stages.len != expected.len) return error.GlobalGkrManifestRoster;
    for (expected, stages) |worker, stage| {
        if (version == .m6_v2_gkr) {
            if (stage.local != null) return error.UnexpectedGlobalGkrLocalChild;
        } else {
            if (worker.kind == .cpu and stage.local == null) return error.MissingGlobalGkrLocalChild;
            if (worker.kind != .cpu and stage.local != null) return error.UnexpectedGlobalGkrLocalChild;
        }
    }
}
const Writer = struct {
    hash: std.crypto.hash.blake2.Blake2s256 = .init(.{}),
    fn bytes(self: *Writer, value: []const u8) void {
        self.hash.update(value);
    }
    fn integer(self: *Writer, value: anytype) void {
        var encoded: [8]u8 = undefined;
        std.mem.writeInt(u64, &encoded, @intCast(value), .little);
        self.hash.update(&encoded);
    }
    fn field(self: *Writer, value: O) !void {
        try canonical(value);
        for (value.toM31Array()) |coordinate| {
            var encoded: [4]u8 = undefined;
            std.mem.writeInt(u32, &encoded, coordinate.v, .little);
            self.hash.update(&encoded);
        }
    }
};
/// Shared canonical framing authority, suitable for a later constrained writer.
/// Entry.local can only be supplied from the checked child transcript by the
/// receiving path; wire-declared marginals must never populate these entries.
pub fn emitCanonical(execution: [32]u8, entries: anytype, writer: anytype) !void {
    writer.bytes(PROFILE);
    writer.bytes(&execution);
    writer.integer(8);
    writer.integer(entries.len);
    for (entries) |entry| {
        writer.integer(@intFromEnum(entry.kind));
        writer.integer(entry.global_relations.bits());
        writer.integer(entry.mass.ram);
        writer.integer(entry.mass.kio);
        writer.integer(entry.mass.wire);
        writer.integer(entry.scope.ordinal);
        writer.bytes(&entry.scope.statement);
        writer.bytes(&entry.scope.fixed);
        writer.bytes(&entry.scope.main);
        writer.integer(@intFromBool(entry.local != null));
        if (entry.local) |pending| {
            writer.bytes(&pending.digest);
            // Also bind the independently reconstructed terminal marginals
            // explicitly, rather than accepting a producer's marginal list.
            const marginals = if (comptime @hasField(@TypeOf(pending), "artifact")) pending.artifact.claims_to_verify_by_instance else pending.claims_to_verify_by_instance;
            writer.integer(marginals.len);
            for (marginals) |values| {
                writer.integer(values.len);
                for (values) |value| try writer.field(value);
            }
        }
    }
}
pub const Commitment = struct { digest: [32]u8, shared: Shared };
/// Fiat–Shamir derivation only, never acceptance. Views must already be bound
/// to the complete receiver-owned inventory and authenticated leaf statements.
pub fn commitViews(execution: [32]u8, entries: []const CommitmentView) !Commitment {
    return commitViewsFor(try @import("chain.zig").version(), execution, entries);
}
/// Explicit-version form (tests, table tools); production uses the policy.
pub fn commitViewsFor(version: @import("chain.zig").Version, execution: [32]u8, entries: []const CommitmentView) !Commitment {
    if (entries.len == 0 or entries.len > MAX_WORKERS) return error.GlobalGkrManifestRoster;
    const digest = try manifestDigest(version, execution, entries);
    return .{ .digest = digest, .shared = drawShared(digest) };
}
/// Flat v1 digest (historical bytes) unless every entry carries m5 chain
/// fields; then chi = H(chi, stmt || m_kappa) over the ordered segment chain.
fn manifestDigest(version: @import("chain.zig").Version, execution: [32]u8, entries: anytype) ![32]u8 {
    if (try chainDigestFor(version, execution, entries)) |chi| return chi;
    var writer = Writer{};
    try emitCanonical(execution, entries, &writer);
    var digest: [32]u8 = undefined;
    writer.hash.final(&digest);
    return digest;
}
pub fn chainDigest(execution: [32]u8, entries: anytype) !?[32]u8 {
    return chainDigestFor(try @import("chain.zig").version(), execution, entries);
}
pub fn chainDigestFor(version: @import("chain.zig").Version, execution: [32]u8, entries: anytype) !?[32]u8 {
    // The version is receiver POLICY, not data (canon-native review A4): a
    // chained policy with an entry lacking chain fields is refused, and a
    // flat policy never reads chain fields.
    if (!version.chained()) return null;
    for (entries) |entry| if (entry.chain == null) return error.NativeChainMissing;
    var m = Canon.chainIv(try @import("chain.zig").versionIdentity(version));
    for (entries, 0..) |entry, k| {
        if (entry.scope.ordinal != k) return error.NativeChainOrder;
        const c = entry.chain.?;
        m = Canon.chainStep(m, .{ .k = @intCast(k), .family = c.family, .rung = c.rung, .vkhash = c.vkhash, .stmt = c.stmt, .s_in = c.s_in, .s_out = c.s_out, .rho = try rhoOf(entry) });
    }
    return Canon.chi(execution, m);
}
/// rho_k = H(rho, main || local_present || local_digest || marginals): every
/// stage-one commitment of segment k, exactly what the flat digest framed.
fn rhoOf(entry: anytype) ![32]u8 {
    var h = Canon.Hasher.init(.rho);
    h.digest(entry.scope.main);
    h.word(@intFromBool(entry.local != null));
    if (entry.local) |pending| {
        h.digest(pending.digest);
        const marginals = if (comptime @hasField(@TypeOf(pending), "artifact")) pending.artifact.claims_to_verify_by_instance else pending.claims_to_verify_by_instance;
        h.word(@intCast(marginals.len));
        for (marginals) |values| {
            h.word(@intCast(values.len));
            for (values) |value| {
                try canonical(value);
                for (value.toM31Array()) |coordinate| h.word(coordinate.v);
            }
        }
    } else {
        h.digest(@splat(0));
        h.word(0);
    }
    return h.final();
}
fn mixDigest(ch: *C, digest: [32]u8) void {
    var words: [8]u32 = undefined;
    for (&words, 0..) |*word, i| word.* = std.mem.readInt(u32, digest[4 * i ..][0..4], .little);
    ch.mixU32s(&words);
}
pub fn drawShared(digest: [32]u8) Shared {
    var ch = C.init();
    ch.mixU32s(&.{ 0x53474d31, 1, 8 });
    mixDigest(&ch, digest);
    ch.mixU32s(&.{ 0x52414d31, 14 });
    var ram: A.memory.closed_ram.types.RamChallengesFor(O) = undefined;
    ram.offset = ch.drawSecureFelt();
    for (&ram.coefficients) |*coefficient| coefficient.* = ch.drawSecureFelt();
    ch.mixU32s(&.{ 0x4b494f31, 11 });
    const kio = A.crypto.keccak.equations.IoFor(O).draw(&ch);
    ch.mixU32s(&.{ 0x53574952, 35 });
    return .{ .ram = ram, .kio = kio, .wire = A.crypto.secp256k1.equations.WireFor(O).draw(&ch) };
}
/// Expected roster is receiver authority derived from trusted setup/admission,
/// not a copy of producer declarations. MAIN roots are stage-one commitments;
/// checkPhysicalRoots must match them to every later accepted native proof.
/// A successfully returned value contains PENDING physical-binding obligations.
pub fn verifyAndSeal(a: std.mem.Allocator, execution: [32]u8, expected: []const ExpectedWorker, stages: []const StageOne) !PendingManifest {
    return verifyAndSealFor(try @import("chain.zig").version(), a, execution, expected, stages);
}
pub fn verifyAndSealFor(version: @import("chain.zig").Version, a: std.mem.Allocator, execution: [32]u8, expected: []const ExpectedWorker, stages: []const StageOne) !PendingManifest {
    try validateStageOneShapeFor(version, expected, stages);
    const entries = try a.alloc(Entry, expected.len);
    errdefer a.free(entries);
    var initialized: usize = 0;
    errdefer for (entries[0..initialized]) |*entry| {
        if (entry.local) |*pending| pending.deinit(a);
    };
    for (expected, stages, 0..) |worker, stage, i| {
        const scope = Receipt.Scope{ .ordinal = worker.ordinal, .statement = worker.statement, .fixed = worker.fixed, .main = stage.main };
        entries[i] = .{ .kind = worker.kind, .global_relations = worker.global_relations, .mass = worker.mass, .scope = scope, .local = if (stage.local) |local| try Child.verifyPending(a, scope, worker.local_instances.?, local.proof, local.receipt_digest) else null, .chain = worker.chain };
        initialized += 1;
    }
    const digest = try manifestDigest(version, execution, entries);
    return .{ .entries = entries, .digest = digest, .shared = drawShared(digest) };
}

test "native-GKR MAIN-only roster is explicit and cannot downgrade a local child" {
    var worker = ExpectedWorker{ .kind = .cpu, .ordinal = 0, .statement = @splat(1), .fixed = @splat(2), .global_relations = .{ .ram = true, .kio = false, .wire = false }, .mass = .{ .ram = 0, .kio = 0, .wire = 0 }, .local_instances = null, .chain = .{ .family = 0, .rung = 0, .vkhash = @splat(3), .stmt = @splat(1), .s_in = @splat(4), .s_out = @splat(5) } };
    const stages = [_]StageOne{.{ .main = @splat(6), .local = null }};
    try validateStageOneShapeFor(.m6_v2_gkr, &.{worker}, &stages);
    try std.testing.expectError(error.MissingGlobalGkrLocalChild, validateStageOneShape(&.{worker}, &stages));
    worker.local_instances = &.{};
    try std.testing.expectError(error.UnexpectedGlobalGkrLocalChild, validateRosterFor(.m6_v2_gkr, &.{worker}));
    worker.local_instances = null;
    worker.chain.?.stmt = @splat(9);
    try std.testing.expectError(error.NativeGkrCompactStatementMismatch, validateRosterFor(.m6_v2_gkr, &.{worker}));
    worker.chain = null;
    try std.testing.expectError(error.NativeChainMissing, validateRosterFor(.m6_v2_gkr, &.{worker}));
}
