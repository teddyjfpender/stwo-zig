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
pub const BULK_PROFILE = "RV64-SERVICES-CPU-GKR-BULK-OM31-V3-1";
pub const Kind = enum(u32) { cpu, keccak, secp_add, secp_double };
pub const Relations = struct {
    ram: bool,
    kio: bool,
    wire: bool,
    fn bits(self: Relations) usize {
        return @as(usize, @intFromBool(self.ram)) | (@as(usize, @intFromBool(self.kio)) << 1) | (@as(usize, @intFromBool(self.wire)) << 2);
    }
};
pub const Mass = struct { ram: u64, kio: u64, wire: u64 };
pub const ExpectedWorker = struct {
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
pub const Entry = struct { kind: Kind, global_relations: Relations, mass: Mass, scope: Receipt.Scope, local: ?Child.Pending };
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
        if (claims.len != self.entries.len) return error.GlobalGkrManifestRoster;
        var sum = Claims{ .ram = O.zero(), .kio = O.zero(), .wire = O.zero() };
        for (claims, self.entries) |claim, entry| {
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
};
fn canonical(value: O) !void {
    for (value.toM31Array()) |coordinate| if (coordinate.v >= core.fields.m31.Modulus) return error.NoncanonicalGlobalGkrCoordinate;
}
pub fn validateRoster(expected: []const ExpectedWorker) !void {
    if (expected.len == 0 or expected.len > MAX_WORKERS or expected[0].kind != .cpu) return error.GlobalGkrManifestRoster;
    var previous: u32 = 0;
    var mass = Mass{ .ram = 0, .kio = 0, .wire = 0 };
    for (expected, 0..) |worker, i| {
        if (worker.ordinal != i or @intFromEnum(worker.kind) < previous) return error.GlobalGkrManifestOrdinal;
        previous = @intFromEnum(worker.kind);
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
            .secp_add, .secp_double => if (mask.ram or mask.kio or !mask.wire) return error.GlobalGkrRelationRoster,
        }
        if (worker.kind == .cpu) {
            const instances = worker.local_instances orelse return error.MissingGlobalGkrLocalChild;
            if (instances.len == 0 or instances.len > Receipt.MAX_INSTANCES) return error.MissingGlobalGkrLocalChild;
            for (instances) |instance| _ = try instance.variables();
        } else if (worker.local_instances != null) return error.UnexpectedGlobalGkrLocalChild;
    }
}
pub fn validateStageOneShape(expected: []const ExpectedWorker, stages: []const StageOne) !void {
    try validateRoster(expected);
    if (stages.len != expected.len) return error.GlobalGkrManifestRoster;
    for (expected, stages) |worker, stage| {
        if (worker.kind == .cpu and stage.local == null) return error.MissingGlobalGkrLocalChild;
        if (worker.kind != .cpu and stage.local != null) return error.UnexpectedGlobalGkrLocalChild;
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
pub fn emitCanonical(execution: [32]u8, entries: []const Entry, writer: anytype) !void {
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
            writer.integer(pending.artifact.claims_to_verify_by_instance.len);
            for (pending.artifact.claims_to_verify_by_instance) |values| {
                writer.integer(values.len);
                for (values) |value| try writer.field(value);
            }
        }
    }
}
fn mixDigest(ch: *C, digest: [32]u8) void {
    var words: [8]u32 = undefined;
    for (&words, 0..) |*word, i| word.* = std.mem.readInt(u32, digest[4 * i ..][0..4], .little);
    ch.mixU32s(&words);
}
fn drawShared(digest: [32]u8) Shared {
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
    try validateStageOneShape(expected, stages);
    const entries = try a.alloc(Entry, expected.len);
    errdefer a.free(entries);
    var initialized: usize = 0;
    errdefer for (entries[0..initialized]) |*entry| {
        if (entry.local) |*pending| pending.deinit(a);
    };
    for (expected, stages, 0..) |worker, stage, i| {
        const scope = Receipt.Scope{ .ordinal = worker.ordinal, .statement = worker.statement, .fixed = worker.fixed, .main = stage.main };
        entries[i] = .{ .kind = worker.kind, .global_relations = worker.global_relations, .mass = worker.mass, .scope = scope, .local = if (stage.local) |local| try Child.verifyPending(a, scope, worker.local_instances.?, local.proof, local.receipt_digest) else null };
        initialized += 1;
    }
    var writer = Writer{};
    try emitCanonical(execution, entries, &writer);
    var digest: [32]u8 = undefined;
    writer.hash.final(&digest);
    return .{ .entries = entries, .digest = digest, .shared = drawShared(digest) };
}
