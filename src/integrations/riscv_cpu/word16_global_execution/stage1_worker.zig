//! Concrete worker ownership barrier. Coordinator data are Sealed values only;
//! Source, PCS coefficients and narrow advice remain worker-owned until drained.
const std = @import("std");
const engine = @import("stwo_prover_engine");
const wire = @import("stwo_proof_wire");
const P = @import("protocol.zig");
const S = @import("../word16_execution/sources.zig");
const Components = @import("../word16_execution/components.zig").Components;
const Encoded = @import("encoded.zig").Encoded;
const Cell = @import("stwo_riscv_frontend").rv64_air.memory.closed_ram.types.Cell;
const Backend = @import("stwo_cpu_backend").CpuBackend;
pub const Stage1Worker = struct {
    pub const Phase = enum { prepared, sealed, completed, failed };
    pub const Sealed = struct { ordinal: usize, statement: [32]u8, roots: P.Receipt };
    allocator: std.mem.Allocator,
    setup: *const P.Setup,
    source: ?S.Source,
    request: P.Old.Request,
    scheme: P.T.Scheme,
    channel: P.T.P.Channel,
    ordinal: usize,
    statement: [32]u8,
    sealed: ?Sealed = null,
    phase: Phase = .prepared,
    owns_scheme: bool = true,
    /// Consumes Source on success AND error. Setup must remain at its stable
    /// final address through completion/deinit. No challenge is drawn here.
    pub fn init(a: std.mem.Allocator, setup: *const P.Setup, owned_source: S.Source, expected: P.Expected, ordinal: usize, first_step: u64) !Stage1Worker {
        var source = owned_source;
        errdefer source.deinit();
        if (!@import("stwo_riscv_frontend").rv64_air.memory.ownership.same(a, source.allocator)) return error.PreparedAllocatorMismatch;
        if (source.materials != &setup.materials or source.cpu.program != &setup.materials.program) return error.PreparedSetupMismatch;
        if (ordinal >= 65535 or source.cpu.epoch != ordinal + 1 or !std.mem.eql(u8, &setup.materials.program.identity, &expected.program_identity)) return error.GlobalWorkerContextMismatch;
        var scheme = try P.T.Scheme.init(a, P.T.P.config());
        errdefer scheme.deinit(a);
        scheme.setCompactPolynomialStorage(5);
        var channel = P.T.P.Channel{};
        const request = source.request();
        try P.begin(&channel, setup, request, expected, ordinal, first_step);
        return .{ .allocator = a, .setup = setup, .source = source, .request = request, .scheme = scheme, .channel = channel, .ordinal = ordinal, .statement = channel.digestBytes() };
    }
    pub fn deinit(self: *Stage1Worker) void {
        if (self.owns_scheme) self.scheme.deinit(self.allocator);
        if (self.source) |*source| source.deinit();
        self.* = undefined;
    }
    /// Publication happens only after actual fixed/MAIN commits, geometry
    /// inspection and joined native work. MAIN is retired before returning.
    pub fn seal(self: *Stage1Worker) !Sealed {
        if (self.phase != .prepared) return error.InvalidGlobalWorkerPhase;
        errdefer self.phase = .failed;
        try self.setup.appendFixed(self.allocator, &self.scheme, &self.channel);
        const source = &self.source.?;
        const main = try source.takeMainForCommit();
        // The PCS consumes descriptors and original backing allocations on
        // success and failure; only narrow relation metadata remains here.
        try self.scheme.commitOwnedStreamingWithRecorderAndBacking(self.allocator, main.columns, main.backings, 8, null, &self.channel);
        const roots = try checkStage1(self.allocator, &self.scheme, self.setup);
        const descriptor = Sealed{ .ordinal = self.ordinal, .statement = self.statement, .roots = roots };
        self.sealed = descriptor;
        self.phase = .sealed;
        return descriptor;
    }
    /// Coordinator copies ONLY ordinal/spec digest/two actual32-byte roots.
    /// This does not verify a proof or certify coverage by itself.
    pub fn manifestFromSeals(a: std.mem.Allocator, seals: []const Sealed) !P.Manifest {
        if (seals.len == 0 or seals.len > 65535) return error.IncompleteGlobalExecutionManifest;
        const specs = try a.alloc([32]u8, seals.len);
        defer a.free(specs);
        const roots = try a.alloc(P.Receipt, seals.len);
        defer a.free(roots);
        for (seals, specs, roots, 0..) |sealed, *spec, *root, i| {
            if (sealed.ordinal != i) return error.GlobalExecutionInventoryMismatch;
            spec.* = sealed.statement;
            root.* = sealed.roots;
        }
        return P.Manifest.init(a, specs, roots);
    }
    /// The ONLY randomness input is the complete Manifest. Retained roots and
    /// own public/spec binding are checked immediately before any FS mutation.
    /// A failing post-draw completion must be discarded, never retried.
    pub fn complete(self: *Stage1Worker, manifest: *const P.Manifest) !Encoded {
        if (self.phase != .sealed) return error.InvalidGlobalWorkerPhase;
        try manifest.check(manifest.specs);
        if (self.ordinal >= manifest.specs.len or !std.mem.eql(u8, &self.statement, &manifest.specs[self.ordinal])) return error.GlobalExecutionInventoryMismatch;
        const actual = try checkStage1(self.allocator, &self.scheme, self.setup);
        if (!std.meta.eql(actual, manifest.roots[self.ordinal])) return error.GlobalStage1RootMismatch;
        errdefer self.phase = .failed;
        const a = self.allocator;
        const source = &self.source.?;
        const ch = try P.draw(&self.channel, manifest, self.ordinal);
        const claims = (try source.generateOpenForGlobalRam(ch)).physical;
        self.channel.mixFelts(&claims.values());
        const interaction = try source.takeInteractionForCommit();
        try self.scheme.commitOwnedStreamingWithRecorderAndBacking(a, interaction.columns, interaction.backings, 8, null, &self.channel);
        source.releaseCommittedInteraction();
        var components = try Components.init(&self.setup.materials, self.request, ch, claims);
        const handles = try components.provers(a);
        defer a.free(handles);
        self.owns_scheme = false;
        var proof = try engine.prove.prove(Backend, P.T.P.Hasher, P.T.P.MerkleChannel, a, handles, &self.channel, self.scheme);
        defer proof.deinit(a);
        const bytes = try wire.encodeProofBytesBinary(a, proof);
        errdefer a.free(bytes);
        var request = self.request;
        request.memory.initial = try a.dupe(Cell, request.memory.initial);
        errdefer a.free(request.memory.initial);
        request.memory.terminal = try a.dupe(Cell, request.memory.terminal);
        source.deinit();
        self.source = null;
        self.phase = .completed;
        return .{ .bytes = bytes, .request = request, .claims = claims };
    }
};
fn checkStage1(a: std.mem.Allocator, scheme: *P.T.Scheme, setup: *const P.Setup) !P.Receipt {
    if (!std.meta.eql(scheme.config, P.T.P.config()) or scheme.revision_config != null) return error.GlobalPcsSuiteMismatch;
    var roots = try scheme.roots(a);
    defer roots.deinit(a);
    if (roots.items.len != 2) return error.InvalidGlobalStage1;
    if (!std.mem.eql(u8, &roots.items[0], &setup.fixed_root.value)) return error.GlobalFixedRootMismatch;
    for (0..2) |tree| {
        const logs = try setup.materials.logs(a, tree);
        defer a.free(logs);
        if (logs.len != scheme.trees.items[tree].columns.len) return error.GlobalStage1GeometryMismatch;
        for (logs, scheme.trees.items[tree].columns) |log, col| if (col.log_size != log + P.T.P.config().fri_config.log_blowup_factor) return error.GlobalStage1GeometryMismatch;
    }
    return .{ .fixed = .{ .bytes = roots.items[0] }, .main = .{ .bytes = roots.items[1] } };
}
