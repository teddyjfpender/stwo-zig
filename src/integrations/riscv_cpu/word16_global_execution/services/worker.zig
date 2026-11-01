//! One owned seal/complete lifecycle for the canonical CPU and crypto workers.
//! Shared randomness is derived only from the complete checked manifest.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const wire = @import("stwo_proof_wire");
const Profile = @import("stwo_prover_api").stage_profile;
const A = @import("stwo_riscv_frontend").rv64_air;
const G = @import("../protocol.zig");
const P = @import("protocol.zig");
const R = @import("roster.zig");
const T = @import("types.zig");
const S = @import("statement.zig");
const Adapters = @import("air_components.zig");
const Components = @import("../../word16_execution/components.zig").Components;
const Profiling = @import("profiling.zig");
const Q = G.Q;
pub const Cpu = struct { setup: *const R.CpuSetup, request: P.Request, ordinal: usize, first_step: u64, first_ids: [T.FAMILIES]u32 };
pub const Descriptor = union(enum) {
    cpu: Cpu,
    truth: struct { value: R.Truth, ordinal: usize },
    fn key(self: Descriptor) *const @import("../keccak/shared/key.zig").Key {
        return switch (self) {
            .cpu => |c| &c.setup.key,
            .truth => |t| t.value.key(),
        };
    }
    fn logs(self: Descriptor, a: std.mem.Allocator, tree: usize) ![]u32 {
        return switch (self) {
            .cpu => |c| c.setup.logs(a, tree),
            .truth => |t| t.value.logs(a, tree),
        };
    }
    fn begin(self: Descriptor, channel: *G.T.P.Channel, expected: P.Expected) !void {
        switch (self) {
            .cpu => |c| try P.beginCpu(channel, c.setup, c.request, expected, c.ordinal, c.first_step, c.first_ids),
            .truth => |t| P.beginTruth(channel, t.value, expected, t.ordinal),
        }
    }
};
pub const Source = union(enum) {
    cpu: R.Sources,
    truth: R.TruthSource,
    fn deinit(self: *Source) void {
        switch (self.*) {
            inline else => |*s| s.deinit(),
        }
    }
    fn take(self: *Source, descriptor: Descriptor, tree: usize) !@import("../../word16_execution/main_ownership.zig").Commit {
        return switch (self.*) {
            .cpu => |*s| if (descriptor == .cpu) (if (tree == 1) s.takeMain(descriptor.cpu.setup) else s.takeInteraction(descriptor.cpu.setup)) else error.ServiceWorkerKindMismatch,
            .truth => |*s| if (descriptor == .truth) (if (tree == 1) s.takeMain() else s.takeInteraction()) else error.ServiceWorkerKindMismatch,
        };
    }
};
pub const Result = union(enum) {
    cpu: S.CpuEncoded,
    truth: S.TruthEncoded,
    pub fn deinit(self: *Result, a: std.mem.Allocator) void {
        switch (self.*) {
            .cpu => |*c| c.deinit(a),
            .truth => |t| a.free(t.bytes),
        }
    }
};
const Claims = union(enum) { cpu: S.CpuClaims, truth: [3]Q };
const Air = union(enum) {
    cpu: struct { base: Components, bridges: Adapters.Bridges },
    truth: Adapters.TruthComponents,
    fn init(descriptor: Descriptor, draw: Draw, claims: Claims) !Air {
        return switch (descriptor) {
            .cpu => |c| .{ .cpu = .{ .base = try Components.init(&c.setup.materials, c.request.base, draw.cpu.local, claims.cpu.base), .bridges = Adapters.Bridges.init(c.setup, c.request.calls, c.first_ids, draw.cpu.local, draw.cpu.shared, claims.cpu.extras).withBulk(c.setup, c.request.bulk, draw.cpu.local, claims.cpu.bulk) } },
            .truth => |t| .{ .truth = try Adapters.TruthComponents.init(t.value, draw.truth, claims.truth) },
        };
    }
    fn provers(self: *Air, a: std.mem.Allocator) ![]engine.air.component_prover.ComponentProver {
        return switch (self.*) {
            .cpu => |*c| Adapters.cpuHandles(a, &c.base, &c.bridges),
            .truth => |*t| blk: {
                var buffer: [3]engine.air.component_prover.ComponentProver = undefined;
                break :blk a.dupe(engine.air.component_prover.ComponentProver, t.provers(&buffer));
            },
        };
    }
};
const Draw = union(enum) { cpu: struct { local: G.Old.Draw, shared: P.Shared }, truth: P.TruthDraw };
pub const Worker = struct {
    descriptor: Descriptor,
    source: Source,
    scheme: G.T.Scheme,
    channel: G.T.P.Channel = .{},
    spec: [32]u8 = undefined,
    owns_scheme: bool = true,
    owns_source: bool = true,
    sealed: bool = false,
    started: bool = false,
    failed: bool = false,
    retained_store: ?*@import("../retained_main_store.zig").Store = null,
    pub fn init(a: std.mem.Allocator, descriptor: Descriptor, source: Source) !Worker {
        if ((descriptor == .cpu) != (source == .cpu)) return error.ServiceWorkerKindMismatch;
        try descriptor.key().suite.validate();
        var scheme = try G.T.Scheme.init(a, descriptor.key().suite.config());
        scheme.setCompactPolynomialStorage(5);
        return .{ .descriptor = descriptor, .source = source, .scheme = scheme };
    }
    pub fn retireSource(self: *Worker) void {
        if (self.owns_source) {
            self.source.deinit();
            self.owns_source = false;
        }
    }
    pub fn deinit(self: *Worker, a: std.mem.Allocator) void {
        if (self.owns_scheme) self.scheme.deinit(a);
        self.retireSource();
    }
    pub fn actual(self: *Worker, a: std.mem.Allocator) !G.Receipt {
        if (!std.meta.eql(self.scheme.config, self.descriptor.key().suite.config()) or self.scheme.revision_config != null) return error.CombinedPcsSuiteMismatch;
        var roots = try self.scheme.roots(a);
        defer roots.deinit(a);
        if (roots.items.len != 2 or !std.mem.eql(u8, &roots.items[0], &self.descriptor.key().root)) return error.CombinedStage1Mismatch;
        for (0..2) |tree| {
            const logs = try self.descriptor.logs(a, tree);
            defer a.free(logs);
            if (logs.len != self.scheme.trees.items[tree].columns.len) return error.CombinedStage1Mismatch;
            for (logs, self.scheme.trees.items[tree].columns) |log, column| if (column.log_size != log + self.descriptor.key().suite.config().fri_config.log_blowup_factor) return error.CombinedStage1Mismatch;
        }
        return .{ .fixed = .{ .bytes = roots.items[0] }, .main = .{ .bytes = roots.items[1] } };
    }
    pub fn seal(self: *Worker, a: std.mem.Allocator, expected: P.Expected, options: Profiling.Options, ordinal: usize) !G.Receipt {
        if (self.failed or self.sealed or self.started) return error.InvalidServiceWorkerPhase;
        errdefer self.failed = true;
        try self.descriptor.begin(&self.channel, expected);
        self.spec = self.channel.digestBytes();
        try self.descriptor.key().append(a, &self.scheme, &self.channel);
        var stage = try Profile.StageScope.begin(options.recorder(ordinal), "main_commit", "Owned worker MAIN streaming commitment");
        defer stage.end();
        const main = try self.source.take(self.descriptor, 1);
        try self.scheme.commitOwnedStreamingWithRecorderAndBacking(a, main.columns, main.backings, options.commit_batch_columns, options.recorder(ordinal), &self.channel);
        stage.end();
        const receipt = try self.actual(a);
        if (options.retained_main) |store| {
            var spill = try Profile.StageScope.begin(options.recorder(ordinal), "retained_main_spill", "Retain sealed native MAIN coefficients");
            defer spill.end();
            _ = try store.spill(a, &self.scheme.trees.items[1]);
            self.retained_store = store;
        }
        self.sealed = true;
        return receipt;
    }
    fn generate(self: *Worker, draw: Draw, recorder: ?*Profile.Recorder) !Claims {
        return switch (self.source) {
            .cpu => |*source| block: {
                const ch = draw.cpu.local;
                const common = draw.cpu.shared;
                const base = (try source.core.generateForDelegationJoinProfiled(ch, recorder)).physical;
                var extras: [T.FAMILIES]T.ExtraClaims = @splat(T.ExtraClaims.zero());
                if (source.keccak) |*b| extras[0] = T.ExtraClaims.fromK(try b.generate(.{ .ram = ch.memory.ram, .owner = ch.cpu.owner, .io = common.kio, .range16 = ch.memory.range16, .range8 = ch.memory.range8 }, source.core.range16.dictionary, source.core.range8.dictionary));
                inline for (.{ "add", "double", "sha256", "arith256_mod" }, 1..) |name, k| if (@field(source, name)) |*b| {
                    extras[k] = T.ExtraClaims.fromSecp(try b.generate(.{ .ram = ch.memory.ram, .owner = ch.cpu.owner, .wire = common.wire, .range16 = ch.memory.range16, .range8 = ch.memory.range8 }, source.core.range16.dictionary, source.core.range8.dictionary));
                };
                var bulk: [3]T.BulkClaims = @splat(T.BulkClaims.zero());
                for (&source.bulk, &bulk) |*b, *out| if (b.*) |*s| {
                    out.* = try s.generate(.{ .ram = ch.memory.ram, .owner = ch.cpu.owner, .range16 = ch.memory.range16 }, source.core.range16.dictionary);
                };
                const claims = S.CpuClaims{ .base = base, .extras = extras, .bulk = bulk };
                try claims.presence(self.descriptor.cpu.setup);
                break :block .{ .cpu = claims };
            },
            .truth => |*source| .{ .truth = try truthClaims(source, draw.truth) },
        };
    }
    pub fn complete(self: *Worker, a: std.mem.Allocator, manifest: *const G.Manifest, options: Profiling.Options, ordinal: usize) !Result {
        if (!self.sealed or self.started or self.failed) return error.InvalidServiceWorkerPhase;
        // No loose shared challenge is accepted. Preserve sealed owners on a
        // pre-draw mismatch; after drawing, every error is terminal for this worker.
        try manifest.check(manifest.specs);
        if (ordinal >= manifest.specs.len or !std.mem.eql(u8, &self.spec, &manifest.specs[ordinal]) or !std.meta.eql(try self.actual(a), manifest.roots[ordinal])) return error.CombinedStage1Mismatch;
        self.started = true;
        errdefer self.failed = true;
        const recorder = options.recorder(ordinal);
        var main_ready = false;
        if (options.prefetch_main_bytes != 0) if (self.retained_store) |store| {
            var prefetch = try Profile.StageScope.begin(recorder, "retained_main_prefetch", "Advise current stable MAIN before interaction generation");
            defer prefetch.end();
            const result = try store.prefetchMain(&self.scheme.trees.items[1], options.prefetch_main_bytes);
            main_ready = result.ready;
        };
        const draw: Draw = switch (self.descriptor) {
            .cpu => |c| .{ .cpu = .{ .local = try P.drawCpu(&self.channel, manifest, c.ordinal), .shared = try P.shared(manifest) } },
            .truth => |t| .{ .truth = try P.drawTruth(&self.channel, manifest, t.value, t.ordinal) },
        };
        var generation = try Profile.StageScope.begin(recorder, "interaction_generation", "Worker native interactions");
        defer generation.end();
        const claims = try self.generate(draw, recorder);
        generation.end();
        switch (claims) {
            .cpu => |c| c.mix(&self.channel, self.descriptor.cpu.setup),
            .truth => |t| self.channel.mixFelts(&t),
        }
        var inter_stage = try Profile.StageScope.begin(recorder, "interaction_commit", "Owned worker interaction streaming commitment");
        defer inter_stage.end();
        const inter = try self.source.take(self.descriptor, 2);
        try self.scheme.commitOwnedStreamingWithRecorderAndBacking(a, inter.columns, inter.backings, options.commit_batch_columns, recorder, &self.channel);
        inter_stage.end();
        if (!main_ready) if (self.retained_store) |store| {
            var restore = try Profile.StageScope.begin(recorder, "retained_main_restore", "Restore parked sealed native MAIN coefficients");
            defer restore.end();
            _ = try store.restore(&self.scheme.trees.items[1]);
        };
        var components = try Air.init(self.descriptor, draw, claims);
        const handles = try components.provers(a);
        defer a.free(handles);
        self.owns_scheme = false; // prove consumes and tears down on every path.
        var proof = try Profiling.prove(a, handles, &self.channel, self.scheme, recorder);
        defer proof.deinit(a);
        const bytes = try wire.encodeProofBytesBinary(a, proof);
        errdefer a.free(bytes);
        var result: Result = switch (self.descriptor) {
            .truth => .{ .truth = .{ .bytes = bytes, .claims = claims.truth } },
            .cpu => |c| block: {
                var request = c.request;
                request.base.memory.initial = try a.dupe(A.memory.closed_ram.types.Cell, c.request.base.memory.initial);
                errdefer a.free(request.base.memory.initial);
                request.base.memory.terminal = try a.dupe(A.memory.closed_ram.types.Cell, c.request.base.memory.terminal);
                break :block .{ .cpu = .{ .bytes = bytes, .request = request, .claims = claims.cpu } };
            },
        };
        // bytes is now result-owned. On observation failure release it once.
        self.retireSource();
        options.finish(a, ordinal) catch |err| {
            switch (result) {
                .cpu => |*c| {
                    a.free(c.request.base.memory.initial);
                    a.free(c.request.base.memory.terminal);
                },
                .truth => {},
            }
            return err;
        };
        return result;
    }
};
fn truthClaims(source: *R.TruthSource, draw: P.TruthDraw) ![3]Q {
    return switch (source.*) {
        .keccak => |*s| switch (draw) {
            .keccak => |ch| .{ try A.crypto.keccak.interaction.generate(&s.permutation, ch), try s.chi.generateInteraction(ch), try s.xor5.generateInteraction(ch) },
            else => error.InvalidCombinedTruthChallenge,
        },
        .secp => |*s| switch (draw) {
            .secp => |ch| .{ try s.batch.product.generateInteraction(ch), try s.batch.linear.generateInteraction(ch), try s.bytes.generateInteraction(ch.bytes) },
            else => error.InvalidCombinedTruthChallenge,
        },
        // One component; the unused claim slots are fixed zero (receiver-checked).
        .sha256 => |*s| switch (draw) {
            .sha256 => |wire_ch| .{ try s.source.generateInteraction(wire_ch), G.Q.zero(), G.Q.zero() },
            else => error.InvalidCombinedTruthChallenge,
        },
        // BYTE chain closes to zero in-AIR; only the Wire35 claim is public.
        .arith256_mod => |*s| switch (draw) {
            .arith256_mod => |ch| .{ try s.source.generateInteraction(ch), G.Q.zero(), G.Q.zero() },
            else => error.InvalidCombinedTruthChallenge,
        },
    };
}
