//! Finite producer/verifier implementation for the original terminal and
//! explicitly nonterminal window memory protocols. No runtime mode selection.
pub fn ForMode(comptime window: bool) type {
    return struct {
        //! One genuine heterogeneous original STARK for all RAM shards and the exact
        //! initialization/range/terminal providers. Its transition relation remains
        //! open until independently verified native/caller execution closes it.
        const std = @import("std");
        const core = @import("stwo_core");
        const engine = @import("stwo_prover_engine");
        const suite = core.proof_suites.Blake3;
        const Budget = engine.host_budget_allocator.SharedHostBudget;
        const Column = engine.pcs.ColumnEvaluation;
        const Q = core.fields.qm31.QM31;
        const Policy = @import("block_v7_execution_policy_v1.zig").Policy;
        const E = @import("block_v7_execution_epoch_v1.zig");
        const T = @import("block_v7_memory_trace_v1.zig");
        const R = @import("block_v7_memory_relations_v1.zig");
        const Halt = @import("block_v7_halt_algebra_v1.zig");
        const Ram = if (window) @import("block_v7_window_ram_component_v1.zig") else @import("block_v7_ram_component_v1.zig");
        const Provider = @import("block_v7_provider_component_v1.zig");
        const Geometry = @import("block_v5_ram_lanes_protocol_v1.zig");
        const Layout = if (window) @import("block_v7_window_memory_joint_layout_v1.zig") else @import("block_v7_memory_joint_layout_v1.zig");
        const Air = if (window) @import("block_v7_window_memory_joint_air_v1.zig") else @import("block_v7_memory_joint_air_v1.zig");
        const Protocol = if (window) @import("block_v7_window_memory_joint_protocol_v1.zig") else @import("block_v7_memory_joint_protocol_v1.zig");
        const Witness = if (window) @import("block_v7_window_memory_witness_v1.zig") else @import("block_v7_memory_witness_v1.zig");
        const Original = @import("../air/block/word_memory_lanes_trace_v1.zig");
        const B = @import("block_v7_memory_bundle_v1.zig");
        pub const Limits = struct { memory: B.Limits = .{}, layout: Layout.Limits = .{}, max_live_bytes: usize = 8 << 30, ram_quotient: @import("block_v7_ram_quotient_policy_v1.zig").Policy = .{ .bounded_tiles = .{} }, input_storage: @import("block_v7_input_storage_v1.zig").Policy = .resident, interaction_storage: @import("block_v7_input_storage_v1.zig").Policy = .resident, consume_rows: bool = false };
        pub const Proof = struct {
            allocator: std.mem.Allocator,
            budget: *Budget,
            ram: []Air.RamClaim,
            interval_log: u32,
            interval: [2]Q,
            range16: [2]Q,
            terminal: if (window) void else [1]Q,
            roots: [2][32]u8,
            stark: suite.Proof,
            pub fn claims(self: *const Proof) Air.Claims {
                return .{ .ram = self.ram, .interval = self.interval, .range16 = self.range16, .terminal = self.terminal };
            }
            pub fn deinit(self: *Proof) void {
                const budget = self.budget;
                self.stark.deinit(self.allocator);
                self.allocator.free(self.ram);
                self.* = undefined;
                budget.destroy();
            }
        };
        /// Owns only verifier-reconstructed material and copied physical claims. The
        /// original proof file, producer matrices and caller-owned proposal may die.
        pub const VerifiedCapture = struct {
            allocator: std.mem.Allocator,
            budget: *Budget,
            proof: core.verifier.ProofCapture(suite.Hasher),
            final_channel: suite.Channel,
            ram: []Air.RamClaim,
            interval: [2]Q,
            range16: [2]Q,
            terminal: if (window) void else [1]Q,
            interval_log: u32,
            roots: [2][32]u8,
            open: Protocol.Open,
            pub fn claims(self: *const VerifiedCapture) Air.Claims {
                return .{ .ram = self.ram, .interval = self.interval, .range16 = self.range16, .terminal = self.terminal };
            }
            pub fn deinit(self: *VerifiedCapture) void {
                const budget = self.budget;
                self.proof.deinit(self.allocator);
                self.allocator.free(self.ram);
                self.* = undefined;
                budget.destroy();
            }
        };
        pub fn For(comptime Backend: type) type {
            const Scheme = engine.pcs.CommitmentSchemeProver(Backend, suite.Hasher, suite.MerkleChannel);
            return struct {
                pub const Stage = struct {
                    allocator: std.mem.Allocator,
                    budget: *Budget,
                    policy: Policy,
                    limits: Limits,
                    witness: Witness.Owner,
                    layout: Layout.Layout,
                    scheme: Scheme,
                    roots: [2][32]u8,
                    owns_scheme: bool = true,
                    consumed: bool = false,
                    witness_live: bool = true,
                    preparation: @import("block_v7_memory_preparation_stats_v1.zig").Stats = .{},
                    pub fn init(backing: std.mem.Allocator, policy: Policy, guest: []const @import("../air/block/memory_transition.zig").Transition, high_byte: u8, per_shard: u32, limits: Limits) !*Stage {
                        if (limits.max_live_bytes == 0) return error.V7JointResourceLimit;
                        try limits.ram_quotient.validate();
                        try limits.interaction_storage.validate();
                        const compact_log = try limits.input_storage.minimumCommitmentLog(policy.config);
                        const budget = try Budget.createRetainingParent(backing, limits.max_live_bytes);
                        errdefer budget.destroy();
                        const a = budget.allocator();
                        const self = try a.create(Stage);
                        errdefer a.destroy(self);
                        var phase_timer = try std.time.Timer.start();
                        var preparation: @import("block_v7_memory_preparation_stats_v1.zig").Stats = .{};
                        var witness = try Witness.Owner.init(a, policy, guest, high_byte, per_shard, limits.memory);
                        errdefer witness.deinit();
                        preparation.witness_ns = phase_timer.lap();
                        const geometries = try a.alloc(Geometry.Claim, witness.ram.len);
                        defer a.free(geometries);
                        for (geometries, witness.ram) |*g, item| g.* = item.geometry;
                        var layout = try Layout.Layout.init(a, geometries, witness.interval.log, limits.layout);
                        errdefer layout.deinit();
                        var scheme = try Scheme.init(a, policy.config);
                        errdefer scheme.deinit(a);
                        scheme.setCoefficientRetentionPolicy(.always);
                        if (compact_log) |log| scheme.setCompactPolynomialStorage(log);
                        var channel = try Protocol.firstChannel(policy, &layout);
                        preparation.layout_ns = phase_timer.lap();
                        for (0..2) |tree| {
                            const columns = try witnessColumns(a, &witness, &layout, tree);
                            defer a.free(columns);
                            const columns_ns = phase_timer.lap();
                            if (tree == 0) preparation.fixed_columns_ns = columns_ns else preparation.main_columns_ns = columns_ns;
                            try scheme.commitBorrowedStreaming(a, columns, 16, &channel);
                            const commitment_ns = phase_timer.lap();
                            if (tree == 0) preparation.fixed_commitment_ns = commitment_ns else preparation.main_commitment_ns = commitment_ns;
                        }
                        // Only original input trees use this policy. Interaction and
                        // composition storage remain governed by their existing path.
                        scheme.compact_polynomial_storage = false;
                        var roots = try scheme.roots(a);
                        defer roots.deinit(a);
                        if (roots.items.len != 2) return error.InvalidV7JointFirstRound;
                        preparation.finalize_ns = phase_timer.lap();
                        preparation.whole_ns = preparation.witness_ns + preparation.layout_ns + preparation.fixed_columns_ns + preparation.fixed_commitment_ns + preparation.main_columns_ns + preparation.main_commitment_ns + preparation.finalize_ns;
                        self.* = .{ .allocator = a, .budget = budget, .policy = policy, .limits = limits, .witness = witness, .layout = layout, .scheme = scheme, .roots = roots.items[0..2].*, .preparation = preparation };
                        return self;
                    }
                    pub fn entry(self: *const Stage) !E.Entry {
                        return Protocol.entry(self.policy, &self.layout, self.roots);
                    }
                    pub fn deinit(self: *Stage) void {
                        const a = self.allocator;
                        const budget = self.budget;
                        if (self.owns_scheme) self.scheme.deinit(a);
                        self.layout.deinit();
                        if (self.witness_live) self.witness.deinit();
                        a.destroy(self);
                        budget.destroy();
                    }
                    /// Caller must have finished all fixed-column and interaction reads.
                    /// Layout, claims held by the caller, and committed PCS remain live.
                    pub fn releaseWitness(self: *Stage) !void {
                        if (!self.witness_live) return error.InvalidV7JointPhase;
                        self.witness.deinit();
                        self.witness_live = false;
                        self.consumed = true;
                    }
                    /// A union must already own every physical tree it still needs.
                    /// Shared tree leases survive; this source can no longer prove.
                    pub fn releaseProducerState(self: *Stage) !void {
                        if (!self.owns_scheme or !self.witness_live) return error.InvalidV7JointPhase;
                        try self.releaseWitness();
                        self.scheme.deinit(self.allocator);
                        self.owns_scheme = false;
                    }
                    pub fn prove(self: *Stage, epoch: E.Epoch, roster: []const E.Entry) !Proof {
                        if (self.consumed or !self.owns_scheme or !self.witness_live) return error.InvalidV7JointPhase;
                        const pin = try self.entry();
                        try Protocol.requireEpoch(self.policy, epoch, roster, pin);
                        self.consumed = true;
                        const a = self.allocator;
                        const drawn = try epoch.draw(a);
                        const ram = try a.alloc(Air.RamClaim, self.witness.ram.len);
                        errdefer a.free(ram);
                        const generated = try a.alloc(T.Generated(Ram.PLANES), ram.len);
                        defer a.free(generated);
                        var ready: usize = 0;
                        defer for (generated[0..ready]) |*g| g.deinit();
                        for (ram, generated, self.witness.ram) |*claim, *g, item| {
                            g.* = try T.interactions(Ram.PLANES, a, item.matrix, RamContext{ .spec = ramSpec(item.geometry, drawn, self.policy) catch |err| return err }, self.limits.memory.max_matrix_bytes);
                            ready += 1;
                            claim.* = .{ .geometry = item.geometry, .sums = g.sums };
                        }
                        var interval = try providerInteractions(.interval, a, self.witness.interval, drawn.memory, self.limits.memory.max_matrix_bytes);
                        var provider_rows_live = true;
                        defer if (provider_rows_live) interval.deinit();
                        var range16 = try providerInteractions(.range16, a, self.witness.range16, drawn.memory, self.limits.memory.max_matrix_bytes);
                        defer if (provider_rows_live) range16.deinit();
                        var terminal = if (window) {} else try providerInteractions(.terminal, a, self.witness.terminal, drawn.memory, self.limits.memory.max_matrix_bytes);
                        defer if (!window and provider_rows_live) terminal.deinit();
                        const claims = Air.Claims{ .ram = ram, .interval = interval.sums, .range16 = range16.sums, .terminal = if (window) {} else terminal.sums };
                        const interval_log = self.witness.interval.log;
                        const owner = try airOwner(a, &self.layout, claims, drawn, self.policy);
                        defer owner.deinit();
                        try owner.configureRamQuotient(self.limits.ram_quotient, self.limits.max_live_bytes);
                        var channel = try Protocol.proofChannel(drawn, pin, &self.layout, claims);
                        const columns = try a.alloc(Column, self.layout.columns[2]);
                        defer a.free(columns);
                        for (generated, self.layout.parts[0..ram.len]) |g, part| @memcpy(columns[part.offset[2]..][0..part.width[2]], g.matrix.columns);
                        inline for ((if (window) .{ &interval, &range16 } else .{ &interval, &range16, &terminal }), 0..) |g, i| {
                            const part = self.layout.parts[ram.len + i];
                            @memcpy(columns[part.offset[2]..][0..part.width[2]], g.matrix.columns);
                        }
                        if (self.limits.consume_rows) try self.releaseWitness();
                        if (try self.limits.interaction_storage.minimumCommitmentLog(self.policy.config)) |log| self.scheme.setCompactPolynomialStorage(log);
                        try self.scheme.commitBorrowedStreaming(a, columns, 8, &channel);
                        self.scheme.compact_polynomial_storage = false;
                        if (self.limits.consume_rows) {
                            for (generated[0..ready]) |*g| g.deinit();
                            ready = 0;
                            interval.deinit();
                            range16.deinit();
                            if (!window) terminal.deinit();
                            provider_rows_live = false;
                        }
                        self.owns_scheme = false;
                        const stark = try engine.prove.prove(Backend, suite.Hasher, suite.MerkleChannel, a, owner.provers, &channel, self.scheme);
                        return .{ .allocator = a, .budget = self.budget.retain(), .ram = ram, .interval_log = interval_log, .interval = claims.interval, .range16 = claims.range16, .terminal = claims.terminal, .roots = self.roots, .stark = stark };
                    }
                };
                /// Independent policy-fixed commitment authority for detached recursive
                /// verification. No proof file or successful capture is required.
                pub fn requireFixedRoot(backing: std.mem.Allocator, policy: Policy, geometries: []const Geometry.Claim, interval_log: u32, expected: [32]u8, limits: Limits) !void {
                    try policy.validate();
                    if ((policy.window != null) != window) return error.InvalidV7MemoryPolicyMode;
                    if (limits.max_live_bytes == 0 or geometries.len == 0 or geometries.len > limits.memory.max_shards) return error.V7JointResourceLimit;
                    const budget = try Budget.createRetainingParent(backing, limits.max_live_bytes);
                    defer budget.destroy();
                    const a = budget.allocator();
                    const total = geometries[0].total_events;
                    const count_bound = std.math.mul(u64, total, 24) catch return error.V7MemoryResourceLimit;
                    if (total < (if (window) @as(u64, 1) else 13) or total > limits.memory.max_events or count_bound >= core.fields.m31.Modulus) return error.V7MemoryResourceLimit;
                    var layout = try Layout.Layout.init(a, geometries, interval_log, limits.layout);
                    defer layout.deinit();
                    for (layout.parts) |part| {
                        if (part.family == .ram and part.log > limits.memory.max_row_log) return error.V7MemoryResourceLimit;
                        try @import("block_v5_ram_lanes_proof_v1.zig").validateGeometry(part.log, policy.config);
                    }
                    try requireFixedRootWithLayout(a, policy, geometries, &layout, expected, limits);
                }
                fn requireFixedRootWithLayout(a: std.mem.Allocator, policy: Policy, geometries: []const Geometry.Claim, layout: *const Layout.Layout, expected: [32]u8, limits: Limits) !void {
                    var trusted = try Scheme.init(a, policy.config);
                    defer trusted.deinit(a);
                    trusted.setCoefficientRetentionPolicy(.never);
                    var fixed_channel = try Protocol.firstChannel(policy, layout);
                    const fixed = try fixedColumns(a, policy, geometries, layout, limits.memory);
                    defer freeColumns(a, fixed);
                    try trusted.commitBorrowedStreaming(a, fixed, 16, &fixed_channel);
                    var expected_roots = try trusted.roots(a);
                    defer expected_roots.deinit(a);
                    if (expected_roots.items.len != 1 or !std.meta.eql(expected_roots.items[0], expected)) return error.UntrustedV7JointFixedRoot;
                }
                pub fn verify(backing: std.mem.Allocator, policy: Policy, epoch: E.Epoch, roster: []const E.Entry, proof: *const Proof, limits: Limits) !Protocol.Open {
                    var captured = try verifyAndCapture(backing, policy, epoch, roster, proof, limits);
                    defer captured.deinit();
                    return captured.open;
                }
                pub fn verifyAndCapture(backing: std.mem.Allocator, policy: Policy, epoch: E.Epoch, roster: []const E.Entry, proof: *const Proof, limits: Limits) !VerifiedCapture {
                    try policy.validate();
                    if ((policy.window != null) != window) return error.InvalidV7MemoryPolicyMode;
                    if (limits.max_live_bytes == 0 or proof.ram.len == 0 or proof.ram.len > limits.memory.max_shards) return error.V7JointResourceLimit;
                    const budget = try Budget.createRetainingParent(backing, limits.max_live_bytes);
                    defer budget.destroy();
                    const a = budget.allocator();
                    const geometries = try a.alloc(Geometry.Claim, proof.ram.len);
                    defer a.free(geometries);
                    for (geometries, proof.ram) |*g, item| g.* = item.geometry;
                    const total = geometries[0].total_events;
                    const count_bound = std.math.mul(u64, total, 24) catch return error.V7MemoryResourceLimit;
                    if (total < (if (window) @as(u64, 1) else 13) or total > limits.memory.max_events or count_bound >= core.fields.m31.Modulus) return error.V7MemoryResourceLimit;
                    var layout = try Layout.Layout.init(a, geometries, proof.interval_log, limits.layout);
                    defer layout.deinit();
                    for (layout.parts) |part| {
                        if (part.family == .ram and part.log > limits.memory.max_row_log) return error.V7MemoryResourceLimit;
                        try @import("block_v5_ram_lanes_proof_v1.zig").validateGeometry(part.log, policy.config);
                    }
                    const pin = try Protocol.entry(policy, &layout, proof.roots);
                    try Protocol.requireEpoch(policy, epoch, roster, pin);
                    const roots = proof.stark.commitment_scheme_proof.commitments.items;
                    if (roots.len != 4 or !std.meta.eql(roots[0..2].*, proof.roots) or !std.meta.eql(proof.stark.commitment_scheme_proof.config, policy.config)) return error.InvalidV7JointProofShape;
                    // Reject malformed physical claim framing before rebuilding fixed data.
                    const drawn = try epoch.draw(a);
                    var channel = try Protocol.proofChannel(drawn, pin, &layout, proof.claims());
                    try requireFixedRootWithLayout(a, policy, geometries, &layout, proof.roots[0], limits);
                    const owner = try airOwner(a, &layout, proof.claims(), drawn, policy);
                    defer owner.deinit();
                    var verifier = try core.pcs.verifier.CommitmentSchemeVerifier(suite.Hasher, suite.MerkleChannel).init(a, policy.config);
                    defer verifier.deinit(a);
                    var first = try Protocol.firstChannel(policy, &layout);
                    for (0..2) |tree| {
                        const logs = try layout.logs(a, tree);
                        defer a.free(logs);
                        try verifier.commit(a, proof.roots[tree], logs, &first);
                    }
                    const logs = try layout.logs(a, 2);
                    defer a.free(logs);
                    try verifier.commit(a, roots[2], logs, &channel);
                    var captured: core.verifier.ProofCapture(suite.Hasher) = undefined;
                    try core.verifier.verifyBorrowedWithProofCapture(suite.Hasher, suite.MerkleChannel, a, owner.verifiers, &channel, &verifier, &proof.stark, &captured);
                    errdefer captured.deinit(a);
                    const open = if (window) try Protocol.closeVerifiedClaims(policy, drawn.word.initial, proof.claims()) else try Protocol.closeVerifiedClaims(proof.claims());
                    const ram = try a.dupe(Air.RamClaim, proof.ram);
                    return .{ .allocator = a, .budget = budget.retain(), .proof = captured, .final_channel = channel, .ram = ram, .interval = proof.interval, .range16 = proof.range16, .terminal = proof.terminal, .interval_log = proof.interval_log, .roots = proof.roots, .open = open };
                }
            };
        }
        pub fn providerInteractions(comptime kind: Provider.Kind, a: std.mem.Allocator, matrix: T.Matrix, challenges: R.Challenges(Q), max_bytes: usize) !T.Generated(Provider.For(kind).PLANES) {
            const S = Provider.For(kind);
            const Context = struct {
                ch: R.Challenges(Q),
                pub fn termsAt(self: @This(), m: T.Matrix, logical: usize) ![S.PLANES]R.Term(Q) {
                    return S.terms(Q, self.ch, m.row(S.FIXED_COUNT, 0, logical), m.row(S.MAIN_COUNT, S.FIXED_COUNT, logical));
                }
            };
            return T.interactions(S.PLANES, a, matrix, Context{ .ch = challenges }, max_bytes);
        }
        pub fn witnessColumns(a: std.mem.Allocator, witness: *const Witness.Owner, layout: *const Layout.Layout, tree: usize) ![]Column {
            if (tree >= 2) return error.InvalidV7JointTree;
            const columns = try a.alloc(Column, layout.columns[tree]);
            errdefer a.free(columns);
            for (witness.ram, layout.parts[0..witness.ram.len]) |item, part| {
                const start = if (tree == 0) 0 else part.width[0];
                @memcpy(columns[part.offset[tree]..][0..part.width[tree]], item.matrix.columns[start..][0..part.width[tree]]);
            }
            inline for ((if (window) .{ "interval", "range16" } else .{ "interval", "range16", "terminal" }), 0..) |name, i| {
                const part = layout.parts[witness.ram.len + i];
                const start = if (tree == 0) 0 else part.width[0];
                @memcpy(columns[part.offset[tree]..][0..part.width[tree]], @field(witness, name).columns[start..][0..part.width[tree]]);
            }
            return columns;
        }
        fn freeColumns(a: std.mem.Allocator, columns: []Column) void {
            for (columns) |column| a.free(column.values);
            a.free(columns);
        }
        pub fn fixedColumns(a: std.mem.Allocator, policy: Policy, ram: []const Geometry.Claim, layout: *const Layout.Layout, limits: B.Limits) ![]Column {
            const result = try a.alloc(Column, layout.columns[0]);
            var ready: usize = 0;
            errdefer {
                for (result[0..ready]) |column| a.free(column.values);
                a.free(result);
            }
            for (ram, layout.parts[0..ram.len]) |g, part| {
                var original = try Original.FixedTrace.init(a, g, limits.max_matrix_bytes);
                defer original.deinit();
                if (part.offset[0] != ready) return error.InvalidV7JointPlacement;
                for (0..24) |i| {
                    result[ready] = .{ .log_size = g.row_log, .values = try a.dupe(core.fields.m31.M31, original.column(i)) };
                    ready += 1;
                }
            }
            const counts = try a.alloc(u32, policy.initialized.intervals.len);
            defer a.free(counts);
            @memset(counts, 0);
            var interval = try T.interval(a, policy.initialized, counts, limits.max_matrix_bytes);
            defer interval.deinit();
            if (interval.log != layout.parts[ram.len].log) return error.InvalidV7JointGeometry;
            const ranges = try a.alloc(u32, 65536);
            defer a.free(ranges);
            @memset(ranges, 0);
            var range = try T.range16(a, ranges, limits.max_matrix_bytes);
            defer range.deinit();
            var terminal = if (window) {} else try T.terminal(a, try @import("block_v7_terminal_protocol_v1.zig").Plan.init(policy.terminal), 0, limits.max_matrix_bytes);
            defer if (!window) terminal.deinit();
            inline for ((if (window) .{ interval, range } else .{ interval, range, terminal }), 0..) |matrix, i| {
                const part = layout.parts[ram.len + i];
                if (part.offset[0] != ready) return error.InvalidV7JointPlacement;
                for (matrix.columns[0..part.width[0]]) |column| {
                    result[ready] = .{ .log_size = column.log_size, .values = try a.dupe(core.fields.m31.M31, column.values) };
                    ready += 1;
                }
            }
            if (ready != result.len) return error.InvalidV7JointPlacement;
            return result;
        }

        pub fn ramSpec(geometry: Geometry.Claim, drawn: E.Drawn, policy: Policy) !Ram.Spec {
            if (window) return .{ .claim = geometry, .sums = @splat(Q.zero()), .challenges = drawn.memory, .delta = R.Relation(Q, 5).from(drawn.word.initial), .halt = try policy.window.?.nonhaltConstants() };
            return .{ .claim = geometry, .sums = @splat(Q.zero()), .challenges = drawn.memory, .halt = try Halt.derive(policy.terminal) };
        }
        pub fn airOwner(a: std.mem.Allocator, layout: *const Layout.Layout, claims: Air.Claims, drawn: E.Drawn, policy: Policy) !*Air.Owner {
            if (window) return Air.Owner.init(a, layout, claims, drawn.memory, R.Relation(Q, 5).from(drawn.word.initial), try policy.window.?.nonhaltConstants());
            return Air.Owner.init(a, layout, claims, drawn.memory, try Halt.derive(policy.terminal));
        }
        pub const RamContext = if (!window) B.RamContext else struct {
            spec: Ram.Spec,
            pub const Prepared = struct {
                spec: Ram.Spec,
                incoming: Q,
                pub fn termsAt(self: @This(), matrix: T.Matrix, logical: usize) ![Ram.PLANES]R.Term(Q) {
                    const fixed = Original.fixedPoint(Q, matrix.row(24, 0, logical), self.spec.claim);
                    return Ram.terms(Q, self.spec.challenges, self.incoming, fixed, matrix.row(Ram.Spec.MAIN_COUNT, 24, logical), matrix.row(Ram.Spec.MAIN_COUNT, 24, if (logical == 0) matrix.size() - 1 else logical - 1), self.spec.delta);
                }
            };
            pub fn prepare(self: @This(), size: usize) !Prepared {
                const domain = try self.spec.prepareDomain(@intCast(size));
                return .{ .spec = self.spec, .incoming = domain.original.incoming };
            }
            pub fn termsAt(self: @This(), matrix: T.Matrix, logical: usize) ![Ram.PLANES]R.Term(Q) {
                return (try self.prepare(matrix.size())).termsAt(matrix, logical);
            }
        };
    };
}
