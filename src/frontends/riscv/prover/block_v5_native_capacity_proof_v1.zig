//! Real versioned native-capacity lifecycle, deliberately off canonical until
//! fresh-proof, fused, typed transport and recursive receivers are qualified.
//! A distinct OpenReceipt retains every ordinary/global closure obligation.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const suite = core.proof_suites.Blake3;
const protocol = @import("block_v5_native_capacity_protocol_v1.zig");
const activity = @import("block_v5_native_capacity_activity_v1.zig");
const catalog_module = @import("block_v5_native_capacity_catalog_v1.zig");
const basis_module = @import("block_v5_native_capacity_fixed_basis_v1.zig");
const composite = @import("block_v5_native_capacity_component_v1.zig");
const statement = @import("../air/statement.zig");
const native = @import("blake3_execution_trace.zig");
const joined = @import("block_v5_native_components_v3.zig");
const admission = @import("block_v5_native_public_admission_v1.zig");
const seal = @import("block_v5_source_seal_v1.zig");
const frame = @import("block_v5_native_frame_v1.zig");
const relations = @import("block_memory_relation_v2.zig");
const providers = @import("../recursion/air/universal_provider_relations.zig");
const Column = engine.pcs.ColumnEvaluation;
pub const Template = protocol.Template;
pub const Proof = struct {
    stark: suite.Proof,
    claims: *statement.RiscVInteractionClaim,
    template_id: protocol.Digest,
    instance_id: protocol.Digest,
    protocol_version: u32 = protocol.VERSION,
    pub fn deinit(self: *Proof, a: std.mem.Allocator) void {
        self.stark.deinit(a);
        a.destroy(self.claims);
        self.* = undefined;
    }
};
pub const OpenReceipt = struct {
    template_id: protocol.Digest,
    instance_id: protocol.Digest,
    first_roots: seal.Roots,
    sealed_digest: protocol.Digest,
    exact_geometry_digest: protocol.Digest,
    open_sum: core.fields.qm31.QM31,
};
/// Distinct fresh capacity-verifier witness, never a legacy native receipt.
/// Owns every capture vector and interaction claim, including borrowed inputs.
pub const VerifiedCapture = struct {
    allocator: std.mem.Allocator,
    proof: core.verifier.ProofCapture(suite.Hasher),
    native_claims: *statement.RiscVInteractionClaim,
    relations: @import("../recursion/air/universal_challenges.zig").UniversalRelations,
    final_channel: suite.Channel,
    receipt: OpenReceipt,
    seal: protocol.Digest,
    pub fn deinit(self: *VerifiedCapture) void {
        self.proof.deinit(self.allocator);
        self.allocator.destroy(self.native_claims);
        self.* = undefined;
    }
    pub fn identity(self: *const VerifiedCapture, shape: *const statement.Blake3ExecutionStatement, external: u32) !protocol.Digest {
        var channel = suite.Channel{};
        channel.mixU32s(&.{ 0x42354352, protocol.VERSION }); // B5CR mutation seal.
        channel.mixRoot(@import("proof_capture_sha256.zig").compute(&self.proof));
        channel.mixRoot(self.receipt.template_id);
        channel.mixRoot(self.receipt.instance_id);
        channel.mixRoot(self.receipt.sealed_digest);
        channel.mixRoot(self.receipt.exact_geometry_digest);
        channel.mixRoot(try protocol.capacityDigest(shape, external));
        channel.mixFelts(&.{self.receipt.open_sum});
        try protocol.mixClaims(&channel, shape, self.native_claims);
        for (self.relations.elements) |element| channel.mixFelts(&.{ element.z, element.alpha });
        channel.mixRoot(self.final_channel.digestBytes());
        channel.mixU64(self.final_channel.n_draws);
        return channel.digestBytes();
    }
    pub fn validate(self: *const VerifiedCapture, prepared: anytype, expected: protocol.Digest) !void {
        try prepared.validate(expected);
        if (self.proof.commitments.len != 4 or !std.meta.eql(self.receipt.template_id, expected) or
            !std.meta.eql(self.receipt.first_roots, self.proof.commitments[0..2].*) or
            !std.meta.eql(self.receipt.exact_geometry_digest, try @import("block_v5_native_template_protocol_v3.zig").geometryDigest(prepared.shape, prepared.external_retirements)) or
            !std.meta.eql(self.seal, try self.identity(prepared.shape, prepared.external_retirements))) return error.InvalidNativeCapacityRecursiveCapture;
        const challenges = try relations.Challenges.draw(self.allocator, prepared.sealed);
        if (!std.meta.eql(self.relations, challenges.universal_prefix) or !std.meta.eql(self.receipt.sealed_digest, prepared.sealed.digest)) return error.InvalidNativeCapacityRecursiveCapture;
        try admitWithAdmission(self.allocator, prepared.shape, prepared.external_retirements, prepared.pin, prepared.template, expected, self.receipt.instance_id, self.receipt.first_roots, prepared.index, prepared.sealed, prepared.pins, prepared.entries, prepared.catalog);
    }
};
pub const Limits = struct {
    max_main_cells: usize = 1 << 29,
    max_shards: usize = protocol.MAX_SHARDS,
    max_log: u32 = 24,
    max_public_words: usize = 1 << 20,
    max_metadata_bytes: usize = 64 << 20,
    pub fn require(self: Limits, plan: *const protocol.Plan, shape: *const statement.Blake3ExecutionStatement) !void {
        if (self.max_shards > protocol.MAX_SHARDS or self.max_log > 24 or plan.len > self.max_shards) return error.NativeCapacityResourceLimit;
        const io = shape.public_data.io_entries;
        if (try std.math.add(usize, io.input_words.len, io.output_words.len) > self.max_public_words) return error.NativeCapacityResourceLimit;
        var cells: usize = 0;
        for (shape.component_descs[0..shape.n_components]) |desc| {
            if (desc.log_size > self.max_log) return error.NativeCapacityResourceLimit;
            cells = try std.math.add(usize, cells, try std.math.mul(usize, desc.n_columns + 2, @as(usize, 1) << @intCast(desc.log_size)));
        }
        for (shape.infra_descs[0..shape.n_infra]) |desc| {
            if (desc.log_size > self.max_log) return error.NativeCapacityResourceLimit;
            cells = try std.math.add(usize, cells, try std.math.mul(usize, desc.n_columns + 2, @as(usize, 1) << @intCast(desc.log_size)));
        }
        if (plan.len == 0) {
            if (frame.LOG_SIZE > self.max_log) return error.NativeCapacityResourceLimit;
            cells = frame.MAIN_COLUMNS * (@as(usize, 1) << frame.LOG_SIZE);
        }
        if (cells > self.max_main_cells) return error.NativeCapacityResourceLimit;
    }
};
/// First-pass physical proposal, not verifier authority. Exact public words
/// are owned independently of NativeOwner/segment/replay lifetimes.
pub const Proposal = struct {
    allocator: std.mem.Allocator,
    shape: statement.Blake3ExecutionStatement,
    external_retirements: u32,
    template: Template,
    template_id: protocol.Digest,
    roots: seal.Roots,
    index: u32,
    public_digest: protocol.Digest,
    pub fn deinit(self: *Proposal) void {
        self.allocator.free(self.shape.public_data.io_entries.input_words);
        self.allocator.free(self.shape.public_data.io_entries.output_words);
        self.* = undefined;
    }
    pub fn bind(self: *const Proposal, context: admission.Context) !seal.Entry {
        if (!std.meta.eql(self.public_digest, admission.publicDigest(&self.shape.public_data)) or !std.meta.eql(self.roots[0], self.template.fixed_root)) return error.ChangedNativeCapacityProposal;
        try self.template.admit(&self.shape, self.external_retirements, self.template_id);
        const pin = try admission.Admission.init(context, &self.shape.public_data);
        const id = try protocol.instanceId(self.template_id, &self.shape, self.external_retirements, pin, self.roots, self.index);
        return .{ .family = .execution, .index = self.index, .roots = self.roots, .instance_id = id };
    }
    pub fn requireReplay(self: *const Proposal, first: anytype) !void {
        const entry = try self.bind(first.pin.context);
        if (!std.meta.eql(entry, first.entry()) or !std.meta.eql(self.template, first.template) or !std.meta.eql(self.template_id, first.template_id)) return error.NativeCapacityReplayMismatch;
    }
};
pub fn ForBackend(comptime Backend: type) type {
    return struct {
        const Scheme = engine.pcs.CommitmentSchemeProver(Backend, suite.Hasher, suite.MerkleChannel);
        const Verifier = core.pcs.verifier.CommitmentSchemeVerifier(suite.Hasher, suite.MerkleChannel);
        pub const FixedBasis = basis_module.ForBackend(Backend).Owner;
        pub const FirstRound = struct {
            scheme: Scheme,
            roots: seal.Roots,
            template: Template,
            template_id: protocol.Digest,
            instance_id: protocol.Digest,
            index: u32,
            source: *native.Owner,
            pin: admission.Admission,
            plan: protocol.Plan,
            limits: Limits,
            public_digest: protocol.Digest,
            owns_scheme: bool = true,
            pub fn entry(self: *const FirstRound) seal.Entry {
                return .{ .family = .execution, .index = self.index, .roots = self.roots, .instance_id = self.instance_id };
            }
            pub fn deinit(self: *FirstRound, a: std.mem.Allocator) void {
                if (self.owns_scheme) self.scheme.deinit(a);
                self.* = undefined;
            }
        };
        pub const PhysicalFirstRound = struct {
            scheme: Scheme,
            roots: seal.Roots,
            template: Template,
            template_id: protocol.Digest,
            index: u32,
            source: *native.Owner,
            plan: protocol.Plan,
            limits: Limits,
            public_digest: protocol.Digest,
            owns_scheme: bool = true,
            pub fn deinit(self: *PhysicalFirstRound, a: std.mem.Allocator) void {
                if (self.owns_scheme) self.scheme.deinit(a);
                self.* = undefined;
            }
            /// Late real admission transfers the already committed PCS trees.
            /// On error this object retains ownership; there is no fake fresh
            /// receipt and no second physical commitment at this boundary.
            pub fn bind(self: *PhysicalFirstRound, pin: admission.Admission) !FirstRound {
                if (!self.owns_scheme) return error.InvalidNativeCapacityPhase;
                if (!std.meta.eql(self.public_digest, admission.publicDigest(&self.source.statement.public_data))) return error.ChangedNativeCapacityFirstRound;
                const plan = try protocol.Plan.fromShape(&self.source.statement, self.source.external_retirements);
                if (!std.meta.eql(plan, self.plan)) return error.ChangedNativeCapacityFirstRound;
                try self.template.admit(&self.source.statement, self.source.external_retirements, self.template_id);
                const id = try protocol.instanceId(self.template_id, &self.source.statement, self.source.external_retirements, pin, self.roots, self.index);
                self.owns_scheme = false;
                return .{ .scheme = self.scheme, .roots = self.roots, .template = self.template, .template_id = self.template_id, .instance_id = id, .index = self.index, .source = self.source, .pin = pin, .plan = self.plan, .limits = self.limits, .public_digest = self.public_digest };
            }
        };
        /// Owns the two first trees. NativeOwner remains borrowed through
        /// proving; no count or shape supplied by a proof is an admission.
        pub fn commitFirstRound(a: std.mem.Allocator, source: *native.Owner, pin: admission.Admission, config: core.pcs.PcsConfig, selected: @import("../isa/execution_profile.zig").ExecutionProfile, index: u32, limits: Limits) !FirstRound {
            try pin.validatePublic(&source.statement.public_data);
            var physical = try commitPhysical(a, source, config, selected, index, limits);
            defer physical.deinit(a);
            return physical.bind(pin);
        }
        /// Reuses only the authenticated immutable fixed tree. The actual
        /// source cells/counts, admission and instance roots remain fresh.
        pub fn commitFirstRoundWithBasis(a: std.mem.Allocator, source: *native.Owner, pin: admission.Admission, config: core.pcs.PcsConfig, selected: @import("../isa/execution_profile.zig").ExecutionProfile, index: u32, limits: Limits, basis: *FixedBasis) !FirstRound {
            try pin.validatePublic(&source.statement.public_data);
            var physical = try commitPhysicalWithBasis(a, source, config, selected, index, limits, basis);
            defer physical.deinit(a);
            return physical.bind(pin);
        }
        pub fn commitPhysical(a: std.mem.Allocator, source: *native.Owner, config: core.pcs.PcsConfig, selected: @import("../isa/execution_profile.zig").ExecutionProfile, index: u32, limits: Limits) !PhysicalFirstRound {
            return commitPhysicalSelected(a, source, config, selected, index, limits, null);
        }
        pub fn commitPhysicalWithBasis(a: std.mem.Allocator, source: *native.Owner, config: core.pcs.PcsConfig, selected: @import("../isa/execution_profile.zig").ExecutionProfile, index: u32, limits: Limits, basis: *FixedBasis) !PhysicalFirstRound {
            return commitPhysicalSelected(a, source, config, selected, index, limits, basis);
        }
        fn commitPhysicalSelected(a: std.mem.Allocator, source: *native.Owner, config: core.pcs.PcsConfig, selected: @import("../isa/execution_profile.zig").ExecutionProfile, index: u32, limits: Limits, basis: ?*FixedBasis) !PhysicalFirstRound {
            if (!source.native_only_v5 or !source.tables_ready or source.failed or source.interaction_ready) return error.InvalidNativeCapacityPhase;
            const plan = try protocol.Plan.fromShape(&source.statement, source.external_retirements);
            try limits.require(&plan, &source.statement);
            try @import("blake3_execution_protocol.zig").validateConfig(config);
            var channel = suite.Channel{};
            channel.mixU32s(&.{ protocol.TAG, protocol.VERSION, 0, index });
            var scheme = if (basis) |owner|
                try owner.lease(a, &source.statement, source.external_retirements, config, selected, &channel)
            else
                try Scheme.init(a, config);
            errdefer scheme.deinit(a);
            scheme.setCoefficientRetentionPolicy(.never);
            if (basis == null) {
                const fixed = try protocol.fixedColumns(a, &source.statement, source.external_retirements);
                defer protocol.freeColumns(a, fixed);
                try scheme.commitBorrowedStreaming(a, fixed, 8, &channel);
            }
            if (plan.len == 0) {
                if (source.main.items.len != 0) return error.InvalidNativeCapacityGeometry;
                const main = try frame.mainColumns(a, try frame.expected(&source.statement, source.external_retirements));
                defer frame.freeColumns(a, main);
                try scheme.commitBorrowedStreaming(a, main, 8, &channel);
            } else {
                if (source.main.items.len != plan.native_main_count) return error.InvalidNativeCapacityGeometry;
                const dynamic = try activity.columns(a, &plan);
                defer protocol.freeColumns(a, dynamic);
                const main = try a.alloc(Column, plan.mainCount());
                defer a.free(main);
                @memcpy(main[0..source.main.items.len], source.main.items);
                @memcpy(main[source.main.items.len..], dynamic);
                try scheme.commitBorrowedStreaming(a, main, 8, &channel);
            }
            var roots = try scheme.roots(a);
            defer roots.deinit(a);
            if (roots.items.len != 2) return error.InvalidNativeCapacityFirstRound;
            const first_roots: seal.Roots = .{ roots.items[0], roots.items[1] };
            const template = try Template.fromShape(&source.statement, source.external_retirements, config, selected, first_roots[0]);
            const template_id = try template.identity();
            return .{ .scheme = scheme, .roots = first_roots, .template = template, .template_id = template_id, .index = index, .source = source, .plan = plan, .limits = limits, .public_digest = admission.publicDigest(&source.statement.public_data) };
        }
        /// Planner path: commit once, retain only bounded immutable metadata,
        /// release PCS immediately, then bind real block plans later.
        pub fn collect(a: std.mem.Allocator, source: *native.Owner, config: core.pcs.PcsConfig, selected: @import("../isa/execution_profile.zig").ExecutionProfile, index: u32, limits: Limits) !Proposal {
            return collectSelected(a, source, config, selected, index, limits, null);
        }
        /// First-pass proposals retain plain roots/public metadata, not a
        /// cached proof or PCS main tree. Basis acquisition is producer-only.
        pub fn collectWithBasis(a: std.mem.Allocator, source: *native.Owner, config: core.pcs.PcsConfig, selected: @import("../isa/execution_profile.zig").ExecutionProfile, index: u32, limits: Limits, basis: *FixedBasis) !Proposal {
            return collectSelected(a, source, config, selected, index, limits, basis);
        }
        fn collectSelected(a: std.mem.Allocator, source: *native.Owner, config: core.pcs.PcsConfig, selected: @import("../isa/execution_profile.zig").ExecutionProfile, index: u32, limits: Limits, basis: ?*FixedBasis) !Proposal {
            const io = source.statement.public_data.io_entries;
            const words = try std.math.add(usize, io.input_words.len, io.output_words.len);
            const bytes = try std.math.add(usize, @sizeOf(Proposal), try std.math.add(usize, try std.math.mul(usize, io.input_words.len, @sizeOf(u32)), try std.math.mul(usize, io.output_words.len, @sizeOf(@import("../air/public_data.zig").OutputWord))));
            if (words > limits.max_public_words or bytes > limits.max_metadata_bytes) return error.NativeCapacityResourceLimit;
            var physical = try commitPhysicalSelected(a, source, config, selected, index, limits, basis);
            defer physical.deinit(a);
            const input = try a.dupe(u32, io.input_words);
            errdefer a.free(input);
            const output = try a.dupe(@import("../air/public_data.zig").OutputWord, io.output_words);
            errdefer a.free(output);
            var shape = source.statement;
            shape.public_data.io_entries.input_words = input;
            shape.public_data.io_entries.output_words = output;
            return .{ .allocator = a, .shape = shape, .external_retirements = source.external_retirements, .template = physical.template, .template_id = physical.template_id, .roots = physical.roots, .index = index, .public_digest = admission.publicDigest(&shape.public_data) };
        }
        /// All opcode, auxiliary-clock and dynamic-activity equations share
        /// one interaction/composition/FRI proof and the one main commitment.
        pub fn prove(a: std.mem.Allocator, first: *FirstRound, sealed: seal.Sealed, pins: seal.Pins, entries: []const seal.Entry) !Proof {
            return proveWithAdmission(a, first, sealed, pins, entries, null);
        }
        pub fn proveWithCatalog(a: std.mem.Allocator, first: *FirstRound, sealed: seal.Sealed, pins: seal.Pins, entries: []const seal.Entry, catalog: catalog_module.Admission) !Proof {
            return proveWithAdmission(a, first, sealed, pins, entries, catalog);
        }
        fn proveWithAdmission(a: std.mem.Allocator, first: *FirstRound, sealed: seal.Sealed, pins: seal.Pins, entries: []const seal.Entry, catalog: ?catalog_module.Admission) !Proof {
            if (!first.owns_scheme or !first.source.native_only_v5 or first.source.interaction_ready or first.source.failed) return error.InvalidNativeCapacityPhase;
            const shape = &first.source.statement;
            const external = first.source.external_retirements;
            if (!std.meta.eql(first.public_digest, admission.publicDigest(&shape.public_data))) return error.ChangedNativeCapacityFirstRound;
            const plan = try protocol.Plan.fromShape(shape, external);
            try first.limits.require(&plan, shape);
            if (!std.meta.eql(plan, first.plan)) return error.ChangedNativeCapacityFirstRound;
            try admitWithAdmission(a, shape, external, first.pin, first.template, first.template_id, first.instance_id, first.roots, first.index, sealed, pins, entries, catalog);
            const challenges = try relations.Challenges.draw(a, sealed);
            const shared = try providers.SharedProviderRelations.init(&challenges.universal_prefix);
            try first.source.generateInteractions(&shared.native);
            var owner = try joined.Owner.initWithExternalForProfile(a, shape, &first.source.claims, challenges.universal_prefix, first.pin, external, first.template.execution_profile);
            defer owner.deinit();
            const claims = try a.create(statement.RiscVInteractionClaim);
            errdefer a.destroy(claims);
            @memcpy(std.mem.asBytes(claims), std.mem.asBytes(&first.source.claims));
            var scratch = std.heap.ArenaAllocator.init(a);
            defer scratch.deinit();
            const component = try makeComponent(scratch.allocator(), owner, shape, external);
            var channel = try protocol.pcsChannel(a, sealed, first.template_id, first.instance_id, first.roots, first.index);
            try protocol.mixClaims(&channel, shape, claims);
            if (plan.len == 0) {
                const interaction = try frame.interactionColumns(a);
                defer frame.freeColumns(a, interaction);
                try first.scheme.commitBorrowedStreaming(a, interaction, 8, &channel);
            } else try first.scheme.commitBorrowedStreaming(a, first.source.interaction.items, 8, &channel);
            // engine.prove.prove takes ownership of the scheme even on failure.
            first.owns_scheme = false;
            const stark = try engine.prove.prove(Backend, suite.Hasher, suite.MerkleChannel, a, &.{component.asProverComponent()}, &channel, first.scheme);
            return .{ .stark = stark, .claims = claims, .template_id = first.template_id, .instance_id = first.instance_id };
        }
        /// Independently pinned exact geometry is mandatory. The CPU receiver
        /// rebuilds capacity fixed rows and freshly checks dynamic counts and
        /// all original equations. It cannot emit a legacy NativeV3 receipt.
        pub fn verifyOwned(a: std.mem.Allocator, received: Proof, shape: *const statement.Blake3ExecutionStatement, external: u32, pin: admission.Admission, expected: Template, expected_id: protocol.Digest, index: u32, sealed: seal.Sealed, pins: seal.Pins, entries: []const seal.Entry, limits: Limits) !OpenReceipt {
            return verifyInternal(false, true, a, received, shape, external, pin, expected, expected_id, index, sealed, pins, entries, limits, null);
        }
        pub fn verifyOwnedWithCatalog(a: std.mem.Allocator, received: Proof, shape: *const statement.Blake3ExecutionStatement, external: u32, pin: admission.Admission, expected: Template, expected_id: protocol.Digest, index: u32, sealed: seal.Sealed, pins: seal.Pins, entries: []const seal.Entry, limits: Limits, catalog: catalog_module.Admission) !OpenReceipt {
            return verifyInternal(false, true, a, received, shape, external, pin, expected, expected_id, index, sealed, pins, entries, limits, catalog);
        }
        pub fn verifyCaptureOwnedWithCatalog(a: std.mem.Allocator, received: Proof, shape: *const statement.Blake3ExecutionStatement, external: u32, pin: admission.Admission, expected: Template, expected_id: protocol.Digest, index: u32, sealed: seal.Sealed, pins: seal.Pins, entries: []const seal.Entry, limits: Limits, catalog: catalog_module.Admission) !VerifiedCapture {
            return verifyInternal(true, true, a, received, shape, external, pin, expected, expected_id, index, sealed, pins, entries, limits, catalog);
        }
        pub fn verifyCaptureBorrowedWithCatalog(a: std.mem.Allocator, received: *const Proof, shape: *const statement.Blake3ExecutionStatement, external: u32, pin: admission.Admission, expected: Template, expected_id: protocol.Digest, index: u32, sealed: seal.Sealed, pins: seal.Pins, entries: []const seal.Entry, limits: Limits, catalog: catalog_module.Admission) !VerifiedCapture {
            return verifyInternal(true, false, a, received.*, shape, external, pin, expected, expected_id, index, sealed, pins, entries, limits, catalog);
        }
        pub fn verifyCaptureOwned(a: std.mem.Allocator, received: Proof, shape: *const statement.Blake3ExecutionStatement, external: u32, pin: admission.Admission, expected: Template, expected_id: protocol.Digest, index: u32, sealed: seal.Sealed, pins: seal.Pins, entries: []const seal.Entry, limits: Limits) !VerifiedCapture {
            return verifyInternal(true, true, a, received, shape, external, pin, expected, expected_id, index, sealed, pins, entries, limits, null);
        }
        pub fn verifyCaptureBorrowed(a: std.mem.Allocator, received: *const Proof, shape: *const statement.Blake3ExecutionStatement, external: u32, pin: admission.Admission, expected: Template, expected_id: protocol.Digest, index: u32, sealed: seal.Sealed, pins: seal.Pins, entries: []const seal.Entry, limits: Limits) !VerifiedCapture {
            return verifyInternal(true, false, a, received.*, shape, external, pin, expected, expected_id, index, sealed, pins, entries, limits, null);
        }
        fn verifyInternal(comptime capture_mode: bool, comptime owns_received: bool, a: std.mem.Allocator, received: Proof, shape: *const statement.Blake3ExecutionStatement, external: u32, pin: admission.Admission, expected: Template, expected_id: protocol.Digest, index: u32, sealed: seal.Sealed, pins: seal.Pins, entries: []const seal.Entry, limits: Limits, catalog: ?catalog_module.Admission) !(if (capture_mode) VerifiedCapture else OpenReceipt) {
            var proof = received;
            var owns = owns_received;
            defer if (owns) proof.deinit(a);
            try requireProtocol(proof.protocol_version);
            const plan = try protocol.Plan.fromShape(shape, external);
            try limits.require(&plan, shape);
            const roots = proof.stark.commitment_scheme_proof.commitments.items;
            if (roots.len != 4 or !std.meta.eql(proof.stark.commitment_scheme_proof.config, pins.config)) return error.InvalidNativeCapacityProofShape;
            const first_roots: seal.Roots = .{ roots[0], roots[1] };
            if (!std.meta.eql(proof.template_id, expected_id)) return error.UntrustedNativeCapacityTemplate;
            try admitWithAdmission(a, shape, external, pin, expected, expected_id, proof.instance_id, first_roots, index, sealed, pins, entries, catalog);
            var arena = std.heap.ArenaAllocator.init(a);
            defer arena.deinit();
            const scratch = arena.allocator();
            const fixed = try protocol.fixedColumns(scratch, shape, external);
            var fixed_scheme = try Scheme.init(a, pins.config);
            defer fixed_scheme.deinit(a);
            fixed_scheme.setCoefficientRetentionPolicy(.never);
            var fixed_channel = suite.Channel{};
            try fixed_scheme.commitBorrowedStreaming(a, fixed, 8, &fixed_channel);
            var rebuilt = try fixed_scheme.roots(a);
            defer rebuilt.deinit(a);
            if (rebuilt.items.len != 1 or !std.meta.eql(rebuilt.items[0], first_roots[0])) return error.UntrustedNativeCapacityFixedRoot;
            const challenges = try relations.Challenges.draw(a, sealed);
            var owner = try joined.Owner.initWithExternalForProfile(a, shape, proof.claims, challenges.universal_prefix, pin, external, expected.execution_profile);
            defer owner.deinit();
            const component = try makeComponent(scratch, owner, shape, external);
            var verifier = try Verifier.init(a, pins.config);
            defer verifier.deinit(a);
            var first_channel = suite.Channel{};
            try verifier.commit(a, first_roots[0], component.fixed_logs, &first_channel);
            try verifier.commit(a, first_roots[1], component.main_logs, &first_channel);
            var channel = try protocol.pcsChannel(a, sealed, expected_id, proof.instance_id, first_roots, index);
            try protocol.mixClaims(&channel, shape, proof.claims);
            try verifier.commit(a, roots[2], component.interaction_logs, &channel);
            var sum = try owner.publicCompensation();
            for (shape.component_descs[0..shape.n_components], 0..) |desc, i| sum = sum.add(try proof.claims.opcodeClaimTotal(desc.family, i));
            for (shape.infra_descs[0..shape.n_infra], 0..) |desc, i| sum = sum.add(try proof.claims.infraClaimTotal(desc.kind, i));
            const receipt = OpenReceipt{ .template_id = expected_id, .instance_id = proof.instance_id, .first_roots = first_roots, .sealed_digest = sealed.digest, .exact_geometry_digest = try @import("block_v5_native_template_protocol_v3.zig").geometryDigest(shape, external), .open_sum = sum };
            if (capture_mode) {
                const captured_claims = if (owns_received) proof.claims else try a.create(statement.RiscVInteractionClaim);
                if (!owns_received) @memcpy(std.mem.asBytes(captured_claims), std.mem.asBytes(proof.claims));
                owns = false;
                errdefer a.destroy(captured_claims);
                var capture: core.verifier.ProofCapture(suite.Hasher) = undefined;
                if (owns_received) {
                    try core.verifier.verifyWithProofCapture(suite.Hasher, suite.MerkleChannel, a, &.{component.asVerifierComponent()}, &channel, &verifier, proof.stark, &capture);
                } else {
                    try core.verifier.verifyBorrowedWithProofCapture(suite.Hasher, suite.MerkleChannel, a, &.{component.asVerifierComponent()}, &channel, &verifier, &proof.stark, &capture);
                }
                errdefer capture.deinit(a);
                var result = VerifiedCapture{ .allocator = a, .proof = capture, .native_claims = captured_claims, .relations = challenges.universal_prefix, .final_channel = channel, .receipt = receipt, .seal = undefined };
                result.seal = try result.identity(shape, external);
                return result;
            } else {
                owns = false;
                defer a.destroy(proof.claims);
                try core.verifier.verify(suite.Hasher, suite.MerkleChannel, a, &.{component.asVerifierComponent()}, &channel, &verifier, proof.stark);
                return receipt;
            }
        }
    };
}
pub fn requireProtocol(version: u32) !void {
    if (version != protocol.VERSION) return error.UntrustedNativeCapacityProtocol;
}
pub fn makeComponent(a: std.mem.Allocator, owner: *joined.Owner, shape: *const statement.Blake3ExecutionStatement, external: u32) !composite.Component {
    return .{ .inner = owner, .plan = try protocol.Plan.fromShape(shape, external), .fixed_logs = try protocol.columnLogs(a, shape, external, .fixed), .main_logs = try protocol.columnLogs(a, shape, external, .main), .interaction_logs = try protocol.columnLogs(a, shape, external, .interaction) };
}
/// Singular capacity admission remains explicit; capacity catalogs enter only
/// through the independently versioned WithCatalog path.
pub fn admit(a: std.mem.Allocator, shape: *const statement.Blake3ExecutionStatement, external: u32, pin: admission.Admission, expected: Template, template_id: protocol.Digest, instance_id: protocol.Digest, roots: seal.Roots, index: u32, sealed: seal.Sealed, pins: seal.Pins, entries: []const seal.Entry) !void {
    return admitWithAdmission(a, shape, external, pin, expected, template_id, instance_id, roots, index, sealed, pins, entries, null);
}
pub fn admitWithCatalog(a: std.mem.Allocator, shape: *const statement.Blake3ExecutionStatement, external: u32, pin: admission.Admission, expected: Template, template_id: protocol.Digest, instance_id: protocol.Digest, roots: seal.Roots, index: u32, sealed: seal.Sealed, pins: seal.Pins, entries: []const seal.Entry, catalog: catalog_module.Admission) !void {
    return admitWithAdmission(a, shape, external, pin, expected, template_id, instance_id, roots, index, sealed, pins, entries, catalog);
}
fn admitWithAdmission(a: std.mem.Allocator, shape: *const statement.Blake3ExecutionStatement, external: u32, pin: admission.Admission, expected: Template, template_id: protocol.Digest, instance_id: protocol.Digest, roots: seal.Roots, index: u32, sealed: seal.Sealed, pins: seal.Pins, entries: []const seal.Entry, catalog: ?catalog_module.Admission) !void {
    _ = a;
    try sealed.require(pins, entries);
    try pin.require(pins, &shape.public_data);
    try expected.admit(shape, external, template_id);
    if (!std.meta.eql(expected.config, pins.config) or !std.meta.eql(roots[0], expected.fixed_root)) return error.UntrustedNativeCapacityTemplate;
    if (catalog) |roster| {
        try roster.admit(pins, sealed, index, expected, template_id);
    } else if (!std.meta.eql(pins.native_template_id, template_id) or !std.mem.allEqual(u8, &pins.native_template_catalog_digest, 0)) return error.UntrustedNativeCapacityTemplate;
    if (!std.meta.eql(instance_id, try protocol.instanceId(template_id, shape, external, pin, roots, index))) return error.UntrustedNativeCapacityInstance;
    try @import("block_v5_native_execution_proof_v3.zig").admitEntry(index, roots, instance_id, sealed, entries);
}
