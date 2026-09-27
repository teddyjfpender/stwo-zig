//! Native-v5 v3: lightweight global public admission, PC/clock compensation
//! only, and explicitly open ROM/RW/lookup claims. Existing v2 stays separate.
//! Native-only block-v5 STARK. The fixed tree contains no per-leaf BLAKE3
//! custody, and the 47 universal challenges come from the complete B5SS
//! roster. This proof returns an OPEN relation claim. It grants no execution
//! or block authority until fresh global program, memory, table and public
//! providers cancel every native claim under the same challenge bundle.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const suite = core.proof_suites.Blake3;
const Q = core.fields.qm31.QM31;
const Column = engine.pcs.ColumnEvaluation;
const statement = @import("../air/statement.zig");
const profile_mod = @import("../isa/execution_profile.zig");
const native_mod = @import("blake3_execution_trace.zig");
const plan_mod = @import("block_v5_native_public_admission_v1.zig");
const joined_mod = @import("block_v5_native_components_v3.zig");
const template_mod = @import("block_v5_native_template_protocol_v3.zig");
const catalog_mod = @import("block_v5_native_template_catalog_v1.zig");
const seal_mod = @import("block_v5_source_seal_v1.zig");
const relations_mod = @import("block_memory_relation_v2.zig");
const providers = @import("../recursion/air/universal_provider_relations.zig");
const native_protocol = @import("blake3_execution_protocol.zig");
const frame = @import("block_v5_native_frame_v1.zig");

pub const Template = template_mod.Template;
pub const Digest = [32]u8;
pub const Proof = struct {
    stark: suite.Proof,
    claims: *statement.RiscVInteractionClaim,
    template_id: Digest,
    instance_id: Digest,
    pub fn deinit(self: *Proof, a: std.mem.Allocator) void {
        self.stark.deinit(a);
        a.destroy(self.claims);
        self.* = undefined;
    }
};

/// Private fresh-verifier output. This scalar remains deliberately open: a
/// complete receiver must cancel it with independently fresh provider proofs,
/// including a provider for native universal memory_access. The v5 sorted
/// 21-byte transition bus alone does not cancel that older universal bus.
pub const OpenReceipt = struct {
    template_id: Digest,
    instance_id: Digest,
    first_roots: seal_mod.Roots,
    sealed_digest: Digest,
    open_sum: Q,
};

/// Fresh native verifier capture for an actual recursive verifier circuit.
/// This is witness material, not an independently closable block receipt.
pub const VerifiedCapture = struct {
    allocator: std.mem.Allocator,
    proof: core.verifier.ProofCapture(suite.Hasher),
    native_claims: *statement.RiscVInteractionClaim,
    relations: @import("../recursion/air/universal_challenges.zig").UniversalRelations,
    final_channel: suite.Channel,
    receipt: OpenReceipt,
    seal: Digest,

    pub fn deinit(self: *VerifiedCapture) void {
        self.proof.deinit(self.allocator);
        self.allocator.destroy(self.native_claims);
        self.* = undefined;
    }

    pub fn identity(self: *const VerifiedCapture, shape: *const statement.Blake3ExecutionStatement) !Digest {
        var channel = suite.Channel{};
        channel.mixU32s(&.{ 0x42354e52, 3 }); // B5NR witness mutation seal
        channel.mixRoot(@import("proof_capture_sha256.zig").compute(&self.proof));
        channel.mixRoot(self.receipt.template_id);
        channel.mixRoot(self.receipt.instance_id);
        channel.mixRoot(self.receipt.sealed_digest);
        channel.mixFelts(&.{self.receipt.open_sum});
        try template_mod.mixClaims(&channel, shape, self.native_claims);
        for (self.relations.elements) |element| channel.mixFelts(&.{ element.z, element.alpha });
        channel.mixRoot(self.final_channel.digestBytes());
        channel.mixU64(self.final_channel.n_draws);
        return channel.digestBytes();
    }

    pub fn validate(self: *const VerifiedCapture, prepared: *const @import("block_v5_native_recursive_admission_v3.zig").Prepared, expected: Digest) !void {
        try prepared.validate(expected);
        if (self.proof.commitments.len != 4 or !std.meta.eql(self.receipt.template_id, expected) or
            !std.meta.eql(self.receipt.first_roots, self.proof.commitments[0..2].*) or
            !std.meta.eql(self.receipt.first_roots[0], prepared.template.fixed_root) or
            !std.meta.eql(self.receipt.sealed_digest, prepared.sealed.digest) or
            !std.meta.eql(self.receipt.instance_id, try template_mod.instanceId(expected, prepared.shape, prepared.pin, self.receipt.first_roots, prepared.index)) or
            !std.meta.eql(self.seal, try self.identity(prepared.shape)))
            return error.InvalidNativeV5RecursiveCapture;
        const challenges = try relations_mod.Challenges.draw(self.allocator, prepared.sealed);
        if (!std.meta.eql(self.relations, challenges.universal_prefix))
            return error.InvalidNativeV5RecursiveCapture;
        try admitEntry(prepared.index, self.receipt.first_roots, self.receipt.instance_id, prepared.sealed, prepared.entries);
    }
};

pub fn ForBackend(comptime Backend: type) type {
    return struct {
        const Scheme = engine.pcs.CommitmentSchemeProver(Backend, suite.Hasher, suite.MerkleChannel);
        const Verifier = core.pcs.verifier.CommitmentSchemeVerifier(suite.Hasher, suite.MerkleChannel);

        pub const FirstRound = struct {
            scheme: Scheme,
            roots: seal_mod.Roots,
            template: Template,
            template_id: Digest,
            instance_id: Digest,
            index: u32,
            native: *native_mod.Owner,
            pin: plan_mod.Admission,
            owns_scheme: bool = true,

            pub fn deinit(self: *FirstRound, a: std.mem.Allocator) void {
                if (self.owns_scheme) self.scheme.deinit(a);
                self.* = undefined;
            }

            pub fn entry(self: *const FirstRound) seal_mod.Entry {
                return .{ .family = .execution, .index = self.index, .instance_id = self.instance_id, .roots = self.roots };
            }
        };

        pub fn commitFirstRound(a: std.mem.Allocator, native: *native_mod.Owner, pin: plan_mod.Admission, config: core.pcs.PcsConfig, execution_profile: profile_mod.ExecutionProfile, index: u32) !FirstRound {
            try pin.validatePublic(&native.statement.public_data);
            // Census proposals and proving share the same physical kernel.
            // Only this admitted branch adds the real instance/public binding.
            const Physical = @import("block_v5_cpu_native_root_proposal_v1.zig").ForBackend(Backend);
            var physical = try Physical.commitPhysical(a, native, config, execution_profile, index);
            errdefer physical.deinit(a);
            const instance_id = try template_mod.instanceId(physical.template_id, &native.statement, pin, physical.roots, index);
            return .{
                .scheme = physical.scheme,
                .roots = physical.roots,
                .template = physical.template,
                .template_id = physical.template_id,
                .instance_id = instance_id,
                .index = index,
                .native = native,
                .pin = pin,
            };
        }

        /// First-round roots must already appear in the exact sealed roster.
        /// No local relation closure is performed or implied by this proof.
        pub fn prove(a: std.mem.Allocator, first: *FirstRound, sealed: seal_mod.Sealed, pins: seal_mod.Pins, entries: []const seal_mod.Entry) !Proof {
            return proveWithAdmission(a, first, sealed, pins, entries, null);
        }

        /// Catalog records must be supplied from independent policy, never
        /// decoded from the proof being admitted.
        pub fn proveWithCatalog(a: std.mem.Allocator, first: *FirstRound, sealed: seal_mod.Sealed, pins: seal_mod.Pins, entries: []const seal_mod.Entry, catalog: catalog_mod.Admission) !Proof {
            return proveWithAdmission(a, first, sealed, pins, entries, catalog);
        }

        fn proveWithAdmission(a: std.mem.Allocator, first: *FirstRound, sealed: seal_mod.Sealed, pins: seal_mod.Pins, entries: []const seal_mod.Entry, catalog: ?catalog_mod.Admission) !Proof {
            try admitFirst(first, sealed, pins, entries, catalog);
            const native = first.native;
            const challenges = try relations_mod.Challenges.draw(a, sealed);
            const shared = try providers.SharedProviderRelations.init(&challenges.universal_prefix);
            try native.generateInteractions(&shared.native);
            var joined = try joined_mod.Owner.initWithExternalForProfile(
                a,
                &native.statement,
                &native.claims,
                challenges.universal_prefix,
                first.pin,
                native.external_retirements,
                first.template.execution_profile,
            );
            defer joined.deinit();
            const claims = try a.create(statement.RiscVInteractionClaim);
            errdefer a.destroy(claims);
            claims.* = native.claims;
            var channel = try template_mod.pcsChannel(a, sealed, first.template_id, first.instance_id, first.roots, first.index);
            try template_mod.mixClaims(&channel, &native.statement, claims);
            if (frame.required(&native.statement)) {
                if (native.interaction.items.len != 0) return error.InvalidNativeV5FrameColumns;
                const pad = try frame.interactionColumns(a);
                defer frame.freeColumns(a, pad);
                try first.scheme.commitBorrowedStreaming(a, pad, 8, &channel);
            } else try first.scheme.commitBorrowedStreaming(a, native.interaction.items, 8, &channel);
            first.owns_scheme = false;
            return .{
                .stark = try engine.prove.prove(Backend, suite.Hasher, suite.MerkleChannel, a, joined.proving.components.active(), &channel, first.scheme),
                .claims = claims,
                .template_id = first.template_id,
                .instance_id = first.instance_id,
            };
        }

        /// Fresh native STARK verification under an independently pinned
        /// template and full B5SS roster. The returned sum is still OPEN.
        pub fn verifyOwned(a: std.mem.Allocator, received: Proof, shape: *const statement.Blake3ExecutionStatement, pin: plan_mod.Admission, expected_template: Template, expected_template_id: Digest, execution_profile: profile_mod.ExecutionProfile, index: u32, sealed: seal_mod.Sealed, pins: seal_mod.Pins, entries: []const seal_mod.Entry) !OpenReceipt {
            return verifyOwnedWithAdmission(a, received, shape, pin, expected_template, expected_template_id, execution_profile, index, sealed, pins, entries, null);
        }

        pub fn verifyOwnedWithCatalog(a: std.mem.Allocator, received: Proof, shape: *const statement.Blake3ExecutionStatement, pin: plan_mod.Admission, expected_template: Template, expected_template_id: Digest, execution_profile: profile_mod.ExecutionProfile, index: u32, sealed: seal_mod.Sealed, pins: seal_mod.Pins, entries: []const seal_mod.Entry, catalog: catalog_mod.Admission) !OpenReceipt {
            return verifyOwnedWithAdmission(a, received, shape, pin, expected_template, expected_template_id, execution_profile, index, sealed, pins, entries, catalog);
        }

        pub fn verifyCaptureOwnedWithCatalog(a: std.mem.Allocator, received: Proof, shape: *const statement.Blake3ExecutionStatement, pin: plan_mod.Admission, expected_template: Template, expected_template_id: Digest, execution_profile: profile_mod.ExecutionProfile, index: u32, sealed: seal_mod.Sealed, pins: seal_mod.Pins, entries: []const seal_mod.Entry, catalog: catalog_mod.Admission) !VerifiedCapture {
            return verifyInternal(true, true, a, received, shape, pin, expected_template, expected_template_id, execution_profile, index, sealed, pins, entries, catalog);
        }

        /// Producer callback: the bounded original proof stays immutable and
        /// owned by its producer. Capture vectors and claims are independent;
        /// no source proof pointer survives this call. External wire receivers
        /// still decode and verify their own strictly admitted artifacts.
        pub fn verifyCaptureBorrowedWithCatalog(a: std.mem.Allocator, received: *const Proof, shape: *const statement.Blake3ExecutionStatement, pin: plan_mod.Admission, expected_template: Template, expected_template_id: Digest, execution_profile: profile_mod.ExecutionProfile, index: u32, sealed: seal_mod.Sealed, pins: seal_mod.Pins, entries: []const seal_mod.Entry, catalog: catalog_mod.Admission) !VerifiedCapture {
            return verifyInternal(true, false, a, received.*, shape, pin, expected_template, expected_template_id, execution_profile, index, sealed, pins, entries, catalog);
        }

        fn verifyOwnedWithAdmission(a: std.mem.Allocator, received: Proof, shape: *const statement.Blake3ExecutionStatement, pin: plan_mod.Admission, expected_template: Template, expected_template_id: Digest, execution_profile: profile_mod.ExecutionProfile, index: u32, sealed: seal_mod.Sealed, pins: seal_mod.Pins, entries: []const seal_mod.Entry, catalog: ?catalog_mod.Admission) !OpenReceipt {
            return verifyInternal(false, true, a, received, shape, pin, expected_template, expected_template_id, execution_profile, index, sealed, pins, entries, catalog);
        }

        fn verifyInternal(comptime capture_mode: bool, comptime owns_received: bool, a: std.mem.Allocator, received: Proof, shape: *const statement.Blake3ExecutionStatement, pin: plan_mod.Admission, expected_template: Template, expected_template_id: Digest, execution_profile: profile_mod.ExecutionProfile, index: u32, sealed: seal_mod.Sealed, pins: seal_mod.Pins, entries: []const seal_mod.Entry, catalog: ?catalog_mod.Admission) !(if (capture_mode) VerifiedCapture else OpenReceipt) {
            var proof = received;
            var owns_proof = owns_received;
            defer if (owns_proof) proof.deinit(a);
            try sealed.require(pins, entries);
            try pin.require(pins, &shape.public_data);
            if (pin.context.execution_index != index) return error.UntrustedNativeV5PublicAdmission;
            if (!std.meta.eql(expected_template.config, pins.config) or
                expected_template.execution_profile != execution_profile or
                !std.meta.eql(try expected_template.identity(), expected_template_id))
                return error.UntrustedNativeV5Template;
            try expected_template.admit(shape, expected_template_id);
            try admitTemplate(expected_template, expected_template_id, index, sealed, pins, catalog);
            const roots = proof.stark.commitment_scheme_proof.commitments.items;
            if (roots.len != 4 or !std.meta.eql(proof.stark.commitment_scheme_proof.config, pins.config))
                return error.InvalidNativeV5ProofShape;
            const first_roots: seal_mod.Roots = .{ roots[0], roots[1] };
            if (!std.meta.eql(first_roots[0], expected_template.fixed_root)) return error.UntrustedNativeV5FixedRoot;
            const expected_instance_id = try template_mod.instanceId(expected_template_id, shape, pin, first_roots, index);
            if (!std.meta.eql(proof.template_id, expected_template_id) or
                !std.meta.eql(proof.instance_id, expected_instance_id))
                return error.UntrustedNativeV5Instance;
            try admitEntry(index, first_roots, expected_instance_id, sealed, entries);

            // Deterministic fixed columns are reconstructed from independently
            // admitted geometry, never taken from the proof or its JSON wire.
            var arena = std.heap.ArenaAllocator.init(a);
            defer arena.deinit();
            const scratch = arena.allocator();
            var fixed_columns: std.ArrayList(Column) = .empty;
            if (frame.required(shape)) {
                _ = try frame.expected(shape, expected_template.external_retirements);
                try fixed_columns.appendSlice(scratch, try frame.fixedColumns(scratch));
            } else try native_protocol.nativePreprocessedWithExternal(scratch, shape, expected_template.external_retirements, &fixed_columns);
            var fixed_scheme = try Scheme.init(a, pins.config);
            defer fixed_scheme.deinit(a);
            fixed_scheme.setCoefficientRetentionPolicy(.never);
            var fixed_channel = suite.Channel{};
            try fixed_scheme.commitBorrowedStreaming(a, fixed_columns.items, 8, &fixed_channel);
            var fixed_roots = try fixed_scheme.roots(a);
            defer fixed_roots.deinit(a);
            if (fixed_roots.items.len != 1 or !std.meta.eql(fixed_roots.items[0], first_roots[0]))
                return error.UntrustedNativeV5FixedRoot;

            const challenges = try relations_mod.Challenges.draw(a, sealed);
            const shared = try providers.SharedProviderRelations.init(&challenges.universal_prefix);
            var joined = try joined_mod.Owner.initWithExternalForProfile(
                a,
                shape,
                proof.claims,
                challenges.universal_prefix,
                pin,
                expected_template.external_retirements,
                execution_profile,
            );
            defer joined.deinit();
            try shared.validateAgainst(&challenges.universal_prefix);
            const fixed_logs = try template_mod.columnLogs(scratch, shape, expected_template.external_retirements, .fixed);
            const main_logs = try template_mod.columnLogs(scratch, shape, expected_template.external_retirements, .main);
            const interaction_logs = try template_mod.columnLogs(scratch, shape, expected_template.external_retirements, .interaction);
            var verifier = try Verifier.init(a, pins.config);
            defer verifier.deinit(a);
            var first_channel = suite.Channel{};
            try verifier.commit(a, first_roots[0], fixed_logs, &first_channel);
            try verifier.commit(a, first_roots[1], main_logs, &first_channel);
            var channel = try template_mod.pcsChannel(a, sealed, expected_template_id, expected_instance_id, first_roots, index);
            try template_mod.mixClaims(&channel, shape, proof.claims);
            try verifier.commit(a, roots[2], interaction_logs, &channel);
            const open_sum = try openSum(joined, shape, proof.claims);
            const receipt = OpenReceipt{
                .template_id = expected_template_id,
                .instance_id = expected_instance_id,
                .first_roots = first_roots,
                .sealed_digest = sealed.digest,
                .open_sum = open_sum,
            };
            if (capture_mode) {
                const captured_claims = if (owns_received) proof.claims else try a.create(statement.RiscVInteractionClaim);
                if (!owns_received) @memcpy(std.mem.asBytes(captured_claims), std.mem.asBytes(proof.claims));
                owns_proof = false;
                errdefer a.destroy(captured_claims);
                var capture: core.verifier.ProofCapture(suite.Hasher) = undefined;
                if (owns_received) {
                    try core.verifier.verifyWithProofCapture(suite.Hasher, suite.MerkleChannel, a, joined.verifying.components.active(), &channel, &verifier, proof.stark, &capture);
                } else {
                    try core.verifier.verifyBorrowedWithProofCapture(suite.Hasher, suite.MerkleChannel, a, joined.verifying.components.active(), &channel, &verifier, &proof.stark, &capture);
                }
                var result = VerifiedCapture{ .allocator = a, .proof = capture, .native_claims = captured_claims, .relations = challenges.universal_prefix, .final_channel = channel, .receipt = receipt, .seal = undefined };
                errdefer capture.deinit(a);
                result.seal = try result.identity(shape);
                return result;
            } else {
                owns_proof = false;
                defer a.destroy(proof.claims);
                try core.verifier.verify(suite.Hasher, suite.MerkleChannel, a, joined.verifying.components.active(), &channel, &verifier, proof.stark);
                return receipt;
            }
        }
    };
}

fn admitFirst(first: anytype, sealed: seal_mod.Sealed, pins: seal_mod.Pins, entries: []const seal_mod.Entry, catalog: ?catalog_mod.Admission) !void {
    if (!first.owns_scheme or !first.native.native_only_v5 or
        !std.meta.eql(first.template.config, pins.config))
        return error.UntrustedNativeV5FirstRound;
    try sealed.require(pins, entries);
    try first.pin.require(pins, &first.native.statement.public_data);
    if (first.pin.context.execution_index != first.index) return error.UntrustedNativeV5PublicAdmission;
    try admitTemplate(first.template, first.template_id, first.index, sealed, pins, catalog);
    return admitEntry(first.index, first.roots, first.instance_id, sealed, entries);
}

fn admitTemplate(template: Template, template_id: Digest, index: u32, sealed: seal_mod.Sealed, pins: seal_mod.Pins, catalog: ?catalog_mod.Admission) !void {
    if (catalog) |trusted| {
        try trusted.admit(pins, sealed, index, template, template_id);
    } else if (!std.meta.eql(pins.native_template_id, template_id) or
        !std.meta.eql(pins.native_template_catalog_digest, @as(Digest, @splat(0))))
    {
        return error.UntrustedNativeV5Template;
    }
}

pub fn admitEntry(index: u32, roots: seal_mod.Roots, instance_id: Digest, sealed: seal_mod.Sealed, entries: []const seal_mod.Entry) !void {
    if (index >= sealed.execution_instance_count) return error.InvalidNativeV5Ordinal;
    var found = false;
    for (entries) |entry| if (entry.family == .execution and entry.index == index) {
        if (!std.meta.eql(entry.roots, roots) or !std.meta.eql(entry.instance_id, instance_id))
            return error.UntrustedNativeV5FirstRound;
        found = true;
        break;
    };
    if (!found) return error.MissingNativeV5FirstRound;
}

fn openSum(joined: *const joined_mod.Owner, shape: *const statement.Blake3ExecutionStatement, claims: *const statement.RiscVInteractionClaim) !Q {
    var sum = try joined.publicCompensation();
    for (shape.component_descs[0..shape.n_components], 0..) |desc, index|
        sum = sum.add(try claims.opcodeClaimTotal(desc.family, index));
    for (shape.infra_descs[0..shape.n_infra], 0..) |desc, index|
        sum = sum.add(try claims.infraClaimTotal(desc.kind, index));
    return sum;
}
