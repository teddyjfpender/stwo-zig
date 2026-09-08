//! Ethereum split-2 composition witness from an independently keyed field9
//! proof. Reuses the active leaf's symbolic equations and exact input ABI.
//! Parent AIR admission/closure and child shape selection remain separate.
const std = @import("std");
const core = @import("stwo_core");
const recursion = @import("stwo_riscv_frontend").recursion;
const transcript_mod = @import("ethereum_wrapper_detached_transcript_v1.zig");
const verifier_mod = @import("ethereum_wrapper_root_verifier_v1.zig");
const components_mod = @import("ethereum_wrapper_verifier_components_v1.zig");
const shared = @import("recursive_common_ethereum_incremental_leaf_composition_capture_owner_v4.zig");
const native = @import("recursive_common_ethereum_incremental_leaf_native_core_v4.zig");
const public = @import("recursive_field_node_public_v2.zig");
const composition = recursion.air.composition_circuit;
const composition_v3 = recursion.recursion_air_composition_circuit_v3;
const recorder = composition_v3.segment_recorder_v3.graph_recorder;
const QM31 = core.fields.qm31.QM31;
pub const FOLD_ADMISSION_AVAILABLE = false;

const ordinary_manifest = @import("recursive_common_ethereum_incremental_leaf_universal_manifest_v4.zig");
pub const Ordinary = Types(ordinary_manifest);
pub const Initial38 = Types(recursion.air.ethereum_initial_input_manifest_v1);
pub const OwnedV1 = Ordinary.OwnedV1;
pub const testFromVerifiedTranscript = Ordinary.testFromVerifiedTranscript;

pub fn Types(comptime ManifestMod: type) type {
    const initial = ManifestMod == recursion.air.ethereum_initial_input_manifest_v1;
    if (!initial and ManifestMod != ordinary_manifest) @compileError("unsupported Ethereum detached composition manifest");
    const transcript = transcript_mod.Types(ManifestMod);
    const verifier = verifier_mod.Types(ManifestMod);
    const Components = components_mod.Types(ManifestMod);
    const Recording = shared.RecordingForManifest(ManifestMod);
    return struct {
        const Selected = @This();
        const Boundary = struct {
            key: *const verifier.KeyV1,

            pub fn recordPublicWireBoundary(self: Boundary, challenges: *const recorder.ChallengeSet) !recorder.Scalar {
                // init validates the independently admitted key before recording. These
                // are its fixed graph anchors; the sum remains challenge-dependent.
                return native.recordPublicWireTerms(self.key.wire_terms, challenges);
            }
        };

        fn recordComponents(program: anytype, components: *const Components.OwnedComponentsV1) @TypeOf(program.finishProgram()) {
            return components.recordComponents(program);
        }

        pub const OwnedV1 = opaque {
            const Self = @This();
            const Storage = struct {
                allocator: std.mem.Allocator,
                layout: composition_v3.capture_layout_v3.CaptureLayoutV3,
                profile: composition_v3.InputProfileV3,
                program: shared.OwnedProgram,
                inputs: []QM31,
                values: []QM31,
            };

            pub fn init(allocator: std.mem.Allocator, witness: *const transcript.OwnedV1) !*Self {
                const key = witness.admittedKey();
                try key.validate();
                const capture = witness.proofCapture();
                var layout = if (initial)
                    try composition_v3.capture_layout_v3.CaptureLayoutV3.initEthereumInitialWrapperV1(allocator, &key.manifest, capture)
                else
                    try composition_v3.capture_layout_v3.CaptureLayoutV3.initEthereumWrapperV1(allocator, &key.manifest, capture);
                errdefer layout.deinit();
                const profile = composition_v3.InputProfileV3{ .sampled_value_count = layout.sampled_value_count, .field_public_extra_word_count = public.AIR_WORD_COUNT - public.STATEMENT_WORD_COUNT };
                try profile.validate();
                const components = try Components.OwnedComponentsV1.init(allocator, &key.manifest, key.parameters, witness.relations(), witness.claimValues().*);
                defer components.deinit();
                var program = try Recording.recordProgramWithAuthority(recordComponents, allocator, &key.manifest, &layout, profile, components, Boundary{ .key = key });
                errdefer program.deinit();
                const inputs = try allocator.alloc(QM31, try composition.recursionInputCount(profile.graphProfile()));
                errdefer allocator.free(inputs);
                var claim_inputs: [composition_v3.COMPOSITION_CLAIM_INPUT_COUNT]QM31 = undefined;
                try composition_v3.writeClaimInputsForManifest(.binary_node, Recording.CLAIM_MANIFEST_FAMILY, &witness.claimValues().values, &witness.claimValues().poseidon_partials, &claim_inputs);
                try Recording.writePublicInputs(profile, &try witness.publicNode().canonicalAirWords(), &claim_inputs, witness.wireClaim(), witness.relations(), capture, inputs);
                const values = try allocator.alloc(QM31, program.circuit.nodes.len);
                errdefer allocator.free(values);
                // Checks every graph output, including the same split-2 OODS equation
                // already checked by core.verifyWithProofCapture for this capture.
                try program.circuit.evaluateInto(inputs, values);
                const value = try allocator.create(Storage);
                value.* = .{ .allocator = allocator, .layout = layout, .profile = profile, .program = program, .inputs = inputs, .values = values };
                return @ptrCast(value);
            }

            fn storage(self: *const Self) *const Storage {
                return @ptrCast(@alignCast(self));
            }

            pub fn deinit(self: *Self) void {
                const value: *Storage = @ptrCast(@alignCast(self));
                const allocator = value.allocator;
                allocator.free(value.values);
                allocator.free(value.inputs);
                value.program.deinit();
                value.layout.deinit();
                allocator.destroy(value);
            }

            pub fn captureLayout(self: *const Self) *const composition_v3.capture_layout_v3.CaptureLayoutV3 {
                return &self.storage().layout;
            }

            /// Plain borrowed graph/evaluation, not a role capability or circuit key.
            pub fn circuit(self: *const Self) *const recorder.Circuit {
                return &self.storage().program.circuit;
            }
            pub fn inputBindings(self: *const Self) []const composition.RecursionInputBinding {
                return self.storage().program.bindings;
            }
            pub fn inputProfile(self: *const Self) composition_v3.InputProfileV3 {
                return self.storage().profile;
            }
            pub fn inputValues(self: *const Self) []const QM31 {
                return self.storage().inputs;
            }
            pub fn nodeValues(self: *const Self) []const QM31 {
                return self.storage().values;
            }
        };

        /// Genuine artifact regression, called only after actual field9 verification.
        /// Values change inside the fixed graph; no resealed host comparison supplies
        /// the rejection. This is still not a proof of the enclosing fold AIR.
        pub fn testFromVerifiedTranscript(allocator: std.mem.Allocator, witness: *const transcript.OwnedV1) !void {
            if (!@import("builtin").is_test) @compileError("detached composition mutation checks are test-only");
            const owned = try Selected.OwnedV1.init(allocator, witness);
            defer owned.deinit();
            const value = owned.storage();
            try testWireBoundaryRoute(allocator, witness, owned);
            try std.testing.expectEqual(@as(u32, 2), value.layout.composition_log_split);
            try std.testing.expectEqual(@as(u32, 16), value.layout.tree_column_counts[3]);
            const inputs = try allocator.dupe(QM31, value.inputs);
            defer allocator.free(inputs);
            const outputs = try allocator.alloc(QM31, value.values.len);
            defer allocator.free(outputs);
            // One independent input from each substantive equation/route.
            const Categories = enum { public_word, wire_sum, component_claim, composition_sample };
            inline for (std.meta.tags(Categories)) |category| {
                var found = false;
                for (value.program.bindings, 0..) |binding, index| {
                    const selected = switch (binding.source) {
                        .statement_word => category == .public_word,
                        .public_wire_boundary => category == .wire_sum,
                        .claimed_sum => |coordinate| category == .component_claim and coordinate.item_index == 0,
                        .sampled_value => |coordinate| category == .composition_sample and coordinate.item_index == value.layout.offsets[3][0],
                        else => false,
                    };
                    if (!selected) continue;
                    const original = inputs[index];
                    inputs[index] = original.add(QM31.one());
                    try std.testing.expectError(error.UnsatisfiedCircuit, value.program.circuit.evaluateInto(inputs, outputs));
                    inputs[index] = original;
                    found = true;
                    break;
                }
                try std.testing.expect(found);
            }
            if (initial) {
                // The two initial claims are substantive AIR inputs. The shared
                // ABI's remaining zero slot and both partials must be constrained too.
                for (36..composition_v3.COMPOSITION_CLAIM_INPUT_COUNT) |item| {
                    var found = false;
                    for (value.program.bindings, 0..) |binding, index| {
                        if (binding.source != .claimed_sum or binding.source.claimed_sum.item_index != item) continue;
                        const original = inputs[index];
                        inputs[index] = original.add(QM31.one());
                        try std.testing.expectError(error.UnsatisfiedCircuit, value.program.circuit.evaluateInto(inputs, outputs));
                        inputs[index] = original;
                        found = true;
                        break;
                    }
                    try std.testing.expect(found);
                }
            }
            try value.program.circuit.evaluateInto(inputs, outputs);
            try std.testing.expectEqualDeep(value.values, outputs);
            std.debug.print("ETHEREUM_DETACHED_COMPOSITION q2=true native_oods_parity=true public_wire_claim_sample_mutations_rejected=true fold_admitted=false nodes={d}\n", .{value.program.circuit.nodes.len});
        }

        // Join actual transcript payload AIR entries to input-source AIR entries from
        // the verified graph bindings. Internal arithmetic-wire events are excluded;
        // their fanout is irrelevant here and full parent closure remains separate.
        fn testWireBoundaryRoute(allocator: std.mem.Allocator, witness: *const transcript.OwnedV1, owned: *const Selected.OwnedV1) !void {
            const row_mod = @import("recursive_secure_transcript_rows_v1.zig");
            const air = recursion.air;
            var prepared = try witness.transcriptView().prepareTranscriptRows(allocator, 1);
            defer prepared.deinit();
            const Payload = std.meta.Child(@TypeOf(prepared.payload));
            var payload: [4]Payload = undefined;
            const item = composition_v3.COMPOSITION_CLAIM_INPUT_COUNT;
            const kind = @intFromEnum(air.transcript_payload.VerifierInputKind.claimed_sum);
            try std.testing.expect(row_mod.Prepared.bindsVerifierInputForKind(.ethereum_incremental_field_v1, kind, item));
            try std.testing.expect(row_mod.Prepared.bindsVerifierInputForKind(.canonical_empty, kind, item));
            try std.testing.expect(!row_mod.Prepared.isFixedZeroInput(.ethereum_incremental_field_v1, item));
            try std.testing.expect(row_mod.Prepared.isFixedZeroInput(.common_fold, item));
            try std.testing.expect(!row_mod.Prepared.bindsVerifierInputForKind(.ethereum_incremental_field_v1, kind, item + 1));
            var count: usize = 0;
            for (prepared.payload) |row| if (row.preprocessing.source_kind == .claimed_sum and row.preprocessing.item_index == item) {
                if (count >= payload.len) return error.EthereumWireBoundaryRouteMismatch;
                payload[count] = row;
                count += 1;
            };
            try std.testing.expectEqual(payload.len, count);
            var input_rows: [4]composition.Row = undefined;
            var values: [4]core.fields.m31.M31 = undefined;
            count = 0;
            for (owned.inputBindings(), owned.inputValues()) |binding, value| if (binding.source == .public_wire_boundary) {
                if (count >= input_rows.len) return error.EthereumWireBoundaryRouteMismatch;
                input_rows[count] = .{ .classification = .{ .recursion_input = .{ .verifier_id = 1, .statement_scope = recursion.binary_fri_outer_source.LEFT_COMPOSITION_STATEMENT_SCOPE, .source = binding.source } }, .circuit_id = shared.CIRCUIT_ID, .node_id = binding.node_id, .use_count = 0 };
                values[count] = try value.tryIntoM31();
                count += 1;
            };
            try std.testing.expectEqual(input_rows.len, count);
            const Check = struct {
                fn run(a: std.mem.Allocator, sources: []const Payload, consumers: []const composition.Row, inputs: []const core.fields.m31.M31, mutation: ?usize) !void {
                    var payload_air = try air.transcript_payload.build(a);
                    defer payload_air.deinit();
                    const payload_plan = try air.universal_relation_binding.Binding(air.transcript_payload).authenticate(&payload_air);
                    const direct = air.direct_constraint_program;
                    const constraints = try direct.authenticate(&payload_air.arena, air.transcript_payload.SEMANTIC_DIGEST, air.transcript_payload.LOGICAL_INPUT_COUNT);
                    var scratch: [direct.MAX_NODES]core.fields.m31.M31 = undefined;
                    var roots: [air.transcript_payload.DIRECT_CONSTRAINT_COUNT]core.fields.m31.M31 = undefined;
                    var input_air = try air.vm_air_composition_input.build(a);
                    defer input_air.deinit();
                    const input_plan = try air.universal_relation_binding.Binding(air.vm_air_composition_input).authenticate(&input_air);
                    var ledger = air.relation_interaction.TupleLedger.init(a);
                    defer ledger.deinit();
                    for (sources, 0..) |row, index| {
                        var logical = try row_mod.logicalRow(5, row);
                        if (index == 0) if (mutation) |which| {
                            const witness_air = air.transcript_payload_witness;
                            const pp = witness_air.MAIN_COLUMN_COUNT;
                            const Column = witness_air.PreprocessedSource;
                            const one = core.fields.m31.M31.one();
                            switch (which) {
                                0 => logical[@intFromEnum(witness_air.MainSource.value)] = logical[@intFromEnum(witness_air.MainSource.value)].add(one),
                                1 => logical[pp + @intFromEnum(Column.verifier_id)] = core.fields.m31.M31.fromCanonical(2),
                                2 => logical[pp + @intFromEnum(Column.item_index)] = logical[pp + @intFromEnum(Column.item_index)].add(one),
                                3 => logical[pp + @intFromEnum(Column.limb_index)] = one,
                                4 => logical[pp + @intFromEnum(Column.input_use_count)] = core.fields.m31.M31.zero(),
                                5 => logical[pp + @intFromEnum(Column.row_mask)] = core.fields.m31.M31.zero(),
                                else => unreachable,
                            }
                        };
                        try constraints.evaluateBaseInto(&logical, &scratch, &roots);
                        for (roots) |root| if (!root.isZero()) return error.EthereumWireBoundaryRouteMismatch;
                        for (payload_plan.preparedEntries(logical)) |entry| {
                            if (entry.domain == .recursion_verifier_input_word) try ledger.append(entry.domain, 5, entry.ordinal, entry.role, entry.numerator, entry.values[0..entry.arity]);
                        }
                    }
                    for (consumers, inputs) |row, value| for (input_plan.preparedEntries(try air.vm_air_composition_input_witness.logicalRow(row, value, .binary_node))) |entry| {
                        if (entry.domain == .recursion_verifier_input_word) try ledger.append(entry.domain, 18, entry.ordinal, entry.role, entry.numerator, entry.values[0..entry.arity]);
                    };
                    if (!ledger.classify().isClosed()) return error.EthereumWireBoundaryRouteMismatch;
                }
            };
            try Check.run(allocator, &payload, &input_rows, &values, null);
            for (0..6) |mutation| {
                try std.testing.expectError(error.EthereumWireBoundaryRouteMismatch, Check.run(allocator, &payload, &input_rows, &values, mutation));
            }
            std.debug.print("ETHEREUM_DETACHED_WIRE_BOUNDARY actual_payload_to_graph=true limbs=4 mutations=6 fold_admitted=false\n", .{});
        }
    };
}
