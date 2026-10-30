//! Opaque, independently compiled caller verifier. Never deserialized from a
//! producer and never accepted on a self-reported digest. Cold setup and live
//! evaluation share its original graph; live arrays remain separately owned.
pub fn For(comptime Policy: type) type {
    return struct {
        const std = @import("std");
        const core = @import("stwo_core");
        const Q = core.fields.qm31.QM31;
        const Native = Policy.Fixed;
        const Profile = Policy.FixedProfile;
        const Capture = Policy.Capture;
        const Shared = @import("air/blake3_execution_composition.zig");
        const Circuit = @import("air/composition_graph_recorder.zig").Circuit;
        pub const Capsule = opaque {
            pub fn derive(a: std.mem.Allocator, input: Profile.Input, limits: Native.Limits) !*Capsule {
                return @ptrCast(try Native.Owned.derive(a, input, limits));
            }
            /// Read-only original compiler product; the opaque handle has no public
            /// unchecked constructor. The owner must outlive this borrowed reference.
            pub fn compiler(self: *const Capsule) *const Native.Owned {
                return @ptrCast(@alignCast(self));
            }
            pub fn admitted(self: *const Capsule) *const Policy.Admission.Prepared {
                return &self.compiler().profile.admitted;
            }
            /// Match the independently selected metadata without rebuilding any graph.
            /// Physical claim values remain dynamic but must match this cold frame.
            pub fn requireProfile(self: *const Capsule, a: std.mem.Allocator, expected: *const Profile.Owned) !void {
                const got = self.compiler().profile;
                if (!std.meta.eql(got.admitted.template_id, expected.admitted.template_id) or
                    !std.meta.eql(got.admitted.epoch, expected.admitted.epoch) or
                    got.admitted.entries.len != expected.admitted.entries.len) return error.CallerCompilerProfileMismatch;
                for (got.admitted.entries, expected.admitted.entries) |x, y| if (!std.meta.eql(x, y)) return error.CallerCompilerProfileMismatch;
                const Public = Policy.Public;
                const left = try Public.publicInputs(a, &got.admitted, &got.arithmetic, &got.claims);
                defer a.free(left);
                const right = try Public.publicInputs(a, &expected.admitted, &expected.arithmetic, &expected.claims);
                defer a.free(right);
                if (left.len != right.len) return error.CallerCompilerProfileMismatch;
                for (left, right) |x, y| if (!x.eql(y)) return error.CallerCompilerProfileMismatch;
            }
            /// Clone immutable compiled geometry; proof-derived values remain fresh
            /// and independently checked by the original capture and PCS adapters.
            pub fn prepareDeep(self: *const Capsule, a: std.mem.Allocator, capture: *const Capture.VerifiedCapture) !@import("air/blake3_native_deep.zig").Prepared {
                const native = self.compiler();
                var inputs = try @import("pcs_arithmetic_capture.zig").Owned.init(a, native.profile.deepProfile(), &capture.original.proof);
                errdefer inputs.deinit();
                var graph = try @import("air/compiled_pcs_graph_clone_v1.zig").deep(a, &native.deep_graph);
                errdefer graph.deinit();
                const evaluation = try graph.evaluate(a, inputs.inputs);
                return .{ .graph = graph, .inputs = inputs, .evaluation = evaluation };
            }
            pub fn deinit(self: *Capsule) void {
                const native: *Native.Owned = @ptrCast(@alignCast(self));
                native.deinit();
            }
            /// Fill the independently compiled source map using the exact native draw
            /// order and a freshly admitted original capture, then evaluate its DAG.
            /// No original constraint recorder/compiler is invoked on this path.
            pub fn prepareComposition(self: *const Capsule, a: std.mem.Allocator, capture: *const Capture.VerifiedCapture) !Shared.Prepared {
                const native = self.compiler();
                const admission = self.admitted();
                try capture.validate(admission, admission.template_id);
                var arena = std.heap.ArenaAllocator.init(a);
                errdefer arena.deinit();
                const temp = arena.allocator();
                const public = try Policy.Public.publicInputs(temp, admission, &capture.original.arithmetic, &capture.original.claims);
                const Source = Policy.Source;
                const entry = try admission.pin().require(temp, admission.epoch, admission.entries);
                const drawn = try Source.draw(temp, admission.epoch, entry);
                var challenges: [134]Q = undefined;
                for (drawn.epoch.word.universal_prefix.elements, 0..) |element, i| {
                    challenges[2 * i] = element.z;
                    challenges[2 * i + 1] = element.alpha;
                }
                const suffix = drawn.relations.draws();
                @memcpy(challenges[94..122], &suffix);
                inline for (.{ "transition", "link", "initial", "endpoint", "range16" }, 0..) |name, i| {
                    const element = @field(drawn.epoch.word, name);
                    challenges[122 + 2 * i] = element.z;
                    challenges[123 + 2 * i] = element.alpha;
                }
                challenges[132] = drawn.epoch.memory.interval.z;
                challenges[133] = drawn.epoch.memory.interval.powers[1];
                const original = &capture.original.proof;
                const sources = try temp.dupe(Shared.Source, native.composition.sources);
                const inputs = try temp.alloc(Q, sources.len);
                for (sources, inputs) |source, *value| value.* = switch (source) {
                    .sample => |i| if (i < original.sampled_values.len) original.sampled_values[i] else return error.InvalidJointCompiledSource,
                    .public_input => |i| if (i < public.len) public[i] else return error.InvalidJointCompiledSource,
                    .challenge => |i| if (i < challenges.len) challenges[i] else return error.InvalidJointCompiledSource,
                    .composition => original.composition_randomness,
                    .oods => original.oods_seed,
                    .claim, .packed_public_input => return error.InvalidJointCompiledSource,
                };
                var circuit = try cloneCircuit(a, &native.composition.circuit);
                errdefer circuit.deinit();
                const values = try temp.alloc(Q, circuit.nodes.len);
                try circuit.evaluateInto(inputs, values);
                var result = Shared.Prepared{ .arena = arena, .circuit = circuit, .inputs = inputs, .sources = sources, .values = values, .key_id = admission.template_id, .capture_seal = capture.seal, .seal = undefined };
                result.seal = result.identity();
                return result;
            }
        };
        fn cloneCircuit(a: std.mem.Allocator, original: *const Circuit) !Circuit {
            const nodes = try a.dupe(@TypeOf(original.nodes[0]), original.nodes);
            errdefer a.free(nodes);
            const outputs = try a.dupe(u32, original.outputs);
            return .{ .allocator = a, .nodes = nodes, .outputs = outputs, .input_count = original.input_count, .identity_digest = original.identity_digest };
        }
    };
}
