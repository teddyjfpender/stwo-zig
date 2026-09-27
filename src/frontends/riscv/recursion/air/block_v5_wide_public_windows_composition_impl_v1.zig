//! Actual public boundary/compensation and full-u64 window equations. B5SS
//! challenge inputs are supplied by the shared channel AIR, never host tokens.
const std = @import("std");
const Arena = @import("stable_graph_arena_v1.zig").Owned;
const core = @import("stwo_core");
const Q = core.fields.qm31.QM31;
const M = core.fields.m31.M31;
const U = @import("universal_challenges.zig");
const R = @import("composition_graph_recorder.zig");
const Tuple = @import("block_v5_global_public_tuple_algebra_v1.zig");
const Wide = @import("block_v5_wide_native_public_graph_v1.zig");
const Increment = @import("block_v5_recursive_u64_span_v1.zig");
pub fn ForModules(comptime Public: type, comptime Bus: type) type {
    return struct {
        pub const VERSION: u32 = Public.VERSION;
        pub const Source = union(enum) { public: Bus.Source, challenge: u32 };
        pub const Prepared = struct {
            arena: Arena,
            circuit: R.Circuit,
            inputs: []Q,
            values: []Q,
            sources: []Source,
            relations: U.UniversalRelations,
            semantic_identity: [32]u8,
            pub const complete_source_authority = false;
            pub fn deinit(self: *Prepared) void {
                self.circuit.deinit();
                self.arena.deinit();
                self.* = undefined;
            }
            pub fn validate(self: *const Prepared, owner: *const Public.Owner) !void {
                var expected = try prepare(self.arena.child_allocator, owner);
                defer expected.deinit();
                if (!std.meta.eql(self.circuit.identity_digest, expected.circuit.identity_digest) or !std.meta.eql(self.semantic_identity, expected.semantic_identity) or self.sources.len != expected.sources.len or self.inputs.len != expected.inputs.len or self.values.len != expected.values.len) return error.MutatedWidePublicGraph;
                for (self.sources, expected.sources) |a, b| if (!std.meta.eql(a, b)) return error.MutatedWidePublicGraph;
                for (self.inputs, expected.inputs) |a, b| if (!a.eql(b)) return error.MutatedWidePublicGraph;
                for (self.values, expected.values) |a, b| if (!a.eql(b)) return error.MutatedWidePublicGraph;
            }
        };
        const Sink = struct {
            builder: *R.Builder,
            pub fn zero(self: *@This(), value: R.Scalar, _: anyerror) !void {
                try self.builder.check();
                try self.builder.constrainZero(value);
            }
        };
        const Relations = struct {
            set: R.ChallengeSet,
            pub fn getExact(self: *const @This(), domain: @import("../../air/lang/relation.zig").Domain) !*const R.ChallengeSet.Element {
                return self.set.get(domain);
            }
        };
        const Inputs = struct {
            a: std.mem.Allocator,
            builder: *R.Builder,
            public: Bus.Values,
            values: std.ArrayList(Q) = .empty,
            sources: std.ArrayList(Source) = .empty,
            fn add(self: *@This(), value: Q, source: Source) !R.Scalar {
                const symbol = (try self.builder.input()).value;
                try self.values.append(self.a, value);
                try self.sources.append(self.a, source);
                return symbol;
            }
            fn take(self: *@This(), source: Bus.Source) !R.Scalar {
                return self.add(Q.fromM31Array(try self.public.at(.{ .circuit = 0, .wire = 0, .uses = 1, .source = source })), .{ .public = source });
            }
            fn word(self: *@This(), window: u32, coordinate: u32) !Tuple.Word(R.Scalar) {
                var out: Tuple.Word(R.Scalar) = undefined;
                for (&out, 0..) |*symbol, part| symbol.* = try self.take(.{ .public_byte = .{ .window = window, .word = coordinate, .part = @intCast(part) } });
                return out;
            }
            fn original(self: *@This(), window: u32, coordinate: u32) !Tuple.Word(R.Scalar) {
                var out: Tuple.Word(R.Scalar) = undefined;
                for (&out, 0..) |*symbol, part| symbol.* = try self.take(.{ .original = .{ .child = window, .kind = .pairing_coordinate, .coordinate = coordinate, .part = @intCast(part) } });
                return out;
            }
        };
        fn claim(bytes: [16]R.Scalar) R.Scalar {
            var result = R.Scalar.zero();
            for (0..4) |limb| {
                var basis: [4]M = @splat(M.zero());
                basis[limb] = M.one();
                for (0..4) |part| result = result.add(bytes[4 * limb + part].mul(R.Scalar.fromSecure(Q.fromM31Array(basis).mul(Q.fromBase(M.fromU64(@as(u64, 1) << @as(u6, @intCast(8 * part))))))));
            }
            return result;
        }
        pub fn prepare(backing: std.mem.Allocator, owner: *const Public.Owner) !Prepared {
            try owner.validate();
            var arena = try Arena.init(backing);
            errdefer arena.deinit();
            const a = arena.allocator();
            var builder = R.Builder.init(a);
            defer builder.deinit();
            var input = Inputs{ .a = a, .builder = &builder, .public = .{ .public = owner } };
            const data = try a.alloc(Tuple.Data(R.Scalar), owner.fields.len);
            const digests = try a.alloc([2][32]R.Scalar, owner.fields.len);
            const terms = try a.alloc([3][16]R.Scalar, owner.fields.len);
            const native_comp = try a.alloc([16]R.Scalar, owner.fields.len);
            const auxiliary = try a.alloc([9]Tuple.Word(R.Scalar), owner.fields.len);
            for (owner.fields, data, digests, terms, native_comp, auxiliary, 0..) |field, *d, *digest, *exports, *compensation, *aux, index| {
                const window = try std.math.add(u32, owner.policy.first_window, @intCast(index));
                const l = field.layout;
                d.initial_pc = try input.word(window, l.pc_clock);
                d.final_pc = try input.word(window, l.pc_clock + 1);
                d.clock = try input.word(window, l.pc_clock + 2);
                d.completion_address = try input.word(window, l.completion + 2);
                for (0..32) |reg| {
                    const offset: u32 = @intCast(reg);
                    d.initial[reg] = try input.word(window, l.initial + offset);
                    d.final[reg] = try input.word(window, l.final + offset);
                    d.clocks[reg] = try input.word(window, l.clocks + offset);
                }
                for (&d.decoded, 0..) |*symbol, part| symbol.* = try input.word(window, l.decoded + @as(u32, @intCast(part)));
                for (0..2) |limb| {
                    const first = try input.word(window, l.cycles + @as(u32, @intCast(limb)));
                    const last = try input.word(window, l.cycles + 2 + @as(u32, @intCast(limb)));
                    @memcpy(d.first_cycle[4 * limb ..][0..4], &first);
                    @memcpy(d.last_cycle[4 * limb ..][0..4], &last);
                }
                const original_digest = try owner.sources[index].frameAt(9);
                if (original_digest.operation != .root) return error.UntrustedWidePublicDigest;
                for (0..8) |limb| {
                    const original = try input.original(@intCast(index), original_digest.first + @as(u32, @intCast(limb)));
                    @memcpy(digest[0][4 * limb ..][0..4], &original);
                    for (0..4) |part| digest[1][4 * limb + part] = try input.take(.{ .public_digest = .{ .window = window, .word = @intCast(limb), .part = @intCast(part) } });
                }
                const last_frame = try owner.sources[index].frameAt(@intCast(owner.sources[index].frames.len - 1));
                if (last_frame.operation != .felts or last_frame.operation.felts.len != 2) return error.UntrustedWidePublicNativeClaims;
                for (0..4) |limb| {
                    const original = try input.original(@intCast(index), last_frame.first + @as(u32, @intCast(limb)));
                    @memcpy(compensation[4 * limb ..][0..4], &original);
                }
                for (exports, 0..) |*bytes, kind| {
                    for (bytes, 0..) |*symbol, part| {
                        symbol.* = try input.take(.{ .term_byte = .{ .window = window, .kind = @enumFromInt(kind), .limb = @intCast(part / 4), .part = @intCast(part % 4) } });
                    }
                }
                for (aux, 0..) |*symbols, ordinal| symbols.* = try input.word(window, field.word_count + @as(u32, @intCast(ordinal)));
            }
            var outer_initial: [32]Tuple.Word(R.Scalar) = undefined;
            var outer_final: [32]Tuple.Word(R.Scalar) = undefined;
            for (&outer_initial, &outer_final, 0..) |*first, *last, reg| {
                for (first, last, 0..) |*before, *after, part| {
                    before.* = try input.take(.{ .outer_register_byte = .{ .final = false, .register = @intCast(reg), .part = @intCast(part) } });
                    after.* = try input.take(.{ .outer_register_byte = .{ .final = true, .register = @intCast(reg), .part = @intCast(part) } });
                }
            }
            var channel = owner.policy.instances[0].admitted.sealed.sharedChannel();
            const relations = try U.UniversalRelations.draw(a, &channel);
            var symbolic: [U.RELATION_COUNT][2]R.Scalar = undefined;
            for (&symbolic, relations.elements, 0..) |*pair, element, index| {
                pair[0] = try input.add(element.z, .{ .challenge = @intCast(2 * index) });
                pair[1] = try input.add(element.alpha, .{ .challenge = @intCast(2 * index + 1) });
            }
            try builder.activate();
            defer if (builder.active) builder.deactivate();
            var sink = Sink{ .builder = &builder };
            var challenges = Relations{ .set = try R.ChallengeSet.init(symbolic) };
            if (owner.policy.first_window == 0) try Tuple.registerContinuity(R.Scalar, &sink, outer_initial, data[0].initial);
            if (@as(usize, owner.policy.first_window) + data.len == owner.expected.expected().windows.len) try Tuple.registerContinuity(R.Scalar, &sink, data[data.len - 1].final, outer_final);
            for (data, digests, terms, native_comp, auxiliary, 0..) |d, digest, exports, original_comp, aux, index| {
                for (digest[0], digest[1]) |original, expected| try sink.zero(original.sub(expected), error.UntrustedWidePublicDigest);
                const p = owner.policy.instances[index].admitted;
                const exported = [3]R.Scalar{ claim(exports[0]), claim(exports[1]), claim(exports[2]) };
                try windowEquations(R.Scalar, &sink, d, &challenges, p.shape.public_data.completion.?.kind != .halt_flag, claim(original_comp), exported, aux);
                if (index == 0) {
                    if (owner.policy.first_window == 0) try Tuple.initialCycle(R.Scalar, &sink, d.first_cycle);
                } else {
                    try Tuple.nextCycle(R.Scalar, &sink, data[index - 1].last_cycle, d.first_cycle);
                    try Tuple.registerContinuity(R.Scalar, &sink, data[index - 1].final, d.initial);
                }
            }
            try builder.check();
            builder.deactivate();
            var circuit = try builder.finish();
            errdefer circuit.deinit();
            const inputs = try input.values.toOwnedSlice(a);
            const sources = try input.sources.toOwnedSlice(a);
            const values = try a.alloc(Q, circuit.nodes.len);
            try circuit.evaluateInto(inputs, values);
            var identity = core.channel.blake3.Channel{};
            identity.mixU32s(&.{ 0x42355747, VERSION, @intCast(owner.sources.len), owner.policy.first_window });
            identity.mixRoot(owner.policy.coverage.pinned_digest);
            identity.mixRoot(try owner.expected.expected().register_plan.digest());
            for (owner.sources) |source| {
                identity.mixRoot(source.policy.key_id);
                identity.mixRoot(source.policy.physical.instance_id);
                identity.mixRoot(source.public_input_digest);
            }
            return .{ .arena = arena, .circuit = circuit, .inputs = inputs, .sources = sources, .values = values, .relations = relations, .semantic_identity = identity.digestBytes() };
        }

        /// One shared exact equation body used by production and pure scalar/symbolic
        /// oracle fixtures. It confers no admission/capture/receipt authority.
        pub fn windowEquations(comptime S: type, sink: anytype, data: Tuple.Data(S), relations: anytype, terminal_fetch: bool, native_compensation: S, exports: [3]S, auxiliary: [9]Tuple.Word(S)) !void {
            const sums = try Tuple.evaluate(S, data, relations, true, terminal_fetch);
            try sink.zero(sums.native_compensation.sub(native_compensation), error.UntrustedWidePublicNativeClaims);
            for ([_]S{ sums.native_compensation, sums.register_compensation, sums.program_boundary }, exports) |actual, exported| try sink.zero(actual.sub(exported), error.UntrustedWidePublicTerms);
            try Tuple.localZero(S, sink, data);
            var clock: [8]S = @splat(S.zero());
            var steps: [8]S = @splat(S.zero());
            @memcpy(clock[0..4], &data.clock);
            @memcpy(steps[0..4], &auxiliary[0]);
            var add_carries: [4]S = undefined;
            var increment_carries: [4]S = undefined;
            for (&add_carries, &increment_carries, 0..) |*carry, *increment, index| {
                carry.* = auxiliary[1 + index][0];
                increment.* = auxiliary[5 + index][0];
                for (1..4) |part| {
                    try sink.zero(auxiliary[1 + index][part], error.UntrustedWidePublicCarry);
                    try sink.zero(auxiliary[5 + index][part], error.UntrustedWidePublicCarry);
                }
            }
            try Increment.increment(S, sink, steps, clock, increment_carries);
            try Wide.add(S, sink, data.first_cycle, steps, data.last_cycle, add_carries);
        }
    };
}
