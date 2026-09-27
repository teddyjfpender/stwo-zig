//! Shared owned fused public transport, exact wire scheduling and real parent
//! preparation. Typed family policies own claim admission and original framing.
const std = @import("std");
const core = @import("stwo_core");
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const Universal = @import("air/universal_challenges.zig");
pub fn ForFamily(comptime Policy: type) type {
    return ForFamilyInternal(Policy, null);
}
/// Explicit PAGE family. Only independently selected Policy can choose eight
/// public prefix roots; existing family entrypoints retain their 2/3 grammar.
pub fn ForFamilyWithRoots(comptime Policy: type, comptime roots: usize) type {
    comptime if (roots != 8) @compileError("explicit PAGE public prefix requires eight roots");
    return ForFamilyInternal(Policy, roots);
}
fn ForFamilyInternal(comptime Policy: type, comptime exact_roots: ?usize) type {
    return struct {
        const Admission = Policy.Admission;
        const Statement = Policy.Statement;
        pub const VERSION: u32 = 1;
        pub const PUBLIC_CIRCUIT = Statement.PUBLIC_CIRCUIT;
        pub const MAX_WIRES: usize = core.fields.m31.Modulus - 1;
        pub const Source = enum(u8) { word, felt_word, public_input, first_root };
        pub const Wire = struct { circuit: u32, wire: u32, uses: u32, source: Source, coordinate: u32 };
        pub const Values = struct {
            allocator: std.mem.Allocator,
            template: [32]u8,
            statement: Statement.Statement,
            public: []Q,
            roots_count: usize,
            pub fn init(a: std.mem.Allocator, admitted: *const Admission.Prepared, claims: Policy.Claims) !Values {
                try admitted.validate(admitted.template_id);
                try Policy.validateClaims(admitted, claims);
                var statement = try Policy.statement(a, admitted, claims);
                errdefer statement.deinit();
                const public = try Policy.publicInputs(a, admitted, claims);
                errdefer a.free(public);
                const result = Values{ .allocator = a, .template = admitted.template_id, .statement = statement, .public = public, .roots_count = Policy.rootsCount(admitted) };
                try result.validate();
                return result;
            }
            pub fn fromCapture(a: std.mem.Allocator, admitted: *const Admission.Prepared, capture: *const Policy.Capture) !Values {
                try capture.validate(admitted, admitted.template_id);
                return init(a, admitted, Policy.claims(capture));
            }
            pub fn clone(self: Values, a: std.mem.Allocator) !Values {
                var statement = try self.statement.clone(a);
                errdefer statement.deinit();
                const public = try a.dupe(Q, self.public);
                var result = self;
                result.allocator = a;
                result.public = public;
                result.statement = statement;
                return result;
            }
            pub fn deinit(self: *Values) void {
                self.statement.deinit();
                self.allocator.free(self.public);
                self.* = undefined;
            }
            pub fn validate(self: Values) !void {
                if (comptime exact_roots) |count| {
                    if (self.roots_count != count) return error.InvalidFusedRecursivePublicInputs;
                } else if (self.roots_count != 2 and self.roots_count != 3) return error.InvalidFusedRecursivePublicInputs;
                const fields = try std.math.mul(usize, self.statement.felts.len, 4);
                if (try std.math.add(usize, self.statement.words.len, fields) >= core.fields.m31.Modulus or self.public.len >= core.fields.m31.Modulus) return error.InvalidFusedRecursivePublicInputs;
                for (self.public) |value| if (!@import("air/universal_provider_relations.zig").secureIsCanonical(&value)) return error.InvalidFusedRecursivePublicInputs;
                for (self.statement.felts) |value| if (!@import("air/universal_provider_relations.zig").secureIsCanonical(&value)) return error.InvalidFusedRecursivePublicInputs;
            }
            pub fn at(self: Values, source: Source, coordinate: u32) ![4]M {
                if (source == .public_input) {
                    if (coordinate >= self.public.len) return error.InvalidFusedRecursivePublicSchedule;
                    return self.public[coordinate].toM31Array();
                }
                const word: u32 = switch (source) {
                    .word => blk: {
                        if (coordinate >= self.statement.words.len) return error.InvalidFusedRecursivePublicSchedule;
                        break :blk self.statement.words[coordinate];
                    },
                    .felt_word => blk: {
                        const field = coordinate / 4;
                        if (field >= self.statement.felts.len) return error.InvalidFusedRecursivePublicSchedule;
                        break :blk self.statement.felts[field].toM31Array()[coordinate % 4].toU32();
                    },
                    .first_root => blk: {
                        const tree = coordinate / 8;
                        if (tree >= self.roots_count) return error.InvalidFusedRecursivePublicSchedule;
                        const offset = self.statement.roots_offset[tree];
                        if (offset > self.statement.words.len or 8 > self.statement.words.len - offset) return error.InvalidFusedRecursivePublicSchedule;
                        break :blk self.statement.words[offset + coordinate % 8];
                    },
                    .public_input => unreachable,
                };
                var bytes: [4]M = undefined;
                for (&bytes, 0..) |*out, i| out.* = M.fromCanonical((word >> @as(u5, @intCast(8 * i))) & 255);
                return bytes;
            }
            pub fn mix(self: Values, channel: anytype) void {
                channel.mixU32s(&.{ Policy.IDENTITY_TAG, VERSION, @intCast(self.roots_count), @intCast(self.statement.words.len), @intCast(self.statement.felts.len), @intCast(self.public.len) });
                channel.mixRoot(self.template);
                channel.mixU32s(self.statement.words);
                channel.mixFelts(self.statement.felts);
                channel.mixFelts(self.public);
            }
        };
        pub fn scheduleDigest(wires: []const Wire) ![32]u8 {
            if (wires.len == 0 or wires.len > MAX_WIRES) return error.InvalidFusedRecursivePublicSchedule;
            var channel = core.proof_suites.Blake3.Channel{};
            channel.mixU32s(&.{ Policy.SCHEDULE_TAG, VERSION, @intCast(wires.len) });
            for (wires, 0..) |wire, i| {
                if (wire.circuit >= core.fields.m31.Modulus or wire.wire >= core.fields.m31.Modulus or wire.uses == 0 or wire.uses >= core.fields.m31.Modulus or wire.coordinate >= core.fields.m31.Modulus) return error.InvalidFusedRecursivePublicSchedule;
                if (i != 0 and !less({}, wires[i - 1], wire)) return error.InvalidFusedRecursivePublicSchedule;
                channel.mixU32s(&.{ wire.circuit, wire.wire, wire.uses, @intFromEnum(wire.source), wire.coordinate });
            }
            return channel.digestBytes();
        }
        pub fn supply(wires: []const Wire, values: Values, relations: Universal.UniversalRelations) !Q {
            _ = try scheduleDigest(wires);
            try values.validate();
            const elements = try relations.getExact(.recursion_wire);
            var sum = Q.zero();
            for (wires) |wire| {
                const denominator = try elements.combineBase(&(.{ M.fromCanonical(wire.circuit), M.fromCanonical(wire.wire) } ++ try values.at(wire.source, wire.coordinate)));
                if (denominator.isZero()) return error.FusedRecursivePublicDenominatorZero;
                sum = sum.add(Q.fromBase(M.fromCanonical(wire.uses)).mul(try denominator.inv()));
            }
            return sum;
        }
        pub const Prepared = struct {
            allocator: std.mem.Allocator,
            budget: *@import("stwo_prover_engine").host_budget_allocator.SharedHostBudget,
            recursive: @import("blake3_execution_parent_preparation.zig").Prepared,
            wires: []Wire,
            values: Values,
            pub fn deinit(self: *Prepared) void {
                self.recursive.deinit();
                self.allocator.free(self.wires);
                self.values.deinit();
                self.budget.destroy();
                self.* = undefined;
            }
        };
        fn append(a: std.mem.Allocator, wires: *std.ArrayList(Wire), wire: Wire) !void {
            if (wire.uses == 0) return;
            try wires.append(a, wire);
        }
        fn less(_: void, left: Wire, right: Wire) bool {
            return left.circuit < right.circuit or (left.circuit == right.circuit and left.wire < right.wire);
        }
        fn canonicalize(wires: *std.ArrayList(Wire)) !void {
            std.mem.sort(Wire, wires.items, {}, less);
            var count: usize = 0;
            for (wires.items) |wire| {
                if (count != 0 and wires.items[count - 1].circuit == wire.circuit and wires.items[count - 1].wire == wire.wire) {
                    const prior = &wires.items[count - 1];
                    if (prior.source != wire.source or prior.coordinate != wire.coordinate) return error.InvalidFusedRecursivePublicSchedule;
                    prior.uses = try std.math.add(u32, prior.uses, wire.uses);
                } else {
                    wires.items[count] = wire;
                    count += 1;
                }
            }
            wires.items.len = count;
        }

        /// Structural routing only. The typed fixed caller authenticates its
        /// original native graph/plan and public extents; the live caller below
        /// retains actual public input equality checks before this delegation.
        pub fn collectFixedSchedule(a: std.mem.Allocator, plan: *const @import("air/blake3_transcript_plan.zig").Plan, composition: anytype, words_count: usize, public_count: usize, roots_count: usize, path_reads: u32, max_wires: usize) ![]Wire {
            if (comptime exact_roots) |count| {
                if (roots_count != count) return error.InvalidFusedRecursivePublicSchedule;
            } else if (roots_count != 2 and roots_count != 3) return error.InvalidFusedRecursivePublicSchedule;
            if (path_reads == 0 or path_reads >= core.fields.m31.Modulus or words_count >= core.fields.m31.Modulus or public_count >= core.fields.m31.Modulus or max_wires == 0 or composition.sources.len != composition.circuit.input_count) return error.InvalidFusedRecursivePublicSchedule;
            var wires: std.ArrayList(Wire) = .empty;
            errdefer wires.deinit(a);
            const root_circuit = @import("air/blake3_root_sources.zig").CIRCUIT;
            for (0..roots_count) |tree| {
                for (0..8) |coordinate| try append(a, &wires, .{ .circuit = root_circuit, .wire = @intCast(8 * tree + coordinate), .uses = path_reads, .source = .first_root, .coordinate = @intCast(8 * tree + coordinate) });
            }
            for (plan.fixed.root_reads) |receipt| {
                if (receipt.source.circuit != PUBLIC_CIRCUIT) continue;
                if (receipt.uses.len != 8) return error.InvalidFusedRecursivePublicSchedule;
                for (receipt.uses, 0..) |uses, coordinate| try append(a, &wires, .{ .circuit = PUBLIC_CIRCUIT, .wire = receipt.source.first_wire + @as(u32, @intCast(coordinate)), .uses = uses, .source = .word, .coordinate = receipt.source.first_wire + @as(u32, @intCast(coordinate)) });
            }
            for (plan.fixed.payload_reads) |receipt| {
                if (receipt.source.circuit != PUBLIC_CIRCUIT) continue;
                for (receipt.uses, 0..) |uses, coordinate| {
                    const wire = try std.math.add(u32, receipt.source.first_wire, @intCast(coordinate));
                    const field = wire >= words_count;
                    try append(a, &wires, .{ .circuit = PUBLIC_CIRCUIT, .wire = wire, .uses = uses, .source = if (field) .felt_word else .word, .coordinate = if (field) @intCast(wire - words_count) else wire });
                }
            }
            const use_counts = try a.alloc(u32, composition.circuit.nodes.len);
            defer a.free(use_counts);
            const uses = try @import("air/verifier_arithmetic_lowering.zig").computeUseCountsInto(composition.circuit.graph(), use_counts);
            for (composition.sources, 0..) |source, node| switch (source) {
                .public_input => |index| {
                    if (index >= public_count) return error.InvalidFusedRecursivePublicSchedule;
                    if (uses[node] != 0) try append(a, &wires, .{ .circuit = 1500, .wire = @intCast(node), .uses = uses[node], .source = .public_input, .coordinate = index });
                },
                else => {},
            };
            if (wires.items.len > max_wires) return error.FusedRecursiveResourceLimit;
            try canonicalize(&wires);
            _ = try scheduleDigest(wires.items);
            return wires.toOwnedSlice(a);
        }

        pub fn prepare(a: std.mem.Allocator, admitted: *const Admission.Prepared, capture: *const Policy.Capture, capacity: u32) !Prepared {
            const Budget = @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget;
            const budget = if (comptime exact_roots != null) try Budget.createRetainingParent(a, admitted.limits.max_preparation_bytes) else try Budget.create(a, admitted.limits.max_preparation_bytes);
            errdefer budget.destroy();
            const bounded = budget.allocator();
            var values = try Values.fromCapture(bounded, admitted, capture);
            errdefer values.deinit();
            var planned = try @import("blake3_execution_parent_preparation.zig").State.plan(bounded, admitted, capture, admitted.template_id, capacity);
            defer planned.deinit();
            const state = planned.state.?;
            const transcript = &planned.transcript.?;
            // Actual witness equality remains mandatory at the live boundary.
            for (state.composition.sources, 0..) |source, node| switch (source) {
                .public_input => |index| {
                    if (index >= values.public.len or !state.composition.inputs[node].eql(values.public[index])) return error.InvalidFusedRecursivePublicSchedule;
                },
                else => {},
            };
            const path_reads = std.math.cast(u32, capture.proof.queries.raw.len) orelse return error.InvalidFusedRecursivePublicSchedule;
            const wires = try collectFixedSchedule(bounded, &transcript.plan, &state.composition, values.statement.words.len, values.public.len, values.roots_count, path_reads, admitted.limits.max_public_wires);
            errdefer bounded.free(wires);
            const emitted = try planned.emit();
            defer emitted.deinit();
            var recursive = try emitted.finishReleasingRows();
            errdefer recursive.deinit();
            return .{ .allocator = bounded, .budget = budget, .recursive = recursive, .wires = wires, .values = values };
        }
    };
}
