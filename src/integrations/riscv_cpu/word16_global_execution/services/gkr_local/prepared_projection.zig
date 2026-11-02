//! Domain-only constant folding of the SAME terminal projection. OODS retains
//! binding.ProjectionFor as independent authority; no polynomial/degree changes.
const std = @import("std");
const core = @import("stwo_core");
const E = @import("stwo_riscv_frontend").rv64_air.evaluation;
const R = @import("fractions.zig");
const O = core.fields.om31.OM31;
const Ch = @import("challenges.zig").For(O);
pub const MAX_PREPARED_BYTES: usize = 1024 * 1024;
pub fn For(comptime F: type) type {
    const S = E.SecureFor(F);
    return struct {
        const Entry = struct { relation: R.Relation, start: usize, weight: S, offset: S };
        allocator: std.mem.Allocator,
        entries: []Entry,
        coefficients: []S,
        padded: S,
        pub fn maxBytesForTerms(terms: usize) !usize {
            if (terms == 0 or terms > @import("frame.zig").MAX_LOCAL_TERMS) return error.LocalGkrProjectionShape;
            return std.math.add(usize, try std.math.mul(usize, terms, @sizeOf(Entry)), try std.math.mul(usize, try std.math.mul(usize, terms, R.MAX_ARITY), @sizeOf(S)));
        }
        pub fn init(a: std.mem.Allocator, relations: []const R.Relation, ch: *const Ch, weights: []const O) !@This() {
            if (relations.len == 0 or relations.len > @import("frame.zig").MAX_LOCAL_TERMS or relations.len > weights.len or weights.len > @import("frame.zig").MAX_LOCAL_TERMS or !std.math.isPowerOfTwo(weights.len)) return error.LocalGkrProjectionShape;
            var count: usize = 0;
            for (relations) |relation| count = try std.math.add(usize, count, relation.arity());
            const allocation_bytes = try std.math.add(usize, try std.math.mul(usize, relations.len, @sizeOf(Entry)), try std.math.mul(usize, count, @sizeOf(S)));
            if (allocation_bytes > MAX_PREPARED_BYTES) return error.LocalProjectionScratchBudgetExceeded;
            const entries = try a.alloc(Entry, relations.len);
            errdefer a.free(entries);
            const coefficients = try a.alloc(S, count);
            errdefer a.free(coefficients);
            var at: usize = 0;
            for (entries, relations, weights[0..relations.len]) |*entry, relation, weight| {
                const index = @intFromEnum(relation);
                entry.* = .{ .relation = relation, .start = at, .weight = E.splatFor(F, weight), .offset = E.splatFor(F, weight.mul(ch.offsets[index])) };
                for (0..relation.arity()) |coordinate| {
                    coefficients[at] = E.splatFor(F, weight.mul(ch.coefficients[index][coordinate]));
                    at += 1;
                }
            }
            var padded = O.zero();
            for (weights[relations.len..]) |weight| padded = padded.add(weight);
            return .{ .allocator = a, .entries = entries, .coefficients = coefficients, .padded = E.splatFor(F, padded) };
        }
        pub fn initComponent(a: std.mem.Allocator, component: anytype) !@This() {
            const C = @typeInfo(@TypeOf(component)).pointer.child;
            const Collector = struct {
                relations: [@import("frame.zig").MAX_LOCAL_TERMS]R.Relation = undefined,
                count: usize = 0,
                invalid: bool = false,
                pub fn emit(self: *@This(), relation: R.Relation, tuple: anytype, weight: anytype) void {
                    _ = weight;
                    if (self.count >= @import("frame.zig").MAX_LOCAL_TERMS or tuple.len != relation.arity()) {
                        self.invalid = true;
                        return;
                    }
                    self.relations[self.count] = relation;
                    self.count += 1;
                }
            };
            var collector = Collector{};
            const shape = component.mainShape();
            const fixed = [_]O{O.zero()} ** C.MAX_FIXED;
            const main = [_]O{O.zero()} ** C.MAX_MAIN;
            component.emitLocalFor(O, fixed[0..shape.fixed], main[0..shape.main], &collector);
            if (collector.invalid or collector.count != component.data.instance.terms) return error.LocalGkrProjectionShape;
            return init(a, collector.relations[0..collector.count], &component.data.challenges, component.data.lane_weights[0..component.data.lane_count]);
        }
        pub fn bytes(self: *const @This()) usize {
            return self.entries.len * @sizeOf(Entry) + self.coefficients.len * @sizeOf(S);
        }
        pub fn deinit(self: *@This()) void {
            self.allocator.free(self.entries);
            self.allocator.free(self.coefficients);
            self.* = undefined;
        }
        pub const Projection = struct {
            prepared: *const For(F),
            used: usize = 0,
            numerator: S = .zero(),
            denominator: S = .zero(),
            invalid: bool = false,
            pub fn emit(self: *@This(), relation: R.Relation, tuple: anytype, weight: F) void {
                if (self.used >= self.prepared.entries.len) {
                    self.invalid = true;
                    return;
                }
                const entry = self.prepared.entries[self.used];
                if (entry.relation != relation or tuple.len != relation.arity()) {
                    self.invalid = true;
                    return;
                }
                self.numerator = self.numerator.add(E.mulBaseFor(F, entry.weight, weight));
                var d = entry.offset;
                for (tuple, 0..) |value, i| d = d.sub(E.mulBaseFor(F, self.prepared.coefficients[entry.start + i], value));
                self.denominator = self.denominator.add(d);
                self.used += 1;
            }
            /// Native metadata projection keeps tuple values in M31. Public
            /// lane/challenge products are hoisted once, never rematerialized
            /// as full denominator planes or secure tuple values.
            pub fn emitBase(self: *@This(), relation: R.Relation, tuple: anytype, weight: core.fields.m31.M31) void {
                comptime if (F != O) @compileError("native base projection requires OM31");
                if (self.used >= self.prepared.entries.len) {
                    self.invalid = true;
                    return;
                }
                const entry = self.prepared.entries[self.used];
                if (entry.relation != relation or tuple.len != relation.arity()) {
                    self.invalid = true;
                    return;
                }
                self.numerator = self.numerator.add(entry.weight.mulM31(weight));
                var d = entry.offset;
                for (tuple, 0..) |value, i| d = d.sub(self.prepared.coefficients[entry.start + i].mulM31(value));
                self.denominator = self.denominator.add(d);
                self.used += 1;
            }
            pub fn finish(self: *@This()) !void {
                if (self.invalid or self.used != self.prepared.entries.len) return error.LocalGkrProjectionShape;
                self.denominator = self.denominator.add(self.prepared.padded);
            }
            pub fn combine(self: *const @This(), eta: S) S {
                return self.numerator.add(eta.mul(self.denominator));
            }
        };
        pub fn projection(self: *const @This()) Projection {
            return .{ .prepared = self };
        }
    };
}
