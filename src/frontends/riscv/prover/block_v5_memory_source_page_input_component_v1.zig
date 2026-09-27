//! Complete original-cell -> PAGE arithmetic input suppliers. Source/capture
//! values alias their ORIGINAL committed main trees. Only graph-derived
//! circuit/node/use routing is new fixed data; no copied requester main.
const std = @import("std");
const core = @import("stwo_core");
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const P = core.fields.packed_qm31.PackedQM31;
const Semantic = @import("block_v5_memory_source_page_semantic_columns_v1.zig");
const Place = @import("../air/block/memory_component_trace.zig");
pub const Limits = struct { max_fixed_cells: usize = 1 << 25, max_interaction_cells: usize = 1 << 25, max_requests: u64 = 500_000_000, max_row_log: u32 = 14 };
pub fn ForWidth(comptime width: usize) type {
    if (width == 0 or width > 1859) @compileError("source PAGE input supplier width outside exact inventories");
    return struct {
        const Self = @This();
        pub const FIXED_COUNT: usize = 1 + 2 * width;
        pub const MAIN_COUNT: usize = width;
        pub const PAIRS: usize = (width + 1) / 2;
        pub const INTERACTION_COUNT: usize = 4 * PAIRS;
        pub const CONSTRAINT_COUNT: usize = PAIRS;
        pub const Claim = struct { sums: [PAIRS]Q, requests: u64 };
        pub const Plan = struct {
            a: std.mem.Allocator,
            group: Semantic.Group,
            graph_identity: [32]u8,
            row_log: u32,
            cells: []M,
            requests: u64,
            identity: [32]u8,
            pub fn deinit(self: *Plan) void {
                self.a.free(self.cells);
                self.* = undefined;
            }
            pub fn column(self: *const Plan, index: usize) []const M {
                const rows = @as(usize, 1) << @intCast(self.row_log);
                return self.cells[index * rows ..][0..rows];
            }
            pub fn init(a: std.mem.Allocator, graph: *const Semantic.Prepared, group: Semantic.Group, row_log: u32, limits: Limits) !Plan {
                if (row_log < 1 or row_log > limits.max_row_log or limits.max_row_log > 14 or limits.max_requests == 0 or limits.max_requests >= core.fields.m31.Modulus or graph.circuit == null)
                    return error.SourcePageInputResourceLimit;
                try graph.circuit.?.validate();
                const rows = @as(usize, 1) << @intCast(row_log);
                const count = try std.math.mul(usize, rows, Self.FIXED_COUNT);
                if (count > limits.max_fixed_cells) return error.SourcePageInputResourceLimit;
                const cells = try a.alloc(M, count);
                errdefer a.free(cells);
                @memset(cells, M.zero());
                // Boolean bitmap distinguishes an unused real node0 from a
                // duplicate cell/node. It is transient, never proof authority.
                const seen = try a.alloc(bool, try std.math.mul(usize, rows, width));
                defer a.free(seen);
                @memset(seen, false);
                const nodes = try a.alloc(bool, graph.circuit.?.input_count);
                defer a.free(nodes);
                @memset(nodes, false);
                const scratch = try a.alloc(u32, graph.circuit.?.nodes.len);
                defer a.free(scratch);
                const uses = try @import("../recursion/air/verifier_arithmetic_lowering.zig").computeUseCountsInto(graph.circuit.?.graph(), scratch);
                var requests: u64 = 0;
                var total_requests: u64 = 0;
                var input_count: usize = 0;
                for (graph.cells) |cell| {
                    if (cell.node >= nodes.len or nodes[cell.node] or std.meta.activeTag(graph.circuit.?.nodes[cell.node].op) != .input)
                        return error.InvalidSourcePageInputInventory;
                    nodes[cell.node] = true;
                    input_count += 1;
                    if (cell.uses != uses[cell.node]) return error.InvalidSourcePageInputInventory;
                    total_requests = try std.math.add(u64, total_requests, cell.uses);
                    if (cell.group != group) continue;
                    if (cell.column >= width or cell.logical_row >= rows or cell.uses >= core.fields.m31.Modulus)
                        return error.InvalidSourcePageInputInventory;
                    const logical = @as(usize, cell.logical_row) * width + cell.column;
                    if (seen[logical]) return error.DuplicateSourcePageInputCell;
                    seen[logical] = true;
                    const physical = Place.committedRow(cell.logical_row, row_log);
                    cells[physical] = M.fromCanonical(graph.circuit_id);
                    cells[(1 + 2 * @as(usize, cell.column)) * rows + physical] = M.fromCanonical(cell.node);
                    cells[(2 + 2 * @as(usize, cell.column)) * rows + physical] = M.fromCanonical(cell.uses);
                    requests = try std.math.add(u64, requests, cell.uses);
                }
                if (input_count != nodes.len or requests > limits.max_requests or total_requests != graph.input_requests) return error.InvalidSourcePageInputInventory;
                var hash = std.crypto.hash.sha2.Sha256.init(.{});
                hash.update("stwo-zig/block-v5/source-PAGE-input-routing/v1\x00");
                hash.update(&graph.identity);
                var header: [13]u8 = undefined;
                header[0] = @intFromEnum(group);
                std.mem.writeInt(u32, header[1..5], width, .little);
                std.mem.writeInt(u32, header[5..9], row_log, .little);
                std.mem.writeInt(u32, header[9..13], graph.circuit_id, .little);
                hash.update(&header);
                var bytes: [4]u8 = undefined;
                for (cells) |cell| {
                    std.mem.writeInt(u32, &bytes, cell.toU32(), .little);
                    hash.update(&bytes);
                }
                return .{ .a = a, .group = group, .graph_identity = graph.identity, .row_log = row_log, .cells = cells, .requests = requests, .identity = hash.finalResult() };
            }
        };
        pub fn Algebra(comptime S: type) type {
            return struct {
                const A = @This();
                pub const Challenge = struct { z: S, powers: [6]S };
                pub const Term = struct { numerator: S, denominator: S };
                pub fn terms(fixed: [Self.FIXED_COUNT]S, main: [width]S, c: A.Challenge) [2 * Self.PAIRS]A.Term {
                    var out: [2 * Self.PAIRS]A.Term = undefined;
                    for (&out, 0..) |*term, column| {
                        // Odd widths have a literal zero fraction, not a fake
                        // committed cell, fabricated row, or virtual domain.
                        if (column == width) {
                            term.* = .{ .numerator = S.zero(), .denominator = S.one() };
                        } else {
                            term.* = .{ .numerator = fixed[2 + 2 * column], .denominator = c.powers[0].mul(fixed[0]).add(c.powers[1].mul(fixed[1 + 2 * column])).add(c.powers[2].mul(main[column])).sub(c.z) };
                        }
                    }
                    return out;
                }
                pub fn constraints(fixed: [Self.FIXED_COUNT]S, main: [width]S, current: [Self.INTERACTION_COUNT]S, previous: [Self.INTERACTION_COUNT]S, normalized: [Self.PAIRS]S, c: A.Challenge) [Self.PAIRS]S {
                    const values = terms(fixed, main, c);
                    var out: [Self.PAIRS]S = undefined;
                    for (&out, 0..) |*value, pair| {
                        const left = values[2 * pair];
                        const right = values[2 * pair + 1];
                        const delta = S.fromPartialEvals(current[4 * pair ..][0..4].*).sub(S.fromPartialEvals(previous[4 * pair ..][0..4].*)).add(normalized[pair]);
                        value.* = delta.mul(left.denominator).mul(right.denominator).sub(left.numerator.mul(right.denominator)).sub(right.numerator.mul(left.denominator));
                    }
                    return out;
                }
            };
        }
        pub fn normalize(claim: Self.Claim, rows: usize, requests: u64) ![Self.PAIRS]Q {
            if (rows == 0 or rows >= core.fields.m31.Modulus or requests >= core.fields.m31.Modulus or claim.requests != requests) return error.InvalidSourcePageInputClaim;
            const inv = try M.fromCanonical(@intCast(rows)).inv();
            var out: [Self.PAIRS]Q = undefined;
            for (&out, claim.sums) |*value, sum| value.* = sum.mulM31(inv);
            return out;
        }
        pub const Generated = struct {
            a: std.mem.Allocator,
            cells: []M,
            claim: Self.Claim,
            pub fn deinit(self: *Generated) void {
                self.a.free(self.cells);
                self.* = undefined;
            }
        };
        fn contribution(left: Self.Algebra(Q).Term, right: Self.Algebra(Q).Term) !Q {
            var sum = Q.zero();
            if (!left.numerator.isZero()) sum = sum.add(left.numerator.mul(try left.denominator.inv()));
            if (!right.numerator.isZero()) sum = sum.add(right.numerator.mul(try right.denominator.inv()));
            return sum;
        }
        pub fn generate(a: std.mem.Allocator, plan: *const Self.Plan, main: []const []const M, c: Self.Algebra(Q).Challenge, limits: Limits) !Self.Generated {
            if (plan.row_log < 1 or plan.row_log > limits.max_row_log or limits.max_row_log > 14 or main.len != width or plan.requests > limits.max_requests) return error.InvalidSourcePageInputGeometry;
            const rows = @as(usize, 1) << @intCast(plan.row_log);
            if (plan.cells.len != rows * Self.FIXED_COUNT) return error.InvalidSourcePageInputGeometry;
            for (main) |column| if (column.len != rows) return error.InvalidSourcePageInputGeometry;
            const count = try std.math.mul(usize, rows, Self.INTERACTION_COUNT);
            if (count > limits.max_interaction_cells) return error.SourcePageInputResourceLimit;
            const cells = try a.alloc(M, count);
            errdefer a.free(cells);
            var claim = Self.Claim{ .sums = @splat(Q.zero()), .requests = plan.requests };
            for (0..rows) |physical| {
                const values = rowTerms(plan, main, physical, c);
                for (0..Self.PAIRS) |pair| claim.sums[pair] = claim.sums[pair].add(try contribution(values[2 * pair], values[2 * pair + 1]));
            }
            const normalized = try Self.normalize(claim, rows, plan.requests);
            var running: [Self.PAIRS]Q = @splat(Q.zero());
            for (0..rows) |logical| {
                const physical = Place.committedRow(logical, plan.row_log);
                const values = rowTerms(plan, main, physical, c);
                for (0..Self.PAIRS) |pair| {
                    running[pair] = running[pair].add(try contribution(values[2 * pair], values[2 * pair + 1])).sub(normalized[pair]);
                    for (running[pair].toM31Array(), 0..) |value, coordinate| cells[(4 * pair + coordinate) * rows + physical] = value;
                }
            }
            return .{ .a = a, .cells = cells, .claim = claim };
        }
        fn rowTerms(plan: *const Self.Plan, main: []const []const M, row: usize, c: Self.Algebra(Q).Challenge) [2 * Self.PAIRS]Self.Algebra(Q).Term {
            var fixed: [Self.FIXED_COUNT]Q = undefined;
            var values: [width]Q = undefined;
            for (&fixed, 0..) |*value, i| value.* = Q.fromBase(plan.column(i)[row]);
            for (&values, main) |*value, column| value.* = Q.fromBase(column[row]);
            return Self.Algebra(Q).terms(fixed, values, c);
        }
        pub const Spec = struct {
            pub const FIXED_COUNT = Self.FIXED_COUNT;
            pub const MAIN_COUNT = width;
            pub const INTERACTION_COUNT = Self.INTERACTION_COUNT;
            pub const CONSTRAINT_COUNT = Self.PAIRS;
            pub const PREVIOUS_MAIN_MASK: [width]bool = @splat(false);
            pub const DEGREE: u32 = 3;
            pub const EXPANSION_BITS: u32 = 2;
            rows: u32,
            requests: u64,
            claim: Self.Claim,
            challenge: Self.Algebra(Q).Challenge,
            pub const Domain = struct {
                size: u32,
                challenge: Self.Algebra(Q).Challenge,
                normalized: [Self.PAIRS]Q,
                packed_challenge: Self.Algebra(P).Challenge,
                packed_normalized: [Self.PAIRS]P,
                pub fn evaluate(self: Domain, fixed: [Self.FIXED_COUNT]Q, main: [width]Q, _: [width]Q, current: [Self.INTERACTION_COUNT]Q, previous: [Self.INTERACTION_COUNT]Q, size: u32) ![Self.PAIRS]Q {
                    if (self.size != size) return error.InvalidSourcePageInputGeometry;
                    return Self.Algebra(Q).constraints(fixed, main, current, previous, self.normalized, self.challenge);
                }
                pub fn evaluatePacked(self: *const Domain, fixed: [Self.FIXED_COUNT]P, main: [width]P, _: [width]P, current: [Self.INTERACTION_COUNT]P, previous: [Self.INTERACTION_COUNT]P) [Self.PAIRS]P {
                    return Self.Algebra(P).constraints(fixed, main, current, previous, self.packed_normalized, self.packed_challenge);
                }
            };
            pub fn prepareDomain(self: Spec, rows: u32) !Domain {
                if (rows != self.rows) return error.InvalidSourcePageInputGeometry;
                const normalized = try Self.normalize(self.claim, rows, self.requests);
                var powers: [6]P = undefined;
                var sums: [Self.PAIRS]P = undefined;
                for (&powers, self.challenge.powers) |*value, coordinate| value.* = P.splat(coordinate);
                for (&sums, normalized) |*value, sum| value.* = P.splat(sum);
                return .{ .size = rows, .challenge = self.challenge, .normalized = normalized, .packed_challenge = .{ .z = P.splat(self.challenge.z), .powers = powers }, .packed_normalized = sums };
            }
            pub fn evaluate(self: Spec, fixed: [Self.FIXED_COUNT]Q, main: [width]Q, previous_main: [width]Q, current: [Self.INTERACTION_COUNT]Q, previous: [Self.INTERACTION_COUNT]Q, rows: u32) ![Self.PAIRS]Q {
                return (try self.prepareDomain(rows)).evaluate(fixed, main, previous_main, current, previous, rows);
            }
        };
        pub const Component = @import("block_v5_word_quotient_adapter_v1.zig").For(Spec);
    };
}
