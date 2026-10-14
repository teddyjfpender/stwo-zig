//! Audit-only accepted-relation checker shared by CAS05/XDM04 and CAS07/XDM05.
//!
//! A successful extraction has passed the complete statement-bound verifier,
//! reauthenticated the exact sampled source and line rows, and checked this
//! explicit all-query, all-height algebraic relation. The returned rows are
//! *conditionally* committed rows: identifying them with a unique oracle
//! requires collision resistance of the tagged Merkle hashes. This module
//! makes no BCS/Fiat-Shamir or proximity-security claim and is not dispatched
//! by production PCS.

const std = @import("std");
const circle = @import("../circle.zig");
const blake2s_channel = @import("../channel/blake2s.zig");
const m31 = @import("../fields/m31.zig");
const cm31 = @import("../fields/cm31.zig");
const qm31 = @import("../fields/qm31.zig");
const canonic = @import("../poly/circle/canonic.zig");
const line = @import("../poly/line.zig");
const utils = @import("../utils.zig");
const queries = @import("../queries.zig");
const blake2_merkle = @import("../vcs_lifted/blake2_merkle.zig");
const vcs_verifier = @import("../vcs_lifted/verifier.zig");

const M31 = m31.M31;
const CM31 = cm31.CM31;
const QM31 = qm31.QM31;
const Hasher = blake2_merkle.Blake2sMerkleHasher;

/// Instantiate the same authenticated-row and algebraic checks for a complete
/// versioned cascade and its matching source commitment.
pub fn Relation(comptime cascade: type, comptime xdm: type) type {
    return struct {
        fn pair(left: QM31, right: QM31, coordinate: M31, alpha: QM31) !QM31 {
            return left.add(right).add(alpha.mul(left.sub(right).mulM31(try coordinate.inv())));
        }

        fn word(opening: cascade.LineOpening, at: usize) QM31 {
            return QM31.fromM31Array(.{
                opening.queried_coordinates[0][at], opening.queried_coordinates[1][at],
                opening.queried_coordinates[2][at], opening.queried_coordinates[3][at],
            });
        }

        /// The quotient is evaluated by direct interpolation of the OOD claim and its
        /// complex conjugate. Both native verifiers use cross-multiplied line
        /// coefficients, making this an independent arithmetic expression.
        fn pairedWord(
            accepted: *const AcceptedRelation,
            height: usize,
            query: usize,
            side: usize,
            p: circle.CirclePointM31,
        ) !QM31 {
            // An absent XDM05 source height has no quotient denominator at
            // all. Its inserted batch is identically zero, including at
            // points where a hypothetical denominator would vanish.
            if (accepted.claims[height].len == 0) return QM31.zero();
            const point = accepted.sampled_point;
            const conjugate = point.complexConjugate();
            const y_span = conjugate.y.sub(point.y);
            if (y_span.isZero()) return error.DegenerateOodPoint;
            const denominator = point.x.c0.sub(CM31.fromBase(p.x)).mul(point.y.c1)
                .sub(point.y.c0.sub(CM31.fromBase(p.y)).mul(point.x.c1));
            const inverse = try denominator.inv();
            var weight = QM31.one();
            var result = QM31.zero();
            for (accepted.claims[height], 0..) |claim, column| {
                const opened = accepted.source.at(height, query, side, column);
                const slope = claim.complexConjugate().sub(claim);
                const interpolated = claim.add(try slope.mul(
                    QM31.fromBase(p.y).sub(point.y),
                ).div(y_span));
                const residual = QM31.fromBase(opened).sub(interpolated).mul(y_span);
                result = result.add(weight.mul(QM31.fromBase(opened)));
                weight = weight.mul(accepted.batch_challenge);
                result = result.add(weight.mul(residual.mulCM31(inverse)));
                weight = weight.mul(accepted.batch_challenge);
            }
            return result;
        }

        pub const AcceptedRelation = struct {
            /// Stable address required by `source.allocator`, which remains public.
            arena: *std.heap.ArenaAllocator,
            arena_owner: std.mem.Allocator,
            profile: cascade.Profile,
            source_root: xdm.Hash,
            line_roots: []xdm.Hash,
            sampled_point: circle.CirclePointQM31,
            claims: []const []const QM31,
            batch_challenge: QM31,
            alphas: []QM31,
            raw_queries: []usize,
            source: xdm.VerifiedOpenings,
            /// Two authenticated line words per query at each nonterminal height.
            line_pairs: [][]QM31,
            terminal_ordered_coeffs: []QM31,
            /// Values forwarded at each height, selected from the next line pair or
            /// evaluated from the terminal polynomial, in raw-query order.
            forwarded: [][]QM31,

            pub fn deinit(self: *AcceptedRelation) void {
                self.arena.deinit();
                self.arena_owner.destroy(self.arena);
                self.* = undefined;
            }

            /// Pure algebraic check of the extracted relation for every raw query and
            /// every height. Authentication is an explicit extraction premise, not a
            /// property inferred from this check or from caller-built structures.
            pub fn check(self: *const AcceptedRelation, allocator: std.mem.Allocator) !void {
                try self.profile.validate();
                const source = self.profile.source;
                const h = source.height_count;
                const q = source.query_count;
                const k = source.largest_log_size;
                if (!std.meta.eql(self.source.profile, source) or self.source.values.len != h or
                    self.claims.len != h or self.alphas.len != h or
                    self.raw_queries.len != q or self.line_pairs.len != h - 1 or
                    self.line_roots.len != h - 1 or self.forwarded.len != h or
                    self.terminal_ordered_coeffs.len != self.profile.terminalLength() or
                    !self.sampled_point.isOnCircle() or self.sampled_point.y.c1.isZero())
                    return error.InvalidAcceptedRelation;
                for (0..h) |height| {
                    if (self.claims[height].len != source.columns[height] or
                        self.source.values[height].len != q * 2 * source.columns[height] or
                        self.forwarded[height].len != q)
                        return error.InvalidAcceptedRelation;
                    if (height + 1 < h and self.line_pairs[height].len != q * 2)
                        return error.InvalidAcceptedRelation;
                }

                // Equal projected rows must carry equal values, even when two raw
                // queries overlap at a smaller height. XDM04 already enforces this;
                // the standalone algebraic certificate checks it again.
                var seen_source = std.AutoHashMap(u64, usize).init(allocator);
                defer seen_source.deinit();
                var seen_line = std.AutoHashMap(u64, QM31).init(allocator);
                defer seen_line.deinit();
                for (self.raw_queries, 0..) |raw, query| {
                    if (raw >= (@as(usize, 1) << @intCast(k))) return error.InvalidAcceptedRelation;
                    for (0..h) |height| {
                        const base = xdm.pairBase(raw, height);
                        for (0..2) |side| {
                            const key = (@as(u64, @intCast(height)) << 32) | @as(u64, @intCast(base + side));
                            if (seen_source.get(key)) |previous| {
                                for (0..source.columns[height]) |column|
                                    if (!self.source.at(height, query, side, column).eql(
                                        self.source.at(height, previous, side, column),
                                    )) return error.InconsistentSourceRow;
                            } else try seen_source.put(key, query);
                        }
                        if (height + 1 < h) {
                            const line_base = xdm.pairBase(raw, height + 1);
                            for (0..2) |side| {
                                const key = (@as(u64, @intCast(height)) << 32) |
                                    @as(u64, @intCast(line_base + side));
                                const value = self.line_pairs[height][query * 2 + side];
                                if (seen_line.get(key)) |previous| {
                                    if (!value.eql(previous)) return error.InconsistentLineRow;
                                } else try seen_line.put(key, value);
                            }
                        }
                    }
                }

                const coefficients = try allocator.dupe(QM31, self.terminal_ordered_coeffs);
                var terminal = line.LinePoly.fromOrderedCoefficients(coefficients);
                defer terminal.deinit(allocator);
                const terminal_domain = line.LineDomain.fromCircleDomain(
                    canonic.CanonicCoset.new(k - @as(u32, @intCast(h - 1))).circleDomain(),
                );
                const first_domain = canonic.CanonicCoset.new(k).circleDomain();
                const two = QM31.fromBase(M31.fromCanonical(2));
                const half = try two.inv();
                for (self.raw_queries, 0..) |raw, query| {
                    var projected = first_domain.at(utils.bitReverseIndex(raw, k));
                    var scale = QM31.one();
                    for (0..h) |height| {
                        const circle_log = k - @as(u32, @intCast(height));
                        const base = xdm.pairBase(raw, height);
                        const circle_domain = canonic.CanonicCoset.new(circle_log).circleDomain();
                        const selected_circle = base | (raw & 1);
                        const expected_circle = circle_domain.at(
                            utils.bitReverseIndex(selected_circle, circle_log),
                        );
                        if (!projected.eql(expected_circle)) return error.InvalidQueryProjection;
                        projected = projected.double();
                        const y = circle_domain.at(utils.bitReverseIndex(base, circle_log)).y;
                        const inserted_even = try pairedWord(self, height, query, 0, circle_domain.at(
                            utils.bitReverseIndex(base, circle_log),
                        ));
                        const inserted_odd = try pairedWord(self, height, query, 1, circle_domain.at(
                            utils.bitReverseIndex(base + 1, circle_log),
                        ));
                        const inserted = try pair(inserted_even, inserted_odd, y, self.alphas[height]);
                        const folded = if (height == 0) inserted else blk: {
                            const line_domain = line.LineDomain.fromCircleDomain(
                                canonic.CanonicCoset.new(circle_log + 1).circleDomain(),
                            );
                            const x = line_domain.at(utils.bitReverseIndex(base, circle_log));
                            const previous = self.line_pairs[height - 1];
                            const carried = try pair(
                                previous[query * 2],
                                previous[query * 2 + 1],
                                x,
                                self.alphas[height],
                            );
                            break :blk carried.add(self.alphas[height].square().mul(inserted));
                        };
                        if (!folded.eql(self.forwarded[height][query])) return error.InvalidFoldRelation;

                        // The published normalized butterfly has a 1/2 factor.
                        // Both the carried layer and this height's inserted batch
                        // are divided by the accumulated native factor 2^height.
                        const normalized_inserted = try pair(
                            try inserted_even.div(scale),
                            try inserted_odd.div(scale),
                            y,
                            self.alphas[height],
                        );
                        const normalized = if (height == 0) half.mul(normalized_inserted) else blk: {
                            const line_domain = line.LineDomain.fromCircleDomain(
                                canonic.CanonicCoset.new(circle_log + 1).circleDomain(),
                            );
                            const x = line_domain.at(utils.bitReverseIndex(base, circle_log));
                            const previous = self.line_pairs[height - 1];
                            const carried = try pair(
                                try previous[query * 2].div(scale),
                                try previous[query * 2 + 1].div(scale),
                                x,
                                self.alphas[height],
                            );
                            break :blk half.mul(carried)
                                .add(self.alphas[height].square().mul(half.mul(normalized_inserted)));
                        };
                        if (!folded.eql(two.mul(scale).mul(normalized)))
                            return error.InvalidNormalizedFold;
                        scale = scale.mul(two);

                        if (height + 1 < h) {
                            const selected = (raw >> @intCast(height + 1)) & 1;
                            if (!self.forwarded[height][query].eql(
                                self.line_pairs[height][query * 2 + selected],
                            )) return error.InvalidForwardedLine;
                        } else {
                            const row = raw >> @intCast(h);
                            const x = terminal_domain.at(utils.bitReverseIndex(row, terminal_domain.logSize()));
                            const expected = try terminal.evalAtPoint(allocator, QM31.fromBase(x));
                            if (!self.forwarded[height][query].eql(expected))
                                return error.InvalidTerminalRelation;
                        }
                    }
                }
            }
        };

        /// Audit-only full verifier and extractor. The caller's channel changes only
        /// after both the complete native verifier and the independent relation check
        /// succeed. The returned owned certificate survives destruction of a decoded
        /// outer-wire proof. The concrete value-only Blake2s channel makes staged and
        /// replay copies independent. No authenticated-oracle uniqueness is asserted
        /// without a concrete Merkle collision bound.
        pub fn verifyAndExtract(
            allocator: std.mem.Allocator,
            proof: cascade.Proof,
            channel: *blake2s_channel.Blake2sChannel,
            statement: cascade.ExpectedStatement,
        ) !AcceptedRelation {
            const arena = try allocator.create(std.heap.ArenaAllocator);
            errdefer allocator.destroy(arena);
            arena.* = std.heap.ArenaAllocator.init(allocator);
            errdefer arena.deinit();
            const a = arena.allocator();
            var staged = channel.*;
            try cascade.verifyAgainstStatement(a, proof, &staged, statement);

            var replay = channel.*;
            cascade.bindVersion(&replay);
            const sampled = try cascade.drawOodPoint(&replay, proof.profile, proof.source_root);
            if (!sampled.eql(proof.sampled_point)) return error.TranscriptMismatch;
            const batch = try cascade.drawBatchAfterOod(&replay, proof.claims);
            const h = proof.profile.source.height_count;
            const alphas = try a.alloc(QM31, h);
            const roots = try a.alloc(xdm.Hash, h - 1);
            for (alphas, 0..) |*alpha, height| {
                alpha.* = replay.drawSecureFelt();
                if (height + 1 < h) {
                    roots[height] = proof.line_openings[height].root;
                    cascade.mixLineRoot(&replay, height, roots[height]);
                }
            }
            cascade.mixTerminal(&replay, proof.terminal_ordered_coeffs);
            const raw = try queries.drawQueries(
                &replay,
                a,
                proof.profile.source.largest_log_size,
                proof.profile.source.query_count,
            );
            const opened = try xdm.verifyAndCollect(
                a,
                proof.source_wire,
                proof.profile.source,
                proof.source_root,
                raw,
            );
            // Arena owns the source allocations after successful extraction.
            const line_pairs = try a.alloc([]QM31, h - 1);
            for (proof.line_openings, 0..) |opening, height| {
                const log_size = proof.profile.source.largest_log_size - @as(u32, @intCast(height + 1));
                const domain = line.LineDomain.fromCircleDomain(
                    canonic.CanonicCoset.new(log_size + 1).circleDomain(),
                );
                const rows = try a.alloc(usize, raw.len * 2);
                for (raw, 0..) |position, query| {
                    const base = xdm.pairBase(position, height + 1);
                    rows[query * 2] = base;
                    rows[query * 2 + 1] = base + 1;
                }
                var verifier = try vcs_verifier.MerkleVerifierLifted(Hasher).init(
                    a,
                    opening.root,
                    &[_]u32{domain.logSize()} ** 4,
                );
                defer verifier.deinit(a);
                const columns = opening.queried_coordinates;
                try verifier.verify(a, rows, &columns, .{ .hash_witness = opening.hash_witness });
                line_pairs[height] = try a.alloc(QM31, raw.len * 2);
                for (line_pairs[height], 0..) |*value, at| value.* = word(opening, at);
            }
            const claims = try a.alloc([]const QM31, h);
            for (claims, proof.claims) |*dst, src| dst.* = try a.dupe(QM31, src);
            const terminal_coeffs = try a.dupe(QM31, proof.terminal_ordered_coeffs);
            const forwarded = try a.alloc([]QM31, h);
            const terminal_copy = try a.dupe(QM31, terminal_coeffs);
            var terminal = line.LinePoly.fromOrderedCoefficients(terminal_copy);
            defer terminal.deinit(a);
            const terminal_domain = line.LineDomain.fromCircleDomain(
                canonic.CanonicCoset.new(proof.profile.source.largest_log_size -
                    @as(u32, @intCast(h - 1))).circleDomain(),
            );
            for (0..h) |height| {
                forwarded[height] = try a.alloc(QM31, raw.len);
                for (raw, 0..) |position, query| {
                    forwarded[height][query] = if (height + 1 < h) blk: {
                        const selected = (position >> @intCast(height + 1)) & 1;
                        break :blk line_pairs[height][query * 2 + selected];
                    } else blk: {
                        const row = position >> @intCast(h);
                        const x = terminal_domain.at(utils.bitReverseIndex(row, terminal_domain.logSize()));
                        break :blk try terminal.evalAtPoint(a, QM31.fromBase(x));
                    };
                }
            }
            var relation = AcceptedRelation{
                .arena = arena,
                .arena_owner = allocator,
                .profile = proof.profile,
                .source_root = proof.source_root,
                .line_roots = roots,
                .sampled_point = sampled,
                .claims = claims,
                .batch_challenge = batch,
                .alphas = alphas,
                .raw_queries = raw,
                .source = opened,
                .line_pairs = line_pairs,
                .terminal_ordered_coeffs = terminal_coeffs,
                .forwarded = forwarded,
            };
            try relation.check(a);
            // Compare the full channel state, including the draw counter, so equal
            // digests alone cannot mask a replay schedule mismatch.
            if (!std.meta.eql(replay, staged))
                return error.TranscriptMismatch;
            channel.* = staged;
            return relation;
        }
    };
}
