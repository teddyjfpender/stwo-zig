//! Field-parametric B5CF row algebra. Native QM31 and symbolic recursion use
//! these same identities; normalization is an explicit public scalar input.
const std = @import("std");
const core = @import("stwo_core");
const M = core.fields.m31.M31;
const Access = @import("block_execution_access_bridge_v2.zig");
const Integer = @import("block_execution_integer_algebra_v1.zig");
const Entries = @import("../air/lookups/opcode_entries.zig");
const Clock = @import("../air/clock_update_interaction.zig");
const Program = @import("block_v5_program_request_source_v1.zig");
const Relation = @import("../air/lang/relation.zig");
pub const BYTE_COUNT: usize = 28;
pub const RANGE_COUNT: usize = 7;
pub const INTERACTION_COUNT: usize = 9 + 4 * RANGE_COUNT + 12;
pub const CONSTRAINT_COUNT: usize = Integer.RESIDUAL_COUNT + 3 + RANGE_COUNT + 3;

pub fn Algebra(comptime S: type) type {
    return struct {
        pub const Integers = Integer.Algebra(S);
        pub const ProjectionPair = struct {
            numerators: [2]S = .{ S.zero(), S.zero() },
            denominators: [2]S = .{ S.one(), S.one() },
            entry_count: u8,
            pub fn numerator(self: @This()) S {
                return self.numerators[0].mul(self.denominators[1]).add(self.numerators[1].mul(self.denominators[0]));
            }
            pub fn denominator(self: @This()) S {
                return self.denominators[0].mul(self.denominators[1]);
            }
        };
        /// Replays the original typed opcode/clock declarations. The admitted
        /// slot chooses exact original entry ordinals and signed partitions.
        pub fn projection(slot: anytype, main: []const S, relations: anytype) !ProjectionPair {
            if (main.len != slot.width) return error.InvalidV5FusedProjectionSlot;
            return switch (slot.kind) {
                .program => |family| blk: {
                    const request = try Program.fromCommittedOpcodeMain(S, family, main);
                    const denominator = try combine(relations.get(.program_access), &request.tuple);
                    break :blk .{ .entry_count = 1, .numerators = .{ request.numerator, S.zero() }, .denominators = .{ denominator, S.one() } };
                },
                .lookup => |lookup| lookupProjection(lookup, main, relations),
            };
        }
        pub fn lookupProjection(slot: anytype, main: []const S, relations: anytype) !ProjectionPair {
            if (main.len != slot.width or slot.entry_count == 0 or slot.entry_count > 2) return error.InvalidV5LookupRequestSlot;
            const list = switch (slot.source) {
                .opcode => |family| try Entries.Entries(S).fromMain(family, main),
                .clock => Clock.orderedEntriesGeneric(S, try Clock.RowFor(S).fromMain(main)),
            };
            var pair = ProjectionPair{ .entry_count = slot.entry_count };
            for (slot.entries[0..slot.entry_count], 0..) |index, at| {
                if (index >= list.len) return error.InvalidV5LookupRequestSlot;
                const entry = list.entries[index];
                const domain = try relationDomain(entry.domain);
                const memory = entry.domain == .memory_access;
                const clock = std.meta.activeTag(slot.source) == .clock;
                const partition_matches = if (memory)
                    (if (clock) slot.partition == .clock_memory_access or slot.partition == .register_clock_memory_access else slot.partition == .register_memory_access)
                else switch (entry.domain) {
                    .registers_state => slot.partition == .registers_state,
                    .bitwise => slot.partition == .bitwise,
                    .range_check_20 => slot.partition == .range_check_20,
                    .range_check_8_11 => slot.partition == .range_check_8_11,
                    .range_check_8_8_4 => slot.partition == .range_check_8_8_4,
                    .range_check_8_8 => slot.partition == .range_check_8_8,
                    .range_check_m31 => slot.partition == .range_check_m31,
                    else => false,
                };
                const element = relations.get(domain);
                if (!partition_matches or entry.arity != element.arity) return error.InvalidV5LookupRequestSlot;
                pair.numerators[at] = entry.numerator;
                if (memory and slot.register_custody_mode == 1) {
                    const weight = if (slot.partition == .clock_memory_access) entry.values[0] else S.one().sub(entry.values[0]);
                    pair.numerators[at] = pair.numerators[at].mul(weight);
                }
                pair.denominators[at] = try combine(element, entry.values[0..entry.arity]);
            }
            return pair;
        }
        pub fn activity(slot: anytype, main: []const S) !S {
            if (main.len != slot.width) return error.InvalidCapacityFusedActivitySource;
            return switch (slot.kind) {
                .program => |family| opcodeActivity(family, main),
                .lookup => |lookup| switch (lookup.source) {
                    .opcode => |family| opcodeActivity(family, main),
                    .clock => if (main.len == Clock.N_MAIN_COLUMNS) main[0] else error.InvalidCapacityFusedActivitySource,
                },
            };
        }
        pub fn opcodeActivity(family: anytype, main: []const S) !S {
            const list = try Entries.Entries(S).fromMain(family, main);
            var found: ?S = null;
            for (list.entries[0..list.len]) |entry| if (entry.domain == .program_access) {
                if (found != null or entry.role != .request or entry.arity != 5) return error.InvalidCapacityFusedActivitySource;
                found = entry.numerator;
            };
            return found orelse error.InvalidCapacityFusedActivitySource;
        }
        pub fn projectionResidual(pair: ProjectionPair, current: [4]S, previous: [4]S, normalized_sum: S) S {
            return secure(&current, 0).sub(secure(&previous, 0)).add(normalized_sum).mul(pair.denominator()).sub(pair.numerator());
        }
        pub fn bytesAtPoint(pair: Access.Pair(S), witness: Integers.Witness) [BYTE_COUNT]S {
            var bytes: [BYTE_COUNT]S = undefined;
            var cursor: usize = 0;
            inline for (.{ witness.word_index, witness.byte_address, witness.local_clock, witness.global_clock, pair.before, pair.after }) |part| {
                @memcpy(bytes[cursor..][0..part.len], &part);
                cursor += part.len;
            }
            return bytes;
        }
        pub fn packedTransition(bytes: [21]S) [11]S {
            var tuple: [11]S = undefined;
            tuple[0] = bytes[0];
            const radix = if (S == M) M.fromCanonical(256) else S.fromBase(M.fromCanonical(256));
            for (0..10) |i| tuple[i + 1] = bytes[1 + 2 * i].add(bytes[2 + 2 * i].mul(radix));
            return tuple;
        }
        pub fn rangeConstraints(element: anytype, active: S, bytes: [BYTE_COUNT]S, current: [RANGE_COUNT]S, previous: [RANGE_COUNT]S, normalized: [RANGE_COUNT]S) ![RANGE_COUNT]S {
            var result: [RANGE_COUNT]S = undefined;
            for (&result, 0..) |*out, batch| {
                const left = try combine(element, &.{ bytes[4 * batch], bytes[4 * batch + 1] });
                const right = try combine(element, &.{ bytes[4 * batch + 2], bytes[4 * batch + 3] });
                const d1 = active.mul(left).add(S.one().sub(active));
                const d2 = active.mul(right).add(S.one().sub(active));
                out.* = current[batch].sub(previous[batch]).add(normalized[batch]).mul(d1).mul(d2).sub(active.mul(d1.add(d2)));
            }
            return result;
        }
        pub fn universalConstraints(element: anytype, pair: Access.Pair(S), consume_term: S, emit_term: S, prefix: S, previous_prefix: S, normalized: S) ![3]S {
            const prior_clock = pair.consume_clock orelse return error.MissingNativeConsumeClock;
            const consumed = .{ pair.space, pair.source_address, prior_clock } ++ pair.before;
            const emitted = .{ pair.space, pair.source_address, pair.local_clock } ++ pair.after;
            return universalPointConstraints(element, pair.active, consumed, emitted, consume_term, emit_term, prefix, previous_prefix, normalized);
        }
        pub fn universalPointConstraints(element: anytype, active: S, consumed: [7]S, emitted: [7]S, consume_term: S, emit_term: S, prefix: S, previous_prefix: S, normalized: S) ![3]S {
            const consume_denominator = active.mul(try combine(element, &consumed)).add(S.one().sub(active));
            const emit_denominator = active.mul(try combine(element, &emitted)).add(S.one().sub(active));
            return .{ consume_denominator.mul(consume_term).sub(active), emit_denominator.mul(emit_term).sub(active), prefix.sub(previous_prefix).add(normalized).sub(consume_term).add(emit_term) };
        }
        pub fn transitionConstraints(active: S, raw: S, term: S, prefix: S, previous_prefix: S, count_prefix: S, previous_count_prefix: S, normalized_sum: S, normalized_count: S) [3]S {
            const denominator = active.mul(raw).add(S.one().sub(active));
            return .{ denominator.mul(term).sub(active), prefix.sub(previous_prefix).add(normalized_sum).sub(term), count_prefix.sub(previous_count_prefix).add(normalized_count).sub(active) };
        }

        /// Exact native order: integer55, transition3, byte7, opposite-memory3.
        pub fn access(pair: Access.Pair(S), witness_columns: [Integer.COLUMN_COUNT]S, current: [INTERACTION_COUNT]S, previous: [INTERACTION_COUNT]S, clock_bytes: [8]S, transition: anytype, universal: anytype, normalized_transition: S, normalized_count: S, normalized_range: [RANGE_COUNT]S, normalized_universal: S) ![CONSTRAINT_COUNT]S {
            const witness = Integers.Witness.fromColumns(witness_columns);
            const direct = Integers.constraints(pair, witness, clock_bytes);
            if (direct.len != Integer.RESIDUAL_COUNT) return error.InvalidExecutionBridgeConstraintCount;
            var result: [CONSTRAINT_COUNT]S = undefined;
            @memcpy(result[0..direct.len], direct.values[0..direct.len]);
            const raw = try combine(transition, packedTransition(Integers.transitionAtPoint(pair, witness)));
            @memcpy(result[55..58], &transitionConstraints(pair.active, raw, secure(&current, 0), secure(&current, 4), secure(&previous, 4), current[8], previous[8], normalized_transition, normalized_count));
            var ranges: [RANGE_COUNT]S = undefined;
            var priors: [RANGE_COUNT]S = undefined;
            for (&ranges, &priors, 0..) |*out, *prior, i| {
                out.* = secure(&current, 9 + 4 * i);
                prior.* = secure(&previous, 9 + 4 * i);
            }
            @memcpy(result[58..65], &(try rangeConstraints(universal.get(.range_check_8_8), pair.active, bytesAtPoint(pair, witness), ranges, priors, normalized_range)));
            @memcpy(result[65..68], &(try universalConstraints(universal.get(.memory_access), pair, secure(&current, 37), secure(&current, 41), secure(&current, 45), secure(&previous, 45), normalized_universal)));
            return result;
        }
        fn combine(element: anytype, values: anytype) !S {
            const result = element.combineSecure(values);
            return if (comptime @typeInfo(@TypeOf(result)) == .error_union) try result else result;
        }
        fn secure(values: []const S, at: usize) S {
            return S.fromPartialEvals(.{ values[at], values[at + 1], values[at + 2], values[at + 3] });
        }
    };
}
fn relationDomain(domain: @import("../air/lookups/entry.zig").Domain) !Relation.Domain {
    return switch (domain) {
        .registers_state => .registers_state,
        .memory_access => .memory_access,
        .bitwise => .bitwise,
        .range_check_20 => .range_check_20,
        .range_check_8_11 => .range_check_8_11,
        .range_check_8_8_4 => .range_check_8_8_4,
        .range_check_8_8 => .range_check_8_8,
        .range_check_m31 => .range_check_m31,
        else => error.InvalidV5LookupRequestSlot,
    };
}
