//! Version-four byte representation. The verifier derives this plan from public
//! opcode support; witness values never choose physical columns. Byte positions
//! consumed by bit equations retain eight bits. Every other byte is committed
//! directly and belongs to the shared byte-table LogUp relation.
const std = @import("std");
const core = @import("stwo_core");
const M = core.fields.m31.M31;
const E = @import("evaluation.zig");
const L = E.L;
const Q = E.Q;
const P = @import("projection.zig");
const ops = @import("operations.zig");
pub const omitted = std.math.maxInt(u16);
pub const derived = omitted - 1;
pub const Plan = struct {
    control_policy: @import("control_policy.zig").Policy = .bytes_v1,
    state_policy: @import("state_policy.zig").Policy = .inverse_v1,
    execution_profile: @import("../execution_profile.zig").Profile = .rv64im,
    arithmetic_policy: @import("delegations/division/policy.zig").Policy = .inline_v4,
    allowed_opcodes: [L.fixed.OPCODES]bool = @splat(true),
    byte_bits: [L.WORDS][8]bool = @splat(@splat(false)),
    support: L.Support,
    main_map: [L.MAIN]u16 = @splat(omitted),
    main_sources: [L.MAIN]u16 = undefined,
    main_count: usize = 0,
    range_sources: [L.WORDS * 8 + 16 + 24]u16 = undefined,
    range_count: usize = 0,
    compact_product_carries: bool = false,
    wide_clocks: bool = false,
    byte_operations: bool = false,
    byte_bitwise: bool = false,
    and_start: usize = 0,
    shift_outputs: usize = 0,
    shift_selectors: usize = 0,
    shift_amount: usize = 0,

    /// Path-independent full-execution profile. Derive every omission from the
    /// admitted public opcode set; the full component constrains all forbidden
    /// selectors to zero. Register-zero enables remain conservatively live.
    pub fn stateInteractionCount(self: *const Plan) usize {
        return @import("state_policy.zig").interactionCount(self.state_policy);
    }
    /// Select only after the complete byte representation has been built.
    /// V3 carries an explicit global-state closure obligation: canonical initial
    /// sources and writes plus bounded strict clocks authenticate read bytes.
    /// Rebuilding also restores the original queries when returning to v1/v2.
    pub fn setStatePolicy(self: *Plan, policy: @import("state_policy.zig").Policy) void {
        std.debug.assert(self.byte_operations and self.wide_clocks);
        self.state_policy = policy;
        self.range_count = 0;
        for (0..L.WORDS) |w| {
            if (!self.support.words[w]) continue;
            const word: L.Word = @enumFromInt(w);
            if ((word == .a and self.support.shifts) or (self.byte_bitwise and (word == .a or word == .rhs))) continue;
            if (@import("state_policy.zig").derivesStateBytes(policy) and (word == .b or word == .previous_rd or word == .memory_after)) continue;
            for (0..8) |i| if (!self.byte_bits[w][i]) {
                self.range_sources[self.range_count] = self.main_map[L.byte(word, i)];
                self.range_count += 1;
            };
        }
        if (self.compact_product_carries) for (0..16) |i| {
            self.range_sources[self.range_count] = self.main_map[L.productCarry(i) + 1];
            self.range_count += 1;
        };
        self.appendClockRanges();
    }
    pub fn fromOpcodes(opcodes: []const E.O) Plan {
        var legacy: P.Projection = undefined;
        legacy.support = .{ .words = @splat(false), .carries = @splat(false), .slots = @splat(false), .shifts = false, .product = false };
        for (opcodes) |op| {
            const effects = @import("../decode.zig").effects(op);
            const slots = [4]bool{ effects.reads_rs1, effects.reads_rs2, effects.writes_rd, effects.memory_width != 0 };
            for (&legacy.support.slots, slots) |*supported, enabled| supported.* = supported.* or enabled;
            for (&legacy.support.words, 0..) |*supported, w| supported.* = supported.* or ops.wordActive(@enumFromInt(w), op, slots);
            for (&legacy.support.carries, 0..) |*supported, c| supported.* = supported.* or ops.carryActive(@enumFromInt(c / 8), c % 8, op);
            legacy.support.shifts = legacy.support.shifts or ops.shift(op);
            legacy.support.product = legacy.support.product or ops.mul(op) or ops.div(op);
        }
        legacy.main_map = @splat(0);
        for (legacy.support.carries, 0..) |supported, c| if (!supported) {
            legacy.main_map[L.carry_start + c] = omitted;
        };
        for (0..16) |i| legacy.main_map[L.productCarry(i)] = derived;
        if (!legacy.support.product) for (L.product_carry_start..L.shift_start) |c| {
            legacy.main_map[c] = omitted;
        };
        if (!legacy.support.shifts) for (L.shift_start..L.clock_start) |c| {
            legacy.main_map[c] = omitted;
        };
        for (0..4) |slot| {
            legacy.main_map[L.previousClock(slot)] = derived;
            legacy.main_map[L.gap(slot)] = derived;
            if (!legacy.support.slots[slot]) for (L.previousClock(slot)..L.gap(slot) + 1 + L.CLOCK_BITS) |c| {
                legacy.main_map[c] = omitted;
            };
        }
        var plan = Plan.init(&legacy, opcodes);
        plan.wideClocks();
        plan.compactProductCarries();
        plan.byteOperations(opcodes);
        return plan;
    }

    /// Explicit public arithmetic-provider policy; legacy callers remain inline.
    /// The service plan requires a CPU typed bus closed against its provider.
    pub fn fromOpcodesWithPolicy(opcodes: []const E.O, policy: @import("delegations/division/policy.zig").Policy) Plan {
        return switch (policy) {
            .inline_v4 => fromOpcodes(opcodes),
            .division_service_v2 => @import("delegations/division/cpu.zig").plan(opcodes),
            .division_multiplication_services_v3 => @import("delegations/division/cpu.zig").planWithMultiplication(opcodes, .rv64im),
        };
    }

    /// Concrete service ABI builder; it cannot imply an unclosed inline CPU.
    pub fn fromOpcodesWithProfiles(opcodes: []const E.O, arithmetic: @import("delegations/division/policy.zig").Policy, execution: @import("../execution_profile.zig").Profile) !Plan {
        if (execution == .rv64im) return fromOpcodesWithPolicy(opcodes, arithmetic);
        if (execution != .keccak_service_v1 and execution != .ethereum_services_v1 and execution != .ethereum_services_v2) return error.UnsupportedRv64ServiceExecutionProfile;
        return switch (arithmetic) {
            .division_service_v2 => @import("delegations/division/cpu.zig").planWithProfile(opcodes, execution),
            .division_multiplication_services_v3 => @import("delegations/division/cpu.zig").planWithMultiplication(opcodes, execution),
            else => error.UnsupportedRv64ServiceArithmetic,
        };
    }

    /// Borrows the existing public projection only during construction.
    pub fn init(projection: *const P.Projection, opcodes: []const E.O) Plan {
        var self: Plan = .{ .support = projection.support };
        self.allowed_opcodes = @splat(false);
        for (opcodes) |op| {
            self.allowed_opcodes[@intFromEnum(op)] = true;
            switch (op) {
                .AND, .ANDI, .OR, .ORI, .XOR, .XORI => {
                    self.markAll(.a);
                    self.markAll(.rhs);
                    self.markAll(.result);
                },
                .SLT, .SLTI, .BLT, .BGE => {
                    self.mark(.a, 7);
                    self.mark(.rhs, 7);
                },
                .MULH, .MULHSU => self.mark(.a, 7),
                else => {},
            }
            if (op == .MULH) self.mark(.b, 7);
            if (ops.word(op)) self.mark(.result, 3);
            if (ops.signedDiv(op)) {
                const i: usize = if (ops.word(op)) 3 else 7;
                self.mark(.a, i);
                self.mark(.b, i);
            }
            if (ops.address(op)) self.mark(.address, 0);
            // Load equations mention even forbidden offsets, multiplied by a
            // constrained zero selector. Keeping every referenced sign byte
            // preserves the original polynomial at arbitrary OODS points.
            if (op == .LB or op == .LH or op == .LW) {
                const width: usize = @import("../decode.zig").effects(op).memory_width;
                for (width - 1..8) |i| self.mark(.memory_before, i);
            }
            if (ops.shift(op)) {
                // Existing barrel equations include all source/result bits,
                // including the zero-gated upper half for W operations.
                self.markAll(.a);
                self.markAll(.result);
                self.mark(.rhs, 0);
            }
        }
        for (0..L.WORDS) |w| {
            if (!self.support.words[w]) continue;
            const word: L.Word = @enumFromInt(w);
            for (0..8) |i| {
                if (self.byte_bits[w][i]) {
                    self.main_map[L.byte(word, i)] = derived;
                    for (0..8) |j| self.keep(L.bit(word, i * 8 + j));
                } else {
                    self.keep(L.byte(word, i));
                    self.range_sources[self.range_count] = self.main_map[L.byte(word, i)];
                    self.range_count += 1;
                }
            }
        }
        // Retain scalar range encodings and all existing auxiliary support.
        for (L.carry_start..L.MAIN) |c| {
            const entry = projection.main_map[c];
            if (entry == omitted) continue;
            if (entry == derived) self.main_map[c] = derived else self.keep(c);
        }
        return self;
    }

    /// Must be selected by the profile, equally at prover and verifier. Each
    /// low-byte source occupies the former bit-zero slot; only the dedicated
    /// compact range evaluator may consume this representation.
    pub fn compactProductCarries(self: *Plan) void {
        std.debug.assert(!self.byte_operations);
        if (self.compact_product_carries or !self.support.product) return;
        self.compact_product_carries = true;
        for (0..16) |i| {
            const start = L.productCarry(i);
            for (2..9) |j| self.main_map[start + j] = omitted;
        }
        self.main_count = 0;
        for (&self.main_map, 0..) |*entry, c| {
            if (entry.* == omitted or entry.* == derived) continue;
            entry.* = @intCast(self.main_count);
            self.main_sources[self.main_count] = @intCast(c);
            self.main_count += 1;
        }
        self.range_count = 0;
        for (0..L.WORDS) |w| {
            if (!self.support.words[w]) continue;
            const word: L.Word = @enumFromInt(w);
            for (0..8) |i| if (!self.byte_bits[w][i]) {
                self.range_sources[self.range_count] = self.main_map[L.byte(word, i)];
                self.range_count += 1;
            };
        }
        for (0..16) |i| {
            self.range_sources[self.range_count] = self.main_map[L.productCarry(i) + 1];
            self.range_count += 1;
        }
        self.appendClockRanges();
    }

    /// A 24-bit integer clock and gap have sum below 2^25 < M31. Consequently
    /// prev+gap+1=tick establishes strict ordinary integer order, without wrap.
    /// Select before byteOperations; old profiles retain their twelve bits.
    pub fn wideClocks(self: *Plan) void {
        std.debug.assert(!self.byte_operations);
        if (self.wide_clocks) return;
        self.wide_clocks = true;
        for (0..4) |slot| {
            if (!self.support.slots[slot]) continue;
            for ([_]usize{ L.previousClock(slot), L.gap(slot) }) |start| {
                self.main_map[start] = derived;
                for (1..L.CLOCK_BITS + 1) |j| self.main_map[start + j] = if (j <= 3) 0 else omitted;
            }
        }
        self.main_count = 0;
        for (&self.main_map, 0..) |*entry, c| {
            if (entry.* == omitted or entry.* == derived) continue;
            entry.* = @intCast(self.main_count);
            self.main_sources[self.main_count] = @intCast(c);
            self.main_count += 1;
        }
        self.range_count = 0;
        for (0..L.WORDS) |w| {
            if (!self.support.words[w]) continue;
            const word: L.Word = @enumFromInt(w);
            for (0..8) |i| if (!self.byte_bits[w][i]) {
                self.range_sources[self.range_count] = self.main_map[L.byte(word, i)];
                self.range_count += 1;
            };
        }
        if (self.compact_product_carries) for (0..16) |i| {
            self.range_sources[self.range_count] = self.main_map[L.productCarry(i) + 1];
            self.range_count += 1;
        };
        self.appendClockRanges();
    }
    fn appendClockRanges(self: *Plan) void {
        if (!self.wide_clocks) return;
        for (0..4) |slot| {
            if (!self.support.slots[slot]) continue;
            for ([_]usize{ L.previousClock(slot), L.gap(slot) }) |start| for (1..4) |j| {
                self.range_sources[self.range_count] = self.main_map[start + j];
                self.range_count += 1;
            };
        }
    }

    /// Select after compactProductCarries. Appended sources have identifiers
    /// beyond L.MAIN and are projected by projectValue, never read as row slots.
    pub fn byteOperations(self: *Plan, opcodes: []const E.O) void {
        std.debug.assert(!self.byte_operations);
        self.byte_operations = true;
        for ([_]L.Word{ .a, .rhs, .result }) |word| self.byte_bits[@intFromEnum(word)] = @splat(false);
        for (opcodes) |op| {
            switch (op) {
                .AND, .ANDI, .OR, .ORI, .XOR, .XORI => self.byte_bitwise = true,
                .SLT, .SLTI, .BLT, .BGE => {
                    self.mark(.a, 7);
                    self.mark(.rhs, 7);
                },
                .MULH, .MULHSU => self.mark(.a, 7),
                else => {},
            }
            if (ops.word(op)) self.mark(.result, 3);
            if (ops.signedDiv(op)) self.mark(.a, if (ops.word(op)) 3 else 7);
            if (ops.shift(op)) self.mark(.rhs, 0);
            if (op == .SRA or op == .SRAI) self.mark(.a, 7);
            if (op == .SRAW or op == .SRAIW) self.mark(.a, 3);
        }
        for (0..L.WORDS) |w| {
            const word: L.Word = @enumFromInt(w);
            for (0..L.WORD_COLUMNS) |i| self.main_map[w * L.WORD_COLUMNS + i] = omitted;
            if (!self.support.words[w]) continue;
            for (0..8) |i| {
                self.main_map[L.byte(word, i)] = if (self.byte_bits[w][i]) derived else 0;
                if (self.byte_bits[w][i]) for (0..8) |j| {
                    self.main_map[L.bit(word, i * 8 + j)] = 0;
                };
            }
        }
        for (L.shift_start..L.clock_start) |c| self.main_map[c] = omitted;
        self.main_count = 0;
        for (&self.main_map, 0..) |*entry, c| {
            if (entry.* == omitted or entry.* == derived) continue;
            entry.* = @intCast(self.main_count);
            self.main_sources[self.main_count] = @intCast(c);
            self.main_count += 1;
        }
        self.and_start = self.main_count;
        if (self.byte_bitwise) for (0..8) |i| self.appendHelper(i);
        self.shift_outputs = self.main_count;
        if (self.support.shifts) for (0..36) |i| self.appendHelper(8 + i);
        self.shift_selectors = self.main_count;
        if (self.support.shifts) for (0..8) |i| self.appendHelper(44 + i);
        self.shift_amount = self.main_count;
        if (self.support.shifts) self.appendHelper(52);
        self.setStatePolicy(self.state_policy);
    }

    fn appendHelper(self: *Plan, helper: usize) void {
        self.main_sources[self.main_count] = @intCast(L.MAIN + helper);
        self.main_count += 1;
    }

    /// Projects one base-field witness cell. No allocation; original logical
    /// rows retain the legacy representation and can be released afterwards.
    pub fn projectValue(self: *const Plan, row: *const [L.MAIN]M, physical: usize) M {
        const source = self.main_sources[physical];
        if (source >= L.MAIN) {
            const helper = source - L.MAIN;
            if (helper < 8) return M.fromCanonical(row[L.byte(.a, helper)].v & row[L.byte(.rhs, helper)].v);
            const shift = row[L.byte(.rhs, 0)].v & 7;
            if (helper < 44) {
                const index = (helper - 8) / 4;
                const input = if (index == 8) 255 else row[L.byte(.a, index)].v;
                const tuple = @import("providers/tables.zig").Kind.byte_shift.tupleAt(input * 8 + shift);
                return M.fromCanonical(tuple[2 + (helper - 8) % 4]);
            }
            if (helper < 52) return M.fromCanonical(@intFromBool((row[L.byte(.rhs, 0)].v >> 3) & 7 == helper - 44));
            return M.fromCanonical(shift);
        }
        if (self.wide_clocks and source >= L.clock_start and source < L.offset_start) {
            const within_slot = (source - L.clock_start) % (2 + 2 * L.CLOCK_BITS);
            const start = if (within_slot < 1 + L.CLOCK_BITS) source - within_slot else source - (within_slot - (1 + L.CLOCK_BITS));
            const byte_index = source - start - 1;
            return M.fromCanonical((row[start].v >> @as(u5, @intCast(byte_index * 8))) & 255);
        }
        if (self.compact_product_carries and source >= L.product_carry_start and source < L.shift_start and (source - L.product_carry_start) % 12 == 1) {
            return M.fromCanonical(row[source - 1].v & 255);
        }
        return row[source];
    }

    fn mark(self: *Plan, word: L.Word, index: usize) void {
        self.byte_bits[@intFromEnum(word)][index] = true;
    }
    fn markAll(self: *Plan, word: L.Word) void {
        self.byte_bits[@intFromEnum(word)] = @splat(true);
    }
    fn keep(self: *Plan, logical: usize) void {
        self.main_map[logical] = @intCast(self.main_count);
        self.main_sources[self.main_count] = @intCast(logical);
        self.main_count += 1;
    }
    pub fn inflateMain(self: *const Plan, physical: []const Q) E.Main {
        var logical: E.Main = @splat(Q.zero());
        self.inflateInto(physical, &logical);
        return logical;
    }
    /// The destination must start at zero and remain attached to this immutable
    /// plan. Every live coordinate is overwritten; permanently omitted fields
    /// retain zero. Domain workers compile inflation() once and reuse its map.
    pub fn inflateInto(self: *const Plan, physical: []const Q, logical: *E.Main) void {
        const compiled = self.inflation();
        compiled.apply(physical, logical);
    }
    pub fn inflation(self: *const Plan) Inflation {
        var result = Inflation{ .physical_count = self.main_count, .product = self.support.product, .compact_product = self.compact_product_carries, .clock_slots = self.support.slots, .wide_clocks = self.wide_clocks };
        for (self.main_sources[0..self.main_count], 0..) |source, physical| {
            if (source >= L.MAIN) continue;
            result.sources[result.source_count] = .{ .logical = source, .physical = @intCast(physical) };
            result.source_count += 1;
            // Retain the polynomial of explicit custom projections as well as
            // canonical plans: a mapped auxiliary always requires derivation.
            if (source >= L.product_carry_start and source < L.shift_start) result.product = true;
            if (source >= L.clock_start and source < L.offset_start) result.clock_slots[(source - L.clock_start) / (2 + 2 * L.CLOCK_BITS)] = true;
        }
        for (0..L.WORDS) |w| {
            if (!self.support.words[w]) continue;
            const word: L.Word = @enumFromInt(w);
            for (0..8) |i| if (self.byte_bits[w][i]) {
                result.bytes[result.byte_count] = .{ .logical = @intCast(L.byte(word, i)), .first_bit = @intCast(L.bit(word, i * 8)) };
                result.byte_count += 1;
            };
        }
        return result;
    }
    /// Counts all physical rows, including padding. This is witness building;
    /// membership soundness comes from the polynomial LogUp closure.
    pub fn counts(self: *const Plan, columns: []const []const M) ![256]u64 {
        if (columns.len != self.main_count or columns.len == 0) return error.InvalidByteRangeGeometry;
        const size = columns[0].len;
        var result: [256]u64 = @splat(0);
        for (self.range_sources[0..self.range_count]) |source| {
            if (columns[source].len != size) return error.InvalidByteRangeGeometry;
            for (columns[source]) |value| {
                if (value.v >= 256) return error.InvalidByteRangeWitness;
                result[value.v] = try std.math.add(u64, result[value.v], 1);
            }
        }
        return result;
    }
};
fn reconstructGeneric(comptime F: type, values: *const E.MainFor(F), start: usize, count: usize) F {
    var result = F.zero();
    for (0..count) |i| result = result.add(values[start + i].mul(E.qFor(F, @as(u32, 1) << @as(u5, @intCast(i)))));
    return result;
}

/// Concrete projection execution metadata, derived only from the public plan.
/// It removes row-time support scans and does not own or cache witness values.
pub const Inflation = struct {
    /// Certifies the logical substitution performed by applyPrepared. General
    /// View evaluators must not accept this contract for independently supplied
    /// logical coordinates: only these substituted reconstruction slots are zero.
    pub fn ResultFor(comptime F: type) type {
        return struct { main: *const E.MainFor(F) };
    }
    pub const Result = ResultFor(Q);
    pub fn applyPrepared(self: *const Inflation, physical: []const Q, logical: *E.Main) Result {
        return self.applyPreparedGeneric(Q, physical, logical);
    }
    pub fn applyPreparedGeneric(self: *const Inflation, comptime F: type, physical: []const F, logical: *E.MainFor(F)) ResultFor(F) {
        self.applyGeneric(F, physical, logical);
        return .{ .main = logical };
    }
    const Source = struct { logical: u16, physical: u16 };
    const Byte = struct { logical: u16, first_bit: u16 };
    physical_count: usize,
    sources: [L.MAIN]Source = undefined,
    source_count: usize = 0,
    bytes: [L.WORDS * 8]Byte = undefined,
    byte_count: usize = 0,
    product: bool,
    compact_product: bool,
    clock_slots: [4]bool,
    wide_clocks: bool,
    pub fn apply(self: *const Inflation, physical: []const Q, logical: *E.Main) void {
        return self.applyGeneric(Q, physical, logical);
    }
    pub fn applyGeneric(self: *const Inflation, comptime F: type, physical: []const F, logical: *E.MainFor(F)) void {
        std.debug.assert(physical.len == self.physical_count);
        for (self.sources[0..self.source_count]) |source| logical[source.logical] = physical[source.physical];
        for (self.bytes[0..self.byte_count]) |byte| logical[byte.logical] = reconstructGeneric(F, logical, byte.first_bit, 8);
        if (self.product) for (0..16) |i| {
            const start = L.productCarry(i);
            logical[start] = if (self.compact_product)
                logical[start + 1].add(reconstructGeneric(F, logical, start + 9, 3).mul(E.qFor(F, 256)))
            else
                reconstructGeneric(F, logical, start + 1, 11);
        };
        for (self.clock_slots, 0..) |enabled, slot| {
            if (!enabled) continue;
            for ([_]usize{ L.previousClock(slot), L.gap(slot) }) |start| {
                logical[start] = if (self.wide_clocks)
                    logical[start + 1].add(logical[start + 2].mul(E.qFor(F, 256))).add(logical[start + 3].mul(E.qFor(F, 65536)))
                else
                    reconstructGeneric(F, logical, start + 1, L.CLOCK_BITS);
            }
        }
    }
};
