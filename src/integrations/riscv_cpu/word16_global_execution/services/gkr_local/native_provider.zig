//! Actual Ethereum services source adapter. Survives owned MAIN take: reads only
//! existing narrow metadata, public program/endpoints and saved multiplicities.
//! Scratch is one row/tuple; no committed-column expansion or tuple planes.
const std = @import("std");
const core = @import("stwo_core");
const A = @import("stwo_riscv_frontend").rv64_air;
const B = A.word16_v1;
const M = core.fields.m31.M31;
const O = core.fields.om31.OM31;
const X = A.word16_execution;
const R = @import("../roster.zig");
const Frame = @import("frame.zig");
const F = @import("fractions.zig");
const Sink = @import("inputs.zig").RowSink;
const BaseSink = struct {
    target: *Sink,
    pub fn emit(self: *@This(), relation: F.Relation, tuple: anytype, weight: M) void {
        self.target.emitBase(relation, tuple, weight);
    }
};
fn count(value: u64) !M {
    if (value >= core.fields.m31.Modulus) return error.LocalGkrMultiplicityMass;
    return M.fromCanonical(@intCast(value));
}
fn payload(meta: anytype) [13]M {
    var out: [13]M = undefined;
    for (meta.payload, &out) |v, *d| d.* = M.fromCanonical(v);
    return out;
}
pub const Provider = struct {
    source: *const R.Sources,
    pub fn emit(self: Provider, instance: Frame.Instance, logical: usize, sink: *Sink) !void {
        if (logical >= try instance.rows()) return error.LocalGkrMetadataShape;
        var base_sink = BaseSink{ .target = sink };
        switch (instance.origin) {
            .dword => |index| {
                const src = &(self.source.ls_dword[index] orelse return error.MissingLocalGkrBridge);
                if (src.log_size != instance.row_log or instance.terms != @import("dword_projection.zig").LOCAL_TERMS or src.metadata.len != try instance.rows()) return error.LocalGkrMetadataShape;
                @import("dword_projection.zig").emitMetadata(src.metadata[logical], sink);
            },
            .sponge => |kind| switch (kind) {
                inline else => |k| {
                    const src = &(self.source.sponge[@intFromEnum(k)] orelse return error.MissingLocalGkrBridge);
                    if (src.kind != k or src.log_size != instance.row_log or instance.terms != @import("sponge_projection.zig").localTerms(k)) return error.LocalGkrMetadataShape;
                    const fixed = [_]M{ M.fromCanonical(@intCast(logical)), M.fromCanonical(@intFromBool(logical == 0)), M.fromCanonical(@intFromBool(logical + 1 == src.size())) };
                    @import("sponge_projection.zig").emitLocalFor(M, k, &fixed, &src.plan.row(k, logical, src.first_id), src.first_id, &base_sink);
                },
            },
            .bulk => |kind| switch (kind) {
                inline else => |k| {
                    const src = &(self.source.bulk[@intFromEnum(k)] orelse return error.MissingLocalGkrBridge);
                    if (src.kind != k or src.log_size != instance.row_log or instance.terms != @import("bulk_projection.zig").localTerms(k)) return error.LocalGkrMetadataShape;
                    if (src.fixed.len != src.size() * A.crypto.bulk_memory.layout.fixedWidth(k)) return error.LocalGkrMetadataRetired;
                    var fixed: [A.crypto.bulk_memory.layout.fixedWidth(k)]M = undefined;
                    const physical = A.crypto.bulk_memory.source.physical(logical, src.log_size);
                    for (&fixed, 0..) |*v, c| v.* = src.fixed[c * src.size() + physical];
                    @import("bulk_projection.zig").emitLocalFor(M, k, &fixed, &src.row(k, logical), &base_sink);
                },
            },
            .core => |role| try self.emitCore(role, logical, sink),
            .bridge => |family| switch (family) {
                .keccak => {
                    const s = self.source.keccak orelse return error.MissingLocalGkrBridge;
                    const lane = logical % 25;
                    const index = logical / 25;
                    const m = A.crypto.keccak.word16_bridge.source.nativeRow(if (index < s.calls.len) s.calls[index] else null, lane, s.first_id + @as(u32, @intCast(index)));
                    var f = [_]M{M.zero()} ** 6;
                    f[4] = M.fromCanonical(@intFromBool(lane == 0));
                    F.keccakBridgeFor(M, &f, &m, &base_sink);
                },
                else => {
                    const s = (switch (family) {
                        .add => self.source.add,
                        .double => self.source.double,
                        .sha256 => self.source.sha256,
                        .arith256_mod => self.source.arith256_mod,
                        else => self.source.curves[@intFromEnum(family) - @import("../types.zig").FIRST_CURVE],
                    }) orelse return error.MissingLocalGkrBridge;
                    const coords = A.crypto.secp256k1.word16_bridge.types.coordinates(s.kind);
                    const coord = logical % coords;
                    const index = logical / coords;
                    const m = A.crypto.secp256k1.word16_bridge.source.nativeRow(s.kind, if (index < s.calls.len) s.calls[index] else null, coord, s.first_id + @as(u32, @intCast(index)));
                    var f = [_]M{M.zero()} ** 8;
                    f[4] = M.fromCanonical(@intFromBool(coord == 0));
                    F.secpBridgeFor(M, s.kind, &f, &m, &base_sink);
                },
            },
        }
    }
    fn emitCore(self: Provider, role: @import("../../../word16_execution/geometry.zig").Role, i: usize, sink: *Sink) !void {
        const s = &self.source.core;
        var base_sink = BaseSink{ .target = sink };
        switch (role) {
            .cpu => try @import("pair_projection.zig").emitCpuMetadata(&s.cpu, i, s.cpu.u8_pairs, sink),
            .rom => sink.emitBase(.rom, try s.rom.program.tupleAt(i), (try count(s.rom.counts[X.layout.physical(i, s.rom.program.log_size)])).neg()),
            .boundary => {
                if (i >= 32) return error.LocalGkrMetadataShape;
                var before: [6]M = undefined;
                var after: [6]M = undefined;
                before[0] = M.fromCanonical(@intCast(i));
                after[0] = before[0];
                const public = s.cpu.public;
                for (0..4) |limb| {
                    const shift: u6 = @intCast(16 * limb);
                    before[1 + limb] = M.fromCanonical(@as(u16, @truncate(public.initial_registers[i] >> shift)));
                    after[1 + limb] = M.fromCanonical(@as(u16, @truncate(public.final_registers[i] >> shift)));
                }
                before[5] = M.zero();
                after[5] = M.fromCanonical(public.register_clocks[i]);
                sink.emitBase(.register, before, M.one().neg());
                sink.emitBase(.register, after, M.one());
            },
            .alu, .alu_tail => {
                const source = if (role == .alu) &s.alu else &(s.tails.alu orelse return error.MissingLocalGkrTail);
                const meta = source.metadata[i];
                for (meta.range_indices) |value| sink.emitBase(.range16, [1]M{M.fromCanonical(value)}, M.one());
                sink.emitBase(.function, payload(meta), (try count(meta.multiplicity())).neg());
            },
            .binary, .binary_tail => {
                const source = if (role == .binary) &s.binary else &(s.tails.binary orelse return error.MissingLocalGkrTail);
                const meta = source.metadata[i];
                for (meta.and_indices) |index| {
                    const tuple = A.providers.tables.Kind.byte_and.tupleAt(index);
                    var v: [3]M = undefined;
                    for (tuple[0..3], &v) |value, *d| d.* = M.fromCanonical(value);
                    sink.emitBase(.and_, v, M.one());
                }
                sink.emitBase(.function, payload(meta), (try count(meta.multiplicity())).neg());
            },
            .shift, .shift_tail => {
                const source = if (role == .shift) &s.shift else &(s.tails.shift orelse return error.MissingLocalGkrTail);
                const meta = source.metadata[i];
                const Support = B.shift_word_packed_experiment.source.InteractionSupport;
                for (0..5) |query| {
                    const tuple = B.shift_word_experiment.table.tupleAt(Support.table(meta, query));
                    var v: [6]M = undefined;
                    for (tuple, &v) |value, *d| d.* = M.fromCanonical(value);
                    sink.emitBase(.shift, v, M.one());
                }
                for (0..5) |query| sink.emitBase(.range16, [1]M{M.fromCanonical(Support.range(meta, query))}, M.one());
                sink.emitBase(.function, payload(meta), (try count(meta.multiplicity())).neg());
            },
            .jalr => F.jalrFor(M, &s.jalr.rowValues(i), &base_sink),
            .division => {
                const q = s.division.metadata[i].queryRow();
                var row: [q.len]M = undefined;
                for (q, &row) |v, *d| d.* = v.toM31Array()[0];
                F.divisionFor(M, &row, &base_sink);
            },
            .multiplication => {
                const L = A.arithmetic.multiplication.layout;
                const row = if (i < s.multiplication.request_metadata.len) try A.arithmetic.multiplication.trace.row(s.multiplication.request_metadata[i]) else [_]M{M.zero()} ** L.MAIN;
                F.multiplicationFor(M, &row, &base_sink);
            },
            .ls, .ls_tail => {
                const source = if (role == .ls) &s.memory.ls else &(s.memory.ls_tail orelse return error.MissingLocalGkrTail);
                const meta = source.metadata[i];
                sink.emitBase(.owner, meta.ownerTuple(), meta.active().neg());
                for (A.memory.load_store_v2.layout.U16_CACHE) |index| sink.emitBase(.range16, [1]M{M.fromCanonical(meta.range16[index])}, M.one());
                for (A.memory.load_store_v2.layout.U8_CACHE) |index| sink.emitBase(.range8, [1]M{M.fromCanonical(meta.range8[index])}, M.one());
                const index = meta.selectionIndex();
                if (index >= A.memory.load_store_v1.selection.SIZE) return error.LocalGkrMetadataShape;
                const tuple = A.memory.load_store_v1.selection.fact(index);
                var v: [5]M = undefined;
                for (tuple, &v) |value, *d| d.* = M.fromCanonical(value);
                sink.emitBase(.selection, v, M.one());
            },
            .range16 => sink.emitBase(.range16, [1]M{M.fromCanonical(@intCast(i))}, (try count(s.range16.counts[i])).neg()),
            .range8 => sink.emitBase(.range8, [1]M{M.fromCanonical(@intCast(i))}, (try count(s.range8.counts[i])).neg()),
            .and_table => {
                var n = s.binary.and_counts[i] + (if (s.tails.binary) |tail| tail.and_counts[i] else 0);
                for (self.source.sponge) |maybe| if (maybe) |src| {
                    n += src.counts_and[i];
                };
                try @import("pair_projection.zig").emitAndMetadata(i, n, s.and_table.pair_counts, s.cpu.u8_pairs, sink);
            },
            .shift_table => for (0..16) |lane| {
                const at = 16 * i + lane;
                const tuple = B.shift_word_experiment.table.tupleAt(at);
                var v: [6]M = undefined;
                for (tuple, &v) |value, *d| d.* = M.fromCanonical(value);
                const n = s.shift.shift_counts[at] + (if (s.tails.shift) |tail| tail.shift_counts[at] else 0);
                sink.emitBase(.shift, v, (try count(n)).neg());
            },
            .selection => for (0..2) |parity| {
                const at = 2 * i + parity;
                const tuple = A.memory.load_store_v1.selection.fact(at);
                var v: [5]M = undefined;
                for (tuple, &v) |value, *d| d.* = M.fromCanonical(value);
                sink.emitBase(.selection, v, (try count(s.memory.selection.counts[at])).neg());
            },
            .initial, .terminal => return error.GlobalOnlyRoleHasNoLocalGkr,
        }
    }
};
