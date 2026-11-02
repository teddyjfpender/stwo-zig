//! LS-D64 arithmetic/local/global projection authority. Only aligned LD/SD;
//! admission and whole-execution RAM/OWNER closure remain mandatory elsewhere.
const core = @import("stwo_core");
const A = @import("stwo_riscv_frontend").rv64_air;
const E = A.evaluation;
const D = A.memory.load_store_dword;
const L = D.layout;
const M = core.fields.m31.M31;
pub const LOCAL_TERMS = L.LOCAL_FRACTIONS;
pub const RAM_TERMS = 2;
pub const MAIN_CONSTRAINTS = D.component.CONSTRAINTS - 3 - (L.LOCAL_PAIRS + 2);
pub const MAIN_SHAPE = A.main_only.authority.Shape{ .fixed = L.FIXED, .main = L.MAIN, .constraints = MAIN_CONSTRAINTS };
pub fn emitMainFor(comptime F: type, fixed: []const F, main: []const F, previous: []const F, count: E.CountFor(E.ConstFor(F)), nonempty: E.FlagFor(E.ConstFor(F)), out: *E.SinkFor(F)) !void {
    if (fixed.len != L.FIXED or main.len != L.MAIN or previous.len != L.MAIN) return error.InvalidDwordGkrShape;
    const logical = L.expandFor(F, main);
    var prior: [L.LOGICAL_MAIN]F = @splat(F.zero());
    prior[0] = previous[0];
    A.memory.load_store_v1.equations.emitLocalWithPublicFor(F, fixed, &logical, &prior, E.scalarFor(F, count), try E.nonzeroFor(F, count, nonempty), out);
}
pub fn emitLocalFor(comptime F: type, main: []const F, sink: anytype) void {
    const logical = L.expandFor(F, main);
    sink.emit(.owner, D.equations.ownerTuple(F, main), logical[0].neg());
    for (L.LOGICAL_U16) |c| sink.emit(.range16, [1]F{logical[c]}, F.one());
    for (L.LOGICAL_U8) |c| sink.emit(.range8, [1]F{logical[c]}, F.one());
}
pub fn emitGlobalFor(comptime F: type, main: []const F, sink: anytype) void {
    const logical = L.expandFor(F, main);
    const R = A.memory.closed_ram.equations;
    sink.emit(.ram, R.ramTuple(F, .transition, &logical, false), logical[0]);
    sink.emit(.ram, R.ramTuple(F, .transition, &logical, true), logical[0].neg());
}
/// Exactly seven queries, including unit range queries on padding. Metadata
/// owns the same82 bytes as LS32 and remains usable after MAIN adoption.
pub fn emitMetadata(meta: D.source.Metadata, sink: anytype) void {
    sink.emitBase(.owner, meta.ownerTuple(), meta.active().neg());
    for (L.U16_CACHE) |i| sink.emitBase(.range16, [1]M{M.fromCanonical(meta.range16[i])}, M.one());
    for (L.U8_CACHE) |i| sink.emitBase(.range8, [1]M{M.fromCanonical(meta.range8[i])}, M.one());
}
pub fn emitGlobalMetadata(meta: D.source.Metadata, sink: anytype) void {
    sink.emitBase(.ram, meta.ramTuple(false), meta.active());
    sink.emitBase(.ram, meta.ramTuple(true), meta.active().neg());
}
