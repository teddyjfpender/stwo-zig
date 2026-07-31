//! Shared relation tuples and semantic constraints for the SM83 PPU policy.
//!
//! This leaf owns protocol constants and AIR equations. It deliberately has
//! no dependency on the public host-admission facade or component adapter.

const std = @import("std");
const core = @import("stwo_core");
const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
const dma_binding_component = @import("air/dma_binding_component.zig");
const dma_execution = @import("air/dma_execution_lookup.zig");
const ppu_binding = @import("air/ppu_binding.zig");
const ppu_binding_component = @import("air/ppu_binding_component.zig");
const ppu_witness = @import("air/ppu_timing_witness.zig");
const runner = @import("runner/mod.zig");

pub const CERTAIN_HBLANK_DOT: u16 = 384;

pub const N_MAIN_COLUMNS: usize = 2;
pub const N_DMA_INTERACTION_COLUMNS: usize = 4;
pub const N_PPU_INTERACTION_COLUMNS: usize = 4;
pub const N_DMA_CONSTRAINTS: usize = 1;
pub const N_PPU_CONSTRAINTS: usize = 13;
pub const N_MAX_CONSTRAINTS: usize = N_PPU_CONSTRAINTS;
pub const MAX_CONSTRAINT_DEGREE: u32 = 3;

pub const VRAM_SELECTOR: usize = 0;
pub const OAM_SELECTOR: usize = 1;
const VRAM_RELATION_TAG: u32 = 0x5050_5601;
const OAM_RELATION_TAG: u32 = 0x5050_4f01;
pub const STAT_REGISTER: usize = @intFromEnum(ppu_binding.Register.stat);
pub const WRITE_STAT_EVENT: usize = 2;
pub const FIRST_VBLANK_LINE_SEGMENT: usize = 6;
pub const FIRST_MODE3_DOT_SEGMENT: usize = 10;
pub const FIRST_CERTAIN_HBLANK_DOT_SEGMENT: usize = 20;

comptime {
    std.debug.assert(
        ppu_witness.DOT_SEGMENTS[FIRST_MODE3_DOT_SEGMENT].start ==
            runner.ppu_timing.MODE2_DOTS,
    );
    std.debug.assert(
        ppu_witness.DOT_SEGMENTS[
            FIRST_CERTAIN_HBLANK_DOT_SEGMENT
        ].start == CERTAIN_HBLANK_DOT,
    );
    std.debug.assert(
        ppu_witness.LINE_SEGMENTS[FIRST_VBLANK_LINE_SEGMENT].start ==
            runner.ppu_timing.VISIBLE_LINES,
    );
}

pub const Claims = struct {
    dma: QM31,
    ppu: QM31,
};

pub fn verifyCancellation(claims: Claims) !void {
    if (!claims.dma.add(claims.ppu).isZero())
        return error.PpuExecutionPolicyLookupSumNonZero;
}
pub fn dmaPair(
    row: dma_binding_component.Row(QM31),
    relations: dma_execution.Relations,
) dma_execution.Pair {
    return policyPair(
        row.address_vram,
        row.address_oam,
        row.mcycle,
        relations,
        false,
    );
}

pub fn ppuPair(
    row: ppu_binding_component.Row(QM31),
    selectors: [N_MAIN_COLUMNS]QM31,
    relations: dma_execution.Relations,
) dma_execution.Pair {
    return policyPair(
        selectors[VRAM_SELECTOR],
        selectors[OAM_SELECTOR],
        row.mcycle,
        relations,
        true,
    );
}

fn policyPair(
    vram: QM31,
    oam: QM31,
    clock: QM31,
    relations: dma_execution.Relations,
    negative: bool,
) dma_execution.Pair {
    const sign = if (negative) QM31.zero().sub(QM31.one()) else QM31.one();
    return .{
        .n1 = sign.mul(vram),
        .d1 = relations.bus.combine(
            clock,
            q(VRAM_RELATION_TAG),
            QM31.zero(),
            QM31.zero(),
        ),
        .n2 = sign.mul(oam),
        .d2 = relations.bus.combine(
            clock,
            q(OAM_RELATION_TAG),
            QM31.zero(),
            QM31.zero(),
        ),
    };
}

pub fn evaluatePpuRows(
    comptime S: type,
    row: ppu_binding_component.Row(S),
    selectors: [N_MAIN_COLUMNS]S,
    current_sum: S,
    previous_sum: S,
    is_first: S,
    claim: S,
    relations: dma_execution.Relations,
) [N_PPU_CONSTRAINTS]S {
    const one = S.one();
    const active = row.active;
    const vram = selectors[VRAM_SELECTOR];
    const oam = selectors[OAM_SELECTOR];
    const phase0 = row.phases[0];
    const line_vblank = sum(
        S,
        row.semantic.before_aux.line_segments[FIRST_VBLANK_LINE_SEGMENT..],
    );
    // The PPU timing AIR proves LCD-off rows have line zero and binds the
    // one-hot line segments to that value, so vblank implies LCD-on.
    const visible = visibleLines(S, row.semantic.before.lcd, line_vblank);
    const early = sum(
        S,
        row.semantic.before_aux.dot_segments[0..FIRST_MODE3_DOT_SEGMENT],
    );
    const late = sum(
        S,
        row.semantic.before_aux.dot_segments[FIRST_CERTAIN_HBLANK_DOT_SEGMENT..],
    );
    const startup = row.semantic.before.startup;
    const variable_window = one.sub(early).sub(late);
    const stat_access = row.read_markers[STAT_REGISTER]
        .add(row.semantic.events[WRITE_STAT_EVENT]);
    const entry = ppuPairGeneric(S, row.mcycle, vram, oam, relations);
    var out: [N_PPU_CONSTRAINTS]S = undefined;
    var at: usize = 0;
    out[at] = bit(S, vram);
    at += 1;
    out[at] = bit(S, oam);
    at += 1;
    out[at] = one.sub(active).mul(vram);
    at += 1;
    out[at] = one.sub(active).mul(oam);
    at += 1;
    out[at] = vram.mul(oam);
    at += 1;
    out[at] = vram.mul(one.sub(phase0));
    at += 1;
    out[at] = oam.mul(one.sub(phase0));
    at += 1;
    out[at] = vram.mul(visible).mul(startup);
    at += 1;
    out[at] = vram.mul(visible).mul(variable_window);
    at += 1;
    out[at] = oam.mul(visible).mul(one.sub(late));
    at += 1;
    out[at] = stat_access.mul(visible).mul(startup);
    at += 1;
    out[at] = stat_access.mul(visible).mul(variable_window);
    at += 1;
    out[at] = dma_execution.pairConstraint(
        S,
        current_sum,
        previous_sum,
        is_first,
        claim,
        entry.n1,
        entry.d1,
        entry.n2,
        entry.d2,
    );
    at += 1;
    std.debug.assert(at == out.len);
    return out;
}

pub fn ppuPairGeneric(
    comptime S: type,
    clock: S,
    vram: S,
    oam: S,
    relations: dma_execution.Relations,
) GenericPair(S) {
    return .{
        .n1 = vram.neg(),
        .d1 = liftRelation(S, relations.bus, clock, VRAM_RELATION_TAG),
        .n2 = oam.neg(),
        .d2 = liftRelation(S, relations.bus, clock, OAM_RELATION_TAG),
    };
}

pub fn dmaPairGeneric(
    comptime S: type,
    row: dma_binding_component.Row(S),
    relations: dma_execution.Relations,
) GenericPair(S) {
    return .{
        .n1 = row.address_vram,
        .d1 = liftRelation(S, relations.bus, row.mcycle, VRAM_RELATION_TAG),
        .n2 = row.address_oam,
        .d2 = liftRelation(S, relations.bus, row.mcycle, OAM_RELATION_TAG),
    };
}

fn GenericPair(comptime S: type) type {
    return struct { n1: S, d1: S, n2: S, d2: S };
}

fn liftRelation(
    comptime S: type,
    relation: dma_execution.LinearRelation,
    clock: S,
    tag: u32,
) S {
    return liftSecure(S, relation.clock_alpha).mul(clock)
        .add(liftSecure(S, relation.address_alpha).mul(constant(S, tag)))
        .sub(liftSecure(S, relation.z));
}
pub const Kind = enum { dma, ppu };
fn liftSecure(comptime S: type, value: QM31) S {
    if (S != QM31) @compileError("secure PPU policy relations require QM31");
    return value;
}

fn constant(comptime S: type, value: u32) S {
    return S.fromBase(M31.fromCanonical(value));
}

fn q(value: u32) QM31 {
    return QM31.fromBase(M31.fromCanonical(value));
}

fn bit(comptime S: type, value: S) S {
    return value.mul(value.sub(S.one()));
}

fn sum(comptime S: type, values: []const S) S {
    var result = S.zero();
    for (values) |value| result = result.add(value);
    return result;
}

fn visibleLines(comptime S: type, lcd: S, line_vblank: S) S {
    return lcd.sub(line_vblank);
}

test "cubic visible selector preserves the PPU timing invariant" {
    for (0..2) |lcd_value| {
        for (0..2) |vblank_value| {
            if (vblank_value > lcd_value) continue;
            const lcd = q(@intCast(lcd_value));
            const vblank = q(@intCast(vblank_value));
            const original = lcd.mul(QM31.one().sub(vblank));
            try std.testing.expect(
                original.eql(visibleLines(QM31, lcd, vblank)),
            );
        }
    }

    // The lowering deliberately relies on the timing AIR's LCD-off line-zero
    // constraint; this forged state demonstrates that dependency.
    const forged_lcd = QM31.zero();
    const forged_vblank = QM31.one();
    try std.testing.expect(!forged_lcd.mul(
        QM31.one().sub(forged_vblank),
    ).eql(visibleLines(QM31, forged_lcd, forged_vblank)));
    try std.testing.expectEqual(@as(u32, 3), MAX_CONSTRAINT_DEGREE);
}
