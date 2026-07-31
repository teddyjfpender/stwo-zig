//! Direct constraints for the minimal deterministic DMG-B PPU scheduler.
//!
//! This binds the transition/checkpoint relation in `runner/ppu_timing.zig`:
//! dot/line/mode, LY/LYC, LCD restart, VBlank IF, the combined STAT edge,
//! activity, and consecutive state chaining.
//!
//! Oracle: SameBoy commit `213a12ce93d66b105a113debd9396306066a7cfc`,
//! `Core/display.c:149-164,523-593,1664-1714,2151-2239` and
//! `Core/memory.c:1452-1482,1503-1569`.
//!
//! This is not a complete PPU proof. It keeps the runner's fixed empty-line
//! mode-3 timing and excludes rendering, scrolling/object/window stalls,
//! first-line sub-dot skew, VRAM/OAM contention and corruption, palettes, and
//! pixel FIFOs. It must not be presented as a timing-sensitive PPU-ROM claim.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const ppu = @import("../runner/ppu_timing.zig");
const witness_builder = @import("ppu_timing_witness.zig");

const N_EVENTS: usize = 4;
const STATE_COLUMNS: usize = 38;
const EVENT_OFFSET: usize = 0;
const BEFORE_OFFSET: usize = EVENT_OFFSET + N_EVENTS;
const ACTION_OFFSET: usize = BEFORE_OFFSET + STATE_COLUMNS;
const AFTER_OFFSET: usize = ACTION_OFFSET + 8;
const INTERRUPT_OFFSET: usize = AFTER_OFFSET + STATE_COLUMNS;
const LY_READ_OFFSET: usize = INTERRUPT_OFFSET + 2;
const STAT_READ_OFFSET: usize = LY_READ_OFFSET + 8;
const BASE_N_MAIN_COLUMNS: usize = STAT_READ_OFFSET + 8;
const N_LINE_SEGMENTS = witness_builder.N_LINE_SEGMENTS;
const N_DOT_SEGMENTS = witness_builder.N_DOT_SEGMENTS;
const N_EQUALITIES = witness_builder.N_EQUALITIES;
const BEFORE_LINE_SEGMENT_OFFSET =
    witness_builder.BEFORE_LINE_SEGMENT_OFFSET;
const AFTER_LINE_SEGMENT_OFFSET =
    witness_builder.AFTER_LINE_SEGMENT_OFFSET;
const CONTROL_OFFSET = witness_builder.CONTROL_OFFSET;
const STARTUP_TICK_OFFSET = witness_builder.STARTUP_TICK_OFFSET;
const REFRESH_OFFSET = witness_builder.REFRESH_OFFSET;
const VBLANK_POSITION_OFFSET = witness_builder.VBLANK_POSITION_OFFSET;
const SPECIAL_MODE2_OFFSET = witness_builder.SPECIAL_MODE2_OFFSET;
const REFRESH_RISE_OFFSET = witness_builder.REFRESH_RISE_OFFSET;
const N_BOOLEAN_COLUMNS = witness_builder.N_BOOLEAN_COLUMNS;
const TICK_LINE_OFFSET = witness_builder.TICK_LINE_OFFSET;
const BEFORE_INVERSE_OFFSET = witness_builder.BEFORE_INVERSE_OFFSET;
const AFTER_INVERSE_OFFSET = witness_builder.AFTER_INVERSE_OFFSET;
const LINE_SEGMENTS = witness_builder.LINE_SEGMENTS;
const DOT_SEGMENTS = witness_builder.DOT_SEGMENTS;

pub const N_MAIN_COLUMNS: usize = witness_builder.N_MAIN_COLUMNS;
pub const N_CONSTRAINTS: usize = 574;
pub const N_CHAIN_CONSTRAINTS: usize = STATE_COLUMNS;
const N_CANONICAL_CONSTRAINTS: usize = 65;

comptime {
    std.debug.assert(
        BASE_N_MAIN_COLUMNS == witness_builder.BASE_N_MAIN_COLUMNS,
    );
}

const StateOffset = struct {
    const lcd: usize = 0;
    const line: usize = lcd + 1;
    const dot: usize = line + 8;
    const startup: usize = dot + 9;
    const lyc: usize = startup + 1;
    const stat_enable: usize = lyc + 8;
    const coincidence: usize = stat_enable + 4;
    const lyc_line: usize = coincidence + 1;
    const stat_line: usize = lyc_line + 1;
    const mode: usize = stat_line + 1;
};

pub const ValidatedStep = struct {
    transition: ppu.Transition,

    pub fn init(
        transition: ppu.Transition,
    ) error{InvalidPpuTimingTransition}!ValidatedStep {
        transition.validate() catch
            return error.InvalidPpuTimingTransition;
        return .{ .transition = transition };
    }
};

pub fn Semantics(comptime S: type) type {
    return struct {
        pub const StateRow = struct {
            values: [STATE_COLUMNS]S,
            lcd: S,
            line: [8]S,
            dot: [9]S,
            startup: S,
            lyc: [8]S,
            stat_enable: [4]S,
            coincidence: S,
            lyc_line: S,
            stat_line: S,
            modes: [4]S,
        };

        pub const AuxRow = struct {
            line_segments: [N_LINE_SEGMENTS]S,
            dot_segments: [N_DOT_SEGMENTS]S,
            equality_zero: [N_EQUALITIES]S,
            comparison_valid: S,
            comparison_matches: S,
            mode_line: S,
            lyc_source: S,
            inverses: [N_EQUALITIES]S,
        };

        pub const Row = struct {
            values: [N_MAIN_COLUMNS]S,
            events: [N_EVENTS]S,
            before: StateRow,
            action: [8]S,
            after: StateRow,
            interrupts: [2]S,
            ly_read: [8]S,
            stat_read: [8]S,
            before_aux: AuxRow,
            after_aux: AuxRow,
            controls: [3]S,
            startup_tick: S,
            refresh: S,
            vblank_position: S,
            special_mode2: S,
            refresh_rise: S,
            tick_line: S,

            pub fn fromColumns(values: []const S) !Row {
                if (values.len != N_MAIN_COLUMNS)
                    return error.InvalidMainTraceShape;
                return .{
                    .values = values[0..N_MAIN_COLUMNS].*,
                    .events = values[EVENT_OFFSET..BEFORE_OFFSET].*,
                    .before = stateFromColumns(values, BEFORE_OFFSET),
                    .action = values[ACTION_OFFSET..AFTER_OFFSET].*,
                    .after = stateFromColumns(values, AFTER_OFFSET),
                    .interrupts = values[INTERRUPT_OFFSET..LY_READ_OFFSET].*,
                    .ly_read = values[LY_READ_OFFSET..STAT_READ_OFFSET].*,
                    .stat_read = values[STAT_READ_OFFSET..BASE_N_MAIN_COLUMNS].*,
                    .before_aux = auxFromColumns(
                        values,
                        BEFORE_LINE_SEGMENT_OFFSET,
                        BEFORE_INVERSE_OFFSET,
                    ),
                    .after_aux = auxFromColumns(
                        values,
                        AFTER_LINE_SEGMENT_OFFSET,
                        AFTER_INVERSE_OFFSET,
                    ),
                    .controls = values[CONTROL_OFFSET..STARTUP_TICK_OFFSET].*,
                    .startup_tick = values[STARTUP_TICK_OFFSET],
                    .refresh = values[REFRESH_OFFSET],
                    .vblank_position = values[VBLANK_POSITION_OFFSET],
                    .special_mode2 = values[SPECIAL_MODE2_OFFSET],
                    .refresh_rise = values[REFRESH_RISE_OFFSET],
                    .tick_line = values[TICK_LINE_OFFSET],
                };
            }
        };

        pub const Evaluation = struct {
            values: [N_CONSTRAINTS]S,

            pub fn allZero(self: @This()) bool {
                for (self.values) |value|
                    if (!value.isZero()) return false;
                return true;
            }
        };

        pub const ChainEvaluation = struct {
            values: [N_CHAIN_CONSTRAINTS]S,

            pub fn allZero(self: @This()) bool {
                for (self.values) |value|
                    if (!value.isZero()) return false;
                return true;
            }
        };

        pub fn evaluate(row: Row, is_active: S) Evaluation {
            @setEvalBranchQuota(2_000_000);
            var out: [N_CONSTRAINTS]S = undefined;
            var at: usize = 0;
            const one = S.one();

            out[at] = bit(is_active);
            at += 1;
            for (row.values[0..N_BOOLEAN_COLUMNS]) |value| {
                out[at] = bit(value);
                at += 1;
            }
            for (row.values) |value| {
                out[at] = one.sub(is_active).mul(value);
                at += 1;
            }

            const tick = event(row, .tick_dot);
            const write_lcdc = event(row, .write_lcdc);
            const write_stat = event(row, .write_stat);
            const write_lyc = event(row, .write_lyc);
            out[at] = tick.add(write_lcdc)
                .add(write_stat)
                .add(write_lyc)
                .sub(is_active);
            at += 1;
            for (row.action) |value| {
                out[at] = tick.mul(value);
                at += 1;
            }

            for (canonicalConstraints(
                row.before,
                row.before_aux,
                is_active,
            )) |constraint| {
                out[at] = constraint;
                at += 1;
            }
            for (canonicalConstraints(
                row.after,
                row.after_aux,
                is_active,
            )) |constraint| {
                out[at] = constraint;
                at += 1;
            }

            const before_line = compose(row.before.line);
            const before_dot = compose(row.before.dot);
            const before_lyc = compose(row.before.lyc);
            const before_stat_enable = compose(row.before.stat_enable);
            const action = compose(row.action);
            const last_dot =
                row.before_aux.dot_segments[N_DOT_SEGMENTS - 1];
            const last_line =
                row.before_aux.line_segments[N_LINE_SEGMENTS - 1];

            const expected_lcdc_enable = write_lcdc
                .mul(one.sub(row.before.lcd))
                .mul(row.action[7]);
            const expected_lcdc_disable = write_lcdc
                .mul(row.before.lcd)
                .mul(one.sub(row.action[7]));
            out[at] = row.controls[0].sub(expected_lcdc_enable);
            at += 1;
            out[at] = row.controls[1].sub(expected_lcdc_disable);
            at += 1;
            out[at] = row.controls[2].sub(
                write_lcdc.sub(row.controls[0]).sub(row.controls[1]),
            );
            at += 1;
            const lcdc_enable = row.controls[0];
            const lcdc_same = row.controls[2];

            const expected_tick_line = before_line.add(
                row.before.lcd.mul(last_dot).mul(
                    one.sub(q(154).mul(last_line)),
                ),
            );
            out[at] = row.tick_line.sub(expected_tick_line);
            at += 1;
            out[at] = row.startup_tick.sub(
                row.before.startup.mul(
                    one.sub(row.before.lcd.mul(last_dot)),
                ),
            );
            at += 1;

            out[at] = row.after.lcd.sub(
                is_active.sub(write_lcdc).mul(row.before.lcd)
                    .add(write_lcdc.mul(row.action[7])),
            );
            at += 1;

            const tick_dot = before_dot
                .add(row.before.lcd)
                .sub(
                row.before.lcd.mul(last_dot).mul(q(456)),
            );
            const position_keep =
                write_stat.add(write_lyc).add(lcdc_same);
            out[at] = compose(row.after.line).sub(
                tick.mul(row.tick_line)
                    .add(position_keep.mul(before_line)),
            );
            at += 1;
            out[at] = compose(row.after.dot).sub(
                tick.mul(tick_dot)
                    .add(position_keep.mul(before_dot)),
            );
            at += 1;
            out[at] = row.after.startup.sub(
                tick.mul(row.startup_tick)
                    .add(lcdc_enable)
                    .add(position_keep.mul(row.before.startup)),
            );
            at += 1;

            out[at] = compose(row.after.lyc).sub(
                is_active.sub(write_lyc).mul(before_lyc)
                    .add(write_lyc.mul(action)),
            );
            at += 1;
            const action_stat = compose(row.action[3..7].*);
            out[at] = compose(row.after.stat_enable).sub(
                is_active.sub(write_stat).mul(before_stat_enable)
                    .add(write_stat.mul(action_stat)),
            );
            at += 1;

            const expected_refresh = tick.mul(row.before.lcd)
                .add(lcdc_enable)
                .add(
                row.before.lcd.mul(write_stat.add(write_lyc)),
            );
            out[at] = row.refresh.sub(expected_refresh);
            at += 1;
            const freeze = is_active.sub(row.refresh);
            out[at] = freeze.mul(
                row.after.coincidence.sub(row.before.coincidence),
            );
            at += 1;
            out[at] = freeze.mul(
                row.after.lyc_line.sub(row.before.lyc_line),
            );
            at += 1;
            out[at] = freeze.mul(
                row.after.stat_line.sub(row.before.stat_line),
            );
            at += 1;

            out[at] = row.refresh
                .mul(
                    row.after.lcd.sub(row.after_aux.comparison_valid),
                )
                .mul(row.after.lyc_line.sub(row.before.lyc_line));
            at += 1;

            out[at] = compose(row.ly_read).sub(
                readLy(row.after, row.after_aux),
            );
            at += 1;
            out[at] = compose(row.stat_read).sub(
                q(0x80).mul(is_active)
                    .add(q(8).mul(compose(row.after.stat_enable)))
                    .add(q(4).mul(row.after.coincidence))
                    .add(modeNumber(row.after)),
            );
            at += 1;

            const line144 = row.before_aux.line_segments[6];
            const dot0 = row.before_aux.dot_segments[0];
            out[at] = row.vblank_position.sub(line144.mul(dot0));
            at += 1;
            out[at] = row.interrupts[0].sub(
                tick.mul(row.before.lcd).mul(row.vblank_position),
            );
            at += 1;

            out[at] = row.special_mode2.sub(
                row.interrupts[0]
                    .mul(row.before.stat_enable[2])
                    .mul(one.sub(row.before.stat_line)),
            );
            at += 1;
            out[at] = row.refresh_rise.sub(
                row.refresh
                    .mul(row.after.stat_line)
                    .mul(one.sub(row.before.stat_line)),
            );
            at += 1;
            out[at] = row.interrupts[1].sub(boolOr(
                row.special_mode2,
                row.refresh_rise,
            ));
            at += 1;

            std.debug.assert(at == out.len);
            return .{ .values = out };
        }

        pub fn evaluateChain(
            previous: Row,
            next: Row,
        ) ChainEvaluation {
            var out: [N_CHAIN_CONSTRAINTS]S = undefined;
            for (
                &out,
                previous.after.values,
                next.before.values,
            ) |*constraint, after, before| {
                constraint.* = after.sub(before);
            }
            return .{ .values = out };
        }

        fn canonicalConstraints(
            state: StateRow,
            aux: AuxRow,
            is_active: S,
        ) [N_CANONICAL_CONSTRAINTS]S {
            var out: [N_CANONICAL_CONSTRAINTS]S = undefined;
            var at: usize = 0;
            const one = S.one();

            appendSegmentConstraints(
                &out,
                &at,
                state.line,
                aux.line_segments,
                is_active,
                LINE_SEGMENTS,
            );
            appendSegmentConstraints(
                &out,
                &at,
                state.dot,
                aux.dot_segments,
                is_active,
                DOT_SEGMENTS,
            );
            out[at] = state.stat_enable[0];
            at += 1;

            const equality_deltas = [N_EQUALITIES]S{
                compose(state.line).sub(compose(state.lyc)),
                compose(state.lyc).sub(q(153)),
                compose(state.lyc),
            };
            for (
                equality_deltas,
                aux.equality_zero,
                aux.inverses,
            ) |delta, zero, inverse| {
                out[at] = zero.mul(delta);
                at += 1;
                out[at] = delta.mul(inverse)
                    .sub(is_active.sub(zero));
                at += 1;
                out[at] = zero.mul(inverse);
                at += 1;
            }

            const line153 =
                aux.line_segments[N_LINE_SEGMENTS - 1];
            const dot6to8 = aux.dot_segments[4];
            const dot12plus = sumRange(
                aux.dot_segments,
                6,
                N_DOT_SEGMENTS,
            );
            const expected_comparison_valid = state.lcd.mul(
                one.sub(line153).add(
                    line153.mul(dot6to8.add(dot12plus)),
                ),
            );
            out[at] = aux.comparison_valid.sub(
                expected_comparison_valid,
            );
            at += 1;
            const expected_comparison_matches =
                one.sub(line153).mul(aux.equality_zero[0])
                    .add(line153.mul(dot6to8)
                        .mul(aux.equality_zero[1]))
                    .add(line153.mul(dot12plus)
                    .mul(aux.equality_zero[2]));
            out[at] = aux.comparison_matches.sub(
                expected_comparison_matches,
            );
            at += 1;

            const dot_mode2 = sumRange(aux.dot_segments, 0, 10);
            const startup_early = state.startup.mul(dot_mode2);
            const expected_mode_line = state.stat_enable[0]
                .mul(
                    state.modes[@intFromEnum(ppu.Mode.hblank)]
                        .sub(startup_early),
                )
                .add(state.stat_enable[1].mul(
                    state.modes[@intFromEnum(ppu.Mode.vblank)],
                ))
                .add(state.stat_enable[2].mul(
                state.modes[@intFromEnum(ppu.Mode.oam)],
            ));
            out[at] = aux.mode_line.sub(expected_mode_line);
            at += 1;
            out[at] = aux.lyc_source.sub(
                state.stat_enable[3].mul(state.lyc_line),
            );
            at += 1;

            const off = is_active.sub(state.lcd);
            out[at] = off.mul(compose(state.line));
            at += 1;
            out[at] = off.mul(compose(state.dot));
            at += 1;
            out[at] = off.mul(state.startup);
            at += 1;
            out[at] = state.startup.mul(compose(state.line));
            at += 1;

            const invalid = state.lcd.sub(aux.comparison_valid);
            out[at] = aux.comparison_valid.mul(
                state.coincidence.sub(aux.comparison_matches),
            );
            at += 1;
            out[at] = aux.comparison_valid.mul(
                state.lyc_line.sub(aux.comparison_matches),
            );
            at += 1;
            out[at] = invalid.mul(state.coincidence);
            at += 1;
            out[at] = state.lcd.mul(
                state.stat_line.sub(boolOr(
                    aux.mode_line,
                    aux.lyc_source,
                )),
            );
            at += 1;

            const expected_modes = modeHot(state, aux, is_active);
            for (state.modes, expected_modes) |actual, expected| {
                out[at] = actual.sub(expected);
                at += 1;
            }
            std.debug.assert(at == out.len);
            return out;
        }

        fn modeHot(
            state: StateRow,
            aux: AuxRow,
            is_active: S,
        ) [4]S {
            const one = S.one();
            const line_vblank = sumRange(
                aux.line_segments,
                6,
                N_LINE_SEGMENTS,
            );
            const visible = state.lcd.mul(one.sub(line_vblank));
            const delayed_vblank = state.lcd
                .mul(aux.line_segments[6])
                .mul(aux.dot_segments[0]);
            const vblank =
                state.lcd.mul(line_vblank).sub(delayed_vblank);
            const dot_mode2 = sumRange(aux.dot_segments, 0, 10);
            const dot_mode3 = sumRange(aux.dot_segments, 10, 17);
            const dot_mode0 = sumRange(
                aux.dot_segments,
                17,
                N_DOT_SEGMENTS,
            );
            const startup_early = state.startup.mul(dot_mode2);
            return .{
                is_active.sub(state.lcd)
                    .add(visible.mul(dot_mode0))
                    .add(startup_early)
                    .add(delayed_vblank),
                vblank,
                visible.mul(dot_mode2).sub(startup_early),
                visible.mul(dot_mode3),
            };
        }

        fn readLy(state: StateRow, aux: AuxRow) S {
            const one = S.one();
            const line153 =
                aux.line_segments[N_LINE_SEGMENTS - 1];
            const before2 = sumRange(aux.dot_segments, 0, 2);
            const dot2to6 = sumRange(aux.dot_segments, 2, 4);
            return state.lcd.mul(
                one.sub(line153).mul(compose(state.line))
                    .add(
                    line153.mul(
                        q(152).mul(before2)
                            .add(q(153).mul(dot2to6)),
                    ),
                ),
            );
        }

        fn modeNumber(state: StateRow) S {
            var result = S.zero();
            for (state.modes, 0..) |selected, index|
                result = result.add(q(index).mul(selected));
            return result;
        }

        fn stateFromColumns(
            values: []const S,
            comptime offset: usize,
        ) StateRow {
            const slice = values[offset .. offset + STATE_COLUMNS];
            return .{
                .values = slice.*,
                .lcd = slice[StateOffset.lcd],
                .line = slice[StateOffset.line..StateOffset.dot].*,
                .dot = slice[StateOffset.dot..StateOffset.startup].*,
                .startup = slice[StateOffset.startup],
                .lyc = slice[StateOffset.lyc..StateOffset.stat_enable].*,
                .stat_enable = slice[StateOffset.stat_enable..StateOffset.coincidence].*,
                .coincidence = slice[StateOffset.coincidence],
                .lyc_line = slice[StateOffset.lyc_line],
                .stat_line = slice[StateOffset.stat_line],
                .modes = slice[StateOffset.mode..STATE_COLUMNS].*,
            };
        }

        fn auxFromColumns(
            values: []const S,
            comptime segment_offset: usize,
            comptime inverse_offset: usize,
        ) AuxRow {
            const dot_offset = segment_offset + N_LINE_SEGMENTS;
            const equality_offset = dot_offset + N_DOT_SEGMENTS;
            const logic_offset = equality_offset + N_EQUALITIES;
            return .{
                .line_segments = values[segment_offset..dot_offset].*,
                .dot_segments = values[dot_offset..equality_offset].*,
                .equality_zero = values[equality_offset..logic_offset].*,
                .comparison_valid = values[logic_offset],
                .comparison_matches = values[logic_offset + 1],
                .mode_line = values[logic_offset + 2],
                .lyc_source = values[logic_offset + 3],
                .inverses = values[inverse_offset .. inverse_offset + N_EQUALITIES].*,
            };
        }

        fn event(row: Row, selected: std.meta.Tag(ppu.Event)) S {
            return row.events[@intFromEnum(selected)];
        }

        fn bit(value: S) S {
            return value.mul(value.sub(S.one()));
        }

        fn boolOr(left: S, right: S) S {
            return left.add(right).sub(left.mul(right));
        }

        fn appendSegmentConstraints(
            out: *[N_CANONICAL_CONSTRAINTS]S,
            at: *usize,
            bits: anytype,
            selectors: anytype,
            is_active: S,
            comptime segments: anytype,
        ) void {
            var selected = S.zero();
            for (selectors) |selector|
                selected = selected.add(selector);
            out[at.*] = selected.sub(is_active);
            at.* += 1;
            inline for (segments, selectors) |segment, selector| {
                const width: usize = segment.log_size;
                out[at.*] = selector.mul(
                    compose(bits[width..]).sub(
                        q(segment.start >> @intCast(width)),
                    ),
                );
                at.* += 1;
            }
        }

        fn sumRange(
            values: anytype,
            comptime start: usize,
            comptime end: usize,
        ) S {
            var result = S.zero();
            for (values[start..end]) |value|
                result = result.add(value);
            return result;
        }

        fn compose(bits: anytype) S {
            var result = S.zero();
            for (bits, 0..) |value, index|
                result = result.add(q(
                    @as(usize, 1) << @intCast(index),
                ).mul(value));
            return result;
        }

        fn q(value: usize) S {
            return S.fromBase(M31.fromU64(value));
        }
    };
}

pub const Shipped = Semantics(QM31);

pub fn columns(step: ValidatedStep) [N_MAIN_COLUMNS]M31 {
    const transition = step.transition;
    var out = [_]M31{M31.zero()} ** N_MAIN_COLUMNS;
    out[
        EVENT_OFFSET + @intFromEnum(
            std.meta.activeTag(transition.event),
        )
    ] = M31.one();
    setState(&out, BEFORE_OFFSET, transition.before);
    switch (transition.event) {
        .write_lcdc => |value| writeBits(
            out[ACTION_OFFSET..AFTER_OFFSET],
            value,
        ),
        .write_stat => |value| writeBits(
            out[ACTION_OFFSET..AFTER_OFFSET],
            value,
        ),
        .write_lyc => |value| writeBits(
            out[ACTION_OFFSET..AFTER_OFFSET],
            value,
        ),
        .tick_dot => {},
    }
    setState(&out, AFTER_OFFSET, transition.after);
    out[INTERRUPT_OFFSET] = boolean(transition.interrupts.vblank);
    out[INTERRUPT_OFFSET + 1] = boolean(transition.interrupts.stat);
    writeBits(out[LY_READ_OFFSET..STAT_READ_OFFSET], transition.ly_read);
    writeBits(
        out[STAT_READ_OFFSET..BASE_N_MAIN_COLUMNS],
        transition.stat_read,
    );
    witness_builder.fill(&out, transition);
    return out;
}

pub fn inactiveColumns() [N_MAIN_COLUMNS]M31 {
    return [_]M31{M31.zero()} ** N_MAIN_COLUMNS;
}

pub fn evaluate(
    values: [N_MAIN_COLUMNS]M31,
    is_active: bool,
) !Shipped.Evaluation {
    var lifted: [N_MAIN_COLUMNS]QM31 = undefined;
    for (&lifted, values) |*destination, value|
        destination.* = QM31.fromBase(value);
    return Shipped.evaluate(
        try Shipped.Row.fromColumns(&lifted),
        QM31.fromBase(boolean(is_active)),
    );
}

pub fn evaluateChain(
    previous: [N_MAIN_COLUMNS]M31,
    next: [N_MAIN_COLUMNS]M31,
) !Shipped.ChainEvaluation {
    var left: [N_MAIN_COLUMNS]QM31 = undefined;
    var right: [N_MAIN_COLUMNS]QM31 = undefined;
    for (&left, previous) |*destination, value|
        destination.* = QM31.fromBase(value);
    for (&right, next) |*destination, value|
        destination.* = QM31.fromBase(value);
    return Shipped.evaluateChain(
        try Shipped.Row.fromColumns(&left),
        try Shipped.Row.fromColumns(&right),
    );
}

fn setState(
    out: *[N_MAIN_COLUMNS]M31,
    offset: usize,
    state: ppu.State,
) void {
    out[offset + StateOffset.lcd] = boolean(state.lcd_enabled);
    writeBits(
        out[offset + StateOffset.line .. offset + StateOffset.dot],
        state.line,
    );
    writeBits(
        out[offset + StateOffset.dot .. offset + StateOffset.startup],
        state.dot,
    );
    out[offset + StateOffset.startup] = boolean(state.startup_line);
    writeBits(
        out[offset + StateOffset.lyc .. offset + StateOffset.stat_enable],
        state.lyc,
    );
    writeBits(
        out[offset + StateOffset.stat_enable .. offset + StateOffset.coincidence],
        state.stat_enable,
    );
    out[offset + StateOffset.coincidence] =
        boolean(state.coincidence);
    out[offset + StateOffset.lyc_line] =
        boolean(state.lyc_interrupt_line);
    out[offset + StateOffset.stat_line] =
        boolean(state.stat_interrupt_line);
    out[offset + StateOffset.mode + @intFromEnum(state.mode())] =
        M31.one();
}

fn writeBits(out: []M31, value: anytype) void {
    const integer: u64 = @intCast(value);
    for (out, 0..) |*column, index|
        column.* = M31.fromCanonical(
            @intCast((integer >> @intCast(index)) & 1),
        );
}

fn boolean(value: bool) M31 {
    return M31.fromCanonical(@intFromBool(value));
}
