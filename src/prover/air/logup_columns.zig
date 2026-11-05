//! Secure-column builder for LogUp interaction traces, with the semantics of
//! Stwo's `LogupTraceGenerator` (`crates/constraint-framework/src/prover/logup.rs`):
//! every interaction column holds, per row, the running sum of its own and all
//! earlier columns' fractions; the last column is shifted by
//! `claimed_sum / 2^log_size` and prefix-summed in coset order
//! (`finalize_last`). The fraction values, not the way a frontend combines
//! paired numerators and denominators, fix the committed bytes.

const std = @import("std");
const fields = @import("stwo_core").fields;
const M31 = fields.m31.M31;
const QM31 = fields.qm31.QM31;
const utils = @import("stwo_core").utils;
const prover_pcs = @import("../pcs/mod.zig");
const work_pool = @import("../work_pool.zig");

pub const ForField = @import("logup_columns_family.zig").ForField;
const Default = ForField(QM31);
pub const Fraction = Default.Fraction;
pub const Output = Default.Output;
pub const build = Default.build;

test "paired LogUp builder accumulates batches and shifts the final column" {
    const Context = struct {
        fn fill(_: @This(), row: usize, out: []Fraction) !void {
            const value = M31.fromU64(row + 1);
            out[0] = .{
                .numerator = QM31.fromBase(value),
                .denominator = QM31.one(),
            };
            out[1] = .{
                .numerator = QM31.fromBase(value),
                .denominator = QM31.one(),
            };
        }
    };
    const allocator = std.testing.allocator;
    const output = try build(allocator, 4, 2, Context{}, Context.fill);
    defer {
        for (output.columns) |column| allocator.free(column.values);
        allocator.free(output.columns);
    }
    try std.testing.expectEqual(@as(usize, 8), output.columns.len);
    try std.testing.expect(output.claimed_sum.eql(QM31.fromBase(M31.fromCanonical(272))));
}
