//! Shared committed secure-row reader used by writer and independent parity checks.

const QM31 = @import("stwo_core").fields.qm31.QM31;
pub fn secureAt(
    columns: anytype,
    secure_column: usize,
    row: usize,
) QM31 {
    return QM31.fromM31Array(.{
        columns[secure_column * 4][row],
        columns[secure_column * 4 + 1][row],
        columns[secure_column * 4 + 2][row],
        columns[secure_column * 4 + 3][row],
    });
}
