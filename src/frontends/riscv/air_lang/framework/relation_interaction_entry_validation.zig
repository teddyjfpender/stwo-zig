//! Exact entry-vector validation for an authenticated interaction plan.

pub fn validateEntries(
    comptime Runtime: type,
    plan: *const Runtime.Plan,
    arena: anytype,
    expected_digest: anytype,
    event_ids: anytype,
    row: Runtime.Row,
    actual: [Runtime.EVENT_COUNT]Runtime.EntryType,
) Runtime.AuthenticationErrorSet!void {
    try plan.validateAgainst(arena, expected_digest, event_ids);
    const expected = plan.preparedEntries(row);
    for (actual, expected, 0..) |got, wanted, ordinal| {
        if (got.ordinal != wanted.ordinal or got.ordinal != ordinal)
            return error.EntryOrderMismatch;
        if (got.schema != wanted.schema or
            got.schema_version != wanted.schema_version or
            got.domain != wanted.domain)
        {
            return error.EntrySchemaMismatch;
        }
        if (got.role != wanted.role) return error.EntryRoleMismatch;
        if (got.arity != wanted.arity) return error.EntryArityMismatch;
        if (!got.numerator.eql(wanted.numerator))
            return error.EntryNumeratorMismatch;
        for (got.values, wanted.values) |got_value, wanted_value| {
            if (!got_value.eql(wanted_value)) return error.EntryTupleMismatch;
        }
    }
}
