//! Authority geometry admission independent of witness construction.
pub fn ForIndex(comptime LogIndex: type) type {
    return struct {
        /// Pure padding selector shared by the constructor and hostile
        /// geometry tests. An explicit request cannot activate a missing
        /// component, shrink an active domain, or exceed the supported field
        /// domain.
        pub fn selectAuthorityLogSizes(
            active: [LogIndex.count]u32,
            requested: ?[LogIndex.count]u32,
        ) ![LogIndex.count]u32 {
            const selected = requested orelse return active;
            for (active, selected) |minimum, candidate| {
                if ((minimum == 0 and candidate != 0) or
                    (minimum != 0 and
                        (candidate < minimum or candidate >= 31)))
                {
                    return error.AuthorityMismatch;
                }
            }
            return selected;
        }
    };
}
