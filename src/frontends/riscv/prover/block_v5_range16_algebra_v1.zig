//! One typed range16 equation owner shared by scalar, packed and GPU export.
pub fn equations(comptime S: type, fixed: [1]S, main: [1]S, current: [8]S, previous: [8]S, normalized_sum: S, normalized_count: S, relation: anytype) [2]S {
    const sum_delta = S.fromPartialEvals(current[0..4].*).sub(S.fromPartialEvals(previous[0..4].*)).add(normalized_sum);
    const count_delta = S.fromPartialEvals(current[4..8].*).sub(S.fromPartialEvals(previous[4..8].*)).add(normalized_count);
    return .{ sum_delta.mul(relation.combineSecure(fixed)).sub(main[0]), count_delta.sub(main[0]) };
}
