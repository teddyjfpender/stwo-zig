//! Bounded public-domain admission for the existing GPU inverse kernels.
//! Detect poles analytically in Z/(2^31), without reading or inverting rows.
const std = @import("std");
const order: u64 = 1 << 31;
pub fn requireDomain(initial: u32, step: u32, count: u32, layers: u32, circle: bool) !void {
    if (initial >= order or step == 0 or step > order or count == 0 or !std.math.isPowerOfTwo(count) or layers == 0 or
        (circle and layers != 1) or (!circle and layers > std.math.log2_int(u32, count))) return error.InvalidFriInverseDomain;
    const gcd = @as(u64, 1) << @intCast(@ctz(step));
    if (order / gcd != count) return error.InvalidFriInverseDomain;
    var current_initial: u64 = initial;
    var current_step: u64 = step;
    var current_count = count;
    for (0..layers) |_| {
        const values = if (circle) current_count else current_count / 2;
        const first_pole: u64 = if (circle) 0 else order / 4;
        const second_pole: u64 = first_pole + order / 2;
        if (hits(current_initial, current_step, values, first_pole) or hits(current_initial, current_step, values, second_pole)) return error.FriInverseDomainPole;
        current_count /= 2;
        current_initial = (current_initial * 2) & (order - 1);
        current_step = (current_step * 2) & (order - 1);
    }
}
fn hits(initial: u64, step: u64, values: u32, target: u64) bool {
    if (values == 0) return false;
    if (step == 0) return initial == target;
    const gcd = @as(u64, 1) << @intCast(@ctz(step));
    const delta = (target + order - initial) & (order - 1);
    if (delta % gcd != 0) return false;
    const modulus = order / gcd;
    const odd = step / gcd;
    // Newton inversion modulo 2^64; only low log2(modulus) bits are used.
    var inverse: u64 = 1;
    for (0..6) |_| inverse = inverse *% (2 -% (odd *% inverse));
    const index = ((delta / gcd) *% inverse) & (modulus - 1);
    return index < values;
}
