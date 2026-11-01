const std = @import("std");
const circle = @import("stwo_core").circle;
const M31 = @import("stwo_core").fields.m31.M31;
pub fn ForField(comptime Secure: type) type {
    return struct {
        const QM31 = Secure;
        const CirclePointQM31 = circle.CirclePoint(Secure);
        pub inline fn evalAtPointIterative(
            coeffs: []const M31,
            factors: []const QM31,
            log_size: u32,
        ) QM31 {
            std.debug.assert(coeffs.len == (@as(usize, 1) << @intCast(log_size)));
            std.debug.assert(factors.len == log_size);

            if (log_size == 0) return QM31.fromBase(coeffs[0]);

            var pending: [circle.M31_CIRCLE_LOG_ORDER + 1]QM31 = undefined;

            for (coeffs, 0..) |coeff, coeff_idx| {
                var value = QM31.fromBase(coeff);
                var level: usize = @as(usize, @intCast(@ctz(~coeff_idx)));
                if (level > @as(usize, @intCast(log_size))) level = @as(usize, @intCast(log_size));
                var merge_level: usize = 0;
                while (merge_level < level) : (merge_level += 1) {
                    value = pending[merge_level].add(value.mul(factors[merge_level]));
                }
                pending[level] = value;
            }

            return pending[log_size];
        }

        pub fn fillEvalFactorsForPoint(
            point: CirclePointQM31,
            log_size: u32,
            out: *[circle.M31_CIRCLE_LOG_ORDER]QM31,
        ) []const QM31 {
            fillEvalFactors(point, log_size, out);
            return out[0..log_size];
        }

        inline fn fillEvalFactors(
            point: CirclePointQM31,
            log_size: u32,
            out: *[circle.M31_CIRCLE_LOG_ORDER]QM31,
        ) void {
            const max_log_size = circle.M31_CIRCLE_LOG_ORDER;
            std.debug.assert(log_size <= max_log_size);
            if (log_size == 0) return;

            out[0] = point.y;
            if (log_size > 1) {
                var x = point.x;
                out[1] = x;
                var bit: u32 = 2;
                while (bit < log_size) : (bit += 1) {
                    x = circle.CirclePoint(QM31).doubleX(x);
                    out[bit] = x;
                }
            }
        }
    };
}
