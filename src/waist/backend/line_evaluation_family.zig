const std = @import("std");
const circle = @import("stwo_core").circle;
const fft = @import("stwo_core").fft;
const m31 = @import("stwo_core").fields.m31;
const qm31 = @import("stwo_core").fields.qm31;
const poly_line = @import("stwo_core").poly.line;
const core_utils = @import("stwo_core").utils;

const M31 = m31.M31;
const QM31 = qm31.QM31;
const LineDomain = poly_line.LineDomain;

const ResidentStorage = @import("resident_storage.zig").ResidentStorage;

/// Evaluations of a univariate polynomial on a line domain.
///
/// The values are expected in bit-reversed order, matching Stwo prover conventions.
pub fn ForField(comptime Secure: type) type {
    return struct {
        const LinePoly = poly_line.LinePolyFor(Secure);
        pub const LineEvaluation = struct {
            values: []const Secure,
            domain_value: LineDomain,
            owns_values: bool = true,
            resident_storage: ?ResidentStorage = null,

            pub const Error = error{
                InvalidLength,
                DivisionByZero,
            };

            pub fn initOwned(line_domain: LineDomain, values: []Secure) Error!LineEvaluation {
                if (values.len != line_domain.size()) return Error.InvalidLength;
                return .{
                    .values = values,
                    .domain_value = line_domain,
                    .owns_values = true,
                };
            }

            pub fn initBorrowed(line_domain: LineDomain, values: []const Secure) Error!LineEvaluation {
                if (values.len != line_domain.size()) return Error.InvalidLength;
                return .{
                    .values = values,
                    .domain_value = line_domain,
                    .owns_values = false,
                };
            }

            pub fn deinit(self: *LineEvaluation, allocator: std.mem.Allocator) void {
                if (self.resident_storage) |storage| {
                    storage.deinit();
                } else if (self.owns_values) allocator.free(self.values);
                self.* = undefined;
            }

            pub fn initResident(
                line_domain: LineDomain,
                values: []Secure,
                storage: ResidentStorage,
            ) Error!LineEvaluation {
                if (values.len != line_domain.size()) return Error.InvalidLength;
                return .{
                    .values = values,
                    .domain_value = line_domain,
                    .owns_values = false,
                    .resident_storage = storage,
                };
            }

            pub fn newZero(allocator: std.mem.Allocator, line_domain: LineDomain) !LineEvaluation {
                const values = try allocator.alloc(Secure, line_domain.size());
                @memset(values, Secure.zero());
                return .{
                    .values = values,
                    .domain_value = line_domain,
                    .owns_values = true,
                };
            }

            pub fn len(self: LineEvaluation) usize {
                return self.values.len;
            }

            pub fn domain(self: LineEvaluation) LineDomain {
                return self.domain_value;
            }

            pub fn cloneOwned(self: LineEvaluation, allocator: std.mem.Allocator) !LineEvaluation {
                return .{
                    .values = try allocator.dupe(Secure, self.values),
                    .domain_value = self.domain_value,
                    .owns_values = true,
                };
            }

            /// Interpolates this evaluation into a line polynomial.
            ///
            /// Consumes ownership of `values` when this evaluation owns them.
            pub fn interpolate(
                self: *LineEvaluation,
                allocator: std.mem.Allocator,
            ) (std.mem.Allocator.Error || Error)!LinePoly {
                const coeffs: []Secure = if (self.owns_values and self.resident_storage == null)
                    @constCast(self.values)
                else
                    try allocator.dupe(Secure, self.values);

                core_utils.bitReverse(Secure, coeffs);
                try lineIfft(coeffs, self.domain_value);

                const len_m31 = M31.fromU64(coeffs.len);
                const len_inv = len_m31.inv() catch return Error.DivisionByZero;
                for (coeffs) |*v| v.* = v.mulM31(len_inv);

                if (self.owns_values and self.resident_storage == null) {
                    self.values = &[_]Secure{};
                    self.owns_values = false;
                }
                return LinePoly.initOwned(coeffs);
            }
        };

        /// In-place line-domain IFFT.
        ///
        /// Preconditions:
        /// - `values.len == domain.size()`
        fn lineIfft(values: []Secure, domain: LineDomain) LineEvaluation.Error!void {
            if (values.len != domain.size()) return LineEvaluation.Error.InvalidLength;

            var current_domain = domain;
            while (current_domain.size() > 1) {
                const chunk_size = current_domain.size();
                const half = chunk_size / 2;
                var chunk_start: usize = 0;
                while (chunk_start < values.len) : (chunk_start += chunk_size) {
                    const chunk = values[chunk_start .. chunk_start + chunk_size];
                    var it = current_domain.iter();
                    var i: usize = 0;
                    while (i < half) : (i += 1) {
                        const x = it.next().?;
                        const inv_x = x.inv() catch return LineEvaluation.Error.DivisionByZero;
                        fft.ibutterfly(Secure, &chunk[i], &chunk[half + i], inv_x);
                    }
                }
                current_domain = current_domain.double();
            }
        }
    };
}
