//! Opt-in diagnostics for the common Word16 composition kernels.
//! Joined elapsed intervals may overlap across components and prover lanes;
//! their sum is not block wall time or CPU time. No witness data is recorded.
const std = @import("std");

pub const Kind = enum { fft, rows };
pub const Span = struct {
    kind: Kind,
    rows: usize,
    width: usize,
    mode: []const u8,
    origin: ?std.time.Instant,

    pub fn begin(kind: Kind, rows: usize, width: usize, mode: []const u8) Span {
        return .{
            .kind = kind,
            .rows = rows,
            .width = width,
            .mode = mode,
            .origin = if (std.process.hasEnvVarConstant("STWO_ZIG_RV64_DOMAIN_TIMING")) std.time.Instant.now() catch null else null,
        };
    }

    pub fn end(self: *Span) void {
        const origin = self.origin orelse return;
        self.origin = null;
        const now = std.time.Instant.now() catch return;
        std.debug.print("rv64_domain kind={s} rows={d} width={d} ns={d} mode={s}\n", .{
            @tagName(self.kind), self.rows, self.width, now.since(origin), self.mode,
        });
    }
};
