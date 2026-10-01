//! Optional variable census for production-size verifier circuits.
//! The census changes neither the circuit nor its witness; enable it only
//! while identifying which verifier phase merits an architectural rewrite.
const std = @import("std");
const circuit = @import("stwo_circuit_frontend");

pub const Profile = struct {
    label: []const u8,
    enabled: bool,
    previous_variables: usize = 0,
    timer: ?std.time.Timer = null,

    pub fn init(label: []const u8) Profile {
        const setting = std.process.getEnvVarOwned(std.heap.page_allocator, "STWO_CIRCUIT_VERIFIER_STAGE_PROFILE") catch return .{
            .label = label,
            .enabled = false,
        };
        defer std.heap.page_allocator.free(setting);
        const enabled = std.mem.eql(u8, setting, "1");
        return .{ .label = label, .enabled = enabled, .timer = if (enabled) std.time.Timer.start() catch null else null };
    }

    pub fn mark(self: *Profile, state: *const circuit.builder.Circuit, stage: circuit.stark_verifier.verify.Stage) !void {
        if (!self.enabled) return;
        const delta = state.n_vars - self.previous_variables;
        const elapsed_ns = if (self.timer) |*timer| timer.lap() else 0;
        if (stage.child) |child| {
            std.debug.print("circuit-verifier-stage kind={s} child={} name={s} variables={} delta={} elapsed_ns={}\n", .{
                self.label, child, stage.name, state.n_vars, delta, elapsed_ns,
            });
        } else {
            std.debug.print("circuit-verifier-stage kind={s} name={s} variables={} delta={} elapsed_ns={}\n", .{
                self.label, stage.name, state.n_vars, delta, elapsed_ns,
            });
        }
        self.previous_variables = state.n_vars;
    }

    pub fn report(self: *Profile, state: *const circuit.builder.Circuit, phase: []const u8) void {
        if (!self.enabled) return;
        const elapsed_ns = if (self.timer) |*timer| timer.lap() else 0;
        std.debug.print("circuit-verifier-size kind={s} phase={s} variables={} add={} sub={} mul={} pointwise_mul={} eq={} triple_xor={} m31_to_u32={} blake_g={} elapsed_ns={}\n", .{
            self.label,
            phase,
            state.n_vars,
            state.add.items.len,
            state.sub.items.len,
            state.mul.items.len,
            state.pointwise_mul.items.len,
            state.eq.items.len,
            state.triple_xor.items.len,
            state.m31_to_u32.items.len,
            state.blake_g_gate.items.len,
            elapsed_ns,
        });
    }
};
