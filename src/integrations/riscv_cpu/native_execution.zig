//! Explicit native operation domains. Every binding aliases its one canonical owner.
pub const legacy = struct {
    pub const statement = @import("rv64_full_statement.zig");
    pub const prover = @import("rv64_authenticated_prover.zig");
    pub const component_profiles = @import("rv64_component_profiles.zig");
    pub const diagnostic = @import("rv64_cpu_diagnostic.zig");
    pub const point_evaluation = @import("rv64_point_evaluation.zig");
    pub const point_layout = @import("rv64_point_layout.zig");
    pub const authenticated = @import("rv64_authenticated_execution.zig");
};
pub const word16 = struct {
    pub const prepared = @import("word16_execution/prepared.zig");
    pub const setup = @import("word16_execution/setup.zig");
    pub const protocol = @import("word16_execution/protocol.zig");
    pub const proof = @import("word16_execution/execution.zig");
    pub const coverage = @import("word16_execution/coverage.zig");
    pub const sources = @import("word16_execution/sources.zig");
    pub const components = @import("word16_execution/components.zig");
    pub const receipt = @import("word16_execution/driver.zig");
    pub const arithmetic_bus = @import("word16_execution/arithmetic_bus.zig");
    pub const rom_source = @import("word16_execution/rom_source.zig");
    pub const metrics = @import("word16_execution/pcs_metrics.zig");
    pub const cells_wire = @import("word16_execution/cells_wire.zig");
};
pub const services = struct {
    pub const protocol = @import("word16_global_execution/services/protocol.zig");
    pub const wire = @import("word16_global_execution/services/wire.zig");
    pub const pipeline = @import("word16_global_execution/services/pipeline.zig");
    pub const scope = @import("word16_global_execution/services/gkr_local/service_scope.zig");
    pub const schedule = @import("word16_global_execution/services/schedule.zig");
    pub const keccak = struct {
        pub const shared = struct {
            pub const key = @import("word16_global_execution/keccak/shared/key.zig");
            pub const proof = @import("word16_global_execution/keccak/shared/execution.zig");
            pub const roster = @import("word16_global_execution/keccak/shared/roster.zig");
        };
        pub const proof = @import("word16_global_execution/keccak/execution.zig");
        pub const roster = @import("word16_global_execution/keccak/roster.zig");
    };
    pub const secp = struct {
        pub const proof = @import("word16_global_execution/secp/execution.zig");
        pub const roster = @import("word16_global_execution/secp/roster.zig");
        pub const row_roster = @import("word16_global_execution/secp/row_roster.zig");
    };
    pub const proof = @import("word16_global_execution/services/execution.zig");
    pub const components = @import("word16_global_execution/services/air_components.zig");
    pub const worker = @import("word16_global_execution/services/worker.zig");
    pub const statement = @import("word16_global_execution/services/statement.zig");
    pub const sha256 = struct {
        pub const roster = @import("word16_global_execution/sha256/roster.zig");
    };
    pub const arith256 = struct {
        pub const roster = @import("word16_global_execution/arith256/roster.zig");
    };
    pub const curves = struct {
        pub const roster = @import("word16_global_execution/curves/roster.zig");
    };
    pub const gkr = struct {
        pub const role = @import("word16_global_execution/services/gkr_local/role.zig");
        pub const inputs = @import("word16_global_execution/services/gkr_local/inputs.zig");
        pub const pair_projection = @import("word16_global_execution/services/gkr_local/pair_projection.zig");
        pub const witness = @import("word16_global_execution/services/gkr_local/witness.zig");
        pub const expected_boundary = @import("word16_global_execution/services/gkr_local/expected_boundary.zig");
        pub const truth_components = @import("word16_global_execution/services/gkr_local/truth_components.zig");
    };
    pub const profiling = @import("word16_global_execution/services/profiling.zig");
};
pub const memory = struct {
    pub const statement = @import("word16_execution/memory/statement.zig");
    pub const prepared = @import("word16_execution/memory/prepared.zig");
    pub const collector = @import("word16_execution/memory/collector.zig");
};
pub const delegations = struct {
    pub const secp = @import("delegations/secp256k1/context.zig");
};
pub const source = struct {
    pub const identity = @import("source_identity.zig");
    pub const program = @import("program_image.zig");
    pub const file_io = @import("bounded_file_io.zig");
    pub const profiles = @import("execution_profile_admission.zig");
};
pub const runtime = struct {
    pub const memory_usage = @import("rv64_batch_memory.zig");
    pub const main_arena = @import("rv64_authenticated_main_arena.zig");
    pub const terminal = @import("rv64_ram_terminal.zig");
    pub const verifier_key = @import("rv64_execution_verifier_key.zig");
    pub const verifier_cache = @import("rv64_execution_verifier_cache.zig");
    pub const setup_audit = @import("word16_setup_audit/ownership.zig");
};
pub const recursion = struct {
    pub const circuit_lane = @import("rv64_recursion/circuit_lane.zig");
    pub const native_fixed_root = @import("rv64_recursion/native_fixed_root.zig");
    pub const transcript_walk = @import("rv64_recursion/transcript_walk.zig");
    pub const fold_root = @import("rv64_recursion/fold_root.zig");
    pub const leaf_wrap = @import("rv64_recursion/leaf_wrap.zig");
    pub const root_derive = @import("rv64_recursion/root_derive.zig");
    pub const om31_native = struct {
        pub const truth_leaf = @import("rv64_recursion/om31_native/truth_leaf.zig");
        pub const keccak_leaf = @import("rv64_recursion/om31_native/keccak_leaf.zig");
        pub const schedule_census = @import("rv64_recursion/om31_native/schedule_census.zig");
    };
    pub const services_truth_leaf = @import("rv64_recursion/services_truth_leaf.zig");
    pub const word16_shape = @import("word16_recursion/shape.zig");
};
pub const global = struct {
    pub const proof = @import("word16_global_execution/execution.zig");
    pub const protocol = @import("word16_global_execution/protocol.zig");
    pub const wire = @import("word16_global_execution/wire.zig");
    pub const worker = @import("word16_global_execution/stage1_worker.zig");
    pub const retained_main_prefetch = @import("word16_global_execution/retained_main_prefetch.zig");
    pub const ledger = @import("word16_global_execution/collector.zig");
};
pub const research = struct {
    pub const logup_gkr = struct {
        pub const witness = @import("logup_gkr/witness.zig");
        pub const protocol = @import("logup_gkr/protocol.zig");
        pub const air = @import("logup_gkr/air.zig");
        pub const fast_gkr = @import("logup_gkr/fast_gkr.zig");
    };
    pub const om_classic = struct {
        pub const control = @import("word16_global_execution/services/benchmarks/om_classic/control.zig");
    };
};

/// Unstable real native fixtures and retained matrix oracles for consumer tests.
/// No production caller may derive execution authority from these constructors.
pub const testing = struct {
    pub const sha256 = @import("word16_global_execution/services/sha256_fixture.zig");
    pub const arith256 = @import("word16_global_execution/services/arith256_fixture.zig");
    pub const zbb_words = @import("word16_global_execution/services/zbb_words.zig");
    pub const keccak = @import("word16_global_execution/keccak/fixture.zig");
    pub const secp = @import("word16_global_execution/secp/fixture.zig");
    pub const services = @import("word16_global_execution/services/fixture.zig");
    pub const boundary_guard = @import("word16_global_execution/boundary_guard_fixture.zig");
    pub const adversarial = @import("word16_global_execution/adversarial_fixture.zig");
    pub const coordinator = @import("word16_global_execution/services/gkr_local/coordinator_fixture.zig");
    pub const ls_projection = @import("word16_execution/memory/projection_test_support.zig");
};
