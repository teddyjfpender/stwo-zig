//! Test-only proof-pool lifecycle and identity audit model.

const std = @import("std");

pub const ProofPoolStage = enum(u8) {
    tree1,
    tree2,
    composition,
    openings,
};

const PROOF_POOL_STAGE_COUNT: usize = 4;

pub const TestProofPoolAuditConfig = struct {
    fail_at_stage: ?ProofPoolStage = null,
    probe_nested_helper: bool = false,
};

/// Immutable receipt copied after a real proof attempt has returned. A zero
/// pool address is the intentional serial (`N=1`) representation.
pub const TestProofPoolAuditSnapshot = struct {
    pool_address: usize,
    pool_init_count: usize,
    pool_deinit_count: usize,
    binding_init_count: usize,
    binding_deinit_count: usize,
    stage_observations: [PROOF_POOL_STAGE_COUNT]usize,
    stage_pool_addresses: [PROOF_POOL_STAGE_COUNT]usize,
    stage_identity_mismatches: usize,
    global_resolution_count: usize,
    global_resolution_mismatches: usize,
    lease_acquire_count: usize,
    lease_release_count: usize,
    active_lease_count: usize,
    active_leased_workers: usize,
    max_leased_workers: usize,
    structured_submitted: usize,
    structured_completed: usize,
    nested_helper_probe_count: usize,
    nested_helper_saw_pool_count: usize,
    nested_binding_denied_count: usize,
    publication_count: usize,
    injected_failure_count: usize,
    deinit_residual_leased_workers: usize,
    deinit_residual_reserved_slots: usize,
    deinit_residual_active_slots: usize,
};

/// Test-only mutable observer. Non-test builds compile every observation call
/// to a no-op; the type remains declared so production modules need no
/// conditional imports or alternate signatures.
pub const TestProofPoolAudit = struct {
    mutex: std.Thread.Mutex = .{},
    config: TestProofPoolAuditConfig,
    pool_address: usize = 0,
    pool_init_count: usize = 0,
    pool_deinit_count: usize = 0,
    binding_init_count: usize = 0,
    binding_deinit_count: usize = 0,
    stage_observations: [PROOF_POOL_STAGE_COUNT]usize =
        [_]usize{0} ** PROOF_POOL_STAGE_COUNT,
    stage_pool_addresses: [PROOF_POOL_STAGE_COUNT]usize =
        [_]usize{0} ** PROOF_POOL_STAGE_COUNT,
    stage_identity_mismatches: usize = 0,
    global_resolution_count: usize = 0,
    global_resolution_mismatches: usize = 0,
    lease_acquire_count: usize = 0,
    lease_release_count: usize = 0,
    active_lease_count: usize = 0,
    active_leased_workers: usize = 0,
    max_leased_workers: usize = 0,
    structured_submitted: usize = 0,
    structured_completed: usize = 0,
    nested_helper_probe_count: usize = 0,
    nested_helper_saw_pool_count: usize = 0,
    nested_binding_denied_count: usize = 0,
    publication_count: usize = 0,
    injected_failure_count: usize = 0,
    deinit_residual_leased_workers: usize = 0,
    deinit_residual_reserved_slots: usize = 0,
    deinit_residual_active_slots: usize = 0,
    nested_probe_started: bool = false,

    pub fn init(config: TestProofPoolAuditConfig) TestProofPoolAudit {
        return .{ .config = config };
    }

    pub fn snapshot(self: *TestProofPoolAudit) TestProofPoolAuditSnapshot {
        self.mutex.lock();
        defer self.mutex.unlock();
        return .{
            .pool_address = self.pool_address,
            .pool_init_count = self.pool_init_count,
            .pool_deinit_count = self.pool_deinit_count,
            .binding_init_count = self.binding_init_count,
            .binding_deinit_count = self.binding_deinit_count,
            .stage_observations = self.stage_observations,
            .stage_pool_addresses = self.stage_pool_addresses,
            .stage_identity_mismatches = self.stage_identity_mismatches,
            .global_resolution_count = self.global_resolution_count,
            .global_resolution_mismatches = self.global_resolution_mismatches,
            .lease_acquire_count = self.lease_acquire_count,
            .lease_release_count = self.lease_release_count,
            .active_lease_count = self.active_lease_count,
            .active_leased_workers = self.active_leased_workers,
            .max_leased_workers = self.max_leased_workers,
            .structured_submitted = self.structured_submitted,
            .structured_completed = self.structured_completed,
            .nested_helper_probe_count = self.nested_helper_probe_count,
            .nested_helper_saw_pool_count = self.nested_helper_saw_pool_count,
            .nested_binding_denied_count = self.nested_binding_denied_count,
            .publication_count = self.publication_count,
            .injected_failure_count = self.injected_failure_count,
            .deinit_residual_leased_workers = self.deinit_residual_leased_workers,
            .deinit_residual_reserved_slots = self.deinit_residual_reserved_slots,
            .deinit_residual_active_slots = self.deinit_residual_active_slots,
        };
    }

    pub fn recordPoolInit(self: *TestProofPoolAudit, address: usize) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        self.pool_init_count += 1;
        if (self.pool_address == 0) {
            self.pool_address = address;
        } else if (self.pool_address != address) {
            self.stage_identity_mismatches += 1;
        }
    }

    pub fn recordPoolDeinit(
        self: *TestProofPoolAudit,
        leased_workers: usize,
        reserved_slots: usize,
        active_slots: usize,
    ) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        self.pool_deinit_count += 1;
        self.deinit_residual_leased_workers += leased_workers;
        self.deinit_residual_reserved_slots += reserved_slots;
        self.deinit_residual_active_slots += active_slots;
    }

    pub fn recordBindingInit(self: *TestProofPoolAudit, address: usize) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        self.binding_init_count += 1;
        if (self.pool_address != address) self.stage_identity_mismatches += 1;
    }

    pub fn recordBindingDeinit(self: *TestProofPoolAudit, address: usize) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        self.binding_deinit_count += 1;
        if (self.pool_address != address) self.stage_identity_mismatches += 1;
    }

    pub fn recordStage(
        self: *TestProofPoolAudit,
        stage: ProofPoolStage,
        address: usize,
    ) bool {
        self.mutex.lock();
        defer self.mutex.unlock();
        const index: usize = @intFromEnum(stage);
        self.stage_observations[index] += 1;
        if (self.stage_observations[index] == 1) {
            self.stage_pool_addresses[index] = address;
        } else if (self.stage_pool_addresses[index] != address) {
            self.stage_identity_mismatches += 1;
        }
        if (self.pool_address != address) self.stage_identity_mismatches += 1;
        if (self.config.fail_at_stage == stage and self.injected_failure_count == 0) {
            self.injected_failure_count = 1;
            return true;
        }
        return false;
    }

    pub fn recordGlobalResolution(self: *TestProofPoolAudit, address: usize) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        self.global_resolution_count += 1;
        if (self.pool_address != address) self.global_resolution_mismatches += 1;
    }

    pub fn recordLeaseAcquire(self: *TestProofPoolAudit, address: usize, workers: usize) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.pool_address != address) self.stage_identity_mismatches += 1;
        self.lease_acquire_count += 1;
        self.active_lease_count += 1;
        self.active_leased_workers += workers;
        self.max_leased_workers = @max(self.max_leased_workers, self.active_leased_workers);
    }

    pub fn recordLeaseRelease(self: *TestProofPoolAudit, address: usize, workers: usize) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.pool_address != address) self.stage_identity_mismatches += 1;
        self.lease_release_count += 1;
        if (self.active_lease_count == 0 or self.active_leased_workers < workers) {
            self.stage_identity_mismatches += 1;
            return;
        }
        self.active_lease_count -= 1;
        self.active_leased_workers -= workers;
    }

    pub fn recordStructuredSubmitted(self: *TestProofPoolAudit) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        self.structured_submitted += 1;
    }

    pub fn recordStructuredCompleted(self: *TestProofPoolAudit) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        self.structured_completed += 1;
    }

    pub fn takeNestedProbe(self: *TestProofPoolAudit) bool {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (!self.config.probe_nested_helper or self.nested_probe_started) return false;
        self.nested_probe_started = true;
        return true;
    }

    pub fn recordNestedProbe(
        self: *TestProofPoolAudit,
        helper_saw_pool: bool,
        nested_binding_denied: bool,
    ) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        self.nested_helper_probe_count += 1;
        if (helper_saw_pool) self.nested_helper_saw_pool_count += 1;
        if (nested_binding_denied) self.nested_binding_denied_count += 1;
    }

    pub fn recordPublication(self: *TestProofPoolAudit, address: usize) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        self.publication_count += 1;
        if (self.pool_address != address) self.stage_identity_mismatches += 1;
    }
};
