//! Source-policy scaffolding only. Validating this descriptor authenticates no
//! page proof, CPU state or RAM snapshot, and grants no execution admission.
const std = @import("std");
pub const VERSION: u32 = 1;
pub const MAX_PAGES = 4096;
pub const MAX_PAGE_WORKERS = 256;
const P: u64 = 2147483647;
pub const Root = [36]u8;
pub const Identity = [32]u8;
pub const Boundary = struct {
    /// Must eventually be computed from ALL architectural PC/register words.
    cpu: Root,
    /// Must eventually authenticate the complete memory state, not touched cells.
    ram: Root,
};
pub const SignedMass = struct { positive: u64 = 0, negative: u64 = 0 };
pub const Page = struct {
    ordinal: u32,
    first_cpu: u64,
    cpu_count: u32,
    worker_count: u32,
    first_step: u64,
    steps: u64,
    before: Boundary,
    after: Boundary,
    /// Independently reconstructed per-page inventory identity.
    inventory: Identity,
    /// Commits every page MAIN/receipt before page relation challenges.
    manifest: Root,
    /// Page root authenticates that page's exact inventory and closure.
    proof_output: Root,
    mass: [3]SignedMass, // RAM, KIO, Wire: distinct namespaces.
    /// v1 rejects cross-page unfinished service obligations.
    pending_services: u32 = 0,
};
pub const Expected = struct {
    version: u32 = VERSION,
    program: Identity,
    input: Identity,
    policy: Identity,
    native_profile: u32,
    total_cpus: u64,
    total_steps: u64,
    initial: Boundary,
    terminal: Boundary,
};
pub const Pending = struct {
    pages: u32,
    workers: u64,
    /// Per-page bounds are NOT summed inside one finite-characteristic relation.
    max_page_mass: u64,
    execution_verified: bool = false,
    production_admission: bool = false,
};
fn requireRoot(root: Root) !void {
    for (0..9) |i| if (std.mem.readInt(u32, root[i * 4 ..][0..4], .little) >= P) return error.HierarchyNoncanonicalRoot;
}
fn requireBoundary(b: Boundary) !void {
    try requireRoot(b.cpu);
    try requireRoot(b.ram);
}
fn same(a: Boundary, b: Boundary) bool {
    return std.mem.eql(u8, &a.cpu, &b.cpu) and std.mem.eql(u8, &a.ram, &b.ram);
}
pub fn validate(expected: Expected, pages: []const Page) !Pending {
    if (expected.version != VERSION or pages.len == 0 or pages.len > MAX_PAGES or expected.total_cpus == 0 or expected.total_steps == 0) return error.HierarchyShape;
    try requireBoundary(expected.initial);
    try requireBoundary(expected.terminal);
    var cpu: u64 = 0;
    var step: u64 = 0;
    var workers: u64 = 0;
    var mass: u64 = 0;
    var boundary = expected.initial;
    for (pages, 0..) |page, i| {
        if (page.ordinal != i or page.first_cpu != cpu or page.first_step != step) return error.HierarchyCoverage;
        if (page.cpu_count == 0 or page.worker_count < page.cpu_count or page.worker_count > MAX_PAGE_WORKERS or page.steps == 0) return error.HierarchyPageShape;
        if (page.pending_services != 0) return error.HierarchyUnclosedServices;
        try requireBoundary(page.before);
        try requireBoundary(page.after);
        try requireRoot(page.manifest);
        try requireRoot(page.proof_output);
        if (!same(boundary, page.before)) return error.HierarchyBoundaryContinuity;
        for (page.mass) |relation| {
            if (relation.positive >= P or relation.negative >= P) return error.HierarchyCharacteristicBound;
            mass = @max(mass, @max(relation.positive, relation.negative));
        }
        cpu = std.math.add(u64, cpu, page.cpu_count) catch return error.HierarchyOverflow;
        step = std.math.add(u64, step, page.steps) catch return error.HierarchyOverflow;
        workers = std.math.add(u64, workers, page.worker_count) catch return error.HierarchyOverflow;
        if (cpu > expected.total_cpus or step > expected.total_steps) return error.HierarchyCoverage;
        boundary = page.after;
    }
    if (cpu != expected.total_cpus or step != expected.total_steps) return error.HierarchyCoverage;
    if (!same(boundary, expected.terminal)) return error.HierarchyTerminal;
    return .{ .pages = @intCast(pages.len), .workers = workers, .max_page_mass = mass };
}
fn integer(h: *std.crypto.hash.sha2.Sha256, x: u64) void {
    var bytes: [8]u8 = undefined;
    std.mem.writeInt(u64, &bytes, x, .little);
    h.update(&bytes);
}
fn boundaryHash(h: *std.crypto.hash.sha2.Sha256, b: Boundary) void {
    h.update(&b.cpu);
    h.update(&b.ram);
}
/// Bookkeeping fingerprint of the canonical typed descriptor, NOT an admitted
/// transcript or supermanifest. It must not replace a constrained root binding.
pub fn fingerprint(expected: Expected, pages: []const Page) !Identity {
    _ = try validate(expected, pages);
    var h = std.crypto.hash.sha2.Sha256.init(.{});
    h.update("OP-execution-hierarchy-source-descriptor/v1\x00");
    integer(&h, expected.version);
    h.update(&expected.program);
    h.update(&expected.input);
    h.update(&expected.policy);
    integer(&h, expected.native_profile);
    integer(&h, expected.total_cpus);
    integer(&h, expected.total_steps);
    boundaryHash(&h, expected.initial);
    boundaryHash(&h, expected.terminal);
    integer(&h, pages.len);
    for (pages) |page| {
        integer(&h, page.ordinal);
        integer(&h, page.first_cpu);
        integer(&h, page.cpu_count);
        integer(&h, page.worker_count);
        integer(&h, page.first_step);
        integer(&h, page.steps);
        boundaryHash(&h, page.before);
        boundaryHash(&h, page.after);
        h.update(&page.inventory);
        h.update(&page.manifest);
        h.update(&page.proof_output);
        for (page.mass) |relation| {
            integer(&h, relation.positive);
            integer(&h, relation.negative);
        }
        integer(&h, page.pending_services);
    }
    var out: Identity = undefined;
    h.final(&out);
    return out;
}
fn testBoundary(x: u8) Boundary {
    var root: Root = @splat(0);
    root[0] = x;
    return .{ .cpu = root, .ram = root };
}
fn fixture() struct { expected: Expected, pages: [4]Page } {
    var pages: [4]Page = undefined;
    var first: u64 = 0;
    for (&pages, 0..) |*page, i| {
        const count: u32 = if (i == 3) 133 else 200;
        page.* = .{ .ordinal = @intCast(i), .first_cpu = first, .cpu_count = count, .worker_count = count + 20, .first_step = first * (1 << 22), .steps = @as(u64, count) * (1 << 22), .before = testBoundary(@intCast(i)), .after = testBoundary(@intCast(i + 1)), .inventory = @splat(@intCast(i)), .manifest = testBoundary(5).ram, .proof_output = testBoundary(6).ram, .mass = @splat(.{ .positive = 1_500_000_000, .negative = 1_500_000_000 }) };
        first += count;
    }
    return .{ .expected = .{ .program = @splat(1), .input = @splat(2), .policy = @splat(3), .native_profile = 7, .total_cpus = first, .total_steps = first * (1 << 22), .initial = testBoundary(0), .terminal = testBoundary(4) }, .pages = pages };
}
test "hierarchy descriptor covers 733 CPU shards without enlarging native page cap" {
    const f = fixture();
    const pending = try validate(f.expected, &f.pages);
    try std.testing.expectEqual(@as(u64, 813), pending.workers);
    try std.testing.expect(!pending.execution_verified and !pending.production_admission);
    const original = try fingerprint(f.expected, &f.pages);
    var changed = f;
    changed.expected.policy[31] ^= 1;
    try std.testing.expect(!std.mem.eql(u8, &original, &try fingerprint(changed.expected, &changed.pages)));
    changed = f;
    changed.pages[2].manifest[32] ^= 1;
    try std.testing.expect(!std.mem.eql(u8, &original, &try fingerprint(changed.expected, &changed.pages)));
}
test "hierarchy rejects gaps duplication reorder continuity and characteristic aliases" {
    const f = fixture();
    var c = f;
    c.pages[1].first_cpu += 1;
    try std.testing.expectError(error.HierarchyCoverage, validate(c.expected, &c.pages));
    c = f;
    c.pages[1] = c.pages[0];
    try std.testing.expectError(error.HierarchyCoverage, validate(c.expected, &c.pages));
    c = f;
    c.pages[1].before.ram[0] ^= 1;
    try std.testing.expectError(error.HierarchyBoundaryContinuity, validate(c.expected, &c.pages));
    c = f;
    c.pages[3].after.cpu[0] ^= 1;
    try std.testing.expectError(error.HierarchyTerminal, validate(c.expected, &c.pages));
    c = f;
    c.pages[0].mass[2].negative = P;
    try std.testing.expectError(error.HierarchyCharacteristicBound, validate(c.expected, &c.pages));
    c = f;
    c.pages[0].pending_services = 1;
    try std.testing.expectError(error.HierarchyUnclosedServices, validate(c.expected, &c.pages));
    c = f;
    c.pages[0].worker_count = 257;
    try std.testing.expectError(error.HierarchyPageShape, validate(c.expected, &c.pages));
    c = f;
    std.mem.writeInt(u32, c.pages[0].manifest[32..36], @intCast(P), .little);
    try std.testing.expectError(error.HierarchyNoncanonicalRoot, validate(c.expected, &c.pages));
    try std.testing.expectError(error.HierarchyCoverage, validate(f.expected, f.pages[0..3]));
    c = f;
    c.expected.total_steps = std.math.maxInt(u64);
    c.pages[0].steps = std.math.maxInt(u64);
    c.pages[1].first_step = std.math.maxInt(u64);
    try std.testing.expectError(error.HierarchyOverflow, validate(c.expected, &c.pages));
    c = f;
    std.mem.swap(Page, &c.pages[1], &c.pages[2]);
    try std.testing.expectError(error.HierarchyCoverage, validate(c.expected, &c.pages));
    try std.testing.expectError(error.HierarchyShape, validate(f.expected, &.{}));
    c = f;
    c.expected.version += 1;
    try std.testing.expectError(error.HierarchyShape, validate(c.expected, &c.pages));
}
