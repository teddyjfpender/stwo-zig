const transition = @import("air/memory_commitment/incremental_transition_v1.zig");
const frontier = @import("air/memory_commitment/incremental_frontier_v1.zig");
const frontier_component = @import("air/memory_commitment/incremental_frontier_component_v1.zig");
const bridge_v2 = @import("air/memory_commitment/incremental_bridge_v2.zig");
const bridge_component_v2 = @import("air/memory_commitment/incremental_bridge_component_v2.zig");
const transition_v2 = @import("air/memory_commitment/incremental_transition_v2.zig");

test {
    _ = transition;
    _ = frontier;
    _ = frontier_component;
    _ = bridge_v2;
    _ = bridge_component_v2;
    _ = transition_v2;
}
