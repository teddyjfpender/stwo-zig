// Canonical fixed24/main54. Reuses the word emitter's exact integer bridge;
// neither virtual event log nor a materialized one-event witness is created.
kernel void stwo_zig_ram_lanes_witness_v1(
    device const uint *records [[buffer(0)]], device const uint *claim [[buffer(1)]],
    device uint *output [[buffer(2)]], device atomic_uint *status [[buffer(3)]],
    constant uint &rows [[buffer(4)]], uint logical [[thread_position_in_grid]]) {
    if(logical>=rows) return;
    uint physical=framework_interaction_row(logical,rows);
    for(uint lane=0u;lane<2u;++lane) {
        uint event=2u*logical+lane;
        stwo_word_emit_event(records,claim,output,status,rows,event,physical,
            lane*12u,24u+lane*27u,logical+1u==rows && lane==1u);
        if(event<claim[4] && records[6ul*event]!=1u)
            atomic_fetch_or_explicit(status,4u,memory_order_relaxed);
    }
}
