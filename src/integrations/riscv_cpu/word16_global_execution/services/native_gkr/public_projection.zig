//! Class-owned map from each PlanSlot's AIR count handles to compact metadata.
//! This describes canonical admission; it does not evaluate a producer claim.
const std=@import("std");const A=@import("stwo_riscv_frontend").rv64_air;
const Legacy=@import("../gkr_local/cpu_components.zig");const Frame=@import("../gkr_local/frame.zig");
pub const Rows=enum{zero,initial_boundary,terminal_boundary,ls_head,ls_tail,multiplication,division,bulk,sponge,dword_head,dword_tail,jump_table};
pub const Policy=struct{
    origin:Frame.Origin,rows:Rows=.zero,
    /// bulk[0..7] or sponge[0..1], only for the matching row kinds.
    index:u8=0,
    /// A bridge owns calls/first_ids[family]; all other slots have calls=0,
    /// first_id=1. Bridge `rows` remains the canonical unused zero public.
    family:?u8=null,
    max_rows:u32,max_calls:u32=0,
    /// mul<=2*steps, div<=steps; zero for other row kinds.
    steps_multiplier:u8=0,
};
pub fn forSlot(slot:Legacy.Slot)!Policy{
    if(slot.log<5 or slot.log>23)return error.NativeGkrPublicProjectionShape;
    const count=@as(u32,1)<<@intCast(slot.log);
    var out=Policy{.origin=slot.origin,.max_rows=count-1};
    switch(slot.origin){
        .core=>|role|switch(role){
            .initial=>out.rows=.initial_boundary,.terminal=>out.rows=.terminal_boundary,
            .ls=>out.rows=.ls_head,.ls_tail=>out.rows=.ls_tail,
            .multiplication=>{out.rows=.multiplication;out.max_rows=count;out.steps_multiplier=2;},
            .division=>{out.rows=.division;out.max_rows=count;out.steps_multiplier=1;},
            else=>{out.max_rows=0;},
        },
        .bridge=>|family|{
            out.family=@intFromEnum(family);out.max_rows=0;
            const per_call:usize=if(family==.keccak)25 else A.crypto.secp256k1.word16_bridge.types.coordinates(@import("../types.zig").bridgeKind(family));
            out.max_calls=@intCast((count-1)/per_call);
        },
        .bulk=>|kind|{out.rows=.bulk;out.index=switch(kind){.desc=>0,.copy=>1,.set=>2,.ucopy=>3,.cdesc=>4,.cmp=>5,.jdesc=>6,.jscan=>7,.jtab=>blk:{out.rows=.jump_table;break :blk 6;}};},
        .sponge=>|kind|{out.rows=.sponge;out.index=if(kind==.call)0 else 1;},
        .dword=>|part|out.rows=if(part==0).dword_head else .dword_tail,
    }
    return out;
}
/// Guards must use nonwrapping bounded integer arithmetic. In particular,
/// LS/DWORD head=min(total,max_rows), tail=total-head; every present tail is
/// allowed zero under the strict class roster. Initial/terminal counts are
/// tied to the independently authorized boundary lengths and first/last flags.
pub fn emit(plan:*const Legacy.Plan,writer:anytype)!void{
    for(plan.slots,0..) |slot,index|try writer.slot(index,try forSlot(slot));
}
pub const JUMP_TABLE_ROWS:u32=@intCast(A.crypto.bulk_memory.types.TABLE_ENTRIES);

test "native public projection pins span families, row capacities and inactive tails"{
    var slot=Legacy.Slot{.origin=.{.core=.ls},.log=18,.fixed_offset=0,.main_offset=0,.inter_offset=0,.binding_index=null,.claim_offset=0};
    try std.testing.expectEqual(@as(u32,(1<<18)-1),(try forSlot(slot)).max_rows);
    slot.origin=.{.bridge=.keccak};const bridge=try forSlot(slot);
    try std.testing.expectEqual(@as(?u8,0),bridge.family);try std.testing.expectEqual(@as(u32,((1<<18)-1)/25),bridge.max_calls);try std.testing.expectEqual(@as(u32,0),bridge.max_rows);
    slot.origin=.{.bulk=.jtab};const table=try forSlot(slot);try std.testing.expectEqual(Rows.jump_table,table.rows);try std.testing.expectEqual(@as(u8,6),table.index);
    slot.origin=.{.core=.multiplication};const mul=try forSlot(slot);try std.testing.expectEqual(@as(u32,1<<18),mul.max_rows);try std.testing.expectEqual(@as(u8,2),mul.steps_multiplier);
    slot.origin=.{.dword=1};try std.testing.expectEqual(Rows.dword_tail,(try forSlot(slot)).rows);
}
