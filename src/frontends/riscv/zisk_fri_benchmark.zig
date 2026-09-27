const std=@import("std");
const core=@import("stwo_core");
const M=core.fields.m31.M31;
const Q=core.fields.qm31.QM31;
const alloc=std.heap.page_allocator;
export fn local_fri_batch(log:u32,rounds:u32,constant:u32) u64 {
 const n=@as(usize,1)<<@intCast(log);
 const input=alloc.alloc(Q,n) catch unreachable;defer alloc.free(input);
 for(input,0..) |*v,i| v.*=if(constant!=0) Q.fromU32Unchecked(1,2,3,4) else Q.fromU32Unchecked(@intCast(i*4+1),@intCast(i*4+2),@intCast(i*4+3),@intCast(i*4+4));
 const domain=core.poly.line.LineDomain.fromCircleDomain(core.poly.circle.canonic.CanonicCoset.new(log+1).circleDomain());
 var workspace=core.fri.FoldLineWorkspace.init(alloc,n/2) catch unreachable;defer workspace.deinit(alloc);
 var sum:u64=0;
 for(0..rounds) |_| {
  const work=alloc.dupe(Q,input) catch unreachable;
  const result=core.fri.foldLineInPlaceNWithWorkspace(alloc,work,domain,Q.fromU32Unchecked(17,29,41,53),&workspace,1) catch unreachable;
  defer alloc.free(result.values);
  for(result.values) |v| for(v.toM31Array(),0..) |x,j| {if(constant!=0 and x.toU32()!=2*(j+1)) return std.math.maxInt(u64);sum +%= x.toU32();};
 }
 return sum;
}
