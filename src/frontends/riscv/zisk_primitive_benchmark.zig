const std=@import("std");
const b3=@import("stwo_core").crypto.blake3_compression;
const keccak=@import("air/guest_precompile/keccakf_authority.zig");
export fn local_keccak(state:*[25]u64) void {keccak.permute(state);}
export fn local_blake3(cv:*const [8]u32,block:*const [16]u32,counter:u64,len:u32,flags:u32,out:*[16]u32) void {out.*=b3.compress(cv.*,block.*,counter,len,flags) catch unreachable;}
export fn local_sha(input:[*]const u8,n:u32,out:*[32]u8) void {std.crypto.hash.sha2.Sha256.hash(input[0..n],out,.{});}
export fn local_primitive_batch(op:u32,n:u32,rounds:u32) u64 {
 const data=std.heap.page_allocator.alloc(u8,@max(n,8)) catch unreachable;defer std.heap.page_allocator.free(data);for(data,0..) |*v,i| v.*=@truncate(i);
 var sum:u64=0;
 for(0..rounds) |r| {
  if(op==0) {var s:[25]u64=undefined;for(&s,0..) |*v,i| v.*=i;s[0]=r;keccak.permute(&s);for(s) |v| sum +%= v;}
  else if(op==1) {std.mem.writeInt(u32,data[0..4],@intCast(r),.little);var out:[32]u8=undefined;local_sha(data.ptr,n,&out);for(0..4) |i| sum +%= std.mem.readInt(u64,out[i*8..][0..8],.little);}
  else {var block:[16]u32=undefined;for(&block,0..) |*v,i| v.*=@as(u32,@intCast(i))*%0x1234567;block[0]=@intCast(r);const out=b3.compress(b3.IV,block,0,64,11) catch unreachable;for(out) |v| sum +%= v;}
 }return sum;
}
