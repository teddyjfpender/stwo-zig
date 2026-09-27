const std=@import("std");
const core=@import("stwo_core");
const batch=@import("pcs/blake3_pow_batch.zig");
const C=core.channel.blake3.Channel;
export fn local_protocol_batch(op:u32,words:u32,rounds:u32) u64 {
 const in=std.heap.page_allocator.alloc(u32,words*2) catch unreachable;defer std.heap.page_allocator.free(in);for(in,0..) |*v,i| v.*=@intCast(i+1);
 var sum:u64=0;var ch=C{};ch.mixU32s(&.{17,29,41});const cv=ch.powChainingValue(26) catch unreachable;
 if(op==0){for(0..rounds) |r| {in[0]=@intCast(r+1);var c=C{};c.mixU32s(in);for(0..8) |_| {const v=c.drawSecureFelt();for(v.toM31Array()) |x| sum +%= x.toU32();}}}
 else {var at:u64=0;while(at<rounds):(at+=4){const out=batch.firstWords(cv,.{at,at+1,at+2,at+3});for(out[0..@min(4,rounds-at)]) |v| sum +%= v;}}
 return sum;
}
export fn local_pow_case(seed:u64,bits:u32,nonce:u64) u32 {var c=C{};c.mixU64(seed);const cv=c.powChainingValue(bits) catch unreachable;return batch.firstWords(cv,.{nonce,nonce,nonce,nonce})[0];}
export fn local_pow_valid(seed:u64,bits:u32,nonce:u64) bool {var c=C{};c.mixU64(seed);return c.verifyPowNonce(bits,nonce);}
// Common canonical-word XOF oracle for TranscriptGL; not our native transcript.
export fn local_transcript_case(data:[*]const u64,words:u32,draws:u32,out:[*]u64) void {
 var h=std.crypto.hash.Blake3.init(.{});var bytes:[8]u8=undefined;const p:u64=0xffffffff00000001;
 for(data[0..words]) |v| {std.mem.writeInt(u64,&bytes,if(v>=p) v-p else v,.little);h.update(&bytes);}
 const digest=std.heap.page_allocator.alloc(u8,@as(usize,draws)*24) catch unreachable;defer std.heap.page_allocator.free(digest);h.final(digest);
 for(0..@as(usize,draws)*3) |i| {const v=std.mem.readInt(u64,digest[i*8..][0..8],.little);out[i]=if(v>=p) v-p else v;}
}
