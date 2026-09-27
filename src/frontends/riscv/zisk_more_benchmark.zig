const std = @import("std");
const core = @import("stwo_core");
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const alloc = std.heap.page_allocator;
fn q(words: [*]const u64) Q {
    var a: [4]M = undefined;
    for (&a, 0..) |*v, i| v.* = M.fromCanonical(@intCast(words[i] % core.fields.m31.Modulus));
    return Q.fromM31Array(a);
}
export fn local_ext(op: u32, a: [*]const u64, b: [*]const u64, out: [*]u64) void {
    const x = q(a); const y = q(b);
    const z = if (op == 0) x.add(y) else if (op == 1) x.mul(y) else x.inv() catch unreachable;
    for (z.toM31Array(), 0..) |v, i| out[i] = v.toU32();
}
export fn local_ext_batch(op: u32, rounds: u32) u64 {
    var x = Q.fromU32Unchecked(19,29,37,41);
    const y = Q.fromU32Unchecked(65537,97,103,107);
    var sum: u64 = 0;
    for (0..rounds) |i| {
        const z = if (op == 0) x.add(y) else if (op == 1) x.mul(y) else blk: { x.c0.a = M.fromCanonical(@intCast(i+1)); break :blk x.inv() catch unreachable; };
        for (z.toM31Array()) |v| sum +%= v.toU32();
        if (op < 2) x = z;
    }
    return sum;
}
const More = struct { n: usize, cols: usize, input: []M, out: []M, words: []u64, tree: []u64 };
export fn local_more_create(n: u32, cols: u32) *More {
    const t = alloc.create(More) catch unreachable;
    t.* = .{ .n=n,.cols=cols,.input=alloc.alloc(M,n) catch unreachable,.out=alloc.alloc(M,n) catch unreachable,.words=alloc.alloc(u64,@as(usize,n)*cols) catch unreachable,.tree=alloc.alloc(u64,@as(usize,n)*8) catch unreachable };
    for(t.input,0..) |*v,i| v.*=M.fromCanonical(@intCast(i+1));
    for(t.words,0..) |*v,i| v.*=i+1;
    return t;
}
export fn local_more_destroy(t: *More) void { alloc.free(t.input);alloc.free(t.out);alloc.free(t.words);alloc.free(t.tree);alloc.destroy(t); }
fn canonical(v: u64) u64 { const p: u64 = 0xffffffff00000001;return if(v>=p) v-p else v; }
fn hashWords(words: []const u64, out: []u64) void {
    var h = std.crypto.hash.Blake3.init(.{});
    var bytes: [512]u8 = undefined;
    var pos: usize = 0;
    while(pos<words.len) { const n:usize=@min(64,words.len-pos);for(words[pos..][0..n],0..) |v,i| std.mem.writeInt(u64,bytes[i*8..][0..8],canonical(v),.little);h.update(bytes[0..n*8]);pos+=n; }
    var digest: [32]u8=undefined;h.final(&digest);
    for(0..4) |i| out[i]=canonical(std.mem.readInt(u64,digest[i*8..][0..8],.little));
}
export fn local_more_run(t: *More, op: u32, rounds: u32, root: [*]u64) u64 {
    var sum: u64=0;
    for(0..rounds) |r| {
        if(op==0) { core.fields.batchInverseInPlace(M,t.input,t.out) catch unreachable;for(t.out) |v| sum +%= v.toU32(); }
        else {
            t.words[0]=r+1;
            for(0..t.n) |i| hashWords(t.words[i*t.cols..][0..t.cols],t.tree[i*4..][0..4]);
            var offset:usize=0;var n=t.n;
            while(n>1) {for(0..n/2) |i| hashWords(t.tree[offset+i*8..][0..8],t.tree[offset+n*4+i*4..][0..4]);offset+=n*4;n/=2;}
            for(0..4) |i| {root[i]=t.tree[offset+i];sum +%= root[i];}
        }
    }
    return sum;
}
export fn local_native_batch(op:u32,rounds:u32) u64 {
    const H=core.vcs_lifted.blake3_merkle.MerkleHasher;
    var left: [32]u8=@splat(0);const right: [32]u8=@splat(1);
    var values:[16]M=undefined;for(&values,0..) |*v,i| v.*=M.fromCanonical(@intCast(i+1));
    var sum:u64=0;
    for(0..rounds) |r| {
        std.mem.writeInt(u64,left[0..8],r+1,.little);values[0]=M.fromCanonical(@intCast(r+1));
        const digest=if(op==0) H.hashChildren(.{.left=left,.right=right}) else blk: { var h=H.defaultWithInitialState();h.updateLeaf(&values);break :blk h.finalize(); };
        for(0..4) |j| sum +%= std.mem.readInt(u64,digest[j*8..][0..8],.little);
    }
    return sum;
}
export fn local_more_dump(t:*More,index:u32,out:[*]u64) void {for(0..4) |j| out[j]=t.tree[@as(usize,index)*4+j];}
