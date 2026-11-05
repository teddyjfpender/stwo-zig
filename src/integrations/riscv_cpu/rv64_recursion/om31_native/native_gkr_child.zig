//! Full native-v2 numerical section in the actual native PCS transcript. Roots
//! remain pending until reduced AIR terminal bindings and the physical PCS pass.
const std=@import("std");const core=@import("stwo_core");const engine=@import("stwo_prover_engine");
const C=@import("common.zig");const Public=@import("frame.zig");const G=@import("../../logup_gkr/om31_circuit_verifier.zig");
const Native=@import("../../word16_global_execution/services/native_gkr/v2.zig");
const S=@import("../../word16_global_execution/services/native_gkr/section.zig");const R=@import("../../word16_global_execution/services/native_gkr/roster.zig");
const Strict=@import("../../outer_gkr/circuit.zig");const circuit=@import("stwo_circuit_frontend");
pub const Scope=struct{ordinal:Public.Word,statement:Public.Digest,fixed:Public.Digest,main:Public.Digest,shared:Public.Digest};
pub const Wired=struct{salt:C.F,proof:G.Proof};
pub const Pending=struct{
    artifact:engine.lookups.verifier_kernel.Artifact(C.F),
    local:Native.LocalElementsFor(C.F),binding:Native.Binding.ChallengesFor(C.F),
    global:Native.GlobalSplitFor(C.F),draws:u32,
    pub fn deinit(self:*@This(),ctx:*C.Context)void{self.artifact.deinit(ctx.gpa);self.*=undefined;}
};
const Checks=struct{ctx:*C.Context,pub fn requireEq(self:@This(),left:C.F,right:C.F,_:anytype)!void{try C.eq(self.ctx,left,right);}};
pub fn wire(ctx:*C.Context,roster:*const R.Roster,section:*const S.Section)!Wired{
    try Native.validate(roster);try S.checkShape(roster,&section.proof);try Native.requireSalt(section.salt);
    return .{.salt=try C.F.guess(ctx,section.salt),.proof=try G.wireProof(ctx,&section.proof)};
}
fn requireSalt(ctx:*C.Context,salt:C.F)!void{
    // This polynomial has exactly the 64 permitted scalar roots in OM31.
    // No guessed complement or witness-dependent graph shape is needed.
    var product=C.F.one();
    for(0..S.MAX_SALT_ATTEMPTS) |value|product=product.mul(salt.sub(C.F.fromBase(core.fields.m31.M31.fromCanonical(@intCast(value)))));
    try C.eq(ctx,product,C.F.zero());
}
const HeaderWriter=struct{
    ctx:*C.Context,channel:*Strict.Channel,failure:?anyerror=null,
    pub fn constants(w:*@This(),words:[]const u32)void{w.channel.mixConstU32s(words);}
    pub fn sectionHeader(w:*@This(),magic:u32,version:u32,ordinal:Public.Word)void{
        if(w.failure!=null)return;
        const words=[_]Public.Word{
            circuit.builder.wrappers.constU32(C.Q,w.ctx,magic) catch |err|{w.failure=err;return;},
            circuit.builder.wrappers.constU32(C.Q,w.ctx,version) catch |err|{w.failure=err;return;},ordinal,
        };
        w.channel.inner.mixU32s(C.Q,w.ctx,&words) catch |err|{w.failure=err;};
    }
    pub fn digest(w:*@This(),words:Public.Digest)void{if(w.failure!=null)return;w.channel.inner.mixU32s(C.Q,w.ctx,&words) catch |err|{w.failure=err;};}
    pub fn salt(w:*@This(),value:C.F)void{w.channel.mixFelts(&.{value});}
};
pub fn verify(ctx:*C.Context,channel:*C.Channel,scope:Scope,roster:*const R.Roster,wired:*const Wired)!Pending{
    try Native.validate(roster);try requireSalt(ctx,wired.salt);
    if(wired.proof.sumcheck_proofs.len!=roster.layers() or wired.proof.output_claims_by_instance.len!=roster.instances.len or wired.proof.layer_masks_by_instance.len!=roster.instances.len)return error.NativeGkrShapeMismatch;
    for(wired.proof.sumcheck_proofs,0..) |sumcheck,depth|{
        if(sumcheck.round_polys.len!=depth)return error.NativeGkrShapeMismatch;
        for(sumcheck.round_polys) |poly|{
            if(poly.coefficients.len!=4)return error.NativeGkrShapeMismatch;
            const leading=poly.coefficients[3];try C.eq(ctx,leading.mul(leading.inv()),C.F.one());
        }
    }
    for(wired.proof.layer_masks_by_instance,roster.instances) |masks,instance|{if(masks.len!=instance.variables())return error.NativeGkrShapeMismatch;for(masks) |mask|if(mask.columns.len!=2)return error.NativeGkrShapeMismatch;}
    var strict=Strict.Channel{.context=ctx,.inner=channel.raw};
    const header=try roster.header(ctx.scratch());
    var writer=HeaderWriter{.ctx=ctx,.channel=&strict};Native.emitHeader(scope,header,wired.salt,&writer);
    if(writer.failure) |err|return err;try strict.finish();
    const local=Native.drawLocalElementsFor(C.F,&strict);
    const gates=try ctx.scratch().alloc(engine.lookups.gkr_verifier.ForField(C.O).Gate,roster.instances.len);@memset(gates,.LogUp);
    var artifact=try engine.lookups.verifier_kernel.partiallyVerifyBatch(C.F,ctx.gpa,gates,&wired.proof,&strict,Checks{.ctx=ctx});errdefer artifact.deinit(ctx.gpa);
    try strict.finish();
    if(artifact.n_variables_by_instance.len!=roster.instances.len)return error.NativeGkrShapeMismatch;
    for(artifact.n_variables_by_instance,roster.instances) |variables,instance|if(variables!=instance.variables())return error.NativeGkrShapeMismatch;
    var max_row:u32=0;for(roster.components) |component|if(component.present()){max_row=@max(max_row,component.row_log);};
    if(artifact.ood_point.len<max_row)return error.NativeGkrShapeMismatch;
    for(artifact.ood_point[artifact.ood_point.len-max_row..]) |coordinate|{
        const factor=coordinate.mul(C.F.one().sub(coordinate));try C.eq(ctx,factor.mul(factor.inv()),C.F.one());
    }
    const inverses=try ctx.scratch().alloc(C.F,roster.instances.len);
    for(wired.proof.output_claims_by_instance,inverses) |pair,*inverse|{if(pair.len!=2)return error.NativeGkrShapeMismatch;inverse.*=pair[1].inv();}
    const global=try Native.closeAndSplitFor(C.F,roster,wired.proof.output_claims_by_instance,inverses,Checks{.ctx=ctx});
    var binding=Native.Binding.ChallengesFor(C.F){.gamma=strict.drawSecureFelt(),.rho=@splat(C.F.zero())};
    for(binding.rho[0..roster.instances.len]) |*rho|rho.*=strict.drawSecureFelt();
    try strict.finish();channel.raw=strict.inner;
    return .{.artifact=artifact,.local=local,.binding=binding,.global=global,.draws=strict.draws};
}
