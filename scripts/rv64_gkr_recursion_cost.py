import json,math,hashlib,argparse
from pathlib import Path
parser=argparse.ArgumentParser(description='Static GKR recursion model; not a security or speed qualification.')
parser.add_argument('--roster',type=Path,default=Path(__file__).resolve().parents[1]/'vectors/reports/rv64-word16-execution-20261101/gkr-recursion-cost/roster.json')
parser.add_argument('--output',type=Path,required=True)
args=parser.parse_args()
p=args.roster;roster=json.loads(p.read_text())['cpu']
# (new interaction width, fraction lanes, surviving classic-prefix columns).
strict={'cpu':(32,7,4),'alu':(8,13,0),'alu_tail':(8,13,0),'shift':(24,6,4),'shift_tail':(24,6,4),'multiplication':(8,97,0),'division':(8,26,0),'ls':(24,16,8),'ls_tail':(24,16,8),'keccak_bridge':(32,41,12),'add_bridge':(44,99,12),'double_bridge':(44,99,12),'jalr':(8,3,0)}
broad={'cpu':(8,15,0),'alu':(8,13,0),'alu_tail':(8,13,0),'binary':(8,9,0),'binary_tail':(8,9,0),'shift':(8,11,0),'shift_tail':(8,11,0),'multiplication':(8,97,0),'division':(8,26,0),'ls':(16,18,4),'ls_tail':(16,18,4),'keccak_bridge':(24,42,8),'add_bridge':(36,100,8),'double_bridge':(36,100,8),'shift_table':(8,16,0),'jalr':(8,3,0)}
old_extra={'cpu':4,'alu':4,'alu_tail':4,'binary':4,'binary_tail':4,'shift':4,'shift_tail':4,'multiplication':4,'division':4,'ls':8,'ls_tail':8,'keccak_bridge':20,'add_bridge':20,'double_bridge':20,'shift_table':4,'jalr':4}
def cost(roles,model):
 old=sum(r['columns'][2] for r in roles if r['present']);new=old; ns=[];removed_oods=0;removed_deep=0;changed=[]
 for r in roles:
  if not r['present'] or r['role'] not in model:continue
  width,lanes,kept_previous=model[r['role']];new+=width-r['columns'][2]
  n=r['log']+(lanes-1).bit_length();ns.append(n)
  old_samples=r['columns'][2]+old_extra[r['role']]
  new_samples=(width-8)+kept_previous+16
  oods=old_samples-new_samples;removed_oods+=oods
  # One extra periodicity sample per two-point base coordinate column.
  deep=oods+old_extra[r['role']]-(kept_previous+8);removed_deep+=deep
  changed.append({'role':r['role'],'log':r['log'],'fractions':lanes,'variables':n,'old_inter':r['columns'][2],'new_inter':width,'removed_oods':oods,'removed_deep_entries':deep})
 L=max(ns);S=sum(ns);R=L*(L-1)//2;T=sum(n*(n-1)//2 for n in ns)
 C=3*(S+R+L); leafsaved=70*(math.ceil(old/16)-math.ceil(new/16));oods_saved_blocks=removed_oods/4
 return {'old_inter':old,'new_inter':new,'removed_inter':old-new,'instances':len(ns),'L':L,'S':S,'sumcheck_rounds':R,'GKR_blake_compressions':C,'GKR_blake_G_gates':80*C,'leaf_compressions_saved_q70':leafsaved,'leaf_blake_G_saved':80*leafsaved,'removed_OODS_samples':removed_oods,'removed_DEEP_entries':removed_deep,'OODS_mix_blocks_saved_approx':oods_saved_blocks,'net_hash_compressions_added_approx':C+1-leafsaved-oods_saved_blocks,'sumcheck_fieldops_literal':{'qm31_mul':12*R+12*S+3*T,'qm31_add_sub':13*R+11*S+3*T,'qm31_times_m31':S},'sumcheck_fieldops_with_optimized_round_eval':{'qm31_mul':3*R+12*S+3*T,'qm31_add_sub':7*R+11*S+3*T,'qm31_times_m31':S},'rows':changed}
out={'scope':'Static arithmetic model against exact native roster, not measured accepting GKR circuit. One common late N/D-binding challenge assumed; gate/error review still required. q70 control only, NOT128-bit profile.','roster_path':str(p),'roster_sha256':hashlib.sha256(p.read_bytes()).hexdigest(),'models':{name:[cost(r,m) for r in roster] for name,m in [('strict_range_byte_function',strict),('all_proof_local_candidate',broad)]}}
args.output.write_text(json.dumps(out,indent=2)+'\n')
for name,rows in out['models'].items():
 print(name)
 for i in [0,1,3,5,12,24]:
  r=rows[i];print(i,{k:r[k] for k in ['old_inter','new_inter','removed_inter','instances','L','S','sumcheck_rounds','GKR_blake_compressions','leaf_compressions_saved_q70','removed_OODS_samples','net_hash_compressions_added_approx']})
 print('TOTAL',{k:sum(r[k] for r in rows) for k in ['removed_inter','GKR_blake_compressions','leaf_compressions_saved_q70','removed_OODS_samples','removed_DEEP_entries']})
