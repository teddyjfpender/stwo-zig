#!/usr/bin/env python3
"""Reproduce oracle-only type/import lift from the pinned primary Stwo source."""
import argparse,hashlib,json,subprocess,tempfile
from pathlib import Path

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--upstream',type=Path,required=True);p.add_argument('--check',action='store_true');a=p.parse_args()
 out=Path(__file__).resolve().parent/'src/om_gkr/reference';prov=json.loads((out/'provenance.json').read_text())
 rev=subprocess.check_output(['git','-C',str(a.upstream),'rev-parse','HEAD'],text=True).strip()
 if rev!=prov['revision']:raise SystemExit('wrong upstream revision')
 for row in prov['files']:
  path=a.upstream/'crates/stwo/src/prover/lookups'/row['file'];src=path.read_text()
  if hashlib.sha256(src.encode()).hexdigest()!=row['upstream_sha256']:raise SystemExit('upstream source changed: '+row['file'])
  s=src.split('#[cfg(test)]')[0]
  if row['file']=='sumcheck.rs':
   s='use num_traits::{One, Zero};\nuse thiserror::Error;\nuse super::utils::UnivariatePoly;\nuse crate::om_gkr::{Channel, SecureField};\n\n'+s[s.index('pub fn partially_verify('):]
  else:
   s=s.replace('use crate::core::channel::Channel;','use crate::om_gkr::Channel;').replace('use crate::core::fields::qm31::SecureField;','use crate::om_gkr::SecureField;').replace('use crate::prover::lookups::sumcheck;','use super::sumcheck;').replace('use crate::core::','use stwo::core::')
  if row['file']=='utils.rs':s=s.replace('pub struct UnivariatePoly<F: Field>(Vec<F>);','pub struct UnivariatePoly<F: Field>(pub(crate) Vec<F>);')
  with tempfile.TemporaryDirectory() as tmp:
   f=Path(tmp)/row['file'];f.write_text('// Mechanically lifted from pinned Stwo; see provenance.json.\n'+s)
   subprocess.run(['rustfmt','+nightly-2025-07-14','--edition','2021','--config','skip_children=true',str(f)],check=True)
   expected=f.read_bytes()
  destination=out/row['file']
  if a.check:
   if destination.read_bytes()!=expected:raise SystemExit('mechanical lift drift: '+row['file'])
   if hashlib.sha256(expected).hexdigest()!=row['lifted_sha256']:raise SystemExit('provenance drift: '+row['file'])
  else:
   destination.write_bytes(expected);row['lifted_sha256']=hashlib.sha256(expected).hexdigest()
 if not a.check:(out/'provenance.json').write_text(json.dumps(prov,indent=2)+'\n')
 print('pinned source lift matches' if a.check else 'pinned source lift regenerated')
if __name__=='__main__':main()
