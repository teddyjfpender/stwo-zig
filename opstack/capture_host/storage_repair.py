"""Explicit bounded native-host storage repair; no consensus/prover integration."""
import json
import math
import subprocess
from pathlib import Path
import time
import transition_capture as C
import transition_rpc_adapter as A
from capture_host.recover_storage_sibling import missing_path,helper_slot

class Repair:
    def __init__(self,adapter,kv,header_path,helper,output,limit=8):
        if type(limit)is not int or not 1<=limit<=8:raise ValueError('storage repair count cap')
        self.adapter=adapter;self.kv=kv;self.helper=helper;self.output=output;self.limit=limit;self.attempts=0;self.proof_bytes=0
        self.header=header_path.read_bytes();self.decoded=C.decode_rlp(self.header);self.block_hash=C.keccak(self.header)
        if adapter.deadline is None:raise ValueError('storage repair requires shared deadline')
        self.helper_hash=C.sha(helper.read_bytes());self.seen=set()

    def __call__(self,target):
        if len(target)!=32 or self.attempts>=self.limit or target in self.seen:raise ValueError('storage repair count/repeated-target refusal')
        self.seen.add(target);self.attempts+=1
        directory=self.output/str(self.attempts);directory.mkdir(parents=True,exist_ok=False)
        entry={'target':target.hex(),'block_hash':self.block_hash.hex(),'state_root':self.decoded[3].hex(),'helper_sha256':self.helper_hash,'attempt':self.attempts,'limit':self.limit}
        try:
            matches=[];roots=set()
            # code_proofs are loaded/reverified by the adapter; recheck independently
            # to ensure that live additions cannot change this pinned-root policy.
            for source in self.adapter.code_proofs.values():
                if C.unhex(source['header_rlp'])!=self.header:raise ValueError('repair provenance header mismatch')
                _,_,root=A.verified_account(self.decoded[3],source['address'],source['account'])
                if root in roots:continue
                roots.add(root)
                try:prefix=missing_path(self.kv,root,target)
                except ValueError as error:
                    if str(error)=='missing node must have one authenticated reachable path':continue
                    raise
                matches.append((source['address'],prefix))
            if len(matches)!=1:raise ValueError('repair requires one authenticated known storage owner')
            address,prefix=matches[0];remaining=math.floor(self.adapter.deadline-time.monotonic())
            if remaining<1:raise ValueError('storage repair global deadline')
            slot,tries=helper_slot(self.helper,prefix,min(60,remaining))
            block=self.adapter.block('0x'+self.block_hash.hex(),readahead=False)
            if C.header_rlp(block)!=self.header:raise ValueError('repair RPC pinned header mismatch')
            proof=self.adapter.remote('eth_getProof',[address,['0x'+slot.hex()],{'blockHash':'0x'+self.block_hash.hex(),'requireCanonical':True}],cap=A.MAX_RESPONSE)
            records,_=A.verified_proof(block,address,[slot],proof)
            if target not in records:raise ValueError('repair proof lacks exact requested node')
            if time.monotonic()>=self.adapter.deadline:raise ValueError('storage repair global deadline')
            proof_data=(json.dumps(proof)+'\n').encode()
            records_data=(json.dumps([(k.hex(),v.hex())for k,v in sorted(records.items())])+'\n').encode()
            if self.proof_bytes+len(proof_data)+len(records_data)>16<<20:raise ValueError('repair aggregate ledger byte bound')
            # Validate aggregate adapter bounds before publishing a successful ledger.
            self.adapter.retain(records)
            C.write_new(directory/'proof.json',proof_data)
            C.write_new(directory/'records.json',records_data)
            self.proof_bytes+=len(proof_data)+len(records_data)
            entry.update(status='verified',address=address,prefix=prefix,slot=slot.hex(),search_attempts=tries,verified_nodes=len(records))
            C.write_new(directory/'repair.json',(json.dumps(entry,indent=2)+'\n').encode())
            return records
        except BaseException as error:
            entry.update(status='failed',error_type=type(error).__name__)
            C.write_new(directory/'failure.json',(json.dumps(entry,indent=2)+'\n').encode())
            if isinstance(error,(OSError,subprocess.SubprocessError)):raise ValueError('bounded storage repair helper/source failure')from None
            raise
