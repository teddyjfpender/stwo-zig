"""Inspect a partial authenticated account trie before capture-cache eviction.

Only account leaves reached from the independently pinned prior state root can
be evicted. Missing subtree preimages are not invented or fetched here. Eviction
merely forces Kona's original address-bearing proof hint on the next real read.
"""
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import transition_capture as C


def read_hash(kv,digest,maximum):
    name=(bytes([2])+digest[1:]).hex();directory=kv/name[:4];file=directory/(name[4:]+'.txt')
    if not file.exists():return None
    if directory.is_symlink()or file.is_symlink()or file.stat().st_size>2*maximum:raise ValueError('cached preimage bound')
    raw=C.unhex(file.read_text())
    if len(raw)>maximum or C.keccak(raw)!=digest:raise ValueError('cached preimage hash mismatch')
    return raw


def missing_code_leaves(kv,state_root,known_codes=()):
    kv=Path(kv);known=set(known_codes);seen=set();missing=[];code_present={};leaves=0
    root=C.unhex(state_root,32)if isinstance(state_root,str)else state_root
    if len(root)!=32:raise ValueError('account root width')
    def walk(reference,depth,is_root=False):
        nonlocal leaves
        if depth>64:raise ValueError('account trie depth')
        digest=None
        if isinstance(reference,bytes):
            if not reference:return
            if len(reference)!=32:raise ValueError('account child reference')
            if (reference,depth) in seen:return
            seen.add((reference,depth))
            if len(seen)>262144:raise ValueError('account trie inspection cap')
            raw=read_hash(kv,reference,4096)
            if raw is None:
                if is_root:raise ValueError('pinned account root not cached')
                return
            if raw==C.rlp(b''):return
            node=C.decode_rlp(raw);digest=reference
        else:
            node=reference
            if not isinstance(node,list)or len(C.rlp(node))>=32:raise ValueError('account inline reference')
        if not isinstance(node,list):raise ValueError('account trie node')
        if len(node)==17:
            if node[16]:raise ValueError('secure account trie branch value')
            for child in node[:16]:walk(child,depth+1)
        elif len(node)==2 and isinstance(node[0],bytes)and node[0]:
            n=[x for b in node[0]for x in(b>>4,b&15)];flag=n[0]
            if flag>3 or(not flag&1 and n[1]!=0):raise ValueError('account compact path')
            size=len(n)-(1 if flag&1 else 2)
            if flag&2:
                if depth+size!=64 or digest is None or not isinstance(node[1],bytes):raise ValueError('account leaf path')
                account=C.decode_rlp(node[1])
                if not isinstance(account,list)or len(account)!=4 or any(not isinstance(v,bytes)for v in account)or len(account[2])!=32 or len(account[3])!=32:raise ValueError('account leaf fields')
                if len(account[0])>8 or len(account[1])>32 or any(v and v[0]==0 for v in account[:2]):raise ValueError('account integer encoding')
                leaves+=1;code=account[3]
                if code==C.keccak(b'')or code in known:return
                if code not in code_present:code_present[code]=read_hash(kv,code,1<<20)is not None
                if not code_present[code]:
                    missing.append({'leaf_hash':digest.hex(),'code_hash':code.hex()})
                    if len(missing)>4096:raise ValueError('account leaf refresh cap')
            else:
                if not size:raise ValueError('empty account extension')
                walk(node[1],depth+size)
        else:raise ValueError('account trie arity')
    walk(root,0,True)
    return {'state_root':root.hex(),'visited_cached_nodes':len(seen),'verified_account_leaves':leaves,
            'evictions':missing,'distinct_missing_code_hashes':len({x['code_hash']for x in missing})}
