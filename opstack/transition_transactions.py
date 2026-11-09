"""Canonical RPC transaction reconstruction for capture-only trie validation."""
import transition_capture as C


def q(value,bits=256):
    raw=C.quantity(value)
    if len(raw)*8>bits:raise ValueError('transaction integer width exceeded')
    return raw


def address(value):
    return b'' if value is None else C.unhex(value,20)


def access_list(value):
    if not isinstance(value,list) or len(value)>4096:raise ValueError('access list bound')
    out=[]
    for item in value:
        keys=item['storageKeys']
        if not isinstance(keys,list) or len(keys)>4096:raise ValueError('access storage bound')
        out.append([C.unhex(item['address'],20),[C.unhex(k,32)for k in keys]])
    return out


def encoded(tx):
    kind=int.from_bytes(q(tx.get('type','0x0'),8),'big')
    data=C.unhex(tx['input'])
    if len(data)>1<<20:raise ValueError('transaction data bound')
    if kind==0x7e:
        system=tx.get('isSystemTx',False)
        if not isinstance(system,bool):raise ValueError('deposit system flag')
        fields=[C.unhex(tx['sourceHash'],32),C.unhex(tx['from'],20),address(tx.get('to')),
                q(tx['mint'])if tx.get('mint')is not None else b'',q(tx['value']),q(tx['gas'],64),b'\x01'if system else b'',data]
    elif kind==0:
        fields=[q(tx['nonce'],64),q(tx['gasPrice']),q(tx['gas'],64),address(tx.get('to')),q(tx['value']),data,q(tx['v']),q(tx['r']),q(tx['s'])]
    elif kind in(1,2,3,4):
        fields=[q(tx['chainId']),q(tx['nonce'],64)]
        fields += [q(tx['gasPrice'])]if kind==1 else[q(tx['maxPriorityFeePerGas']),q(tx['maxFeePerGas'])]
        fields += [q(tx['gas'],64),address(tx.get('to')),q(tx['value']),data,access_list(tx['accessList'])]
        if kind==3:
            hashes=tx['blobVersionedHashes']
            if not isinstance(hashes,list)or len(hashes)>256:raise ValueError('blob hash count')
            fields += [q(tx['maxFeePerBlobGas']),[C.unhex(h,32)for h in hashes]]
        if kind==4:
            auths=tx['authorizationList']
            if not isinstance(auths,list)or len(auths)>4096:raise ValueError('authorization count')
            fields += [[[q(a['chainId']),C.unhex(a['address'],20),q(a['nonce'],64),q(a['yParity'],8),q(a['r']),q(a['s'])]for a in auths]]
            if any(a[3]not in(b'',b'\x01')for a in fields[-1]):raise ValueError('authorization parity')
        parity=q(tx['yParity'] if 'yParity'in tx else tx['v'],8)
        if parity not in(b'',b'\x01'):raise ValueError('transaction parity')
        fields += [parity,q(tx['r']),q(tx['s'])]
    else:raise ValueError('unsupported transaction type')
    raw=(bytes([kind])if kind else b'')+C.rlp(fields)
    if C.keccak(raw)!=C.unhex(tx['hash'],32):raise ValueError('transaction hash mismatch')
    return raw


def verify_block(block):
    from transition_rpc_adapter import trie_root
    C.header_rlp(block)
    txs=block['transactions']
    if not isinstance(txs,list)or len(txs)>16384:raise ValueError('transaction count bound')
    raw=[]
    for i,tx in enumerate(txs):
        if tx.get('blockHash')is not None and C.unhex(tx['blockHash'],32)!=C.unhex(block['hash'],32):raise ValueError('transaction block hash mismatch')
        if tx.get('transactionIndex')is not None and int.from_bytes(q(tx['transactionIndex'],64),'big')!=i:raise ValueError('transaction index mismatch')
        raw.append(encoded(tx))
    root,records=trie_root([(C.rlp(i.to_bytes((i.bit_length()+7)//8,'big')),v)for i,v in enumerate(raw)])
    if root!=C.unhex(block['transactionsRoot'],32):raise ValueError('transaction trie root mismatch')
    return records


def l1_origin(block):
    """Extract only from the authenticated L1-info deposit at transaction zero."""
    verify_block(block)
    if not block['transactions']:raise ValueError('missing L1-info deposit')
    tx=block['transactions'][0]
    if tx['type']!='0x7e' or C.unhex(tx['from'],20)!=bytes.fromhex('deaddeaddeaddeaddeaddeaddeaddeaddead0001') or C.unhex(tx['to'],20)!=bytes.fromhex('4200000000000000000000000000000000000015'):
        raise ValueError('invalid L1-info deposit authority')
    data=C.unhex(tx['input']);selector=data[:4].hex()
    lengths={'015d8eb9':260,'440a5e20':164,'098999be':176,'3db6be2b':178}
    if selector not in lengths or len(data)!=lengths[selector]:raise ValueError('unsupported L1-info format')
    if selector=='015d8eb9':
        number=int.from_bytes(data[4:36],'big');sequence=int.from_bytes(data[132:164],'big')
    else:
        number=int.from_bytes(data[28:36],'big');sequence=int.from_bytes(data[12:20],'big')
    if number>=1<<64 or sequence>=1<<64:raise ValueError('L1-info integer bound')
    digest=data[100:132]
    source=C.keccak((1).to_bytes(32,'big')+C.keccak(digest+sequence.to_bytes(32,'big')))
    if source!=C.unhex(tx['sourceHash'],32):raise ValueError('L1-info source domain mismatch')
    return {'number':number,'hash':'0x'+digest.hex(),'sequence_number':sequence,
            'transaction_hash':tx['hash'],'transactions_root':block['transactionsRoot']}
