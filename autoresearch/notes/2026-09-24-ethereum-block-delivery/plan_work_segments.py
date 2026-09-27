"""Propose exact-cycle schedules from a complete measured commitment census.

This is an interpolation model, not a capacity certificate. Every candidate must
be replayed through the all-segment geometry scan and canonical proving.
"""
from pathlib import Path
from fractions import Fraction
import argparse,hashlib,json

def propose(rows, leaves, maximum, terminal):
    if leaves<1 or leaves&(leaves-1): raise ValueError('power-of-two leaf count required by current span protocol')
    total_cycles=sum(r['cycles'] for r in rows)
    if not rows or terminal<1 or terminal>total_cycles or maximum<1: raise ValueError('invalid execution bounds')
    if terminal>maximum or total_cycles>leaves*maximum or total_cycles<leaves-1+terminal: raise ValueError('infeasible slot capacity')
    weights=[max(1,r['commitment_rows'][0]) for r in rows]
    total_weight=sum(weights)
    boundaries=[0];i=0;prefix=0
    for slot in range(1,leaves):
        target=Fraction(total_weight*slot,leaves)
        while i+1<len(rows) and prefix+weights[i]<target:
            prefix+=weights[i];i+=1
        row=rows[i]
        offset=int((target-prefix)*row['cycles']/weights[i])
        proposed=row['global_first_cycle']-1+offset
        remaining=leaves-slot
        lower=max(boundaries[-1]+1,total_cycles-remaining*maximum)
        upper=min(boundaries[-1]+maximum,total_cycles-terminal-(remaining-1))
        if lower>upper: raise ValueError('infeasible remaining capacity')
        boundaries.append(max(lower,min(upper,proposed)))
    boundaries.append(total_cycles)
    budgets=[b-a for a,b in zip(boundaries,boundaries[1:])]
    if budgets[-1]<terminal:
        delta=terminal-budgets[-1];budgets[-2]-=delta;budgets[-1]+=delta
    if any(n<=0 or n>maximum for n in budgets): raise ValueError('candidate violates execution capacity; increase leaf count')
    assert sum(budgets)==total_cycles and len(budgets)==leaves
    return budgets,total_weight

def main():
    p=argparse.ArgumentParser()
    p.add_argument('census',type=Path);p.add_argument('output',type=Path)
    p.add_argument('--leaves',type=int,required=True)
    p.add_argument('--maximum-cycles',type=int,default=4194304)
    p.add_argument('--required-terminal-cycles',type=int,default=56)
    args=p.parse_args()
    records=[json.loads(x) for x in args.census.read_text().splitlines()]
    summary=records[-1];rows=records[:-1]
    if summary.get('kind')!='summary' or summary['segments_checked']!=len(rows): raise ValueError('incomplete census')
    cycle=1
    for i,row in enumerate(rows):
        if row['target']!=i or row['global_first_cycle']!=cycle or row['proof_verified']: raise ValueError('invalid census coverage')
        cycle+=row['cycles']
    if cycle-1!=summary['cycles']: raise ValueError('wrong total cycles')
    budgets,weight=propose(rows,args.leaves,args.maximum_cycles,args.required_terminal_cycles)
    with args.output.open('x') as f: json.dump(budgets,f);f.write('\n')
    args.output.with_suffix('.metadata.json').write_text(json.dumps({
        'scope':'candidate from piecewise G-row density; requires independent full census and proofs',
        'proof_verified':False,'census_sha256':hashlib.sha256(args.census.read_bytes()).hexdigest(),
        'schedule_sha256':hashlib.sha256(args.output.read_bytes()).hexdigest(),
        'cycles':sum(budgets),'leaves':len(budgets),'min_cycles':min(budgets),'max_cycles':max(budgets),
        'source_G_rows':weight,'source_G_rows_per_target_leaf':weight/args.leaves,
        'required_terminal_cycles':args.required_terminal_cycles,
    },indent=2)+'\n')

if __name__=='__main__': main()
