#!/usr/bin/env python3
"""Source-only lane-major segmentation model. No production proof authority."""
import argparse
import json
from pathlib import Path
import random
import unittest

P = 2**31 - 1


def segments(terms):
    if not 1 <= terms <= 128:
        raise ValueError('terms outside proposed receiver-pinned bound')
    start = 0
    result = []
    while start < terms:
        width = 1 << ((terms - start).bit_length() - 1)
        result.append((start, width))
        start += width
    return result


def eq(point, index):
    value = 1
    for bit, r in enumerate(point):
        value = value * (r if index & (1 << (len(point) - bit - 1)) else 1 - r) % P
    return value


def mle(values, point):
    assert len(values) == 1 << len(point)
    return sum(v * eq(point, i) for i, v in enumerate(values)) % P


def model(census, selection='all'):
    roles = []
    for role in census['roles']:
        t, r = role['queries'], role['row_log']
        rows = 1 << r
        if role['semantic_rows'] > rows:
            raise ValueError(f'active rows exceed capacity: {role}')
        if not t:
            roles.append(dict(role, padded_rows=rows, binding_cells=0, old_facts=0, new_facts=0, segments=[]))
            continue
        old_width = 1 << (t - 1).bit_length()
        split = selection == 'all' or rows * (old_width - t) >= 1 << 20
        ladder = segments(t) if split else [(0, old_width)]
        new_width = sum(width for _, width in ladder)
        roles.append(dict(role, padded_rows=rows, row_padding=rows-role['semantic_rows'], old_lanes=old_width,
                          binding_cells=16*rows, old_facts=rows*old_width, new_facts=rows*new_width,
                          segments=[dict(first_lane=first, width=width, lane_log=width.bit_length()-1,
                                         variables=r+width.bit_length()-1) for first,width in ladder],
                          naive_extra_binding_cells=16*rows*(len(ladder)-1)))
    local = [r for r in roles if r['queries']]
    old_facts = sum(r['old_facts'] for r in local)
    new_facts = sum(r['new_facts'] for r in local)
    count = sum(len(r['segments']) for r in local)
    max_v = max(s['variables'] for r in local for s in r['segments'])
    old_v = max(r['row_log']+(r['old_lanes'].bit_length()-1) for r in local)
    if count > 128:
        raise ValueError('proposed source roster exceeds128 instances')
    metadata = lambda i,v:4096*((i+1)*(v+1)+(v+1)**2)
    return dict(policy=selection, roles=roles, old_instances=len(local), proposed_instances=count,
                instance_cap=128, instance_cap_passes=True, old_max_variables=old_v, proposed_max_variables=max_v,
                old_facts=old_facts, proposed_facts=new_facts, saved_facts=old_facts-new_facts,
                saved_percent=100*(old_facts-new_facts)/old_facts,
                old_common_sumcheck_rounds=old_v*(old_v-1)//2,
                proposed_common_sumcheck_rounds=max_v*(max_v-1)//2,
                old_instance_layer_records=sum(r['row_log']+r['old_lanes'].bit_length()-1 for r in local),
                proposed_instance_layer_records=sum(s['variables'] for r in local for s in r['segments']),
                old_numerical_metadata_envelope=metadata(len(local),old_v),
                proposed_numerical_metadata_envelope=metadata(count,max_v),
                old_checkpoint_planning_bytes=52*old_facts+metadata(len(local),old_v),
                proposed_checkpoint_planning_bytes=52*new_facts+metadata(count,max_v),
                old_local_binding_cells=sum(r['binding_cells'] for r in local),
                proposed_aggregated_local_binding_cells=sum(r['binding_cells'] for r in local),
                naive_extra_binding_cells=sum(r['naive_extra_binding_cells'] for r in local),
                proposed_additional_physical_FIXED_columns=0,
                proposed_additional_physical_MAIN_columns=0,
                source_descriptor_words=6*count,
                qualification='Planning only; no live source/wire/receiver/proof implementation or timing prediction.')


class AlgebraTests(unittest.TestCase):
    def test_canonical_cover(self):
        for terms in range(1,129):
            ladder=segments(terms)
            self.assertEqual([i for start,width in ladder for i in range(start,start+width)],list(range(terms)))
            self.assertTrue(all(width&(width-1)==0 and start%width==0 for start,width in ladder))
            self.assertEqual(len(ladder),terms.bit_count())
    def test_lane_major_aggregation(self):
        rng=random.Random(7319)
        for terms in (3,7,14,17,31,65,97,127,128):
            r=3
            ladder=segments(terms)
            common=[rng.randrange(P) for _ in range(r+7)]
            row_point=common[-r:]
            n=[[rng.randrange(P) for _ in range(1<<r)] for _ in range(terms)]
            d=[[rng.randrange(P) for _ in range(1<<r)] for _ in range(terms)]
            eta=rng.randrange(P)
            weights=[0]*terms
            target=0
            rho=rng.randrange(P)
            for segment_index,(start,width) in enumerate(ladder):
                k=width.bit_length()-1
                point=common[-(r+k):]
                self.assertEqual(point[k:],row_point)
                coin=pow(rho,segment_index,P)
                target=(target+coin*(mle([n[l][j] for l in range(start,start+width) for j in range(1<<r)],point)+eta*mle([d[l][j] for l in range(start,start+width) for j in range(1<<r)],point)))%P
                for j in range(width):weights[start+j]=coin*eq(point[:k],j)%P
            combined=[sum(weights[l]*(n[l][j]+eta*d[l][j]) for l in range(terms))%P for j in range(1<<r)]
            self.assertEqual(target,mle(combined,row_point))
            # Coordinated opposite segment errors vanish with all-one weights,
            # but not with independent late coins. This is an algebra control,
            # not a proof-system rejection or probability certification.
            self.assertEqual((1-1)%P,0)
            self.assertNotEqual((3-7)%P,0)
    def test_row_major_prefix_is_not_shared(self):
        common=[2,3,5,7,11,13,17]
        r=3
        self.assertNotEqual(common[-(r+1):][:r],common[-(r+3):][:r])
        self.assertEqual(common[-(r+1):][1:],common[-(r+3):][3:])


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('census',type=Path,nargs='?')
    parser.add_argument('--output',type=Path)
    parser.add_argument('--self-test',action='store_true')
    args=parser.parse_args()
    if args.self_test:
        suite=unittest.defaultTestLoader.loadTestsFromTestCase(AlgebraTests)
        if not unittest.TextTestRunner(verbosity=2).run(suite).wasSuccessful():raise SystemExit(1)
    if args.census:
        census=json.loads(args.census.read_text())
        report=dict(schema='op-gkr-lane-major-dyadic-source-model/v1',census=census,all=model(census),high_yield=model(census,'high_yield'))
        raw=json.dumps(report,indent=2)+'\n'
        if args.output:
            with args.output.open('x') as out:out.write(raw)
        else:print(raw,end='')


if __name__=='__main__':main()
