#!/usr/bin/env python3
"""Pinned real Ethereum caller-containing original. Global RAM/recursion OPEN."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
from v7_real_window_corpus import ROOT, PINS, checked_bytes, snapshot_bytes


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('bundle','snapshots','binary','build-manifest','destination'):
        parser.add_argument('--'+name,type=Path,required=True)
    parser.add_argument('--capture-sha256',required=True)
    parser.add_argument('--workers',type=int,default=8)
    parser.add_argument('--profile',action='store_true')
    parser.add_argument('--batch-native-projections',action='store_true')
    parser.add_argument('--complete-bundle',action='store_true',help='close the same endpoint commitment through bridge and compact global RAM')
    parser.add_argument('--native-wide-shards',action='store_true',help='use explicit wide native geometry with unchanged caller clock semantics')
    parser.add_argument('--max-cycles',type=int,default=1<<20)
    parser.add_argument('--caller-bytes',type=int,default=4<<30)
    parser.add_argument('--full-execution-boundaries',action='store_true')
    parser.add_argument('--total-cycles',type=int,default=139214856)
    args=parser.parse_args()
    if not 1<=args.workers<=64:parser.error('workers must be between 1 and 64')
    if args.max_cycles<=0 or args.max_cycles>1<<24 or args.caller_bytes<=0:parser.error('invalid source resource bounds')
    if (args.native_wide_shards or args.max_cycles!=1<<20 or args.caller_bytes!=4<<30) and not args.complete_bundle:parser.error('source geometry options require --complete-bundle')
    if args.complete_bundle and (args.profile or args.batch_native_projections):parser.error('complete bundle currently uses its canonical source schedule')
    if args.full_execution_boundaries and (not args.complete_bundle or args.total_cycles<=0):parser.error('full execution boundaries require complete bundle and positive total cycles')
    cap=args.snapshots/'capture.json'
    if cap.stat().st_size>1<<20 or sha(cap)!=args.capture_sha256:raise ValueError('capture mismatch')
    capture=json.loads(cap.read_text())
    checked_bytes(args.bundle/'guest.elf','guest.elf')
    if args.full_execution_boundaries:
        checked_bytes(args.bundle/'input.bin','input.bin')
        checked_bytes(args.bundle/'expected-output.bin','expected-output.bin')
    if capture['elf_sha256']!=PINS['guest.elf'][0]:raise ValueError('ELF mismatch')
    manifest=json.loads(args.build_manifest.read_text())
    if sha(args.binary)!=manifest['binary_sha256']:raise ValueError('frozen executable mismatch')
    if args.destination.exists():raise ValueError('preserving existing evidence')
    args.destination.mkdir(parents=True)
    shutil.copy2(args.build_manifest,args.destination/'build.json')
    env={k:v for k,v in os.environ.items() if not k.startswith('STWO_')}
    with tempfile.TemporaryDirectory(prefix='stwo-b8-mixed-') as temporary:
        staging=Path(temporary)
        for name in ('incoming.b7win','outgoing.b7win'):(staging/name).write_bytes(snapshot_bytes(args.snapshots,name))
        settings={'ENABLE':'1','ELF':str((args.bundle/'guest.elf').resolve()),'ELF_SHA256':capture['elf_sha256'],
            'INCOMING':str(staging/'incoming.b7win'),'OUTGOING':str(staging/'outgoing.b7win'),
            'INCOMING_SHA256':capture['incoming_sha256'],'OUTGOING_SHA256':capture['outgoing_sha256'],
            'SKIP':str(capture['window']['skip_cycles']),'CYCLES':str(capture['window']['cycles']),
            'WORKERS':str(args.workers),'BATCH_NATIVE':'1' if args.batch_native_projections else '0','PROFILE':'1' if args.profile else '0','OUTPUT':str(args.destination.resolve())}
        settings.update(COMPLETE_BUNDLE='1' if args.complete_bundle else '0',NATIVE_WIDE='1' if args.native_wide_shards else '0',MAX_CYCLES=str(args.max_cycles),CALLER_BYTES=str(args.caller_bytes))
        env.update({'STWO_B8_MIXED_'+k:v for k,v in settings.items()})
        if args.full_execution_boundaries:
            env.update(STWO_B8_FULL_INPUT=str((args.bundle/'input.bin').resolve()),STWO_B8_EXPECTED_OUTPUT=str((args.bundle/'expected-output.bin').resolve()),STWO_B8_FULL_INPUT_SHA256=PINS['input.bin'][0],STWO_B8_EXPECTED_OUTPUT_SHA256=PINS['expected-output.bin'][0],STWO_B8_TOTAL_CYCLES=str(args.total_cycles))
        command=['/usr/bin/time','-l',str(args.binary.resolve())]
        invocation=dict(schema='stwo-b8-real-mixed-original-invocation-v1',binary_sha256=sha(args.binary),
            build_manifest_sha256=sha(args.build_manifest),runner_sha256=sha(Path(__file__)),capture_sha256=args.capture_sha256,
            window=capture['window'],elf_sha256=capture['elf_sha256'],incoming_sha256=capture['incoming_sha256'],
            outgoing_sha256=capture['outgoing_sha256'],workers=args.workers,allocator='std.heap.smp_allocator',
            profiled=args.profile,batch_native_projections=args.batch_native_projections,native_wide_shards=args.native_wide_shards,complete_bundle=args.complete_bundle,full_execution_boundaries=args.full_execution_boundaries,total_cycles=args.total_cycles if args.full_execution_boundaries else None,cpu_only=True,global_ram_closed=False,recursive_root=False,ethereum_block=False,skipped_prefix_proved=False,
            command=command,started_unix_ns=time.time_ns(),report_checked=False)
        invocation_path=args.destination/'invocation.json'
        invocation_path.write_text(json.dumps(invocation,indent=2)+'\n')
        with (args.destination/'qualification.log').open('wb') as log:
            result=subprocess.run(command,cwd=ROOT,env=env,stdout=log,stderr=subprocess.STDOUT,check=False)
        invocation.update(returncode=result.returncode,finished_unix_ns=time.time_ns())
        invocation_path.write_text(json.dumps(invocation,indent=2)+'\n')
        if result.returncode:return result.returncode
        report=json.loads((args.destination/'report.json').read_text())
        if args.complete_bundle:
            if report['schema']!='stwo-b8-real-mixed-complete-bundle-benchmark-v1' or report['window']!=capture['window']:raise ValueError('complete bundle scope mismatch')
            if (report['security_queries'],report['security_pow_bits'],report['workers'],report['allocator'],report['native_wide_shards'])!=(70,26,args.workers,'std.heap.smp_allocator',args.native_wide_shards):raise ValueError('complete bundle configuration mismatch')
            if report['initial_boundary']!=(args.full_execution_boundaries and capture['window']['skip_cycles']==0) or report['terminal_boundary']!=(args.full_execution_boundaries and capture['window']['skip_cycles']+capture['window']['cycles']==args.total_cycles):raise ValueError('execution boundary mode mismatch')
            verified=report['verified']
            if verified['scope']!='declared_window_originals_closed' or verified['cycles']!=capture['window']['cycles'] or verified['external_retirements']<=0:raise ValueError('incomplete mixed original closure')
            artifacts=args.destination/'artifacts'
            expected={'local-0.json':None,'local-0.proof':b'B8MIS001','bridge-0.proof':b'B8GBR001','global-memory.proof':b'B8CMR001','global-public.json':None}
            recorded={}
            for name,magic in expected.items():
                path=artifacts/name
                if not path.is_file() or path.stat().st_size==0:raise ValueError('missing durable original artifact: '+name)
                if magic:
                    with path.open('rb') as source:
                        if source.read(8)!=magic:raise ValueError('wrong original family: '+name)
                recorded[name]={'bytes':path.stat().st_size,'sha256':sha(path)}
            invocation.update(report_checked=True,global_ram_closed=True,report_sha256=sha(args.destination/'report.json'),artifacts=recorded)
            invocation_path.write_text(json.dumps(invocation,indent=2)+'\n')
            print(json.dumps(dict(destination=str(args.destination),whole_s=report['whole_ns']/1e9,stages=report['stages'],peak_bytes=report['charged_peak_bytes'],recursive_root=False)))
            return 0
        if report['schema']!='stwo-b8-real-mixed-original-benchmark-v1' or report['window']!=capture['window']:raise ValueError('scope mismatch')
        if (report['security_queries'],report['security_pow_bits'],report['workers'],report['allocator'],report['program_flavor'])!=(70,26,args.workers,'std.heap.smp_allocator','sparse_elf'):raise ValueError('configuration mismatch')
        if report.get('profiled',False)!=args.profile:raise ValueError('profiling mode mismatch')
        if report.get('batch_native_projections',False)!=args.batch_native_projections:raise ValueError('native projection schedule mismatch')
        verified=report['verified']
        if verified['scope']!='mixed_execution_global_ram_open' or verified['cycles']!=capture['window']['cycles']:raise ValueError('incorrect original theorem')
        census=report['caller_statement']
        expected=capture.get('stats',{})
        for actual,key in [(census['ethereum']['counts']['keccak_calls'],'keccak_calls'),(census['ethereum']['counts']['signer_calls'],'recovery_calls'),(census['sha']['call_count'],'sha_calls')]:
            if key in expected and actual!=expected[key]:raise ValueError('caller census mismatch')
        if verified['external_retirements']<=0:raise ValueError('not a mixed workload')
        artifacts=args.destination/'artifacts'
        for name,prefix in [('original.proof','proof'),('source.json','metadata')]:
            artifact_path=artifacts/name
            if artifact_path.stat().st_size!=report[prefix+'_bytes'] or sha(artifact_path)!=report[prefix+'_sha256']:raise ValueError('artifact mismatch')
        if (artifacts/'original.proof').read_bytes()[:8]!=b'B8MIS001':raise ValueError('wrong protocol')
        invocation.update(report_checked=True,report_sha256=sha(args.destination/'report.json'))
        invocation_path.write_text(json.dumps(invocation,indent=2)+'\n')
    print(json.dumps(dict(destination=str(args.destination),whole_s=report['whole_ns']/1e9,original_s=report['original_ns']/1e9,verification_s=report['verification_ns']/1e9,peak_bytes=report['charged_peak_bytes'])))
    return 0


if __name__=='__main__':raise SystemExit(main())
