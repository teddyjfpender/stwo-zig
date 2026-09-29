#!/usr/bin/env python3
"""Compile authenticated Cairo cubins in a local ARM64 Linux CPU container."""
from __future__ import annotations
import argparse
import concurrent.futures
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import time

from cuda_build_lib.builder import Toolchain, aot_compile_command
from cuda_build_lib.cubin_import import SCHEMA, digest, validate_elf
from cuda_build_lib.product_selection import validate_aot_manifest

ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--container-cli', type=Path, required=True)
    parser.add_argument('--container-name', default='stwo-cuda-compiler')
    parser.add_argument('--work-root', type=Path, required=True, help='host directory mounted at /work')
    parser.add_argument('--witness-dir', type=Path, required=True)
    parser.add_argument('--eval-dir', type=Path, required=True)
    parser.add_argument('--jobs', type=int, default=4)
    parser.add_argument('--timeout', type=int, default=600)
    args = parser.parse_args()
    if not 1 <= args.jobs <= 8 or args.timeout < 1:
        parser.error('jobs must be 1..8 and timeout positive')
    work = args.work_root.resolve()
    destination = work / 'native-cubins'
    destination.mkdir(exist_ok=True)
    toolkit = Path('/work/nvidia-toolkit/cuda-arm64')
    def guest(command):
        return subprocess.check_output([str(args.container_cli), 'exec', args.container_name, *command], text=True, timeout=60).strip()
    query = "import hashlib,json,pathlib,subprocess; paths=['/work/nvidia-toolkit/cuda-arm64/bin/nvcc','/usr/bin/g++',subprocess.check_output(['g++','-print-prog-name=cc1plus'],text=True).strip()]; print(json.dumps([hashlib.file_digest(pathlib.Path(p).open('rb'),'sha256').hexdigest() for p in paths]))"
    hashes = json.loads(guest(['python3', '-c', query]))
    producer = {'provider': 'nvidia_nvcc', 'host_arch': 'linux-arm64', 'nvcc_sha256': hashes[0],
                'host_cxx_sha256': hashes[1], 'host_cc1plus_sha256': hashes[2],
                'nvcc_version': guest([str(toolkit/'bin/nvcc'), '--version']),
                'host_cxx_version': guest(['g++','--version']),
                'toolkit_manifest_sha256': digest(work/'nvidia-toolkit/redistrib_12.8.1.json')}
    # Bind the actual materialized toolkit, not only its download manifest.
    tree = hashlib.sha256()
    for path in sorted((work/'nvidia-toolkit/cuda-arm64').rglob('*')):
        if path.is_file():
            name = path.relative_to(work/'nvidia-toolkit/cuda-arm64').as_posix().encode()
            tree.update(len(name).to_bytes(8,'little')); tree.update(name)
            tree.update(bytes.fromhex(digest(path)))
    producer['toolkit_tree_sha256'] = tree.hexdigest()
    containers = json.loads(subprocess.check_output([str(args.container_cli), 'list', '--format', 'json'], text=True, timeout=30))
    configuration = next(item['configuration'] for item in containers if item['id'] == args.container_name)
    producer['container_image_digest'] = configuration['image']['descriptor']['digest']
    producer['container_image_reference'] = configuration['image']['reference']
    toolchain = Toolchain(toolkit/'bin/nvcc',Path('/usr/bin/g++'),Path('/usr/bin/ar'),toolkit,toolkit/'lib64',(90,),args.jobs)
    inventory = []
    for original, selected in ((args.witness_dir,'cairo_witness'),(args.eval_dir,'cairo_canonical_eval')):
        original = original.resolve()
        encoded = (original/'aot_manifest.json').read_bytes()
        if encoded != (ROOT/'src/backends/cuda/aot/native'/selected/'aot_manifest.json').read_bytes():
            parser.error('generated catalogue differs from its checked pin')
        entries = json.loads(encoded)
        validate_aot_manifest(original,entries)
        copied = work/'local-native-sources'/selected
        shutil.copytree(original,copied,dirs_exist_ok=True)
        inventory += [(entry,copied/entry['file'],selected) for entry in entries]
    manifest = destination/'manifest.json'
    prior = json.loads(manifest.read_text()) if manifest.exists() else {}
    previous = {(e['cache_key'],e['sm']):e for e in prior.get('entries',[])} if prior.get('producer') == producer else {}
    def fingerprint(entry):
        return (entry['source_sha256'], tuple(entry['flags']), entry['sm'],
                entry['kernel_name'], entry['abi_schema'], entry['module_globals'])
    by_source = {fingerprint(e): e for e in previous.values()}
    complete, failures = [], []
    def compile_one(item):
        entry, source, selected = item
        filename = entry['cache_key']+'-sm_90.cubin'
        output = destination/filename
        command = aot_compile_command(toolchain,source,output,90)
        flags = command[1:command.index(str(source))]
        old = previous.get((entry['cache_key'],90))
        if old is None:
            old = by_source.get((digest(source), tuple(flags), 90, entry['kernel_name'], entry['abi_schema'], entry['module_globals']))
        old_path = destination/old['file'] if old else None
        if old and old['source_sha256'] == digest(source) and old['flags'] == flags and old_path.is_file() and digest(old_path) == old['cubin_sha256']:
            validate_elf(old_path)
            if old_path != output:
                staged = output.with_suffix('.reuse-staged')
                shutil.copyfile(old_path, staged); staged.replace(output)
            old = dict(old, cache_key=entry['cache_key'], file=filename)
            print('REUSE '+entry['label'],flush=True)
            return old
        command[command.index(str(source))] = '/work/local-native-sources/'+selected+'/'+source.name
        command[-1] = '/work/native-cubins/'+filename+'.staged'
        started = time.monotonic()
        with (destination/(filename+'.log')).open('w') as log:
            try:
                result = subprocess.run([str(args.container_cli),'exec',args.container_name,'env','-u','NVCC_PREPEND_FLAGS','-u','NVCC_APPEND_FLAGS',
                           'timeout','--kill-after=5',str(args.timeout),*command],stdout=log,stderr=subprocess.STDOUT,timeout=args.timeout+60)
            except subprocess.TimeoutExpired:
                print('FAIL container deadline '+entry['label'],flush=True)
                return {'failed':entry['label'],'exit_code':124,'elapsed_s':time.monotonic()-started}
        if result.returncode:
            print('FAIL '+entry['label'],flush=True)
            return {'failed':entry['label'],'exit_code':result.returncode,'elapsed_s':time.monotonic()-started}
        staged = output.with_name(filename+'.staged')
        validate_elf(staged)
        staged.replace(output)
        record = {key:entry[key] for key in ('cache_key','kernel_name','abi_schema','module_globals')}
        record.update({'sm':90,'file':filename,'flags':flags,'source_sha256':digest(source),
                       'cubin_sha256':digest(output),'elapsed_s':time.monotonic()-started})
        print('PASS native cubin '+entry['label'],flush=True)
        return record
    def publish(result):
        (failures if 'failed' in result else complete).append(result)
        document = {'schema':SCHEMA,'producer':producer,'entries':complete,'failures':failures,
                    'complete_inventory':len(complete)==len(inventory),'nvidia_proof_verified':False}
        staged = manifest.with_suffix('.staged')
        staged.write_text(json.dumps(document,indent=2)+'\n');staged.replace(manifest)
    # Keep the two pathological compilers isolated within the 32 GB local VM.
    heavy = [item for item in inventory if item[0]['label']=='ec_op_builtin' or item[1].stat().st_size>=256*1024]
    ordinary = [item for item in inventory if item not in heavy]
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.jobs) as pool:
        futures = [pool.submit(compile_one,item) for item in ordinary]
        for future in concurrent.futures.as_completed(futures):
            publish(future.result())
    for item in heavy:
        publish(compile_one(item))
    return 1 if failures else 0


if __name__=='__main__':
    raise SystemExit(main())
