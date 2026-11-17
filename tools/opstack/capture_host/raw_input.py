#!/usr/bin/env python3
"""Convert a pinned fixture to already supported RAW OPD; never trust host decoding.

The claim, preimage/sidecar bytes and ordering stay byte-exact. The new input
SHA/initial image MUST be pinned independently. Native replay is explicit;
default operation performs no execution, network, RV64 or STARK work.
"""
import argparse
import json
from pathlib import Path
import subprocess
import sys
import time
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import transition_capture as C
from capture_host.unpack_fixture import decode
from capture_host.verify_export import run_native, expected_statement


def raw_variant(data, claim, maximum_input=C.MAX_INPUT):
    if type(maximum_input) is not int or not C.HEADER <= maximum_input <= C.MAX_INPUT:
        raise ValueError('raw transport cap')
    if len(data) > maximum_input:
        raise ValueError('raw source input cap')
    shape, body = C.unpack_container(data, claim)
    if C.HEADER + len(body) > maximum_input:
        raise ValueError('raw input exceeds selected transport cap')
    output = b'STWOPD01' + data[8:C.HEADER] + body
    return output, {
        'schema': 'op-existing-raw-input-variant-v1',
        'source_input_bytes': len(data), 'source_input_sha256': C.sha(data),
        'input_bytes': len(output), 'input_sha256': C.sha(output),
        'body_bytes': len(body), 'body_sha256': C.sha(body),
        'records': shape['records'], 'sidecars': shape['sidecars'],
        'claim_and_payload_byte_exact': True, 'format': 'STWOPD01',
        'guest_inflation_removed': data[:8] == b'STWOPDZ1',
        'initial_image_repin_required': True,
        'preimage_hashes_verified': False, 'kzg_verified': False,
        'native_derivation_accepted': False, 'guest_executed': False,
        'proof_verified': False, 'proving_speedup_measured': False,
    }


def convert(manifest, output, native_host=None):
    data, pinned = decode(manifest)
    raw, result = raw_variant(data, pinned['claim'])
    C.write_new(output, raw)
    if native_host is not None:
        host = native_host.resolve()
        statement, seconds = run_native(host, output, output.parent/(output.stem+'-reads.json'), output.parent, time.monotonic()+180)
        od = expected_statement(statement, pinned['claim'], pinned['statement']['block_hash'])
        if statement != pinned['statement'] or od.hex() != pinned['od_public_output']:
            raise ValueError('raw native statement differs from pinned fixture')
        result.update(native_derivation_accepted=True, native_seconds=seconds,
                      native_host_sha256=C.sha(host.read_bytes()), od_public_output=od.hex())
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manifest', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--native-host', type=Path)
    args = parser.parse_args()
    try:
        print(json.dumps(convert(args.manifest, args.output, args.native_host), indent=2))
    except (ValueError, OSError, KeyError, TypeError, subprocess.SubprocessError) as error:
        print(json.dumps({'status': 'raw_variant_rejected', 'error_type': type(error).__name__}))
        raise SystemExit(1) from None
