"""Give legacy CUDA-private host thunks object-local ELF binding.

CUDA and executable bytes are invariant; only the exact old private helper
symbols may leave the object's external symbol table. Original cache is read-only.
"""
import hashlib
from pathlib import Path
import re
import struct
import subprocess


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def protected_sections(path):
    data = path.read_bytes()
    if data[:6] != b'\x7fELF\x02\x01':
        raise ValueError('expected little-endian ELF64 CUDA object')
    offset = struct.unpack_from('<Q', data, 40)[0]
    stride, count, strings = struct.unpack_from('<HHH', data, 58)
    if stride != 64 or not count or strings >= count or offset + count * stride > len(data):
        raise ValueError('invalid ELF section table')
    sections = [struct.unpack_from('<IIQQQQIIQQ', data, offset + i * stride) for i in range(count)]
    names = data[sections[strings][4]:sections[strings][4] + sections[strings][5]]
    result = {}
    for section in sections:
        name_at, _, flags, _, at, size, *_ = section
        if name_at >= len(names):
            raise ValueError('invalid ELF section name')
        name = names[name_at:names.index(b'\0', name_at)].decode()
        if flags & 4 or 'fatbin' in name.lower():
            if at + size > len(data):
                raise ValueError('invalid protected ELF section')
            result[name] = hashlib.sha256(data[at:at + size]).hexdigest()
    if not result:
        raise ValueError('missing executable/CUDA object sections')
    return result


def exports(path):
    text = subprocess.check_output(['nm', '--defined-only', '--extern-only', '--format=posix', str(path)], text=True)
    return {line.split()[0]: line.split()[1] for line in text.splitlines() if line.strip()}


def localize(path, destination):
    original_sha = sha(path)
    before = exports(path)
    candidates = [name for name in before if re.match(r'^_Z\d+rv64_truth_bounded_step_\d+', name)]
    if not candidates:
        return path, None
    demangled = subprocess.check_output(['c++filt', '-n', *candidates], text=True).splitlines()
    suffix = '(unsigned int volatile*, stwo::cuda::rv64::OM31 volatile*, unsigned int const*, unsigned int const*, unsigned int const*, unsigned long const*, unsigned int const*, unsigned int const*, unsigned int, unsigned int, unsigned int)'
    for name in demangled:
        function, arguments = name.split('(', 1)
        if not re.fullmatch(r'rv64_truth_bounded_step_\d+', function) or '(' + arguments != suffix:
            raise ValueError('unrecognized legacy private helper signature: ' + name)
    protected = protected_sections(path)
    destination.mkdir(parents=True, exist_ok=True)
    output = destination / (path.stem + '-' + original_sha[:16] + '.o')
    command = ['objcopy', *['--localize-symbol=' + name for name in candidates], str(path), str(output)]
    subprocess.run(command, check=True)
    if protected_sections(output) != protected or exports(output) != {k: v for k, v in before.items() if k not in candidates}:
        output.unlink(missing_ok=True)
        raise ValueError('private host localization changed code/CUDA bytes or other exports')
    if sha(path) != original_sha:
        raise ValueError('private host localization modified source object')
    return output, {'original': str(path), 'original_sha256': original_sha,
                    'localized': str(output), 'localized_sha256': sha(output),
                    'whitelist': candidates, 'demangled_whitelist': demangled,
                    'unchanged_protected_sections': protected}
