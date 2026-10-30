"""Isolated pinned VM trace-ownership adaptation; no instruction changes."""
from __future__ import annotations

import json
from pathlib import Path
import subprocess
import tomllib

from .bridge import PINS, digest


def consume_trace(checkout: Path, reference: Path, out: Path, stream_relocation: bool = False) -> dict:
    metadata = json.loads(subprocess.check_output([
        'cargo', '+nightly-2025-04-06', 'metadata', '--locked', '--offline', '--format-version', '1'], cwd=reference))
    vm_package = next(p for p in metadata['packages'] if p['name'] == 'cairo-vm' and p['version'] == '2.0.1')
    original = Path(vm_package['manifest_path']).parents[1]
    pin = PINS['keth']['cairo_vm_revision']
    if subprocess.check_output(['git', '-C', str(original), 'rev-parse', 'HEAD'], text=True).strip() != pin:
        raise ValueError('unexpected Cairo VM source revision')
    vm = out / 'cairo-vm'
    subprocess.run(['git', 'clone', '--shared', '--no-checkout', str(original), str(vm)], check=True)
    subprocess.run(['git', '-C', str(vm), 'checkout', '--detach', pin], check=True)
    source = vm / 'vm/src/vm/runners/cairo_runner.rs'
    original_hash = digest(source)
    text = source.read_text()
    start = text.index('    pub fn relocate_trace(&mut self, relocation_table: &[usize])')
    end = text.index('    /// Relocates the VM\'s memory', start)
    replacement = '''    pub fn witness_buffer_bytes(&self) -> (usize, usize, usize) {
        fn bytes<T>(v: &Vec<T>) -> usize { v.capacity() * std::mem::size_of::<T>() }
        let memory = &self.vm.segments.memory;
        let vm_bytes = memory.data.iter().chain(memory.temp_data.iter()).map(bytes).sum();
        let relocated = bytes(&self.relocated_memory);
        let trace = self.vm.trace.as_ref().map(bytes).unwrap_or(0)
            + self.relocated_trace.as_ref().map(bytes).unwrap_or(0);
        (vm_bytes, relocated, trace)
    }

    pub fn relocate_trace(&mut self, relocation_table: &[usize]) -> Result<(), TraceError> {
        if self.relocated_trace.is_some() {
            return Err(TraceError::AlreadyRelocated);
        }
        let segment_1_base = *relocation_table.get(1).ok_or(TraceError::NoRelocationFound)?;
        let trace = self.vm.trace.as_ref().ok_or(TraceError::TraceNotEnabled)?;
        // Validate before taking ownership, preserving the failure behavior.
        for entry in trace {
            relocate_trace_register(entry.pc, relocation_table)?;
            entry.ap.checked_add(segment_1_base).ok_or(TraceError::NoRelocationFound)?;
            entry.fp.checked_add(segment_1_base).ok_or(TraceError::NoRelocationFound)?;
        }
        let trace = self.vm.trace.take().ok_or(TraceError::TraceNotEnabled)?;
        // Consume the raw trace so it is released after relocation. Allocation
        // reuse depends on the compiler and layouts; measure the actual peak.
        let relocated_trace = trace.into_iter().map(|entry| RelocatedTraceEntry {
            pc: relocate_trace_register(entry.pc, relocation_table).expect("prevalidated trace PC"),
            ap: entry.ap + segment_1_base,
            fp: entry.fp + segment_1_base,
        }).collect();
        self.relocated_trace = Some(relocated_trace);
        Ok(())
    }

'''
    text = text[:start] + replacement + text[end:]
    if stream_relocation:
        from .keth_streamed_relocation import VM_METHOD
        text = text.replace('    pub fn witness_buffer_bytes(', VM_METHOD + '    pub fn witness_buffer_bytes(', 1)
    position = text.rfind('\n}')
    test = '''
    #[test]
    fn consumed_trace_relocation_preserves_registers() {
        let program = program!();
        let mut runner = cairo_runner!(program);
        runner.vm.trace = Some((0..1024).map(|i| TraceEntry {
            pc: (0, i).into(), ap: i + 1, fp: i + 2,
        }).collect());
        runner.relocate_trace(&[7, 100_000]).unwrap();
        assert!(runner.vm.trace.is_none());
        let relocated = runner.relocated_trace.as_ref().unwrap();
        assert_eq!(relocated.len(), 1024);
        for (i, entry) in relocated.iter().enumerate() {
            assert_eq!((entry.pc, entry.ap, entry.fp), (i + 7, i + 100_001, i + 100_002));
        }
    }
'''
    source.write_text(text[:position] + test + text[position:])
    vm_patch = subprocess.check_output(['git', '-C', str(vm), 'diff', '--', str(source.relative_to(vm))])
    (out / 'trace-ownership.patch').write_bytes(vm_patch)
    manifest = checkout / 'Cargo.toml'
    manifest_text = manifest.read_text()
    old = 'cairo-vm = { git = "https://github.com/kkrt-labs/cairo-vm", rev = "' + pin + '" }'
    if manifest_text.count(old) != 1:
        raise ValueError('unexpected Cairo VM workspace patch')
    path_value = json.dumps(str(vm / 'vm'))
    manifest_text = manifest_text.replace(old, 'cairo-vm = { path = ' + path_value + ' }')
    direct = 'cairo-vm = { git = "https://github.com/lambdaclass/cairo-vm.git", tag = "v2.0.1", features = ['
    if manifest_text.count(direct) != 1:
        raise ValueError('unexpected direct Cairo VM dependency')
    manifest_text = manifest_text.replace(direct, 'cairo-vm = { path = ' + path_value + ', features = [')
    manifest_text += '\n[patch."https://github.com/kkrt-labs/cairo-vm"]\ncairo-vm = { path = ' + path_value + ' }\n'
    manifest.write_text(manifest_text)
    before = tomllib.loads((reference / 'Cargo.lock').read_text())['package']
    lock = checkout / 'Cargo.lock'
    source_line = 'source = "git+https://github.com/kkrt-labs/cairo-vm?rev=' + pin + '#' + pin + '"\n'
    lock_text = lock.read_text()
    if lock_text.count(source_line) != 1:
        raise ValueError('unexpected Cairo VM lock identity')
    lock.write_text(lock_text.replace(source_line, ''))
    subprocess.run(['cargo', '+nightly-2025-04-06', 'metadata', '--format-version', '1'],
                   cwd=checkout, check=True, stdout=subprocess.DEVNULL)
    after = tomllib.loads((checkout / 'Cargo.lock').read_text())['package']
    def dependencies(packages):
        return sorted(json.dumps(p, sort_keys=True) for p in packages if p['name'] != 'cairo-vm')
    if dependencies(before) != dependencies(after):
        raise ValueError('trace ownership build changed unrelated locked dependencies')
    return dict(cairo_vm_revision=pin, original_runner_sha256=original_hash,
                adapted_runner_sha256=digest(source), patch_sha256=digest(out / 'trace-ownership.patch'),
                source_diff=vm_patch.decode(), package_path=str(vm / 'vm'))


def consume_adapter_trace(text: str) -> str:
    old = '''    let trace = runner
        .relocated_trace
        .as_ref()
        .unwrap()
        .iter()
        .map(|x| RelocatedTraceEntry { ap: x.ap, fp: x.fp, pc: x.pc })
        .collect::<Vec<_>>();'''
    if text.count(old) != 1:
        raise ValueError('unexpected adapter trace copy')
    segments = '''    let segments = public_input
        .memory_segments
        .iter()
        .map(|(&k, v)| {
            (k, MemorySegmentAddresses { begin_addr: v.begin_addr, stop_ptr: v.stop_ptr })
        })
        .collect::<HashMap<_, _>>();'''
    if text.count(segments) != 1:
        raise ValueError('unexpected public segment metadata')
    text = text.replace(segments, '''    let segment_values = public_input.memory_segments.iter()
        .map(|(&name, value)| (name.to_owned(), value.begin_addr, value.stop_ptr)).collect::<Vec<_>>();
    drop(public_input);
    let segments = segment_values.iter().map(|(name, begin_addr, stop_ptr)|
        (name.as_str(), MemorySegmentAddresses { begin_addr: *begin_addr, stop_ptr: *stop_ptr })
    ).collect::<HashMap<_, _>>();''')
    text = text.replace('prover_input_from_runner(runner: &RustCairoRunner)',
                        'prover_input_from_runner(runner: &mut RustCairoRunner, consume_trace: bool)')
    text = text.replace('prover_input_from_runner(&cairo_runner_mut)',
                        'prover_input_from_runner(&mut cairo_runner_mut, !output_trace_components)')
    text = text.replace('prover_input_from_runner(&cairo_runner)', 'prover_input_from_runner(&mut cairo_runner, true)')
    text = text.replace(old, '''    let trace = if consume_trace {
        runner.relocated_trace.take().unwrap().into_iter()
            .map(|x| RelocatedTraceEntry { ap: x.ap, fp: x.fp, pc: x.pc }).collect::<Vec<_>>()
    } else {
        runner.relocated_trace.as_ref().unwrap().iter()
            .map(|x| RelocatedTraceEntry { ap: x.ap, fp: x.fp, pc: x.pc }).collect::<Vec<_>>()
    };''')
    marker = '    let mem = runner.relocated_memory.iter().enumerate().filter_map(|(i, x)| {'
    if text.count(marker) != 1:
        raise ValueError('unexpected relocated memory adapter')
    # All VM execution, output and public segment extraction are finished.
    # Binary component callers retain the original buffers for their export.
    text = text.replace(marker, '''    if consume_trace {
        runner.vm.segments.memory = cairo_vm::vm::vm_memory::memory::Memory::new();
    }
    let mem = runner.relocated_memory.iter().enumerate().filter_map(|(i, x)| {''')
    marker = '    let mem = MemoryBuilder::from_iter(MemoryConfig::default(), mem);'
    text = text.replace(marker, marker + '''
    if consume_trace {
        runner.relocated_memory = Vec::new();
    }''')
    return text
